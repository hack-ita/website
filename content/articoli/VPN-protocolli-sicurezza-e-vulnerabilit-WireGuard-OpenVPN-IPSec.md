---
title: 'VPN: protocolli, sicurezza e vulnerabilità (WireGuard, OpenVPN, IPSec)'
slug: vpn
description: >-
  Come funzionano e cosa sono le VPN a livello tecnico: IPSec, OpenVPN,
  WireGuard, L2TP e PPTP. Architettura dei tunnel, attacchi reali,
  misconfigurazioni e analisi in pentest.
image: /VPN.webp
draft: false
date: 2026-03-30T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - wireguard
  - ipsec
featured: true
---

Una VPN non è sicura per definizione. Il livello di sicurezza dipende interamente dal protocollo usato, dalla configurazione, e dall'implementazione — e la differenza tra WireGuard e PPTP è la stessa che c'è tra un lucchetto a combinazione e una corda annodata. Questo articolo non è per chi vuole "navigare anonimo": è per chi vuole capire come funzionano i protocolli VPN a livello tecnico, dove si rompono, e come valutarli in un engagement di sicurezza.

## Cosa imparerai in questa guida

* Come funziona una VPN a livello di rete
* Differenza tra IPSec, OpenVPN e WireGuard
* Errori di configurazione più comuni nelle VPN aziendali
* Come analizzare endpoint VPN durante un pentest
* Quali protocolli VPN sono ancora vulnerabili

***

## VPN: cos'è, come funziona e i rischi di sicurezza dei protocolli VPN

Una VPN (Virtual Private Network) è un tunnel cifrato che trasporta traffico di rete attraverso un'infrastruttura pubblica come se fosse una rete privata. Il risultato è che due endpoint geograficamente separati comunicano come se fossero sullo stesso segmento di rete locale.

Tecnicamente, una VPN opera creando un'**interfaccia di rete virtuale** su ogni endpoint. Il traffico destinato alla rete remota viene:

1. **Incapsulato** in un protocollo di tunneling
2. **Cifrato** (nella maggior parte delle implementazioni moderne)
3. **Trasmesso** attraverso la rete pubblica verso il peer remoto
4. **Decapsulato** e **decifrato** all'altro capo
5. **Re-instradato** verso la destinazione finale

```
Host A [10.0.1.10]                          Host B [10.0.2.20]
     |                                            |
 VPN Client                                  VPN Server
     |                                            |
[Pacchetto originale: 10.0.1.10 → 10.0.2.20]
[Incapsulato: 203.0.113.1 → 203.0.113.2 + cifratura]
     |-------- Internet -------->|
                                 |
                          [Decapsula + Decifra]
                                 |
                          [10.0.1.10 → 10.0.2.20]
```

### VPN site-to-site vs remote access

**Site-to-site VPN:** collega due reti intere attraverso Internet. I gateway VPN (router o firewall) gestiscono il tunneling in modo trasparente agli host. Usata da aziende con sedi multiple per far comunicare le reti locali come se fossero una sola.

**Remote access VPN:** un singolo client (laptop, smartphone) si connette alla rete aziendale attraverso Internet. Il client riceve un IP della rete interna e accede alle risorse come se fosse fisicamente in ufficio. È la VPN "da casa" degli utenti corporate.

Le implicazioni di sicurezza sono diverse: in una site-to-site il perimetro da proteggere è il gateway; in una remote access l'endpoint client è spesso il punto debole.

### Split tunneling: rischio e opportunity

Il **split tunneling** è la configurazione VPN in cui solo il traffico verso la rete aziendale passa nel tunnel, mentre il resto (navigazione web, streaming) va direttamente su Internet senza passare per la VPN.

Dal punto di vista del pentester: se un client con split tunneling è compromesso, si ha accesso diretto alla rete aziendale attraverso la VPN — senza passare dal perimetro aziendale. È uno dei percorsi di accesso più comuni durante un red team.

***

## I protocolli VPN: architettura e sicurezza

### IPSec: il protocollo enterprise standard

IPSec (Internet Protocol Security) è il framework di sicurezza a livello 3 usato dalla maggior parte delle VPN enterprise. Non è un singolo protocollo ma un insieme di standard che coprono autenticazione (AH), cifratura (ESP), e negoziazione delle chiavi (IKE).

Opera in due modalità:

* **Transport mode:** cifra solo il payload del pacchetto IP, lascia l'header in chiaro. Usato per comunicazioni host-to-host.
* **Tunnel mode:** cifra l'intero pacchetto originale e aggiunge un nuovo header IP. Usato per le VPN gateway-to-gateway e remote access.

Il processo di negoziazione avviene tramite **IKE (Internet Key Exchange)** su UDP porta 500 (e 4500 per NAT traversal):

```
Fase 1 (IKEv1) / IKE_SA_INIT (IKEv2):
→ Negozia algoritmi di cifratura, autenticazione, DH group
→ Stabilisce il canale IKE sicuro

Fase 2 (IKEv1) / IKE_AUTH (IKEv2):
→ Negozia le SA (Security Association) IPSec
→ Stabilisce il tunnel dati cifrato
```

Le VPN sono uno dei punti di accesso più critici nelle infrastrutture aziendali moderne, e durante un penetration test gli endpoint VPN sono spesso tra i primi target analizzati.

**Vulnerabilità di IPSec in produzione:**

Il problema non è IPSec come standard — è come viene configurato. Le finding più comuni in un assessment:

* IKEv1 in **Aggressive Mode**: espone l'hash del PSK senza completare l'autenticazione. Catturabile con `ike-scan` e attaccabile offline con hashcat.
* **PSK deboli**: password brevi o basate su dizionario per l'autenticazione IKE
* **DH Group 1 o 2** (768/1024 bit): considerati crittograficamente deboli
* **Algoritmi legacy**: 3DES, MD5, SHA-1 ancora presenti in configurazioni vecchie
* **IKEv1 vs IKEv2**: IKEv2 è più sicuro e robusto, IKEv1 ha più superficie di attacco

```bash
# Reconnaissance su endpoint IPSec
nmap -sU -p 500,4500 --script ike-version <target>

# Enumerazione dettagliata con ike-scan
ike-scan <target>
ike-scan --aggressive --id=vpnclient <target>   # Aggressive Mode test

# Se Aggressive Mode risponde: cattura l'hash PSK
ike-scan --aggressive --id=anyid <target> | grep -i "hash"

# Crack offline
hashcat -m 5300 ike_hash.txt wordlist.txt
```

Per una trattazione tecnica completa di IPSec, vedi [IPSec: cos'è e come attaccarlo](https://hackita.it/articoli/ipsec).

***

### L2TP/IPSec: il tunneling legacy più diffuso

L2TP (Layer 2 Tunneling Protocol) da solo non offre cifratura — è solo un meccanismo di tunneling L2. La combinazione **L2TP/IPSec** usa IPSec per la cifratura e L2TP per il tunneling, ed è stata per anni la VPN remote access standard su Windows, macOS, e iOS.

Architettura:

```
[PPP frame] → [L2TP] → [IPSec ESP] → [UDP/IP]
```

Il traffico L2TP viaggia su **UDP porta 1701**, incapsulato dentro IPSec ESP (quindi cifrato). L'autenticazione PPP (PAP, CHAP, MS-CHAPv2) avviene dentro il tunnel L2TP.

**Problemi di sicurezza:**

L2TP/IPSec con PSK pre-condiviso è vulnerabile agli stessi attacchi di IPSec IKEv1 Aggressive Mode. In più, MS-CHAPv2 — usato per l'autenticazione degli utenti dentro il tunnel — è compromesso dal 2012. Con una singola cattura dell'handshake, la password è recuperabile.

**Rilevanza per il pentesting:**

```bash
# Identificare server L2TP
nmap -sU -p 1701 <target>
nmap -sU -p 500 --script ike-version <target>

# Su Windows compromesso: trovare credenziali L2TP salvate
reg query "HKCU\Software\Microsoft\Network\Connections"
cmdkey /list
```

Per i dettagli su PPP e MS-CHAPv2, vedi [PPP: cos'è e come sfruttarlo](https://hackita.it/articoli/ppp-point-to-point-protocol).

***

### PPTP: la VPN da non usare mai più

PPTP (Point-to-Point Tunneling Protocol) è il protocollo VPN più vecchio ancora in circolazione — ed è completamente compromesso dal punto di vista crittografico.

Usa MS-CHAPv2 per l'autenticazione e RC4 per la cifratura (via MPPE). Entrambi sono deboli:

* **MS-CHAPv2**: l'handshake può essere ridotto a un singolo DES a 56 bit — cracckabile con risorse moderate o servizi online come cloudcracker
* **RC4**: vulnerabile a attacchi bit-flipping e ha debolezze strutturali
* **MPPE**: la chiave di cifratura è derivata dalla password MS-CHAPv2 — se la password è crackata, il traffico passato può essere decifrato

```bash
# Rilevare server PPTP
nmap -p 1723 <target>
nmap -p 1723 --script pptp-version <target>

# Catturare l'handshake MS-CHAPv2 e craccare
# Con hashcat mode 5500 (NetNTLMv1) o asleap/chapcrack per PPTP specifico
```

**Finding in un pentest:** trovare un server PPTP in produzione è sempre una finding critica. Qualsiasi azienda che lo usa ancora ha un problema di sicurezza immediato. L'handshake è catturabile in rete e la password è recuperabile offline.

Per i dettagli tecnici su PPTP e MS-CHAPv2, vedi [PPP: Point-to-Point Protocol](https://hackita.it/articoli/ppp-point-to-point-protocol).

***

### OpenVPN: lo standard open-source sicuro

OpenVPN è un protocollo VPN open-source che usa **TLS** per la cifratura e il controllo della sessione, e può operare su **UDP** (raccomandato, porta 1194 di default) o **TCP** (porta 443, utile per bypass firewall).

Architettura:

```
[Dati applicativi]
→ [TLS 1.2/1.3 — cifratura + autenticazione]
→ [UDP o TCP]
→ [IP]
```

Caratteristiche chiave:

* Usa la stessa libreria TLS dei browser (OpenSSL o mbedTLS)
* Supporta certificati X.509 per autenticazione mutual (più sicuro di PSK)
* Può bypassare firewall restrittivi operando su TCP 443 (appare come traffico HTTPS)
* Supporta configurazioni avanzate: routing selettivo, compressione, plugin di autenticazione

**Superficie di attacco di OpenVPN:**

OpenVPN è sicuro come la sua configurazione. Finding tipiche in assessment:

* **Certificati scaduti o self-signed senza validazione**: client configurati con `--ns-cert-type server` invece di verificare il certificato → vulnerabili a server fake
* **tls-auth o tls-crypt assenti**: senza HMAC authentication pre-TLS, il server risponde a qualsiasi client permettendo DoS e fingerprinting
* **Compressione abilitata**: vulnerabilità VORACLE (2018) — informazioni leakage simile a CRIME/BREACH
* **Versioni vecchie**: OpenVPN \< 2.4 ha vulnerabilità note

```bash
# Identificare server OpenVPN
nmap -sU -p 1194 <target>

# Fingerprinting con nmap
nmap -sU -p 1194 --script openvpn-info <target>

# Test connessione e cattura dell'handshake TLS
tcpdump -i eth0 -nn udp port 1194 -w openvpn_capture.pcap

# Analisi in Wireshark
# tls.handshake.type == 1  (ClientHello)
```

Per i dettagli su TLS e le sue vulnerabilità, vedi [TLS/SSL: cos'è e come analizzarlo](https://hackita.it/articoli/tls-ssl).

***

### WireGuard: il nuovo standard minimalista

WireGuard è il protocollo VPN moderno che ha ridefinito il settore. Introdotto nel kernel Linux 5.6 (2020), è ora disponibile su tutte le piattaforme principali.

La filosofia è opposta a OpenVPN e IPSec: **meno codice, meno superficie di attacco, più performance**.

**Stack crittografico fisso (non negoziabile):**

* Scambio chiavi: **Curve25519** (ECDH)
* Cifratura: **ChaCha20-Poly1305** (AEAD)
* Hash: **BLAKE2s**
* MAC: **Poly1305**
* Key derivation: **HKDF**

Non ci sono cipher suite da negoziare — niente downgrade attack. Se il peer non supporta questi algoritmi, non si connette.

**Architettura:**

```
[Pacchetti IP] → [ChaCha20-Poly1305 encryption] → [UDP]
```

WireGuard opera **solo su UDP**, a una porta configurabile (default 51820). Ogni peer ha una coppia di chiavi pubblica/privata. La configurazione è distribuita fuori banda (il server conosce la chiave pubblica dei client autorizzati).

**Differenze chiave rispetto a IPSec e OpenVPN:**

|                    | WireGuard       | OpenVPN            | IPSec            |
| ------------------ | --------------- | ------------------ | ---------------- |
| Linee di codice    | \~4.000         | \~100.000          | \~400.000        |
| Algoritmi fissi    | Sì              | No (configurabili) | No (negoziabili) |
| Protocollo         | UDP only        | UDP + TCP          | UDP (IKE)        |
| NAT traversal      | Nativo          | Manuale            | NAT-T (UDP 4500) |
| Kernel integration | Sì (Linux 5.6+) | No (userspace)     | Sì               |
| Performance        | Molto alta      | Media              | Alta             |

**Superficie di attacco di WireGuard:**

WireGuard è giovane e ha avuto meno audit rispetto a OpenVPN/IPSec. Le considerazioni di sicurezza principali:

* **Privacy by design limitata**: WireGuard associa IP statici ai peer — non è progettato per l'anonimato, le connessioni sono tracciabili per IP
* **Nessun Perfect Forward Secrecy automatico** per le chiavi di lungo periodo: se la chiave privata è compromessa, le sessioni future (non passate, grazie al handshake ephemeral) sono a rischio
* **Chiavi hardcoded**: se un endpoint è compromesso, le chiavi WireGuard sono nel filesystem

```bash
# Identificare endpoint WireGuard
nmap -sU -p 51820 <target>

# WireGuard risponde solo a handshake validi — non ci sono banner
# La detection è basata su comportamento UDP e dimensione dei pacchetti

# Su sistema compromesso: trovare chiavi e configurazione
cat /etc/wireguard/wg0.conf
wg show   # Stato del tunnel, peer connessi, chiavi pubbliche
```

***

### GRE: tunneling senza cifratura

GRE (Generic Routing Encapsulation) è un protocollo di tunneling **senza cifratura nativa**. È usato principalmente come trasporto per altri protocolli — la combinazione GRE over IPSec è comune in reti enterprise.

```
[Pacchetto originale] → [GRE header] → [IPSec ESP] → [IP esterno]
```

GRE puro (senza IPSec) è visibile in chiaro a chiunque intercetti il traffico. Trovarlo in produzione è spesso una finding: significa che il traffico tra due siti viaggia non cifrato su Internet.

Per i dettagli tecnici su GRE e come identificarlo in rete, vedi [GRE: cos'è e come sfruttarlo in un pentest](https://hackita.it/articoli/gre-generic-routing-encapsulation).

***

## Differenza tra VPN e proxy

Una confusione comune che vale la pena chiarire in chiave tecnica:

|                  | VPN                                   | Proxy                             |
| ---------------- | ------------------------------------- | --------------------------------- |
| Layer OSI        | L3 (rete)                             | L7 (applicativo)                  |
| Traffico coperto | Tutto (TCP, UDP, ICMP)                | Solo applicativo (HTTP, SOCKS)    |
| Cifratura        | Sì (nella maggior parte)              | Dipende (HTTPS proxy sì, HTTP no) |
| IP sorgente      | Sostituito con quello del gateway VPN | Sostituito con quello del proxy   |
| DNS leak         | Possibile se mal configurata          | Probabile                         |
| Overhead         | Maggiore                              | Minore                            |

Un proxy HTTP non protegge il traffico non-HTTP. Un proxy SOCKS5 gestisce più protocolli ma opera a livello applicativo — non intercetta il traffico a livello di rete. Una VPN cattura tutto il traffico della macchina.

Per il pentesting: un attaccante in posizione MITM vede il traffico proxy non cifrato anche se l'utente pensa di essere "protetto". La VPN (se configurata correttamente) cifra il traffico prima che raggiunga la posizione MITM.

***

## VPN in un engagement di pentesting

### Reconnaissance su endpoint VPN

```bash
# Scansione porte VPN comuni
nmap -sU -p 500,1194,1701,4500,51820 <target>
nmap -p 1194,1723,443 <target>

# Fingerprinting IPSec
ike-scan <target>
ike-scan --aggressive --id=test <target>

# Identificare vendor da banner e comportamento
nmap -sU -p 500 --script ike-version <target>
# Output: Cisco ASA, Fortinet FortiGate, Palo Alto, strongSwan, ecc.
```

### Attacchi su PSK deboli (IPSec/IKEv1)

```bash
# 1. Verifica se Aggressive Mode è abilitato
ike-scan --aggressive --id=anyid <target>

# 2. Se risponde con hash: brute force offline
# Formato hashcat: $v1$* per IKEv1 PSK
hashcat -m 5300 ike_hash.txt /usr/share/wordlists/rockyou.txt --force

# 3. Con PSK crackata: connettersi come client legittimo
```

### Analisi di configurazioni VPN post-compromise

Su un sistema Windows o Linux compromesso, raccogliere tutte le configurazioni VPN:

```bash
# Linux — trovare configurazioni VPN
find /etc -name "*.conf" 2>/dev/null | xargs grep -l "vpn\|tunnel\|ipsec\|wireguard" 2>/dev/null
cat /etc/ipsec.conf
cat /etc/ipsec.secrets   # PSK e certificati!
cat /etc/wireguard/*.conf  # Chiavi private WireGuard

# Windows — credenziali VPN nel registro
reg query "HKCU\Software\Microsoft\Network\Connections" /s
cmdkey /list
# Credenizali salvate in Windows Credential Manager
```

### VPN split tunneling come vettore di accesso

In un red team, identificare client VPN con split tunneling è prioritario:

```bash
# Su sistema Windows compromesso: verificare routing VPN
route print
# Se vedi una route per 10.0.0.0/8 via VPN interface
# ma il resto del traffico va via default gateway:
# → split tunneling attivo → pivot verso rete aziendale

# Verificare l'interfaccia VPN
ipconfig /all | grep -A5 "VPN\|tun\|tap"
```

***

## Protocolli VPN a confronto: quale scegliere per la sicurezza

| Protocollo      | Sicurezza                 | Performance | Compatibilità           | Raccomandazione                   |
| --------------- | ------------------------- | ----------- | ----------------------- | --------------------------------- |
| **WireGuard**   | Molto alta                | Eccellente  | Buona (5+ anni)         | Prima scelta per nuovi deployment |
| **OpenVPN**     | Alta (se ben configurato) | Media       | Eccellente              | Standard per ambienti eterogenei  |
| **IPSec/IKEv2** | Alta                      | Alta        | Nativa su tutti gli OS  | Enterprise e mobile               |
| **L2TP/IPSec**  | Media                     | Media       | Nativa su Windows/macOS | Legacy, da sostituire             |
| **PPTP**        | Compromessa               | Alta        | Universale              | Da non usare mai                  |
| **GRE**         | Nessuna (senza IPSec)     | Molto alta  | Alta                    | Solo con IPSec                    |

***

## Hardening di una VPN: checklist di sicurezza

### IPSec/IKEv2

```
# Configurazione sicura strongSwan
conn secure-vpn
    keyexchange=ikev2           # Mai IKEv1
    ike=aes256gcm16-sha384-ecp384   # Algoritmi forti
    esp=aes256gcm16-sha384         # Perfect forward secrecy
    authby=rsasig               # Certificati, non PSK
    left=%any
    right=client_ip
    auto=add
```

* Disabilitare IKEv1 se non strettamente necessario
* Usare certificati X.509 invece di PSK
* DH Group minimo: Group 14 (2048 bit), meglio Group 19-21 (ECDH)
* Algoritmi: AES-256-GCM, SHA-384/SHA-512
* Abilitare GTSM (TTL Security) per mitigare DoS

### OpenVPN

```
# Configurazione hardened
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
cipher AES-256-GCM
auth SHA384
tls-crypt ta.key       # HMAC pre-autenticazione (previene DoS e fingerprinting)
verify-client-cert require
tls-cert-profile preferred
```

### WireGuard

WireGuard ha algoritmi fissi e non ha opzioni di misconfiguration crittografica. Le raccomandazioni riguardano:

* Proteggere il file di configurazione (contiene la chiave privata): `chmod 600 /etc/wireguard/wg0.conf`
* Ruotare le chiavi periodicamente
* Monitorare i peer connessi: `wg show`
* Non esporre l'endpoint WireGuard su IP pubblici senza necessità

***

## Detection di VPN non autorizzate

In un engagement difensivo, identificare VPN non autorizzate (shadow IT) o tunnel non documentati è importante:

```bash
# Traffico UDP verso porte VPN comuni
tcpdump -i eth0 -nn 'udp port 1194 or udp port 51820 or udp port 500'

# Connessioni TCP verso porta 443 con traffico non-HTTP
# (OpenVPN su TCP 443 bypassa molti firewall)
tshark -r capture.pcap -Y "tcp.port == 443 and not tls"

# Identificare tunnel GRE non documentati
tcpdump -i eth0 -nn proto 47

# Con Zeek: analisi dei flow per identificare pattern VPN
cat conn.log | zeek-cut proto id.resp_p duration | grep "udp" | sort -k2 -n
```

***

## FAQ sulla VPN

**Cos'è una VPN e a cosa serve in sicurezza informatica?**
Una VPN (Virtual Private Network) è un tunnel cifrato che collega due o più endpoint attraverso una rete pubblica. In sicurezza, serve per proteggere il traffico in transito, connettere sedi remote, fornire accesso sicuro alla rete aziendale da remoto, e isolare segmenti di rete. La sicurezza effettiva dipende dal protocollo usato e dalla configurazione.

**Qual è la differenza tra OpenVPN e WireGuard?**
OpenVPN è maturo, flessibile, e altamente configurabile — ma questa flessibilità è anche il suo punto debole: una configurazione errata può renderlo vulnerabile. WireGuard ha un codice base molto più piccolo (\~4.000 righe vs \~100.000), algoritmi crittografici fissi e non negoziabili, e performance superiori. WireGuard è la scelta migliore per nuovi deployment; OpenVPN rimane lo standard per ambienti eterogenei legacy.

**PPTP è sicuro?**
No. PPTP usa MS-CHAPv2 per l'autenticazione e RC4 per la cifratura, entrambi compromessi. L'handshake MS-CHAPv2 può essere ridotto a un attacco DES a 56 bit e crackkato in tempi accettabili. Qualsiasi sistema che usa ancora PPTP in produzione è vulnerabile.

**Qual è la differenza tra VPN site-to-site e remote access?**
La VPN site-to-site collega due reti intere attraverso gateway VPN dedicati — gli host delle due reti comunicano trasparentemente. La remote access VPN connette un singolo client alla rete aziendale, assegnandogli un IP interno. I rischi di sicurezza sono diversi: nel remote access, l'endpoint client è spesso il punto debole.

**Come si identifica un server VPN durante un pentest?**
Con Nmap sulle porte tipiche: UDP 500/4500 (IPSec), UDP 1194 (OpenVPN), UDP 51820 (WireGuard), TCP 1723 (PPTP), UDP 1701 (L2TP). Per IPSec, `ike-scan` fornisce informazioni dettagliate su versione IKE, algoritmi supportati, e vendor. Il banner e il comportamento durante la negoziazione sono spesso sufficienti per identificare il software VPN specifico.

***

## Conclusione sulla VPN

Le VPN non sono tutte uguali. PPTP è morto crittograficamente dal 2012 ma ancora presente in produzione. IPSec in Aggressive Mode con PSK deboli è la finding più comune in assessment enterprise. OpenVPN sicuro ma spesso mal configurato. WireGuard è il futuro — ma richiede gestione attenta delle chiavi.

In un engagement, gli endpoint VPN sono tra i target con il più alto rapporto finding/effort. Trovare IKEv1 Aggressive Mode attivo, un server PPTP esposto, o credenziali VPN salvate su un sistema compromesso sono tutti percorsi diretti verso la rete interna.

Approfondisci i protocolli correlati:

* [IPSec: autenticazione, cifratura e attacchi](https://hackita.it/articoli/ipsec)
* [GRE: tunneling e GRE over IPSec](https://hackita.it/articoli/gre-generic-routing-encapsulation)
* [PPP e PPTP: autenticazione MS-CHAPv2](https://hackita.it/articoli/ppp-point-to-point-protocol)
* [TLS/SSL: la base crittografica di OpenVPN](https://hackita.it/articoli/tls-ssl)
* [UDP: il trasporto di WireGuard e OpenVPN](https://hackita.it/articoli/udp)
* [TCP: OpenVPN su TCP e bypass firewall](https://hackita.it/articoli/tcp)
* [VLAN e 802.1Q: segmentazione per endpoint VPN](https://hackita.it/articoli/vlan-802-1q)
* [Man in the Middle: VPN come protezione e come target](https://hackita.it/articoli/man-in-the-middle)
* [Sniffing: catturare traffico VPN e handshake](https://hackita.it/articoli/sniffing)
* [IPv4/IPv6: dual-stack e VPN split tunneling](https://hackita.it/articoli/ipv4-ipv6)

Riferimento ufficiale: [RFC 4301 — Security Architecture for IPsec](https://datatracker.ietf.org/doc/html/rfc4301) | [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)

***

Le VPN aziendali mal configurate sono una delle porte d'ingresso più comuni nei breach reali. Se vuoi sapere come regge la tua:
[hackita.it/servizi](https://hackita.it/servizi)

Se HackITA ti è utile nel percorso OSCP o nel lavoro quotidiano:
[hackita.it/supporto](https://hackita.it/supporto)
