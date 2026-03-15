---
title: 'IPSec: VPN Enterprise, IKE, ESP e Errori di Configurazione da Sfruttare'
slug: ipsec
description: 'Scopri come funziona IPSec e perché è cruciale nel pentesting di VPN enterprise: IKEv1/IKEv2, ESP, tunnel mode, Aggressive Mode, PSK deboli, ike-scan e difese.'
image: /ipsec.webp
draft: true
date: 2026-03-24T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - ipsec
---

IPSec è il framework di sicurezza per il traffico IP. Capire cos'è IPSec e come funziona è fondamentale per chi fa pentesting su VPN enterprise, reti site-to-site, e accesso remoto: la configurazione di IPSec è complessa, gli errori sono comuni, e una VPN IPSec mal configurata può esporre credenziali, chiavi deboli, o essere completamente bypassata.

***

## Cos'è IPSec

IPSec (Internet Protocol Security) è un framework di protocolli per la sicurezza delle comunicazioni IP, definito in una serie di RFC tra cui **RFC 4301** (architettura), **RFC 4302** (AH) e **RFC 4303** (ESP). Opera al **livello 3 del modello OSI**, cifrando e autenticando i pacchetti IP prima della trasmissione.

A differenza di TLS (che opera a livello applicativo), IPSec è trasparente alle applicazioni: cifra tutto il traffico IP senza richiedere modifiche ai software che lo usano.

IPSec si compone di tre elementi principali:

* **AH (Authentication Header):** fornisce autenticazione e integrità, ma non cifratura
* **ESP (Encapsulating Security Payload):** fornisce cifratura, autenticazione e integrità
* **IKE (Internet Key Exchange):** protocollo per la negoziazione automatica dei parametri di sicurezza e lo scambio di chiavi

Nella pratica moderna, si usa quasi sempre **ESP** (con cifratura + autenticazione) e **IKEv2** per la negoziazione. AH è raramente usato e incompatibile con NAT.

***

## Come funziona IPSec

### Le due modalità: Transport e Tunnel

**Modalità Transport:**
Cifra solo il payload del pacchetto IP originale. L'header IP originale rimane in chiaro. Usata per comunicazioni host-to-host (es. proteggere una singola connessione tra due server).

```
[IP Header originale] [ESP Header] [Payload cifrato] [ESP Trailer/Auth]
```

**Modalità Tunnel:**
Cifra l'intero pacchetto IP originale (header + payload) e aggiunge un nuovo header IP esterno. Il pacchetto originale è completamente nascosto. Usata per VPN site-to-site e accesso remoto.

```
[Nuovo IP Header] [ESP Header] [IP Header orig. cifrato] [Payload cifrato] [ESP Trailer/Auth]
```

In tunnel mode, chi osserva il traffico vede solo gli IP delle estremità del tunnel (i gateway VPN), non gli IP sorgente e destinazione interni.

### SA: Security Association

Una **SA (Security Association)** è un accordo unidirezionale tra due peer che definisce tutti i parametri crittografici di una connessione IPSec:

* Algoritmo di cifratura e chiave
* Algoritmo di autenticazione e chiave
* SPI (Security Parameter Index): identificatore della SA
* Lifetime della SA

Le SA sono archiviate nel **SAD (Security Association Database)**. Poiché sono unidirezionali, una comunicazione bidirezionale richiede due SA.

### SPD: Security Policy Database

L'**SPD (Security Policy Database)** definisce quale traffico deve essere:

* Processato da IPSec (PROTECT)
* Lasciato passare senza IPSec (BYPASS)
* Scartato (DISCARD)

Le policy sono basate su selettori: indirizzo IP sorgente/destinazione, protocollo, porte.

### IKE: Internet Key Exchange

IKE è il protocollo che negozia automaticamente i parametri IPSec e scambia le chiavi. Usa **UDP porta 500** (e 4500 per NAT traversal).

**IKEv1** (legacy): due fasi.

* **Phase 1 (Main Mode o Aggressive Mode):** stabilisce un canale sicuro tra i peer (ISAKMP SA). Negozia cifratura, hash, metodo di autenticazione (PSK o certificati), DH group.
* **Phase 2 (Quick Mode):** usa il canale Phase 1 per negoziare le SA IPSec (ESP/AH).

**IKEv2** (moderno, RFC 7296): più semplice, più robusto, supporta MOBIKE (mobilità), EAP, e ha meno vulnerabilità note. Usa un unico scambio IKE\_SA\_INIT + IKE\_AUTH invece delle due fasi di IKEv1.

### Algoritmi crittografici

Gli algoritmi usati da IPSec variano in base alla configurazione. Classificazione per sicurezza:

| Categoria      | Algoritmi sicuri                         | Algoritmi da evitare        |
| -------------- | ---------------------------------------- | --------------------------- |
| Cifratura      | AES-GCM, AES-CBC (256 bit), ChaCha20     | DES, 3DES, RC4              |
| Integrità/Auth | SHA-256, SHA-384, SHA-512                | MD5, SHA-1                  |
| DH Group       | Group 14+ (2048 bit), 19-21 (ECC), 31-32 | Group 1, 2, 5 (\< 1024 bit) |
| Auth IKE       | Certificati X.509, EAP                   | PSK deboli                  |

***

## Dove viene usato IPSec nelle reti

IPSec è il protocollo VPN enterprise più diffuso:

* **VPN site-to-site:** connessioni tra sedi aziendali tramite tunnel IPSec, spesso combinati con GRE
* **VPN accesso remoto:** client remoti che si connettono alla rete aziendale (IKEv2/IPSec, L2TP/IPSec)
* **Protezione di comunicazioni critiche:** tra server interni (es. database e application server)
* **Cloud enterprise:** AWS, Azure e GCP supportano VPN IPSec per connettere reti on-premise al cloud
* **Reti OT/ICS:** protezione delle comunicazioni tra PLC e SCADA in ambienti industriali moderni

***

## Perché IPSec è importante in cybersecurity

IPSec è complesso da configurare correttamente. Ogni fase — scelta degli algoritmi, autenticazione IKE, gestione delle chiavi — può introdurre vulnerabilità. I problemi più comuni in produzione:

* **PSK deboli:** usare password corte o basate su dizionario per l'autenticazione IKE
* **Algoritmi deboli:** DH Group 2 (1024 bit), MD5, SHA-1 ancora presenti in configurazioni legacy
* **IKEv1 Aggressive Mode:** espone l'hash del PSK senza richiedere che l'attaccante si autentichi
* **Configurazioni split-tunnel:** possono essere sfruttate per raggiungere reti interne
* **Certificati self-signed o scaduti:** VPN client che accettano qualsiasi certificato

Per il tunneling GRE spesso usato insieme a IPSec, vedi [GRE](https://hackita.it/articoli/gre-generic-routing-encapsulation). Per il livello IP su cui opera, vedi [IP Internet Protocol](https://hackita.it/articoli/ip-internet-protocol).

***

## IPSec in un engagement di pentesting

### Reconnaissance: identificare endpoint IPSec/IKE

IKE usa UDP 500 e UDP 4500 (NAT-T). Identificare questi servizi rivela endpoint VPN:

```bash
nmap -sU -p 500,4500 <target>
nmap -sU -p 500 --script ike-version <target>
```

Lo script `ike-version` di Nmap tenta di identificare la versione IKE, il vendor, e i transform set supportati — informazioni utili per scegliere l'attacco appropriato.

### Enumeration con ike-scan

**ike-scan** è lo strumento specifico per l'analisi di endpoint IKE:

```bash
# Probe base
ike-scan <target>

# Con trasform set specifici
ike-scan --trans=5,2,1,2 <target>
# 5=3DES, 2=SHA1, 1=PSK, 2=DH Group2

# Aggressive Mode (rivela hash del PSK)
ike-scan --aggressive --id=vpnclient <target>
```

L'output rivela:

* Versione IKE supportata
* Transform set accettati (algoritmi di cifratura, hash, DH group)
* Se Aggressive Mode è abilitato
* Vendor ID (identifica il software VPN — Cisco, Checkpoint, Fortinet, ecc.)
* Hash del PSK (se Aggressive Mode + PSK)

### Attacco al PSK via Aggressive Mode

IKEv1 in Aggressive Mode è la vulnerabilità più sfruttata su IPSec. Il processo:

1. Il client invia la propria identità (ID) in chiaro
2. Il server risponde con il proprio ID e un hash del PSK basato su challenge
3. L'hash è catturabile senza completare l'autenticazione

```bash
# Catturare l'hash con ike-scan
ike-scan --aggressive --id=vpnclient <target> | grep -i "hash"
```

L'hash catturato può essere attaccato offline con hashcat (mode `-m 5300` per IKEv1 PSK):

```bash
hashcat -m 5300 ike_hash.txt wordlist.txt
```

### Identificare algoritmi deboli

Una configurazione IPSec con DH Group 1 o 2 (768/1024 bit) è vulnerabile a attacchi di tipo Logjam o, teoricamente, a attacchi con risorse computazionali elevate. Ike-scan rivela i transform set accettati:

```bash
ike-scan --showbackoff <target>
```

Documentare transform set con algoritmi deboli è una finding critica da riportare nel pentest report.

### Post-compromise: analisi delle SA attive

Su un host compromesso con tunnel IPSec attivo, è possibile analizzare le SA:

```bash
# Linux
ip xfrm state    # SA attive
ip xfrm policy   # SPD — quali traffico è protetto da IPSec
```

Le SA rivelano gli algoritmi in uso, i peer, e la struttura dei tunnel. Con accesso root, è possibile aggiungere policy SPD per intercettare traffico che normalmente bypasserebbe IPSec.

### Analisi del traffico ESP

Il traffico ESP è cifrato ma i metadati (IP sorgente, destinazione, dimensione dei pacchetti, timing) sono visibili. L'analisi dei pattern di traffico può rivelare:

* Quando i tunnel sono attivi
* Volume di traffico per tunnel (indicatore di attività)
* Peer VPN

Con Wireshark:

```
esp
isakmp    # Traffico IKE in chiaro durante la negoziazione
```

***

## Attacchi e abusi possibili su IPSec

### PSK Cracking via IKEv1 Aggressive Mode

Come descritto: cattura dell'hash del PSK durante la negoziazione Aggressive Mode e attacco offline con hashcat o john.

### Downgrade Attack

Forzare la negoziazione verso transform set con algoritmi più deboli. Se il server accetta transform set multipli inclusi quelli deboli, un attaccante MITM può modificare le offerte IKE per far negoziare algoritmi vulnerabili.

### ISAKMP Flood (DoS)

Inondare l'endpoint con richieste IKE incomplete per esaurire le risorse del processo IKE:

```bash
# Con ike-scan in flood mode
ike-scan --flood <target>
```

### Certificati non validati (VPN client)

Client VPN che accettano qualsiasi certificato (o non verificano il CN/SAN) sono vulnerabili a attacchi Evil Twin: un server VPN malevolo presenta un certificato qualsiasi, il client accetta, e le credenziali EAP vengono catturate.

### Information Disclosure tramite Vendor ID

I Vendor ID nei messaggi IKE rivelano il software VPN in uso (Cisco ASA, Fortinet FortiGate, Checkpoint, strongSwan, ecc.). Questa informazione permette di cercare CVE specifici per quella versione.

***

## Esempi pratici con IPSec in laboratorio

### Setup strongSwan per test IPSec su Linux

```bash
apt install strongswan

# Configurazione minima /etc/ipsec.conf
conn test-tunnel
    type=tunnel
    left=192.168.1.10
    right=192.168.1.20
    authby=secret
    ike=aes256-sha256-modp2048
    esp=aes256-sha256

# Avvio
ipsec start
ipsec status
```

### Analisi completa con ike-scan

```bash
# Scoprire tutti i transform set accettati
ike-scan --trans=1,1,1,1 <target>    # DES-MD5-PSK-DH1
ike-scan --trans=1,2,1,2 <target>    # DES-SHA1-PSK-DH2
ike-scan --trans=5,2,1,2 <target>    # 3DES-SHA1-PSK-DH2
ike-scan --trans=7/256,2,1,2 <target> # AES256-SHA1-PSK-DH2
```

Documentare quali transform set ricevono risposta.

### Cattura e crack del PSK

```bash
# Passo 1: catturare l'hash
ike-scan --aggressive --id=anyid <target>

# Passo 2: estrarre l'hash dal formato ike-scan
# Passo 3: crack con hashcat
hashcat -m 5300 hash.txt /usr/share/wordlists/rockyou.txt --force
```

***

## Detection e difesa IPSec

Un difensore che monitora IPSec può rilevare:

* **Tentativi di negoziazione IKE con transform set deboli:** DES, MD5, DH Group 1/2
* **Flood di richieste IKE:** volume anomalo su UDP 500/4500 da singolo IP
* **Aggressive Mode da IP non autorizzati:** qualsiasi tentativo di negoziazione Aggressive Mode da IP non nella lista dei peer autorizzati
* **Vendor ID probing:** richieste IKE che includono molti Vendor ID diversi — tipico di ike-scan
* **SA non corrispondenti alla policy aziendale:** SA con algoritmi non approvati nella configurazione

***

## Hardening e mitigazioni IPSec

### Usare IKEv2 al posto di IKEv1

IKEv2 non ha Aggressive Mode e ha una struttura più sicura. Qualsiasi deployment nuovo dovrebbe usare esclusivamente IKEv2.

### Disabilitare Aggressive Mode in IKEv1

Se IKEv1 è ancora necessario per compatibilità, disabilitare Aggressive Mode. Usare solo Main Mode con PSK lunghi e casuali.

### Algoritmi moderni e DH Group elevati

Configurare esclusivamente:

* Cifratura: AES-256-GCM o AES-256-CBC
* Integrità: SHA-256 o superiore
* DH Group: 14 (2048 bit) minimo, meglio 19-21 (ECDH P-256/384)

### Autenticazione con certificati invece di PSK

I certificati X.509 eliminano il rischio di PSK cracking. In ambienti enterprise, usare una PKI interna per emettere certificati ai gateway VPN e ai client.

### Limitare gli endpoint autorizzati

Configurare ACL per accettare traffico IKE (UDP 500/4500) solo dagli IP dei peer autorizzati. Riduce la superficie esposta agli attacchi di enumeration e flooding.

***

## Errori comuni su IPSec

**"IPSec è sempre sicuro perché cifra il traffico"**
La sicurezza dipende interamente dalla configurazione. Algoritmi deboli, PSK corti, Aggressive Mode abilitato: una VPN IPSec mal configurata può essere meno sicura di TLS.

**"Non si può attaccare una VPN IPSec senza conoscere le chiavi"**
Falso nel caso di IKEv1 Aggressive Mode con PSK. L'hash del PSK è catturabile durante la negoziazione e attaccabile offline senza compromettere la sessione attiva.

**"L2TP/IPSec è sicuro"**
L2TP non aggiunge sicurezza — è IPSec che cifra. L2TP/IPSec con PSK deboli ha le stesse vulnerabilità di qualsiasi IPSec con PSK.

**"IKEv2 è immune a tutti gli attacchi"**
IKEv2 risolve molte vulnerabilità di IKEv1, ma rimane vulnerabile a PSK deboli, certificati non validati, e DoS. Non è immune: è significativamente più sicuro di IKEv1 se configurato correttamente.

***

## FAQ su IPSec

**Cos'è IPSec e a cosa serve?**
IPSec (Internet Protocol Security) è un framework di protocolli per cifrare e autenticare il traffico IP a livello di rete. È la base di molte VPN enterprise (site-to-site e accesso remoto) e può proteggere qualsiasi comunicazione IP senza modifiche alle applicazioni.

**Qual è la differenza tra AH e ESP in IPSec?**
AH (Authentication Header) fornisce autenticazione e integrità ma non cifratura. ESP (Encapsulating Security Payload) fornisce cifratura, autenticazione e integrità. In pratica si usa quasi sempre ESP. AH è incompatibile con NAT.

**Cos'è IKE Aggressive Mode e perché è pericoloso?**
IKEv1 Aggressive Mode è una modalità di negoziazione che scambia l'identità dei peer e il hash del PSK in chiaro durante la fase iniziale. Un attaccante può catturare l'hash del PSK senza completare l'autenticazione e attaccarlo offline con un dizionario.

**Come si identifica la versione IKE di un endpoint VPN?**
Con ike-scan: `ike-scan <target>` o con Nmap: `nmap -sU -p 500 --script ike-version <target>`. Entrambi rivelano versione IKE, transform set accettati, e spesso il vendor del software VPN.

**IPSec funziona attraverso NAT?**
IPSec ESP standard ha problemi con NAT perché NAT modifica gli header IP che ESP protegge. La soluzione è **NAT-T (NAT Traversal)**: incapsula ESP dentro UDP porta 4500, permettendo il traversal NAT. Supportato da IKEv1 e nativo in IKEv2.

***

## Conclusione su IPSec

IPSec è il gold standard per le VPN enterprise, ma la sua complessità è anche la sua debolezza principale. Ogni parametro mal configurato — dall'algoritmo al metodo di autenticazione — può trasformare una VPN "sicura" in un vettore di attacco.

In un engagement, enumerare endpoint IPSec con ike-scan spesso rivela configurazioni legacy con Aggressive Mode abilitato, algoritmi deboli, o PSK attaccabili. Questi sono finding critici che in ambienti reali portano direttamente all'accesso alla rete interna.

Approfondisci i protocolli correlati:

* [IP Internet Protocol: il livello di rete](https://hackita.it/articoli/ip-internet-protocol)
* [GRE: tunneling e GRE over IPSec](https://hackita.it/articoli/gre-generic-routing-encapsulation)
* [IPv4 e IPv6: IPSec su entrambi](https://hackita.it/articoli/ipv4-ipv6)
* [VPN: tecnologie e sicurezza](https://hackita.it/articoli/vpn)
* [Nmap: service detection su UDP](https://hackita.it/articoli/nmap)
* [PPP e L2TP: VPN a livello 2](https://hackita.it/articoli/ppp-point-to-point-protocol)
* [Sniffing e analisi del traffico cifrato](https://hackita.it/articoli/sniffing)

Riferimento ufficiale: [RFC 4301 — Security Architecture for the Internet Protocol](https://datatracker.ietf.org/doc/html/rfc4301)

***

Le VPN IPSec sono spesso considerate sicure per definizione. Un penetration test dedicato può rivelare configurazioni legacy o errori di deployment che i tool automatici non trovano.
Scopri il servizio su [hackita.it/servizi](https://hackita.it/servizi).

Se HackITA ti aiuta nel percorso verso l'offensive security:
[hackita.it/supporto](https://hackita.it/supporto)
