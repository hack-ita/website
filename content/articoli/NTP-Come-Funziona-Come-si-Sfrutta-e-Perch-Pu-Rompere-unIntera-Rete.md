---
title: 'NTP: Come Funziona, Come si Sfrutta e Perché Può Rompere un’Intera Rete'
slug: ntp
description: 'Scopri cos’è NTP, come funziona e perché è critico nel pentesting: monlist, amplification DDoS, rogue NTP server, skew temporale, Kerberos, TLS, log e difese.'
image: /ntp.webp
draft: true
date: 2026-03-24T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - ntp
  - time-sync
featured: true
---

NTP è il protocollo che sincronizza gli orologi di tutti i dispositivi in rete. Capire cos'è NTP e come funziona è importante per chi fa pentesting per due motivi distinti: NTP mal configurato è uno dei vettori di amplificazione DDoS più potenti mai documentati, e la desincronizzazione dell'orario di un sistema può invalidare autenticazione Kerberos, certificati TLS, e log forensi — con conseguenze che vanno dal DoS alla manipolazione dell'evidenza digitale.

***

## Cos'è NTP

NTP (Network Time Protocol) è definito nell'**RFC 5905** (NTPv4, 2010), con versioni precedenti risalenti al 1985. Opera al **livello applicativo** su **UDP porta 123**.

NTP sincronizza gli orologi dei sistemi con una precisione che va da millisecondi (su Internet) a microsecondi (su LAN locali), organizzando i time server in una gerarchia chiamata **stratum**:

| Stratum | Descrizione                                            |
| ------- | ------------------------------------------------------ |
| 0       | Reference clock: GPS, orologio atomico, radiofrequenza |
| 1       | Server direttamente connesso a stratum 0               |
| 2       | Server sincronizzato con stratum 1                     |
| 3       | Server sincronizzato con stratum 2                     |
| ...     | Fino a stratum 15                                      |
| 16      | Non sincronizzato (unsynchronized)                     |

Server pubblici NTP come `pool.ntp.org`, `time.google.com`, o `time.cloudflare.com` sono tipicamente stratum 1 o 2.

***

## Come funziona NTP

### Il meccanismo di sincronizzazione

NTP usa un algoritmo che compensa il round-trip delay per calcolare l'offset tra l'orologio locale e quello del server:

```
Client                              Server
  |                                    |
  |--- NTP Request (t1) ------------> |  Client invia timestamp t1
  |                                    |
  |<-- NTP Response (t2, t3) --------- |  Server risponde con t2 (ricezione)
  |    (received at t4)                |  e t3 (trasmissione risposta)
```

Calcolo dell'offset:

```
offset = ((t2 - t1) + (t3 - t4)) / 2
delay  = (t4 - t1) - (t3 - t2)
```

Il client usa l'offset per correggere il proprio orologio gradualmente (stepping se la differenza è > 128ms, slewing se minore).

### Struttura del pacchetto NTP

| Campo               | Dimensione | Descrizione                                        |
| ------------------- | ---------- | -------------------------------------------------- |
| LI (Leap Indicator) | 2 bit      | Warning sul secondo intercalare                    |
| VN (Version Number) | 3 bit      | Versione NTP (4 = NTPv4)                           |
| Mode                | 3 bit      | 3=Client, 4=Server, 5=Broadcast, 6=Control         |
| Stratum             | 8 bit      | Livello nella gerarchia                            |
| Poll Interval       | 8 bit      | Intervallo tra richieste (potenza di 2 in secondi) |
| Precision           | 8 bit      | Precisione dell'orologio locale                    |
| Root Delay          | 32 bit     | Delay totale verso stratum 0                       |
| Root Dispersion     | 32 bit     | Massima dispersione verso stratum 0                |
| Reference ID        | 32 bit     | Identificatore della sorgente di riferimento       |
| Timestamps          | 4×64 bit   | t1, t2, t3, t4                                     |

### Modalità NTP

* **Client/Server (mode 3/4):** client chiede, server risponde — il classico
* **Symmetric (mode 1/2):** due peer si sincronizzano a vicenda — per server NTP ridondanti
* **Broadcast/Multicast (mode 5):** server invia periodicamente senza richiesta — per LAN con molti client
* **Control (mode 6):** gestione e monitoraggio del server NTP — usato da ntpq e ntpdc
* **Private/Monitor (mode 7):** comandi proprietari ntpd — include **monlist**, la funzione alla base degli attacchi di amplificazione

### NTP Authentication

NTPv4 supporta autenticazione simmetrica con MD5 o SHA-1, e NTS (Network Time Security, RFC 8915) per autenticazione moderna con TLS. Nella maggior parte degli ambienti, l'autenticazione NTP non è configurata.

***

## Dove viene usato NTP nelle reti

NTP è fondamentale in quasi ogni infrastruttura:

* **Active Directory:** Kerberos richiede che client e server siano sincronizzati entro 5 minuti (skew massimo). Un orologio desincronizzato causa authentication failure
* **Certificati TLS:** la validità temporale dei certificati è verificata contro l'orologio locale
* **Log e forensics:** l'accuratezza dei timestamp nei log è critica per la correlazione degli eventi
* **Database distribuiti:** sistemi come Cassandra, CockroachDB, e Spanner usano l'orario per la consistenza
* **Trading e finanza:** la sincronizzazione temporale è regolamentata (MiFID II richiede accuratezza a 1ms)
* **Reti industriali OT:** PLC e SCADA usano NTP per la coordinazione temporale
* **CCTV e sistemi di sorveglianza:** timestamp accurati per l'evidenza forense

***

## Perché NTP è importante in cybersecurity

NTP è rilevante in sicurezza per due categorie distinte di attacchi:

**Attacchi che usano NTP come vettore:**
NTP amplification è storicamente uno degli attacchi DDoS con fattori di amplificazione più elevati. Il comando `monlist` risponde con una lista degli ultimi 600 client che hanno interrogato il server — una risposta di centinaia di KB a fronte di una richiesta di pochi byte.

**Attacchi che manipolano NTP come obiettivo:**
Un server NTP compromesso o un rogue NTP server può desincronizzare i sistemi, causando:

* Fallimento dell'autenticazione Kerberos
* Invalidazione di certificati TLS (appare scaduto o non ancora valido)
* Manipolazione dei timestamp nei log (cancellazione forense)
* Bypass di time-based security controls (OTP, token temporali)

Per UDP su cui NTP opera, vedi [UDP](https://hackita.it/articoli/udp). Per Kerberos che dipende da NTP, vedi [Kerberos](https://hackita.it/articoli/kerberos)

***

## NTP in un engagement di pentesting

### Reconnaissance: identificare server NTP

```bash
# Nmap scan NTP
nmap -sU -p 123 --script ntp-info <target>

# Informazioni dettagliate
nmap -sU -p 123 --script ntp-info,ntp-monlist <target>
```

Lo script `ntp-info` rivela:

* Stratum del server
* Reference ID (sorgente di sincronizzazione)
* Sistema operativo (spesso visibile nel Reference ID o nel Version field)
* Uptime del server

### Verificare se monlist è abilitato

```bash
# ntpdc (tool legacy)
ntpdc -n -c monlist <target>

# Se risponde con una lista di IP: monlist è abilitato → vulnerability
# Se risponde con "no association ID's" o timeout: già mitigato
```

Un server con monlist abilitato è vulnerabile all'amplificazione DDoS e rivela anche la lista di tutti i client NTP che lo interrogano — information disclosure.

### NTP Information Disclosure

```bash
# Versione e configurazione
ntpq -c readvar <target>
ntpq -c sysinfo <target>
ntpq -p <target>   # Lista dei peer sincronizzati

# Con ntpdc
ntpdc -c sysinfo <target>
ntpdc -c kerninfo <target>
```

`ntpq -p` mostra i peer NTP del server: rivela l'infrastruttura di sincronizzazione dell'organizzazione, inclusi server NTP interni normalmente non visibili dall'esterno.

### NTP Amplification per DDoS (dimostrazione concettuale)

Il fattore di amplificazione di monlist:

* Richiesta: \~8 byte (NTP mode 7 monlist request)
* Risposta: fino a \~48KB (600 client × 72 byte per entry)
* Fattore: fino a **6000x**

```python
from scapy.all import *

# Dimostrazione: NTP monlist request con IP sorgente spoofato
# (solo per lab autorizzati)
ntp_monlist = IP(src="victim_ip", dst="ntp_server") / \
              UDP(sport=123, dport=123) / \
              NTP(version=2, mode=7)
send(ntp_monlist)
```

### Rogue NTP Server attack

Se un attaccante riesce a posizionarsi come server NTP preferito (via MITM, DHCP option 42, o DNS manipulation), può manipolare l'orario dei client:

**Obiettivi:**

* Desincronizzare Kerberos (skew > 5 minuti → authentication failure completo)
* Far sembrare scaduti i certificati TLS validi
* Manipolare i timestamp dei log pre-incident
* Bypassare controlli time-based (OTP con finestra temporale stretta)

```bash
# Configurare un rogue NTP server con ntpd
# Poi distribuire l'IP tramite DHCP option 42 o DNS manipulation
```

### Post-compromise: analizzare i log con timestamp

In fase di forensics difensiva o durante un engagement, verificare la coerenza dei timestamp nei log con i server NTP è una tecnica per rilevare manipolazioni temporali:

```bash
# Verificare l'offset corrente del sistema
ntpq -p
chronyc tracking

# Log di sincronizzazione NTP
cat /var/log/syslog | grep -i ntp
journalctl -u ntp
```

***

## Attacchi e abusi possibili su NTP

### NTP Amplification / monlist DDoS

Come descritto: sfruttare server NTP con monlist abilitato per attacchi DDoS amplificati. Ancora praticato nonostante le mitigazioni disponibili da anni — molti server NTP legacy non sono stati aggiornati.

### KoD (Kiss-o'-Death) Attack

Inviare pacchetti NTP con il Stratum field impostato a 0 (Stratum 0 = KoD packet) verso un client NTP. Alcune implementazioni NTP reagiscono a questi pacchetti aumentando il poll interval o smettendo di sincronizzarsi temporaneamente.

### NTP MITM (Clock Skew Attack)

Posizionandosi tra client e server NTP, modificare le risposte NTP per alterare gradualmente l'orologio del client. L'alterazione graduale (slewing invece di stepping) è più difficile da rilevare.

### Replay Attack su NTP non autenticato

Catturare e ri-inviare risposte NTP legittime per impedire l'aggiornamento dell'orologio o per bloccare la rilevazione di derive temporali.

***

## Esempi pratici con NTP in laboratorio

### Analisi NTP completa con Wireshark

```
ntp                          # Tutto il traffico NTP
ntp.flags.mode == 3          # Solo client requests
ntp.flags.mode == 4          # Solo server responses
ntp.flags.mode == 7          # Mode 7 (monlist, legacy)
ntp.stratum == 0             # KoD packets
```

### Script di reconnaissance NTP massiva

```bash
#!/bin/bash
# Scan NTP di una subnet
nmap -sU -p 123 --script ntp-info,ntp-monlist \
  --open -oG - 192.168.1.0/24 | \
  grep "open" | awk '{print $2}'
```

### Verificare lo skew NTP su un host Windows (post-compromise)

```cmd
w32tm /query /status
w32tm /query /peers
```

***

## Detection e difesa NTP

Un difensore che monitora NTP può rilevare:

* **monlist response di grandi dimensioni:** risposta UDP 123 > 1KB è anomala in NTPv4 standard
* **Spike di traffico UDP 123:** flood di richieste NTP può indicare un server usato per amplificazione
* **Variazioni anomale dell'orario di sistema:** indicatore di rogue NTP o MITM
* **Client che si sincronizzano con server NTP non autorizzati:** policy violation
* **Mode 7 packets in entrata:** monlist request — dovrebbero essere bloccati

***

## Hardening e mitigazioni NTP

### Disabilitare monlist

```
# ntpd.conf
restrict default noquery nomodify nopeer noserve
restrict 127.0.0.1
restrict ::1
```

`noquery` disabilita le query di status (inclusa monlist). Questa singola riga elimina il vettore di amplificazione principale.

### Migrare a chrony

**chrony** è l'implementazione NTP moderna raccomandata per Linux, che ha sostituito ntpd nella maggior parte delle distribuzioni:

```bash
# Installare chrony
apt install chrony

# /etc/chrony.conf
server time.cloudflare.com iburst
makestep 1.0 3
rtcsync
```

chrony non ha monlist e ha un modello di sicurezza migliore di ntpd legacy.

### NTS (Network Time Security)

NTS (RFC 8915) aggiunge autenticazione e cifratura alle query NTP usando TLS. Supportato da chrony, ntpd 4.2.8p15+, e server pubblici come Cloudflare (`time.cloudflare.com`):

```
# chrony.conf con NTS
server time.cloudflare.com iburst nts
```

### Rate limiting UDP 123

```bash
# iptables — rate limit NTP in uscita (mitiga uso come amplificatore)
iptables -A OUTPUT -p udp --sport 123 -m limit --limit 1/s --limit-burst 10 -j ACCEPT
iptables -A OUTPUT -p udp --sport 123 -j DROP
```

### Autorizzare solo server NTP interni

In ambienti enterprise, i client dovrebbero sincronizzarsi solo con server NTP interni autorizzati, non direttamente con server pubblici:

```
# Windows GPO
Computer Configuration → Windows Settings → Security Settings →
Local Policies → Security Options → Domain member: Maximum machine account password age
```

```bash
# Linux — forzare uso di NTP server specifico
# /etc/chrony.conf
server ntp.corp.internal iburst
deny all    # Blocca accesso al proprio servizio NTP dall'esterno
```

***

## Errori comuni su NTP

**"NTP è solo per sincronizzare l'ora, non è rilevante per la sicurezza"**
Falso. La sincronizzazione temporale è prerequisito per Kerberos, TLS, OTP, e la coerenza dei log. Un sistema desincronizzato può essere compromesso o reso inutilizzabile in termini di autenticazione.

**"monlist è disabilitato per default su sistemi moderni"**
Dipende dalla versione. ntpd \< 4.2.7p26 ha monlist abilitato per default. Molti appliance di rete e sistemi embedded con ntpd vecchio lo hanno ancora attivo.

**"NTP amplification non è più praticata"**
Sbagliato. Server NTP legacy con monlist abilitato sono ancora presenti su Internet e vengono ancora usati per amplificazione. I servizi di threat intelligence documentano attacchi NTP ogni settimana.

**"L'autenticazione MD5 di NTP è sufficiente"**
MD5 è considerato debole. La raccomandazione attuale è NTS (RFC 8915) con autenticazione basata su TLS 1.3.

***

## FAQ su NTP

**Cos'è NTP e a cosa serve?**
NTP (Network Time Protocol) è il protocollo che sincronizza gli orologi dei dispositivi di rete con server di riferimento. Opera su UDP porta 123 e usa una gerarchia (stratum) per distribuire il tempo da sorgenti atomic/GPS fino ai client finali.

**Cos'è monlist NTP e perché è pericoloso?**
monlist è un comando NTP legacy (mode 7) che risponde con la lista degli ultimi 600 client che hanno interrogato il server. Con IP sorgente spoofato, permette di usare il server NTP come amplificatore DDoS con fattori fino a 6000x. Disabilitabile con `restrict default noquery`.

**Come la desincronizzazione NTP impatta Kerberos?**
Kerberos richiede che client e server abbiano orologi sincronizzati entro 5 minuti (clock skew massimo per default). Se la differenza supera questa soglia, Kerberos rifiuta i ticket e l'autenticazione fallisce completamente — effetto DoS sull'intera infrastruttura AD.

**Cos'è NTS?**
NTS (Network Time Security, RFC 8915) è l'estensione di sicurezza per NTP che aggiunge autenticazione e cifratura usando TLS 1.3. Elimina le vulnerabilità di MITM e replay di NTP non autenticato. Supportato da chrony e server pubblici come Cloudflare.

**Come si verifica se un server NTP ha monlist abilitato?**
Con `ntpdc -n -c monlist <server>`: se risponde con una lista di IP, monlist è attivo. Con Nmap: `nmap -sU -p 123 --script ntp-monlist <server>`.

***

## Conclusione su NTP

NTP è uno di quei protocolli che sembrano irrilevanti per la sicurezza fino a quando non lo sono. monlist abilitato trasforma qualsiasi server NTP in un amplificatore DDoS potentissimo. Un rogue NTP server può paralizzare l'autenticazione Kerberos di un'intera organizzazione. La manipolazione dei timestamp può rendere inutilizzabili i log forensi.

Mitigare NTP è semplice: disabilitare monlist, migrare a chrony, abilitare NTS. Eppure server NTP non aggiornati con monlist attivo continuano a essere trovati regolarmente in ogni tipo di assessment.

Approfondisci i protocolli correlati:

* [UDP: il trasporto di NTP](https://hackita.it/articoli/udp)
* [DNS: altro protocollo di infrastruttura critica](https://hackita.it/articoli/dns)
* [DHCP: distribuzione del server NTP via option 42](https://hackita.it/articoli/dhcp)
* [Kerberos: dipendenza critica da NTP](https://hackita.it/articoli/kerberos)
* [TLS/SSL: validità temporale dei certificati](https://hackita.it/articoli/tls-ssl)
* [SNMP: altro protocollo UDP di management](https://hackita.it/articoli/snmp)
* [IP Internet Protocol: il livello di rete](https://hackita.it/articoli/ip-internet-protocol)

Riferimento ufficiale: [RFC 5905 — Network Time Protocol Version 4](https://datatracker.ietf.org/doc/html/rfc5905)

***

Un server NTP con monlist attivo in un assessment è sempre una finding. Se vuoi sapere quante ne trovi nella tua infrastruttura:
[hackita.it/servizi](https://hackita.it/servizi)

HackITA è il tuo riferimento tecnico gratuito. Tienilo attivo:
[hackita.it/supporto](https://hackita.it/supporto)
