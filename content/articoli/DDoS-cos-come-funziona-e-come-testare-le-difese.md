---
title: 'DDoS: cos’è, come funziona e come testare le difese'
slug: ddos
description: 'Cos''è un attacco DDoS e come funziona? Scopri tipi di DDoS, tecniche di attacco, test autorizzati e come verificare l''efficacia delle difese.'
image: /ddos-penetration-testing.webp
draft: true
date: 2026-09-22T00:00:00.000Z
categories:
  - networking
subcategories:
  - servizi
tags:
  - ddos
  - ddos-penetration-testing
  - syn-flood
  - http-flood
  - ddos-mitigation
---

# DDoS: cos’è un attacco DDoS e come si testa

Un attacco DDoS (Distributed Denial of Service) cerca di rendere un servizio lento o irraggiungibile sovraccaricandolo con un volume elevato di traffico, richieste o connessioni, generate da molte sorgenti diverse contemporaneamente.

Il DDoS penetration testing consiste nel simulare questo tipo di pressione in un ambiente autorizzato, per verificare se infrastruttura, applicazioni e sistemi di mitigazione riescono a mantenere il servizio operativo. Non ci si limita a misurare "quanto traffico regge il server": si verificano anche rilevamento, filtraggio, failover, alert e tempi di mitigazione.

## Cos'è un attacco DDoS

**DoS vs DDoS**: un attacco DoS (Denial of Service) proviene da una singola sorgente; un attacco DDoS (Distributed Denial of Service) usa molte sorgenti — spesso migliaia di dispositivi compromessi organizzati in una **botnet** — rendendo l'attacco più difficile da bloccare filtrando un singolo indirizzo IP.

Alcuni termini che ricorreranno spesso in questo articolo:

* **Flood**: inondare il target con un volume enorme di pacchetti o richieste dello stesso tipo
* **Amplification**: sfruttare un servizio terzo (es. un server DNS pubblico) per far sì che a una richiesta piccola dell'attaccante corrisponda una risposta molto più grande, indirizzata alla vittima
* **Volumetrico**: un attacco che punta a saturare la banda di rete disponibile, indipendentemente da cosa faccia l'applicazione
* **Applicativo**: un attacco che punta a esaurire le risorse dell'applicazione (thread, connessioni, CPU) con richieste che sembrano legittime

## Come funziona un DDoS

```
Attaccanti / botnet → Internet → rete e firewall / CDN → applicazione → utenti
```

Il collo di bottiglia può trovarsi in punti diversi della catena: la banda disponibile in ingresso, la capacità del firewall di gestire connessioni, le risorse del server applicativo o del database dietro di esso. Un test DDoS serio deve capire *dove* si romperebbe per primo, non solo *se* si rompe.

## Tipi di attacco DDoS

| Layer             | Cosa riguarda               | Esempio               |
| ----------------- | --------------------------- | --------------------- |
| L3 (rete)         | Pacchetti IP, banda di rete | ICMP flood            |
| L4 (trasporto)    | Connessioni TCP/UDP         | SYN flood, UDP flood  |
| L7 (applicazione) | Richieste applicative       | HTTP flood, Slowloris |

### Layer 3 — Volumetrico

**SYN flood**: l'attaccante invia molti pacchetti TCP SYN (l'avvio di una connessione), spesso con IP sorgente falsificato. Il server alloca memoria per ogni connessione in attesa di essere completata; se il numero di connessioni a metà (SYN backlog) si riempie, il server smette di accettarne di nuove.

**UDP flood**: pacchetti UDP inviati verso porte alte casuali. Il server risponde con messaggi ICMP "porta non raggiungibile" per ognuno: il traffico in entrata e in uscita combinato satura la rete.

**ICMP flood (Smurf)**: tecnica storica, oggi poco usata, basata su richieste ping con IP sorgente falsificato indirizzate a una rete broadcast, che genera un'ondata di risposte verso la vittima.

### Layer 4 — Protocollo

**Flood su stati di connessione TCP**: simile al SYN flood, ma punta a esaurire le risorse che il sistema operativo dedica al tracciamento degli stati di connessione (es. `TIME_WAIT`).

**DNS flood**: un volume elevato di query verso un server DNS, fino a esaurirne CPU o memoria e a farlo smettere di rispondere.

### Layer 7 — Applicazione

**HTTP flood**: richieste GET/POST del tutto simili a traffico legittimo, ma in volume tale da esaurire i thread o le connessioni disponibili sul server applicativo. Proprio perché somigliano a traffico normale, sono più difficili da distinguere e bloccare rispetto a un flood di rete.

**Slowloris**: l'attaccante apre molte connessioni HTTP e le mantiene aperte inviando gli header molto lentamente, senza mai completarli. Il server, in attesa del completamento, tiene occupati gli slot di connessione fino a esaurirli. Serve poco traffico per essere efficace.

**RUDY (R-U-Dead-Yet)**: variante che invia il corpo di una richiesta POST un byte alla volta, con lo stesso obiettivo di Slowloris.

### Reflection e amplification

In un attacco di amplification, l'attaccante invia una richiesta a un servizio terzo (DNS, NTP, SSDP, CLDAP) falsificando l'IP sorgente con quello della vittima. Il servizio terzo risponde alla vittima con un pacchetto molto più grande della richiesta originale — da qui il termine "amplificazione". Alcuni esempi noti: DNS amplification, NTP amplification (tramite il comando `monlist`, oggi disabilitato sulla maggior parte dei server aggiornati), SSDP amplification (sfrutta dispositivi UPnP esposti, spesso router o stampanti domestiche non aggiornate), CLDAP amplification (sfrutta directory server LDAP su UDP).

### Multi-vector

Un attacco multi-vector combina più tecniche contemporaneamente (es. SYN flood + UDP flood + HTTP flood), per colpire più livelli della catena difensiva nello stesso momento e complicare la mitigazione.

## Come si esegue un DDoS penetration test

### Autorizzazione e scope

Prima di generare qualsiasi traffico serve un'autorizzazione scritta che definisca: target esatto (IP o dominio), finestra oraria concordata, contatto di escalation raggiungibile durante il test, limiti massimi di traffico e criteri di successo (uptime, latenza, falsi positivi da misurare).

```text
=== Autorizzazione Test DDoS ===
Target: 203.0.113.100 (staging)
Data/ora: 2026-06-21, 22:00-23:00 UTC
Durata max: 60 minuti
Vettori: SYN flood (max 10 Gbps), HTTP flood (max 50k RPS)
Escalation: soc@azienda.it, reperibile durante il test
Stato: autorizzato dal responsabile sicurezza
```

### Ambiente di test

Un test DDoS in produzione è ad alto rischio: senza una procedura formale, autorizzazione esplicita, coordinamento con il provider e un meccanismo di stop immediato, il rischio di causare un disservizio reale è concreto. Quando possibile, conviene partire da un ambiente di staging isolato, il più simile possibile alla produzione, e passare alla produzione solo con un piano di test controllato e la partecipazione attiva del provider di mitigazione.

### Baseline

Prima di generare qualunque carico, misura il comportamento normale: banda utilizzata, pacchetti al secondo, richieste al secondo, latenza media, tasso di errore. Senza una baseline non è possibile capire se un peggioramento durante il test è significativo.

```bash
iperf3 -c 10.0.0.50 -t 10   # banda disponibile in condizioni normali
```

### Test a carico crescente

Il carico va aumentato in modo graduale, non tutto in una volta, per identificare con precisione la soglia a cui un componente inizia a degradare.

```bash
# SYN flood a intensità crescente (solo in ambiente autorizzato)
hping3 --syn -p 80 -i u10000 10.0.0.50   # ~100 Mbps

# HTTP flood con Vegeta
echo "GET http://10.0.0.50/" | vegeta attack -duration=60s -rate=1000 | vegeta report
```

### Monitoraggio durante il test

```bash
iftop -i eth0                          # traffico in tempo reale
tail -f /var/log/syslog | grep -i "ddos\|attack\|flood"   # log applicativi/sistema
```

### Condizioni di stop

Un test ben pianificato include criteri di interruzione immediata concordati in anticipo (es. superamento di una soglia di errore sugli utenti reali, escalation da parte del cliente), non solo un tempo massimo.

## Come validare le difese DDoS

Questa è la parte con più valore pratico di un test: non basta sapere che il servizio ha retto un certo volume di traffico, bisogna verificare che ogni livello della difesa abbia effettivamente fatto il suo lavoro.

**Rate limiting**: verifica che il sistema scarti traffico in eccesso oltre una soglia configurata, invece di lasciarlo passare tutto.

```bash
watch 'cat /proc/net/dev | grep eth0'   # osserva se ci sono pacchetti scartati durante il carico
```

**Filtraggio**: verifica che il traffico malevolo venga effettivamente bloccato a monte (firewall, WAF) e non solo rallentato.

**CDN e scrubbing center**: se l'infrastruttura prevede un servizio di mitigazione esterno (Cloudflare, Akamai e simili), verifica che il traffico venga effettivamente reindirizzato lì durante l'attacco.

```bash
dig target.com +noall +answer   # confronta l'IP risolto prima, durante e dopo il test
```

**Failover**: verifica che il passaggio verso l'infrastruttura di mitigazione avvenga nei tempi attesi e che il traffico legittimo continui a essere servito nel frattempo.

**Alerting**: verifica che gli alert configurati (SIEM, email, chat operativa) scattino davvero durante il test, e non solo che esistano sulla carta.

**Recovery**: verifica che, terminato il carico, il sistema torni alle condizioni normali senza intervento manuale, e in quanto tempo.

## Metriche da misurare

* **Banda** (Mbps/Gbps) e **pacchetti al secondo (pps)**: per gli attacchi volumetrici
* **Richieste al secondo (RPS)** e **latenza**: per gli attacchi applicativi
* **Tasso di errore**: percentuale di richieste legittime fallite durante il test
* **MTTD (Mean Time To Detect)**: tempo medio impiegato dal sistema a rilevare l'anomalia
* **MTTR (Mean Time To Mitigate/Recover)**: tempo medio per mitigare o tornare alla normalità

## Strumenti

**Generazione di carico**: `hping3` per il traffico di rete (SYN/UDP/ICMP), [Scapy](https://hackita.it/articoli/scapy/) per costruire pacchetti custom (utile anche per dimostrare in lab il meccanismo di un'amplification, senza puntare a servizi di terzi non autorizzati), Vegeta o Apache Bench per il carico HTTP, `iperf3` per il testing di banda.

**Analisi e monitoraggio**: [Wireshark](https://hackita.it/articoli/wireshark/) per il riconoscimento dei pattern di attacco, [tcpdump](https://hackita.it/articoli/tcpdump/) per la cattura raw, strumenti di NetFlow per l'analisi dei flussi, le API del provider di mitigazione (es. Cloudflare, Akamai) per leggere le statistiche in tempo reale durante il test.

## Errori comuni durante un DDoS test

* Saltare la fase di baseline e non avere un termine di paragone
* Aumentare il carico troppo velocemente invece che gradualmente
* Testare solo un vettore (es. solo SYN flood) e concludere che "la difesa regge", senza aver verificato layer applicativo e amplification
* Non coinvolgere il provider di mitigazione, rischiando falsi allarmi o blocchi non previsti
* Non definire in anticipo condizioni di stop chiare

## Statistiche recenti

Cloudflare riporta per il 2025 circa **47,1 milioni di attacchi DDoS mitigati**, con una crescita del **121%** rispetto all'anno precedente. Nel quarto trimestre 2025 è stato registrato un attacco record da **31,4 Tbps, durato circa 35 secondi**, attribuito alla botnet **Aisuru-Kimwolf** — che secondo le stime di Cloudflare ha coinvolto complessivamente tra 1 e 4 milioni di dispositivi infetti (un mix di dispositivi IoT legati all'ecosistema Mirai/Aisuru e dispositivi Android compromessi via ADB per la componente Kimwolf).

Un altro dato rilevante: nel terzo trimestre 2024 Cloudflare ha osservato un aumento del **4.000% degli attacchi SSDP amplification** rispetto al trimestre precedente, legato allo sfruttamento di router e dispositivi UPnP domestici non aggiornati.

## DDoS penetration testing in produzione

Testare in produzione non è impossibile, ma va trattato come un'operazione ad alto rischio: richiede un piano dettagliato, autorizzazione esplicita da chi ha la responsabilità del servizio, coordinamento diretto con il provider di mitigazione, limiti di traffico concordati e un meccanismo di stop immediato testato in anticipo. In assenza di queste condizioni, meglio partire da un ambiente di staging il più realistico possibile.

## Checklist operativa

* Autorizzazione scritta con scope, orario ed escalation definiti
* Ambiente di staging pronto, il più simile possibile alla produzione
* Baseline del traffico normale registrata
* Test a carico crescente su ciascun layer (L3, L4, L7)
* Test di almeno un vettore amplification, solo in lab controllato
* Verifica del rate limiting e del filtraggio
* Verifica del failover verso il sistema di mitigazione
* Verifica che gli alert configurati scattino davvero
* Misurazione di MTTD e MTTR
* Analisi post-test condivisa con il team che gestisce l'infrastruttura

## FAQ

**Cos'è un attacco DDoS?**
Un attacco che punta a rendere un servizio lento o irraggiungibile, generando un volume elevato di traffico o richieste da molte sorgenti diverse contemporaneamente.

**Qual è la differenza tra DoS e DDoS?**
Il DoS proviene da una singola sorgente, il DDoS da molte sorgenti distribuite, spesso una botnet, il che lo rende più difficile da bloccare filtrando un solo indirizzo IP.

**Qual è la differenza tra DDoS volumetrico e applicativo?**
Un attacco volumetrico punta a saturare la banda di rete disponibile; un attacco applicativo punta a esaurire le risorse dell'applicazione (thread, connessioni, CPU) con richieste che sembrano legittime.

**Cos'è un SYN flood?**
Un attacco che invia molti pacchetti TCP SYN per riempire la coda di connessioni in attesa di un server, impedendogli di accettarne di nuove.

**Cos'è un HTTP flood?**
Un volume elevato di richieste HTTP che sembrano legittime, pensato per esaurire le risorse del server applicativo.

**Cos'è un attacco DDoS amplification?**
Una tecnica che sfrutta un servizio terzo per far arrivare alla vittima una risposta molto più grande della richiesta inviata dall'attaccante, il quale ne falsifica l'indirizzo sorgente.

**Come si misura la resilienza a un DDoS?**
Con metriche come banda, pacchetti al secondo, richieste al secondo, latenza, tasso di errore, tempo di rilevamento (MTTD) e tempo di mitigazione (MTTR).

**Come si testa una protezione DDoS senza interrompere il servizio?**
Aumentando il carico gradualmente, partendo da staging quando possibile, definendo in anticipo condizioni di stop e coordinandosi con il provider di mitigazione.

**Cloudflare (o un servizio simile) protegge da tutti gli attacchi DDoS?**
Riduce fortemente il rischio, ma non elimina la necessità di verificare la configurazione: regole di rate limiting troppo permissive o mal configurate possono comunque lasciar passare traffico dannoso.

## Raccomandazioni per chi protegge un'infrastruttura

* Conosci la tua baseline di traffico normale (medie e picchi)
* Configura rate limiting su pps/bps per sorgente
* Valuta un servizio di mitigazione DDoS (Cloudflare, Akamai, Fortinet o simili) con risposta automatizzata
* Monitora l'esposizione di dispositivi IoT/UPnP nella tua rete: sono tra i bersagli preferiti per reclutare botnet
* Prepara un playbook di incident response specifico per DDoS (escalation, failover, comunicazione)
* Pianifica test di resilienza periodici, con scope e autorizzazione chiari

## Risorse esterne

* [Cloudflare – 2025 Q4 DDoS Threat Report](https://blog.cloudflare.com/ddos-threat-report-2025-q4/): fonte dei dati sull'attacco da 31,4 Tbps e sulle statistiche 2025
* [Cloudflare – DDoS Threat Report Q3 2024](https://blog.cloudflare.com/ddos-threat-report-for-2024-q3/): fonte del dato sull'aumento del 4.000% degli attacchi SSDP amplification
* [Cloudflare – Cos'è la botnet Aisuru-Kimwolf](https://www.cloudflare.com/learning/ddos/glossary/aisuru-kimwolf-botnet/): approfondimento sulla botnet citata nell'articolo
* [Yuri Kan – DDoS Testing: Testing System Resilience](https://yrkan.com/blog/ddos-testing-guide/): guida pratica alla validazione di rate limiting, WAF e auto-scaling
* [BlackNeuron – DDoS Resilience Testing](https://blackneuron.ai/blog/ddos-resilience-testing): analisi della differenza tra load testing e vero test di resilienza DDoS
