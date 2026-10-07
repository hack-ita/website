---
title: 'Firewall: Significato, Tipi, Come Funziona e Regole Base'
slug: firewall
description: 'Firewall: cos''è, significato, come funziona, cosa fa, tipi (stateful, NGFW, WAF), regole base, comandi ufw e Windows e come lo vede un pentester con Nmap.'
image: /firewall-sicurezza-rete-network-protection.webp
draft: true
date: 2026-10-11T23:33:58.182Z
lastmod: 2026-10-11T23:34:02.426Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Firewall
  - Firewall di Rete
  - Network Security
  - WAF
  - NGFW
---

# Firewall: Cos'è, Come Protegge una Rete e Come Configurarlo

Il **firewall** è un sistema di sicurezza che controlla il traffico di rete in entrata e in uscita e decide cosa far passare e cosa bloccare in base a **regole** prestabilite. Può essere un dispositivo fisico, un software sul computer o un servizio nel cloud. Il suo compito è mettere un filtro tra reti con livelli di fiducia diversi, per esempio tra Internet e la rete aziendale.

È uno degli strumenti base della sicurezza informatica, ma non è una protezione completa: non ferma il phishing, non rileva un insider e, se è mal configurato o non aggiornato, può diventare esso stesso il punto d'ingresso.

## Firewall significato: cosa vuol dire e perché si chiama così

*Firewall* significa letteralmente **parete tagliafuoco**: nelle costruzioni è il muro che impedisce a un incendio di propagarsi da un'area all'altra. In informatica ha la stessa funzione: se una parte della rete viene compromessa, il firewall limita la diffusione dei danni verso le altre.

Esempio semplice: in un'azienda, il firewall permette ai dipendenti di navigare sul web e di collegarsi ai server interni, ma blocca chiunque da Internet provi a connettersi direttamente al database dei clienti.

## A cosa serve un firewall

Un firewall serve a:

* **bloccare accessi non autorizzati** dall'esterno verso servizi interni;
* **ridurre la superficie d'attacco**, esponendo solo ciò che deve essere raggiungibile;
* **limitare i movimenti dentro la rete** tra zone diverse (utenti, server, ospiti);
* **controllare il traffico in uscita**, per ostacolare malware, esfiltrazione di dati e comunicazioni con server di comando e controllo;
* **registrare i tentativi di connessione**, utili per individuare scansioni e attacchi.

### Firewall per casa e per azienda

A casa il firewall è di solito già integrato nel router e nel sistema operativo: va lasciato attivo e va evitato di inoltrare porte verso Internet senza motivo. In azienda serve un firewall di rete al perimetro (spesso un NGFW), firewall host-based sui server, segmentazione in zone e un processo per gestire e rivedere le regole.

## Come funziona un firewall

Il firewall esamina ogni pacchetto di rete e lo confronta con una lista di regole. Ogni regola dice, in sostanza: *se il traffico ha queste caratteristiche, allora consenti o blocca*. Le caratteristiche più usate sono:

* **indirizzo IP** di origine e destinazione;
* **porta** e **protocollo** (TCP, UDP, ICMP);
* **direzione**: in entrata (*inbound*) o in uscita (*outbound*);
* negli apparati più avanzati, **applicazione**, **utente** e **contenuto**.

Due principi fondamentali:

1. **Le regole si leggono dall'alto verso il basso**: nella maggior parte dei firewall vale la prima regola che corrisponde al traffico.
2. **Default deny**: se nessuna regola consente un traffico, viene bloccato. È la configurazione più sicura: si blocca tutto e si apre solo ciò che serve.

Una regola tipica può essere letta così: *consenti TCP verso 203.0.113.10 sulla porta 443 da qualsiasi origine*. Per capire cosa significano porte e protocolli c'è la guida alle [porte TCP e UDP nel pentest](/articoli/porte-tcp-udp-pentest/).

## Tipi di firewall

| Tipo                                | Cosa guarda                                                    | Caratteristica                                                                           |
| ----------------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **Packet filtering**                | IP, porta, protocollo di ogni singolo pacchetto                | Veloce e semplice, ma non sa a quale connessione appartiene un pacchetto                 |
| **Stateful inspection**             | Come sopra, più lo **stato della connessione**                 | Consente le risposte solo a connessioni avviate dall'interno. È lo standard di base oggi |
| **Proxy / application gateway**     | Il contenuto di uno specifico protocollo (livello applicativo) | Fa da intermediario: la connessione non è diretta. Più controllo, più lento              |
| **Next-Generation Firewall (NGFW)** | Applicazioni, utenti, contenuti, spesso anche traffico cifrato | Unisce firewall, IPS, filtro applicativo e threat intelligence                           |

### Stateful vs stateless

|                              | **Stateless** (packet filtering puro) | **Stateful**                                               |
| ---------------------------- | ------------------------------------- | ---------------------------------------------------------- |
| Cosa valuta                  | Ogni pacchetto da solo                | Il pacchetto e lo stato della connessione a cui appartiene |
| Risposte al traffico interno | Vanno autorizzate esplicitamente      | Vengono riconosciute e permesse automaticamente            |
| Oggi                         | Raro come unica difesa                | Lo standard di base di quasi ogni firewall moderno         |

### Per posizione e forma

* **Firewall di rete (hardware o virtuale)**: protegge un'intera rete, di solito al perimetro.
* **Firewall host-based**: gira su un singolo computer o server (Windows Defender Firewall, `ufw`, `nftables`).
* **Firewall cloud**: filtri come *security group* o *firewall as a service*, che proteggono risorse nel cloud.

## Firewall vs WAF: qual è la differenza?

Sono entrambi firewall, ma guardano cose diverse. Un firewall di rete tradizionale filtra in base a IP, porta e protocollo: non capisce il contenuto di una richiesta HTTP. Un **WAF** (*Web Application Firewall*) lavora invece a livello applicativo, analizza il traffico HTTP/HTTPS verso un sito o un'app e riconosce pattern di attacco come [SQL injection](/articoli/sql-injection/) o [XSS](/articoli/xss/). In pratica: il firewall di rete decide chi può bussare alla porta, il WAF controlla cosa c'è scritto nella richiesta una volta che è entrata.

Molte applicazioni web usano entrambi: firewall di rete per il perimetro, WAF davanti all'applicazione.

## Firewall, antivirus, IDS/IPS e VPN: le differenze

Questi strumenti vengono confusi di continuo, ma fanno cose diverse:

| Strumento                                   | Cosa fa                                                                    |
| ------------------------------------------- | -------------------------------------------------------------------------- |
| **Firewall**                                | Filtra il traffico di rete in base a regole                                |
| **Antivirus / EDR**                         | Rileva e blocca malware e comportamenti sospetti **sul dispositivo**       |
| **IDS**                                     | Rileva traffico sospetto e **avvisa**                                      |
| **IPS**                                     | Rileva traffico sospetto e lo **blocca**                                   |
| **WAF**                                     | Protegge in modo specifico le **applicazioni web**                         |
| **[VPN](/articoli/vpn/)** | Crea un canale cifrato tra due punti: non filtra, **protegge il transito** |

Si usano insieme: il firewall riduce ciò che può arrivare, l'EDR protegge i dispositivi, l'IDS/IPS osserva il traffico, la VPN protegge i collegamenti remoti.

## Firewall, NAT e port forwarding

Spesso si sente parlare di "mappare una porta" sul firewall. Si tratta di **NAT** e **port forwarding**: il router o il firewall inoltra il traffico che arriva su una porta pubblica verso un dispositivo interno (per esempio la porta 443 verso un server web).

Attenzione: il **NAT non è un firewall**. Nasconde gli indirizzi interni ma non filtra per sicurezza. Ogni porta inoltrata verso Internet è un servizio esposto: un server con [RDP aperto sulla porta 3389](/articoli/porta-3389-rdp/) è un classico bersaglio. Prima di aprire una porta, chiediti se serve davvero, a chi serve e se può stare dietro una VPN.

## Configurazione firewall: regole, default deny e best practice

### Default deny vs default allow

| Policy            | Comportamento                                                                               |
| ----------------- | ------------------------------------------------------------------------------------------- |
| **Default deny**  | Blocca tutto ciò che non è esplicitamente consentito. Più sicura: è lo standard consigliato |
| **Default allow** | Consente tutto ciò che non è esplicitamente bloccato. Più comoda, molto più rischiosa       |

Principi che valgono per qualsiasi prodotto:

1. **Blocca tutto per impostazione predefinita** (*default deny*), poi apri solo il necessario.
2. **Privilegio minimo**: regole il più specifiche possibile (IP, porta e protocollo precisi) invece di "any-any".
3. **Filtra anche il traffico in uscita** (*egress*): una macchina compromessa deve poter contattare solo ciò che serve.
4. **Segmenta la rete**: separa server, utenti, ospiti e dispositivi IoT in zone diverse, con una **DMZ** per i servizi esposti.
5. **Proteggi l'interfaccia di amministrazione**: non esporla su Internet, usa MFA, credenziali robuste e accessi dedicati.
6. **Aggiorna il firmware**: i firewall sono bersagli per gli attaccanti.
7. **Registra i log** e portali in un sistema di monitoraggio.
8. **Rivedi le regole ogni tot mesi**: con il tempo restano regole temporanee, obsolete o troppo permissive.
9. **Fai backup della configurazione.**

### Comandi base

Su Linux con **ufw**, una configurazione minima:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
sudo ufw status verbose
```

Per vedere le regole effettive di basso livello:

```bash
sudo nft list ruleset
sudo iptables -L -n -v
```

Su Windows (PowerShell), stato dei profili e regole in ingresso attive:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Select-Object DisplayName, Profile
```

La seconda riga è un buon punto di partenza per trovare regole in ingresso che non ricordavi di aver creato.

## Firewall nel penetration test

Nel penetration test il firewall è uno dei primi ostacoli da capire. Con [Nmap](/articoli/nmap/) si distinguono tre stati: porta **aperta**, **chiusa** (il sistema risponde che non c'è nulla) e **filtrata** (nessuna risposta o rifiuto: probabile presenza di un firewall).

Solo su sistemi tuoi, di un lab o con autorizzazione scritta. Se l'host non risponde al ping, salta la fase di host discovery:

```bash
nmap -Pn -p 1-1000 <IP-autorizzato>
```

Per capire se un firewall è *stateful* e quali porte lascia passare, si può usare la scansione ACK:

```bash
nmap -sA <IP-autorizzato>
```

Una porta `unfiltered` con ACK vuol dire che i pacchetti la raggiungono (non filtrata da regole stateful); `filtered` significa che Nmap non riesce a determinare se la porta è aperta perché un filtro di rete impedisce alle probe di raggiungerla o alle risposte di tornare. Non implica per forza un firewall in senso stretto, ma è il segnale più comune della sua presenza.

Dal lato dell'attaccante, il filtro **in uscita** (*outbound*) è spesso decisivo: una reverse shell deve comunque uscire dalla rete, e un firewall che blocca il traffico non necessario rende più difficile o più rumorosa una tecnica come [Chisel](/articoli/chisel/) o il [pivoting](/articoli/pivoting/). Un firewall con regole outbound "tutto permesso" rende la vita facile a chi è già dentro.

## Errori comuni di configurazione

| Errore                                      | Rischio                                        |
| ------------------------------------------- | ---------------------------------------------- |
| Regole "any any" o troppo ampie             | Il firewall lascia passare più del necessario  |
| Nessun filtro in uscita                     | Malware e reverse shell comunicano liberamente |
| Interfaccia di gestione esposta su Internet | Accesso diretto al cuore del firewall          |
| Credenziali di default o senza MFA          | Presa di controllo dell'apparato               |
| Firmware non aggiornato                     | Vulnerabilità note sfruttabili                 |
| Regole temporanee mai rimosse               | Porte aperte dimenticate                       |
| Nessun log o nessuno che li legge           | Un'intrusione passa inosservata                |
| Rete piatta senza segmentazione             | Una macchina compromessa raggiunge tutto       |

## I limiti del firewall: quando non basta

Un firewall non protegge da:

* **phishing e social engineering**: un utente che consegna le credenziali non viene fermato da regole di rete;
* **traffico cifrato malevolo**, se non c'è ispezione TLS;
* **minacce interne**: un dipendente già dentro la rete;
* **vulnerabilità del firewall stesso**.

Quest'ultimo punto è reale. I firewall e gli altri dispositivi di bordo sono bersagli frequenti di [zero-day](/articoli/zero-day/): nel 2024, per esempio, una vulnerabilità di command injection nel componente GlobalProtect di Palo Alto PAN-OS (CVE-2024-3400) è stata sfruttata attivamente prima della patch. Secondo Google Threat Intelligence, nel 2025 quasi la metà degli zero-day sfruttati ha riguardato tecnologie enterprise, spesso dispositivi di bordo dove non c'è un EDR. Un firewall va quindi trattato come un sistema da monitorare e aggiornare, non come una scatola da installare e dimenticare.

Se un attaccante supera il perimetro, il danno diventa un [data breach](/articoli/data-breach/), con gli obblighi di notifica del [GDPR](/articoli/gdpr/) e, per i soggetti coinvolti, della [direttiva NIS 2](/articoli/nis2/), che richiede misure adeguate di sicurezza di rete.

## Domande frequenti sul firewall

### Cos'è un firewall di rete?

Un firewall che protegge un'intera rete, di solito posizionato al perimetro tra la rete interna e Internet, a differenza di un firewall host-based che protegge un singolo dispositivo.

### Cos'è un firewall stateful?

Un firewall che non valuta solo il singolo pacchetto ma lo stato della connessione a cui appartiene, riconoscendo automaticamente le risposte al traffico avviato dall'interno. È lo standard della maggior parte dei firewall moderni.

### Qual è la differenza tra firewall stateful e stateless?

Lo stateless valuta ogni pacchetto in isolamento; lo stateful tiene traccia delle connessioni attive e permette automaticamente le risposte legittime, con regole più semplici e sicure.

### Quali porte deve avere aperte un firewall?

Non esiste una lista universale: dipende dai servizi che quel sistema deve offrire. La regola è aprire solo le porte dei servizi necessari e bloccare tutto il resto (default deny).

### Cos'è un firewall?

Un sistema che filtra il traffico di rete in entrata e in uscita in base a regole, consentendo o bloccando le connessioni. Può essere hardware, software o nel cloud.

### Cosa significa firewall?

Letteralmente "parete tagliafuoco": come un muro che impedisce a un incendio di propagarsi, il firewall limita la diffusione di un attacco tra reti diverse.

### Come funziona un firewall?

Confronta ogni pacchetto con una lista di regole (IP, porta, protocollo, direzione, a volte applicazione e utente) e decide se consentirlo o bloccarlo. Con *default deny* tutto ciò che non è esplicitamente permesso viene bloccato.

### Quali sono i tipi di firewall?

Packet filtering, stateful inspection, proxy o application gateway, next-generation firewall (NGFW) e WAF per le applicazioni web. Possono essere di rete, host-based o nel cloud.

### Qual è la differenza tra firewall e antivirus?

Il firewall filtra il traffico di rete; l'antivirus o l'EDR rileva malware e comportamenti sospetti sul dispositivo. Si completano a vicenda.

### Cos'è un WAF?

Un Web Application Firewall protegge applicazioni web da attacchi a livello HTTP/HTTPS come SQL injection e XSS. È diverso da un firewall di rete tradizionale.

### Un firewall basta per essere protetti?

No. Non ferma phishing, minacce interne e traffico cifrato malevolo senza ispezione, e può avere vulnerabilità. Serve insieme ad aggiornamenti, MFA, EDR, segmentazione e monitoraggio.

### Il NAT è un firewall?

No. Il NAT traduce gli indirizzi e può nascondere la rete interna, ma non è pensato per filtrare in modo sicuro. Il port forwarding, anzi, espone servizi su Internet.

### Cos'è il default deny?

Una politica per cui ogni traffico non esplicitamente consentito viene bloccato. È la base di una configurazione sicura.

### Cosa significa porta filtrata in Nmap?

Che Nmap non riesce a stabilire se la porta è aperta perché qualcosa, di solito un firewall, scarta o rifiuta i pacchetti.
