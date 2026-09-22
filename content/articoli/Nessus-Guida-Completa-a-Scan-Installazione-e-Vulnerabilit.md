---
title: 'Nessus: Guida Completa a Scan, Installazione e Vulnerabilità'
slug: nessus
description: >-
  Guida a Nessus: installazione, Nessus Essentials, vulnerability scan,
  credentialed scan, policy, tuning e report. Tutto il workflow di vulnerability
  assessment.
image: /nessus-vulnerability-scanning-tenable.webp
draft: false
date: 2026-09-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - easy
tags:
  - Nessus
  - Vulnerability Scanning
  - Tenable
  - Nessus Essentials
  - Vulnerability Assessment
---

# Nessus: Come Funziona il Vulnerability Scanner di Tenable

Nessus è un vulnerability scanner sviluppato da Tenable. Analizza host, sistemi operativi, applicazioni e dispositivi di rete alla ricerca di vulnerabilità, configurazioni errate e software obsoleto, usando un ampio catalogo di plugin (NASL) in continua crescita. Supporta sia scansioni non-credentialed (senza accesso al sistema) sia credentialed (con login diretto sul target).

In un vulnerability assessment, Nessus può essere integrato nella fase successiva alla discovery e all'enumeration iniziale: prima di validare manualmente o tentare di sfruttare qualcosa, dà una mappa di priorità su cosa è potenzialmente vulnerabile.

**Quando usarlo:** vulnerability assessment autorizzato, security assessment periodici, lab HTB, preparazione OSCP/OSEP, compliance (PCI-DSS, SOC 2, ISO 27001).
**Cosa copre questa guida:** cos'è e come funziona, installazione, scan credentialed vs non-credentialed, policy custom, tuning per ridurre falsi positivi, Nessus Agent, compliance scanning, confronto con Nmap.
**Cosa non copre:** Tenable Vulnerability Management (piattaforma cloud) e ASV scanning esterno per PCI — richiedono un vendor approvato, non standalone Nessus.

## Cos'è Nessus?

Nessus identifica vulnerabilità, configurazioni errate e software obsoleto su sistemi, server e dispositivi di rete. Usa migliaia di plugin per eseguire controlli locali e remoti, e può effettuare sia scansioni non-credentialed sia credentialed. È uno dei vulnerability scanner più noti e utilizzati nel settore della cybersecurity, ma non l'unico strumento disponibile per questo compito.

## Nessus e Tenable: qual è la differenza?

Tenable è l'azienda che sviluppa Nessus. Nessus è il vulnerability scanner; Tenable offre inoltre piattaforme e servizi più ampi di vulnerability management ed exposure management.

| Nome                             | Cos'è                                                              |
| -------------------------------- | ------------------------------------------------------------------ |
| Tenable                          | Azienda di cybersecurity                                           |
| Nessus                           | Vulnerability scanner                                              |
| Nessus Essentials                | Edizione gratuita, con limitazioni                                 |
| Nessus Professional              | Edizione commerciale, uso illimitato di IP                         |
| Nessus Expert                    | Edizione commerciale con superficie esterna (domini, cloud)        |
| Tenable Vulnerability Management | Piattaforma cloud di vulnerability management dell'azienda Tenable |

## A cosa serve Nessus

* Vulnerability assessment
* Patch assessment (verifica che le patch di sicurezza siano davvero installate)
* Configuration assessment (configurazioni deboli o errate)
* Compliance assessment (PCI-DSS, SOC 2, ISO 27001, con edizione Professional/Expert)
* Validazione di sicurezza post-remediation (rescan)

Nessus non è principalmente uno strumento di exploitation: identifica condizioni potenzialmente vulnerabili, che vanno poi validate e prioritizzate — un punto su cui torniamo più avanti in questa guida.

## Nessus Essentials: cos'è e cosa include

| Edizione     | Limite IP               | Compliance scanning                     | Uso tipico                            |
| ------------ | ----------------------- | --------------------------------------- | ------------------------------------- |
| Essentials   | Limitato (poche decine) | No                                      | Lab personale, studio, piccoli test   |
| Professional | Illimitato              | Sì                                      | Consulenza, assessment su clienti     |
| Expert       | Illimitato              | Sì + superficie esterna (domini, cloud) | Enterprise, attack surface management |

Essentials è gratuito, supporta sia scan non-credentialed sia credentialed, ed è sufficiente per tutto quello che serve in questa guida, salvo la sezione compliance. Non include i template di compliance scanning: quelli richiedono Professional o Expert.

## Dove scaricare Nessus

Il download ufficiale è disponibile solo dal sito Tenable: [tenable.com/downloads/nessus](https://www.tenable.com/downloads/nessus). Prima di scaricare, seleziona sistema operativo e architettura corretti (`.deb` per Debian/Ubuntu/Kali, `.rpm` per RHEL/CentOS, `.msi` per Windows, `.dmg` per macOS). Evita mirror o pacchetti da fonti terze: essendo un software che gira con privilegi elevati, la provenienza del pacchetto conta.

## Prerequisiti

**Sistemi supportati:** Linux (Debian/Ubuntu/RHEL/CentOS), Windows Server/Desktop, macOS. Il server Nessus gira su qualsiasi di questi; il client è solo il browser (nessuna app dedicata).

**Permessi richiesti:**

* Sul server Nessus: privilegi di amministratore/root per installare e avviare il servizio
* Sui target: nessun permesso per scan non-credentialed; account con privilegi (locale o dominio) per scan credentialed completi
* Rete: il server Nessus deve raggiungere i target sulle porte da scansionare — se sei dietro un firewall o devi raggiungere una subnet interna, serve prima il [pivoting](https://hackita.it/articoli/pivoting)

## Come installare Nessus

### Su Kali Linux / Debian / Ubuntu

```bash
# Scarica il pacchetto per la tua distro dal sito Tenable
wget https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-<version>-debian10_amd64.deb

# Verifica checksum (sempre, non saltare)
sha256sum -c sha256sum_nessus

# Installa
sudo dpkg -i Nessus-<version>-debian10_amd64.deb

# Abilita e avvia il servizio
sudo systemctl enable --now nessusd
```

**Come avviare Nessus su Kali** (se il servizio non parte già da solo):

```bash
sudo systemctl start nessusd
```

**Come verificare che Nessus sia attivo:**

```bash
sudo systemctl status nessusd
```

### Su Windows

Scarica l'installer `.msi` dal sito Tenable, eseguilo come amministratore, segui il wizard grafico. Il servizio parte automaticamente al termine dell'installazione (`Tenable Nessus` in Servizi Windows).

### Su macOS

Scarica il pacchetto `.dmg` dal sito Tenable, apri e segui il wizard di installazione. Nessus gira come demone di sistema; avvio/stop si gestiscono dall'app o da `launchctl`.

### Accesso (uguale su tutti gli OS)

```
https://127.0.0.1:8834
```

Il certificato è self-signed — accetta l'avviso del browser. Registrati per Nessus Essentials (gratuito) o inserisci una licenza Professional/Expert.

Il download e la compilazione dei plugin al primo avvio richiede tempo — su connessioni lente può volerci più del previsto. Non interrompere il processo.

## Come funziona Nessus?

In sintesi, Nessus:

1. Identifica gli host attivi sulla rete target
2. Rileva porte e servizi in ascolto
3. Esegue i plugin di sicurezza pertinenti a quei servizi
4. Correla i risultati con vulnerabilità e configurazioni note, classificandoli per severità

Con uno scan credentialed, il punto 3 si estende: Nessus può accedere direttamente al sistema ed eseguire controlli locali (versione delle patch installate, configurazioni di sicurezza), invece di basarsi solo sulle informazioni esposte dalla rete.

### Nessus Scanning: la pipeline di una scansione

```
Discovery
   ↓
Port scanning
   ↓
Service detection
   ↓
Plugin checks
   ↓
Credentialed checks (se configurati)
   ↓
Vulnerability detection
   ↓
Risk classification
   ↓
Report
```

## Fase 0 — Capire la logica prima dei comandi

Nessus lavora su tre concetti:

1. **Scan** — l'esecuzione effettiva contro un target
2. **Policy** — la configurazione riutilizzabile (quali plugin, quali porte, che intensità)
3. **Plugin** — il singolo check (NASL, Nessus Attack Scripting Language) che rileva una vulnerabilità specifica

Una policy ben fatta è la differenza tra un report utile e un mare di falsi positivi che nessuno legge.

## Host Discovery (prima di tutto)

Non lanciare mai un Vulnerability Scan alla cieca su un range intero. Prima scopri chi è vivo:

1. New Scan → template Host Discovery
2. Target: `192.168.1.0/24` (CIDR, range, o comma-separated)
3. Lancia

Questo evita di sprecare tempo scansionando IP morti nel range. Su reti con host discovery poco affidabile (firewall che droppano ICMP), disabilita il ping check:

```
Discovery → Host Discovery → Ping the remote host: Off
```

Senza questo, Nessus potrebbe marcare host vivi come morti solo perché non rispondono a ICMP.

## Il Tuo Primo Scan: Basic Network Scan

1. New Scan → Basic Network Scan
2. Nome descrittivo (es. "Assessment-ClienteX-2026")
3. Targets:

```
# Singolo host
192.168.1.100

# Range
192.168.1.1-254

# CIDR
192.168.1.0/24

# Misto (comma-separated)
192.168.1.0/24, 10.0.0.1-50, host.internal.local
```

1. Save → Launch

Monitora il progresso da My Scans. Un Basic Network Scan su una rete di medie dimensioni con porte default impiega da minuti a un'ora circa; un full port scan (1-65535) sulla stessa rete richiede molto più tempo — pianifica di conseguenza.

## Il Workflow Completo (Non Solo "Lancia lo Scan")

Nessus da solo non serve a niente se non lo inserisci in un ciclo. Il flusso reale è sempre questo:

```
1. DISCOVERY
   Host Discovery scan → chi è vivo sulla rete

2. SCAN
   Basic/Advanced Scan (credentialed se possibile) → cosa è vulnerabile

3. TRIAGE
   Filtra per severity, distingui vero positivo da falso positivo,
   prioritizza in base a exploitability + criticità dell'asset

4. REMEDIATION
   Il team IT/dev applica patch, cambia configurazioni,
   chiude i finding confermati

5. RESCAN
   Rilancia lo stesso scan (o la stessa policy) sugli stessi target
   → verifica che i finding siano stati davvero chiusi, non solo "segnati come fatto"
```

Il passaggio che quasi tutti saltano è il 5 — rescan. Senza verificarlo, non sai se la remediation ha funzionato davvero o se qualcuno ha solo chiuso il ticket senza applicare la patch. In un assessment strutturato, il rescan finale è spesso richiesto esplicitamente dal cliente come prova di chiusura.

## Credentialed vs Non-Credentialed (la differenza che conta davvero)

Questa è la singola configurazione che più impatta l'accuratezza del report.

| Tipo             | Cosa vede                                                                                | Uso                                     |
| ---------------- | ---------------------------------------------------------------------------------------- | --------------------------------------- |
| Non-credentialed | Solo quello che un attaccante esterno vedrebbe (banner, porte aperte, versioni esposte)  | Perimeter assessment, primo giro        |
| Credentialed     | Login diretto sul target, controlla patch mancanti, configurazioni locali, permessi file | Assessment interno completo, compliance |

Uno scan credentialed trova sistematicamente molte più vulnerabilità di uno non-credentialed, perché conferma se una patch è davvero installata invece di indovinare dal banner del servizio.

### Setup credenziali SSH (Linux target)

```
Scan → Credentials → SSH
```

Se non hai chiaro il funzionamento di base del protocollo, vedi la guida a [SSH](https://hackita.it/articoli/ssh/). Tre metodi di autenticazione:

```
Password       — username/password, sconsigliato in produzione (credenziali salvate in Nessus)
Public Key     — raccomandato, genera coppia di chiavi dedicata
Kerberos       — per host Linux joinati ad Active Directory
```

Best practice — account dedicato, non root:

```bash
# Crea account dedicato per lo scanning
sudo useradd -m -s /bin/bash nessus-scan

# Aggiungi la chiave pubblica
sudo mkdir -p /home/nessus-scan/.ssh
echo "ssh-rsa AAAA... nessus-scanner" | sudo tee -a /home/nessus-scan/.ssh/authorized_keys

# Concedi sudo mirato (non full root) per i comandi che Nessus deve eseguire
# Configura /etc/sudoers.d/nessus-scan con NOPASSWD solo sui comandi necessari
```

### Setup credenziali Windows (SMB)

```
Scan → Credentials → Windows
Tipo: Password, oppure Kerberos per ambienti AD
```

Serve un account con privilegi di amministratore locale (o dominio) sul target per un audit completo. Per capire meglio cosa Nessus interroga in questa fase, vedi la guida a [SMB](https://hackita.it/articoli/smb/).

## Port Range e Performance

| Setting         | Default      | Uso consigliato                                                                                              |
| --------------- | ------------ | ------------------------------------------------------------------------------------------------------------ |
| Port scan range | Porte comuni | Usa `1-65535` solo per assessment di sicurezza completi — un full scan impiega molto più a lungo del default |
| Scan type       | Normal       | Aggressive solo in lab dedicati, mai su ambienti produzione                                                  |
| UDP scanning    | Off          | Aumenta drasticamente la durata, difficile distinguere porte aperte da filtrate                              |

```
Discovery → Port Scanning → Port scan range: 1-65535
```

Per scan mirati su servizi specifici:

```
Discovery → Custom → Port scan range: 80,443,3389,445
```

## Policy Custom (oltre i template default)

I template built-in (Basic Network Scan, Advanced Scan, Web Application Test, Malware Scan, Credentialed Patch Audit) coprono la maggior parte dei casi, ma per assessment mirati serve una policy custom.

### Esempio: Web Application Audit

```
Policies → New Policy → Web Application Tests

Enable:
- CGI scanning
- Web form testing
- Credenziali HTTP (se disponibili)
```

Per la parte di validazione manuale sulle applicazioni web trovate vulnerabili, [Burp Suite](https://hackita.it/articoli/burp-suite/) resta lo strumento di riferimento.

### Esempio: filtro dinamico per CVE specifica

```
New Scan → Advanced Dynamic Scan

Dynamic Plugins tab:
  Left dropdown: CVE
  Middle dropdown: Equals
  Right field: CVE-2021-3156
  → Preview Plugins

Combina filtri (opzionale):
  Filter 2 - Left: Plugin Family
  Filter 2 - Right: Ubuntu Local Security Checks
  → Preview Plugins
```

Utile quando devi verificare rapidamente se una CVE specifica (es. appena pubblicata) è presente sul parco macchine, senza lanciare uno scan completo.

## Riduzione Falsi Positivi (Tuning Reale)

I falsi positivi sono il problema più comune per chi inizia con Nessus — sprecano tempo di analisi.

| Configurazione                                             | Effetto                                                                                                     |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Abilita risoluzione DNS (Discovery → Host Discovery)       | Senza, Nessus può riportare vulnerabilità sull'host sbagliato o duplicare entry per lo stesso sistema       |
| Scan credentialed                                          | Conferma se una patch è davvero installata invece di dedurlo dal banner — riduzione drastica falsi positivi |
| Safe Checks abilitato (default)                            | Evita plugin distruttivi che potrebbero causare crash su servizi fragili                                    |
| Disabilita host discovery se gli host sono già noti attivi | Velocizza e riduce rumore su reti con firewall aggressivi                                                   |

Non disabilitare mai Safe Checks in produzione — alcuni plugin di test distruttivo possono causare crash su servizi vulnerabili. Riservalo a lab isolati.

## Interpretare i Risultati

Dopo il completamento, apri lo scan → tab Vulnerabilities.

Ogni finding include: **Plugin Name** (il check specifico eseguito), **Severity** (Critical/High/Medium/Low/Info), **Description**, **Solution** (passi di remediation concreti), **References** (CVE, CVSS score, link esterni).

Strategia di triage: non farti sommergere da centinaia di risultati Info/Low. Filtra prima su Critical e High disabilitando il raggruppamento (icona ingranaggio → Disable Groups) per una vista dettagliata.

Findings tipici in un Credentialed Patch Audit: patch OS/applicazioni mancanti (per versione e numero patch), applicazioni vulnerabili (Firefox, curl, ecc.), plugin family "Local Security Checks", problemi di configurazione, rischi di privilege escalation (approfondimenti su [Linux privilege escalation](https://hackita.it/articoli/linux-privesc/) e [Windows privilege escalation](https://hackita.it/articoli/privilege-escalation-windows/)).

### Esempio reale: leggere un finding Critical

```
Plugin Name: MS17-010: Security Update for Microsoft Windows SMB Server
Severity: Critical
CVSS: 9.3
Host: 192.168.1.50

Description:
  Il sistema remoto è affetto da una vulnerabilità di esecuzione
  codice remoto nell'implementazione SMBv1 (EternalBlue).

Solution:
  Applicare la patch MS17-010, oppure disabilitare SMBv1.

References:
  CVE-2017-0144, CVE-2017-0145
```

Come lo leggi:

1. Severity Critical + CVSS alto → priorità massima, non aspettare
2. Host specifico → sai esattamente dove intervenire
3. Description → ti dice il meccanismo (SMBv1, RCE) — se conosci la CVE, sai già che è documentata pubblicamente
4. Solution → azione diretta, in questo caso patch o disabilitazione protocollo

Come decidi se è vero positivo o falso positivo:

* Scan credentialed? Se sì, e il plugin ha verificato la versione della patch installata (non solo il banner SMB), è quasi certamente un vero positivo
* Scan non-credentialed? Il plugin potrebbe aver dedotto la vulnerabilità solo dalla risposta del protocollo — verifica manualmente prima di segnalarlo come critico (es. `nmap --script smb-vuln-ms17-010` per conferma incrociata, vedi la guida a [Nmap](https://hackita.it/articoli/nmap/))
* Il servizio è raggiungibile davvero dall'attaccante? Un finding Critical su un host irraggiungibile da fuori la rete interna ha priorità diversa da uno esposto su Internet

Una CVE nota come EternalBlue (MS17-010) con scan credentialed che conferma la versione della patch è un caso da manuale: vero positivo, azione immediata.

## Export e Reporting

Report templates disponibili: Detailed Vulnerabilities By Host (findings completi per host), Complete List By Host (sommario senza dettagli estesi), Executive Summary (overview alto livello per management), Custom templates.

Formati export: HTML, CSV, Nessus (.nessus), Nessus DB.

CSV è ideale per: import in ticketing system (Jira, ServiceNow), trend analysis su scan multipli nel tempo, integrazione SIEM (Splunk, QRadar).

## Nessus Agent: a cosa serve?

Nessus Agent è un componente installato direttamente sull'endpoint, che raccoglie informazioni di sicurezza dal sistema senza affidarsi esclusivamente alla scansione remota tradizionale — utile per dispositivi che non sono sempre raggiungibili in rete (es. laptop aziendali) o per ridurre il carico di rete generato da scan remoti su larga scala.

|                          | Nessus Scanner               | Nessus Agent        |
| ------------------------ | ---------------------------- | ------------------- |
| Installazione sul target | No                           | Sì                  |
| Scan remoto              | Sì                           | No                  |
| Visibilità locale        | Limitata, salvo credentialed | Alta                |
| Uso tipico               | Network assessment           | Endpoint assessment |

## Compliance Scanning e PCI-DSS (Professional/Expert)

Le template di compliance non sono disponibili in Nessus Essentials — servono Professional o Expert.

| Framework   | Cosa copre                                                                             |
| ----------- | -------------------------------------------------------------------------------------- |
| PCI-DSS 4.0 | Requirement 6 (patch/CVE), Requirement 8 (password policy, account lockout)            |
| SOC 2       | Trust Services Criteria: Security, Availability, Processing Integrity, Confidentiality |
| ISO 27001   | Controlli di sicurezza delle informazioni allineati alla ISO                           |

Un punto da tenere ben distinto: gli external ASV scan (Approved Scanning Vendor) richiesti per la compliance PCI non possono essere fatti con Nessus standalone — serve un vendor approvato secondo i requisiti del [PCI Security Standards Council](https://www.pcisecuritystandards.org/) (es. Tenable Vulnerability Management, la piattaforma cloud, o un altro ASV certificato). Nessus standalone può fare scan interni di preparazione, ma non sostituisce l'ASV esterno richiesto trimestralmente.

## Nessus vs Nmap: qual è la differenza?

|                          | Nessus | Nmap                         |
| ------------------------ | ------ | ---------------------------- |
| Port scanning            | Sì     | Sì                           |
| Service discovery        | Sì     | Sì                           |
| Vulnerability assessment | Sì     | Parziale, tramite script NSE |
| Credentialed scanning    | Sì     | Limitato/diverso approccio   |
| Patch assessment         | Sì     | No                           |
| Compliance               | Sì     | No                           |

[Nmap](https://hackita.it/articoli/nmap/) è principalmente uno strumento di discovery ed enumeration; Nessus è progettato principalmente per vulnerability assessment. I due strumenti sono complementari, non alternativi: un flusso tipico usa Nmap per la discovery iniziale e Nessus per l'assessment di vulnerabilità sui servizi trovati.

## Quale scan Nessus scegliere?

| Situazione                     | Scan consigliato                      |
| ------------------------------ | ------------------------------------- |
| Scoprire host attivi           | Host Discovery                        |
| Primo vulnerability assessment | Basic Network Scan                    |
| Audit approfondito             | Advanced Scan                         |
| Verifica patch mancanti        | Credentialed Patch Audit              |
| Applicazione web               | Web Application Tests                 |
| Verificare una CVE specifica   | Advanced Dynamic Scan                 |
| Requisiti normativi            | Compliance scan (Professional/Expert) |

## Best Practice Operative

**Safe Checks:** sempre attivo, salvo lab completamente isolati dove accetti consapevolmente il rischio di crash su servizi fragili durante test aggressivi. Su qualunque ambiente cliente o produzione, non disattivarlo mai.

**Scan full range (1-65535):** per assessment periodici approfonditi (es. trimestrali) o quando sospetti servizi non standard su porte insolite. Per lo scan di routine settimanale, un range mirato sulle porte comuni è sufficiente e molto più veloce.

**Schedulare scan periodici:**

```
Scans → New Scan → [template] → Schedule tab
Frequency: Daily / Weekly / Monthly
```

Pattern comune: Host Discovery quotidiano o quasi (leggero e veloce), Vulnerability Scan completo settimanale o mensile (secondo il ciclo di patching interno), rescan mirato post-remediation on-demand.

**Performance tuning per reti grandi:** su reti con centinaia di host, valuta di dividere lo scan in batch per subnet invece di un unico scan enorme — più semplice da monitorare, e un fallimento parziale non compromette tutto il risultato.

## Limiti Reali di Nessus

**"Found" non significa "exploitable".** Nessus segnala che una condizione vulnerabile esiste (versione software nota per un CVE, configurazione debole) — non conferma che sia effettivamente sfruttabile nel tuo contesto specifico. Alcuni plugin fanno una verifica attiva (es. tentano realmente l'exploit in modo sicuro), altri si limitano a un controllo di versione. La sezione Plugin Output del finding spesso chiarisce quale dei due casi si tratti.

**Il banner grabbing può sbagliare la versione.** Su scan non-credentialed, alcuni finding derivano dal banner del servizio (es. header HTTP `Server: Apache/2.4.41`). Se l'amministratore ha modificato il banner per hardening, o se il servizio è stato patchato senza aggiornare la versione dichiarata (backport di sicurezza), Nessus può segnalare un falso positivo o, peggio, mancare un vero problema.

**I plugin non validano sempre la catena di exploitation completa.** Una vulnerabilità RCE segnalata come Critical potrebbe richiedere precondizioni che Nessus non verifica (es. un servizio raggiungibile solo da una subnet specifica, un'autenticazione preliminare). Il CVSS score riflette la severità teorica, non necessariamente la sfruttabilità pratica nel tuo scenario.

Conclusione pratica: usa Nessus per la fase di discovery e prioritizzazione, non come sostituto della validazione manuale. Un finding Critical con CVSS 9.8 merita sempre una verifica umana prima di finire in un report come "vulnerabilità confermata sfruttabile".

## Errori Comuni

| Errore                                                  | Conseguenza                                              | Fix                                                                                    |
| ------------------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Scan non-credentialed spacciato per assessment completo | Report incompleto, falsa sensazione di sicurezza         | Usa sempre credentialed quando possibile, dichiara la limitazione se non lo è          |
| Full port range su ogni scan di routine                 | Scan che impiegano ore invece di minuti                  | Range mirato per scan frequenti, full range solo per assessment periodici approfonditi |
| Credenziali root/administrator dirette                  | Rischio se Nessus viene compromesso, non-least-privilege | Account dedicato con permessi mirati                                                   |
| Aggressive scan su sistemi di produzione                | Possibili crash di servizi fragili                       | Normal/Slow su produzione, Aggressive solo in lab                                      |
| Nessun DNS resolution abilitato                         | Vulnerabilità riportate sull'host sbagliato, duplicati   | Abilita sempre risoluzione DNS in Host Discovery                                       |
| Scendere subito nei findings senza triage               | Ore perse su Info/Low mentre Critical aspettano          | Disabilita Grouping, filtra per severity prima di tutto                                |

## Nessus nel Workflow di un Pentest

Nessus non è un tool isolato — si colloca in un punto preciso della catena di un assessment:

```
RECON
  Enumerazione passiva/attiva della superficie (Nmap, subdomain enum, OSINT)
  → Nessus non sostituisce questa fase, la presuppone

ENUMERATION
  Nessus entra qui: scan di vulnerabilità su quello che la recon ha trovato
  Output: lista di CVE/misconfigurazioni potenziali per host

VALIDATION
  Qui Nessus si ferma. La validazione manuale (o con tool exploit-specific)
  conferma quali finding sono davvero sfruttabili nel contesto reale

EXPLOITATION
  Metasploit, exploit custom, manual testing — usando i finding Nessus
  come mappa, non come garanzia

REPORTING
  I finding Nessus (grezzi o validati) confluiscono nel report finale,
  spesso correlati con le prove di exploitation raccolte manualmente
```

Il ruolo esatto di Nessus: accelera enormemente l'enumeration e dà una mappa di priorità, ma non è né il punto di partenza (serve la recon prima, es. con [Nmap](https://hackita.it/articoli/nmap/)) né il punto di arrivo (serve la validazione con strumenti come [Metasploit](https://hackita.it/articoli/metasploit/) e l'exploitation dopo). I finding confermati possono poi essere organizzati in un report tramite uno strumento dedicato come [Dradis](https://hackita.it/articoli/dradis-reporting). Chi tratta l'output di Nessus come report finale senza passare per la validazione sta consegnando un documento di falsi positivi mescolati a veri rischi, indistinguibili tra loro.

## Cheat Sheet Finale

| Operazione              | Percorso/Comando                                     |
| ----------------------- | ---------------------------------------------------- |
| Avvia servizio          | `sudo systemctl start nessusd`                       |
| Verifica stato servizio | `sudo systemctl status nessusd`                      |
| Accesso web UI          | `https://127.0.0.1:8834`                             |
| Host Discovery          | New Scan → Host Discovery                            |
| Scan base               | New Scan → Basic Network Scan                        |
| Disabilita ping check   | Discovery → Host Discovery → Ping: Off               |
| Full port range         | Discovery → Port Scanning → 1-65535                  |
| Credenziali SSH         | Scan → Credentials → SSH → Public Key                |
| Credenziali Windows     | Scan → Credentials → Windows                         |
| Filtro per CVE          | Advanced Dynamic Scan → Dynamic Plugins → CVE Equals |
| Disabilita grouping     | Icona ingranaggio → Disable Groups                   |
| Export CSV              | Scan completato → Export → CSV                       |

## FAQ

**Cos'è Nessus?**
Un vulnerability scanner sviluppato da Tenable, che identifica vulnerabilità, configurazioni errate e software obsoleto su host, server e dispositivi di rete.

**A cosa serve Nessus?**
A vulnerability assessment, patch assessment, configuration assessment, compliance assessment e validazione post-remediation.

**Nessus è gratuito?**
Esiste un'edizione gratuita, Nessus Essentials, con un limite di IP scansionabili e senza template di compliance. Le edizioni Professional ed Expert sono a pagamento.

**Cos'è Nessus Essentials?**
L'edizione gratuita di Nessus, pensata per lab personali e studio, con un limite sul numero di IP scansionabili e senza compliance scanning.

**Come installare Nessus su Kali Linux?**
Scarica il pacchetto `.deb` dal sito Tenable, installalo con `dpkg -i`, poi abilita e avvia il servizio con `sudo systemctl enable --now nessusd`.

**Come avviare Nessus su Kali?**
Con `sudo systemctl start nessusd`, verificabile con `sudo systemctl status nessusd`.

**Qual è la porta di Nessus?**
La web UI è raggiungibile su `https://127.0.0.1:8834`.

**Qual è la differenza tra scan credentialed e non-credentialed?**
Il non-credentialed vede solo ciò che è esposto dalla rete (banner, porte); il credentialed accede direttamente al sistema e verifica patch e configurazioni locali, con un'accuratezza molto più alta.

**Nessus può trovare le CVE?**
Sì, i plugin sono spesso mappati direttamente a CVE specifiche, e puoi anche filtrare uno scan per verificare la presenza di una CVE puntuale (Advanced Dynamic Scan).

**Nessus sostituisce Nmap?**
No. Nmap è orientato a discovery ed enumeration, Nessus a vulnerability assessment. Si usano in combinazione, non in alternativa.

**Nessus può eseguire exploit?**
Non è il suo scopo principale: segnala condizioni potenzialmente vulnerabili, che vanno validate con strumenti dedicati (es. Metasploit) o manualmente.

**Nessus può essere usato per la compliance PCI-DSS?**
Per scan interni di preparazione sì (richiede Professional o Expert per i template dedicati), ma non sostituisce l'ASV scan esterno richiesto dallo standard PCI, che va eseguito da un vendor approvato.

**Che differenza c'è tra Nessus e Nessus Agent?**
Nessus (scanner) opera da remoto sulla rete; Nessus Agent è installato direttamente sull'endpoint e raccoglie dati di sicurezza localmente, utile per dispositivi non sempre raggiungibili in rete.

**Quanto dura una scansione Nessus?**
Dipende da range di porte, numero di host e se è credentialed. Un Basic Network Scan su una rete di medie dimensioni con porte default richiede da minuti a circa un'ora; un full port scan (1-65535) richiede molto di più.

## Fonti ufficiali

* [Tenable Nessus Documentation](https://docs.tenable.com/nessus/): documentazione ufficiale completa
* [Nessus Scan Tuning Guide](https://docs.tenable.com/quick-reference/nessus-scan-tuning/): riferimento per la riduzione dei falsi positivi
* [Tenable – Download Nessus](https://www.tenable.com/downloads/nessus): pagina ufficiale di download
* [PCI Security Standards Council](https://www.pcisecuritystandards.org/): riferimento ufficiale per i requisiti PCI-DSS e ASV
* [ADHDecode – Vulnerability Scanning: Nessus CVSS Triage](https://adhdecode.com/network-security/network-penetration-testing/network-vulnerability-scanning-nessus/): riflessione pratica su falsi positivi/negativi e tuning in ambienti reali
* [Jonathan's Blog – Nessus Tutorial](https://jonathansblog.co.uk/vulnerability-scanning-with-nessus-tutorial): guida indipendente con note operative su safe checks e performance
