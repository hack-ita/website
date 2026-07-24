---
title: 'Filesystem Windows: NTFS, cartelle e registro per il pentest'
slug: windows
description: 'Guida pratica al filesystem Windows per il pentest: NTFS, cartelle di sistema, registro, ACL, comandi di enumerazione, privilege escalation e detection.'
image: /windows-filesystem-architecture-hackita.webp
draft: false
date: 2026-07-24T00:00:00.000Z
categories:
  - windows
subcategories:
  - filesystem
tags:
  - NTFS
  - Windows Internals
  - Registro Windows
  - ACL NTFS
  - Privilege Escalation
  - Windows Enumeration
---

# Architettura del filesystem Windows: NTFS, cartelle di sistema e registro spiegati per un pentester

**Il filesystem di Windows** non è semplicemente una lista di cartelle da conoscere a memoria: è un'architettura complessa basata su **volumi, permessi NTFS, registry hive e meccanismi di sicurezza** che determinano come il sistema gestisce file, configurazioni e privilegi.

Capire **come è costruito Windows**, come vengono applicati i permessi e chi può realmente accedere o modificare una risorsa è fondamentale per riconoscere potenziali vettori di attacco durante una fase di **enumerazione**, **penetration test** o **privilege escalation Windows**.

In questo articolo analizzeremo la struttura del **filesystem Windows**, i componenti principali e gli elementi che possono trasformarsi in superfici di attacco. Ogni sezione termina con un box **"Per il pentest"**, collegando la teoria alle verifiche pratiche da eseguire durante un assessment di sicurezza.

## Prima di iniziare: cosa devi sapere

* basi di Windows: cos'è un percorso, la differenza tra utente e amministratore
* accesso a una shell su una macchina Windows (RDP, shell da exploit, o accesso fisico in un lab)
* utile ma non indispensabile: nozioni base di registro e permessi NTFS

## Panoramica visiva della struttura

Prima di entrare nel dettaglio di ogni componente, un colpo d'occhio sull'albero delle cartelle che ricorreranno in tutto l'articolo:

```
C:\
├── Windows
│   ├── System32
│   │   ├── config          (hive SAM, SYSTEM, SECURITY)
│   │   ├── drivers          (.sys)
│   │   ├── DriverStore
│   │   ├── inetsrv          (config IIS)
│   │   └── Tasks
│   ├── SysWOW64
│   ├── WinSxS
│   ├── Prefetch
│   ├── Panther              (unattend.xml)
│   ├── SoftwareDistribution
│   └── Logs
│
├── Users
│   ├── <utente>
│   │   ├── Desktop / Documents / Downloads
│   │   └── AppData
│   │       ├── Roaming
│   │       ├── Local
│   │       └── LocalLow
│   └── Public
│
├── Program Files
├── Program Files (x86)
├── ProgramData
├── inetpub                  (solo se IIS è installato)
├── Recovery
├── PerfLogs
├── System Volume Information
└── $Recycle.Bin
```

## Come è organizzato Windows internamente

Prima di scendere nel dettaglio del filesystem, vale la pena capire su cosa si appoggia: il filesystem non è un'isola, è solo uno dei componenti con cui il sistema operativo lavora. Ad alto livello, un avvio di Windows attraversa questi strati, uno sopra l'altro:

```
Hardware
   ↓
UEFI / BIOS
   ↓
Windows Boot Manager
   ↓
Kernel (ntoskrnl.exe)
   ↓
HAL (Hardware Abstraction Layer)
   ↓
Executive
   ↓
Driver
   ↓
Servizi (Services)
   ↓
Session Manager
   ↓
Winlogon
   ↓
Explorer.exe
   ↓
Applicazioni
```

Il concetto chiave che tiene insieme tutto questo è la separazione tra **kernel mode** e **user mode**:

* **Kernel mode (Ring 0)** — dove girano il kernel stesso, l'HAL e i driver. L'**HAL** (Hardware Abstraction Layer) è il livello software che fa da tramite tra il sistema operativo e l'hardware fisico della macchina: grazie a lui, Windows può girare su hardware diverso senza dover riscrivere il kernel ogni volta. In kernel mode c'è accesso diretto e illimitato all'hardware, e un crash qui può far cadere l'intero sistema (la classica schermata blu)
* **User mode (Ring 3)** — dove girano tutte le applicazioni normali (Explorer, Chrome, `cmd.exe`, PowerShell): accesso controllato alle risorse, sempre mediato dal kernel. Un crash in user mode al massimo chiude quell'applicazione, non abbatte il sistema

Dentro il kernel mode, l'**Executive** non è un singolo programma ma un insieme di sottosistemi specializzati — uno gestisce la memoria, uno i processi, uno la sicurezza, uno l'I/O — su cui si appoggiano i driver e, indirettamente, tutto il resto del sistema.

Un'applicazione in user mode non parla mai direttamente con l'hardware o il filesystem: passa sempre attraverso una catena di livelli — le API pubbliche di **kernel32.dll** (la libreria che espone le funzioni Windows alle applicazioni), poi le funzioni di livello più basso di **ntdll.dll** (spesso prefissate `Nt*` o `Zw*`, che corrispondono quasi direttamente alle operazioni del kernel), infine una **system call** — cioè una richiesta formale che il programma fa al kernel, attraversando il confine tra user mode e kernel mode. Questo confine è anche un confine di sicurezza: è il punto in cui il sistema verifica i permessi prima di lasciar procedere un'operazione.

> **Per il pentest:** capire questa catena spiega perché molte tecniche di evasione o di iniezione di codice lavorano proprio a livello di `ntdll.dll` (per esempio bypassando gli hook di un EDR che intercetta le chiamate a livello di `kernel32.dll` ma non quelle dirette alle syscall). Strumenti come i [LOLBins](https://hackita.it/articoli/lolbins/) sfruttano proprio questi binari di sistema già caricati in memoria per evitare di importare tool evidenti. Non è indispensabile scrivere exploit a questo livello per fare un pentest efficace, ma riconoscere questi nomi quando compaiono in un tool o in un report ti evita di trattarli come scatole nere.

![Kernel Mode vs User Mode: dove girano le applicazioni e i componenti di sistema](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgODYwIDMyMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPHJlY3Qgd2lkdGg9Ijg2MCIgaGVpZ2h0PSIzMjAiIGZpbGw9IiNmZmZmZmYiLz4KICA8dGV4dCB4PSI0MzAiIHk9IjMwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE2IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjMTExMTExIj5LZXJuZWwgTW9kZSB2cyBVc2VyIE1vZGU6IGRvdmUgZ2lyYW5vIGxlIGNvc2U8L3RleHQ+CgogIDwhLS0gVXNlciBNb2RlIGJveCAtLT4KICA8cmVjdCB4PSIzMCIgeT0iNTAiIHdpZHRoPSIzODAiIGhlaWdodD0iMjQwIiByeD0iMTAiIGZpbGw9IiNmNWY1ZjUiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIxLjUiLz4KICA8dGV4dCB4PSIyMjAiIHk9Ijc1IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjMTExMTExIj5VU0VSIE1PREUg4oCUIFJpbmcgMzwvdGV4dD4KICA8dGV4dCB4PSIyMjAiIHk9IjkzIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjExIiBmaWxsPSIjNTU1NTU1Ij5BY2Nlc3NvIGxpbWl0YXRvLCBtZWRpYXRvIGRhbCBrZXJuZWw8L3RleHQ+CgogIDxyZWN0IHg9IjU1IiB5PSIxMDgiIHdpZHRoPSIxNTUiIGhlaWdodD0iNDAiIHJ4PSI2IiBmaWxsPSIjMTExMTExIi8+CiAgPHRleHQgeD0iMTMyIiB5PSIxMzAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNmZmZmZmYiPkV4cGxvcmVyLmV4ZTwvdGV4dD4KICA8cmVjdCB4PSIyMjUiIHk9IjEwOCIgd2lkdGg9IjE1NSIgaGVpZ2h0PSI0MCIgcng9IjYiIGZpbGw9IiMxMTExMTEiLz4KICA8dGV4dCB4PSIzMDIiIHk9IjEzMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2ZmZmZmZiI+Q2hyb21lIC8gRWRnZTwvdGV4dD4KCiAgPHJlY3QgeD0iNTUiIHk9IjE2MCIgd2lkdGg9IjE1NSIgaGVpZ2h0PSI0MCIgcng9IjYiIGZpbGw9IiMxMTExMTEiLz4KICA8dGV4dCB4PSIxMzIiIHk9IjE4MiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2ZmZmZmZiI+Y21kLmV4ZTwvdGV4dD4KICA8cmVjdCB4PSIyMjUiIHk9IjE2MCIgd2lkdGg9IjE1NSIgaGVpZ2h0PSI0MCIgcng9IjYiIGZpbGw9IiMxMTExMTEiLz4KICA8dGV4dCB4PSIzMDIiIHk9IjE4MiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2ZmZmZmZiI+UG93ZXJTaGVsbDwvdGV4dD4KCiAgPHJlY3QgeD0iNTUiIHk9IjIxMiIgd2lkdGg9IjMyNSIgaGVpZ2h0PSI0MCIgcng9IjYiIGZpbGw9IiNkYzI2MjYiLz4KICA8dGV4dCB4PSIyMTciIHk9IjIyOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiI+a2VybmVsMzIuZGxsIOKGkiBudGRsbC5kbGwg4oaSIHN5c2NhbGwg4oaTPC90ZXh0PgogIDx0ZXh0IHg9IjIxNyIgeT0iMjQ0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEwIiBmaWxsPSIjZmZmZmZmIj5pbCBjb25maW5lIGNoZSBzZXBhcmEgdXNlciBtb2RlIGRhbCBrZXJuZWw8L3RleHQ+CgogIDwhLS0gS2VybmVsIE1vZGUgYm94IC0tPgogIDxyZWN0IHg9IjQ1MCIgeT0iNTAiIHdpZHRoPSIzODAiIGhlaWdodD0iMjQwIiByeD0iMTAiIGZpbGw9IiMxMTExMTEiIHN0cm9rZT0iI2RjMjYyNiIgc3Ryb2tlLXdpZHRoPSIxLjUiLz4KICA8dGV4dCB4PSI2NDAiIHk9Ijc1IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZGMyNjI2Ij5LRVJORUwgTU9ERSDigJQgUmluZyAwPC90ZXh0PgogIDx0ZXh0IHg9IjY0MCIgeT0iOTMiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTEiIGZpbGw9IiNhM2EzYTMiPkFjY2Vzc28gZGlyZXR0byBhbGwnaGFyZHdhcmU8L3RleHQ+CgogIDxyZWN0IHg9IjQ3NSIgeT0iMTA4IiB3aWR0aD0iMTU1IiBoZWlnaHQ9IjQwIiByeD0iNiIgZmlsbD0iI2RjMjYyNiIvPgogIDx0ZXh0IHg9IjU1MiIgeT0iMTMwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEyIiBmaWxsPSIjZmZmZmZmIj5udG9za3JubC5leGU8L3RleHQ+CiAgPHJlY3QgeD0iNjQ1IiB5PSIxMDgiIHdpZHRoPSIxNTUiIGhlaWdodD0iNDAiIHJ4PSI2IiBmaWxsPSIjZGMyNjI2Ii8+CiAgPHRleHQgeD0iNzIyIiB5PSIxMzAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNmZmZmZmYiPkhBTDwvdGV4dD4KCiAgPHJlY3QgeD0iNDc1IiB5PSIxNjAiIHdpZHRoPSIxNTUiIGhlaWdodD0iNDAiIHJ4PSI2IiBmaWxsPSIjMzMzMzMzIi8+CiAgPHRleHQgeD0iNTUyIiB5PSIxODIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNmZmZmZmYiPkRyaXZlciAoLnN5cyk8L3RleHQ+CiAgPHJlY3QgeD0iNjQ1IiB5PSIxNjAiIHdpZHRoPSIxNTUiIGhlaWdodD0iNDAiIHJ4PSI2IiBmaWxsPSIjMzMzMzMzIi8+CiAgPHRleHQgeD0iNzIyIiB5PSIxODIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNmZmZmZmYiPkV4ZWN1dGl2ZTwvdGV4dD4KCiAgPHJlY3QgeD0iNDc1IiB5PSIyMTIiIHdpZHRoPSIzMjUiIGhlaWdodD0iNDAiIHJ4PSI2IiBmaWxsPSIjMzMzMzMzIi8+CiAgPHRleHQgeD0iNjM3IiB5PSIyMzYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTEiIGZpbGw9IiNhM2EzYTMiPlVuIGNyYXNoIHF1aSA9IHNjaGVybWF0YSBibHUgKEJTT0QpPC90ZXh0PgoKICA8bGluZSB4MT0iNDEwIiB5MT0iMTYwIiB4Mj0iNDUwIiB5Mj0iMTYwIiBzdHJva2U9IiNkYzI2MjYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnIpIi8+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnIiIHZpZXdCb3g9IjAgMCAxMCAxMCIgcmVmWD0iOSIgcmVmWT0iNSIgbWFya2VyV2lkdGg9IjciIG1hcmtlckhlaWdodD0iNyIgb3JpZW50PSJhdXRvLXN0YXJ0LXJldmVyc2UiPgogICAgICA8cGF0aCBkPSJNMCwwIEwxMCw1IEwwLDEwIHoiIGZpbGw9IiNkYzI2MjYiLz4KICAgIDwvbWFya2VyPgogIDwvZGVmcz4KICA8dGV4dCB4PSI0MzAiIHk9IjE1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMCIgZmlsbD0iI2RjMjYyNiI+c3lzY2FsbDwvdGV4dD4KPC9zdmc+Cg==)

## Architettura del filesystem: NTFS, volumi e collegamenti

Windows organizza i dati su disco con **NTFS** (New Technology File System), il filesystem usato di default da Windows NT in poi. NTFS non è solo "dove stanno i file": gestisce anche i permessi (le ACL, viste più avanti), la cifratura nativa (EFS), e diversi tipi di collegamento tra percorsi che vale la pena distinguere bene.

**Volumi e lettere di unità.** Ogni disco (o partizione) viene assegnato a una lettera — `C:`, `D:` e così via — che Windows tratta come una radice indipendente. `C:` è quasi sempre il volume di sistema, ma su server con più dischi puoi trovare dati applicativi, backup o condivisioni su volumi separati, spesso trascurati durante un'enumerazione che si concentra solo su `C:\`. In fase di [post-exploitation](https://hackita.it/articoli/post-exploitation/), enumerare tutti i volumi montati è uno dei primi passi: backup e share su `D:\` o `E:\` possono contenere dati sensibili non presenti sul volume di sistema.

**Mount point, Junction, Reparse Point, Symbolic Link, Hard Link.** Sono concetti spesso confusi tra loro, ma la differenza conta:

* Un **mount point** collega un intero volume a una cartella vuota su un altro volume, invece che assegnargli una lettera — utile su server con molti dischi
* Una **junction** è un collegamento simbolico a livello di cartella, ma limitato allo stesso computer (non attraversa la rete) e storicamente utilizzabile anche da utenti non amministratori
* Un **reparse point** è il meccanismo tecnico su cui si basano junction e symbolic link: un attributo speciale che NTFS attacca a una cartella o un file per segnalare al filesystem "quando un programma arriva qui, prima di procedere passa attraverso questo filtro" — e quel filtro può reindirizzarlo altrove, decrittare il contenuto, o fare altro ancora
* Un **symbolic link** (symlink) è concettualmente simile a una junction ma più flessibile: può puntare a file singoli, funzionare su percorsi di rete, e — a differenza delle junction — la sua creazione richiede tipicamente privilegi elevati (a meno che la modalità sviluppatore non sia attiva)
* Un **hard link** non è un collegamento ma un secondo nome per **lo stesso** contenuto su disco: cancellare uno dei due nomi non elimina i dati finché esiste almeno un altro hard link che punta a quei blocchi

> **Per il pentest:** junction e reparse point sono stati per anni un vettore di privilege escalation locale su Windows, perché permettono a un utente non privilegiato di far scrivere a un processo con privilegi più alti in un percorso diverso da quello previsto. Ma una junction diventa vettore solo quando si verificano **tutte** queste condizioni insieme: l'utente controlla la directory sorgente, un processo più privilegiato vi esegue un'operazione (lettura, scrittura, rename, delete), quel processo segue il reparse point, e l'operazione può essere attivata o inserita in una race condition. Per enumerare junction e reparse point esistenti:
> **Comandi utili:**

```powershell
Get-ChildItem C:\ -Force -Recurse -Attributes ReparsePoint -ErrorAction SilentlyContinue
cmd /c "dir C:\percorso /al /s"
fsutil reparsepoint query "C:\percorso\link"
```

### Cosa c'è sotto il cofano di NTFS: MFT, ADS, journal

NTFS non si limita a organizzare cartelle e file visibili: tiene traccia di tutto in strutture interne che vale la pena conoscere almeno a grandi linee.

* **Master File Table (MFT)** — pensa alla MFT come all'indice di un libro enorme: contiene un record per ogni file e cartella del volume, con tutti i metadati (posizione, dimensione, permessi, timestamp). Quando Windows deve trovare un file, consulta prima la MFT invece di cercare a tasto sul disco
* **Alternate Data Stream (ADS)** — NTFS permette a un file di avere flussi di dati aggiuntivi e nascosti oltre al contenuto principale. Se hai un file `relazione.txt`, puoi affiancargli `relazione.txt:contenuto_nascosto` e quel secondo flusso non compare con un `dir` normale — è invisibile a chi non sa cercarlo
* **$UsnJrnl (Update Sequence Number Journal)** — il prefisso `$` indica che è un file interno di NTFS, non visibile normalmente. Registra ogni modifica ai file del volume (creazione, rinomina, cancellazione) con un numero di sequenza progressivo, ma **non** conserva il contenuto dei file e la cronologia può sovrascriversi nel tempo. Da distinguere da **$LogFile**, il log transazionale dei metadati NTFS che garantisce la consistenza del filesystem in caso di crash

> **Per il pentest e la forensics:** gli ADS sono stati storicamente usati per nascondere payload o dati dentro file apparentemente innocui. `Zone.Identifier` è l'ADS più comune e **legittimo** (Windows lo aggiunge ai file scaricati da Internet per la Mark of the Web) — la semplice presenza di un ADS non indica un payload. Per enumerare ADS su file o cartelle:

```powershell
cmd /c "dir C:\percorso /r"           # mostra ADS con dimensione
Get-Item "C:\file.exe" -Stream *      # lista tutti gli stream
Get-Content "C:\file.exe" -Stream Zone.Identifier   # legge uno stream specifico
```

> Il journal `$UsnJrnl` è prezioso in forense per ricostruire file creati, modificati o cancellati, anche quando il contenuto non è più recuperabile. Da non confondere con **`$LogFile`**, il log transazionale di NTFS che garantisce la consistenza del filesystem in caso di crash: scopo e struttura sono diversi.

## File "speciali": dove Windows tiene la memoria del sistema

Oltre a file e cartelle normali, la root del disco di sistema contiene alcuni file con un ruolo particolare, legati alla gestione della memoria:

* **`pagefile.sys`** — il file di paging, usato da Windows come estensione della RAM quando la memoria fisica non basta; si trova nella root del volume di sistema
* **`hiberfil.sys`** — contiene lo stato completo della RAM quando il sistema entra in ibernazione; su sistemi con Fast Startup attivo (Windows 10/11) può essere una versione ridotta, non necessariamente il dump completo
* **`swapfile.sys`** — usato principalmente dalle app UWP/Store per la gestione della memoria
* **`%SystemRoot%\MEMORY.DMP`** — un dump completo della RAM, generato in caso di crash grave del sistema (BSOD); i minidump più leggeri vanno in `%SystemRoot%\Minidump\`

> **Per il pentest:** questi file possono contenere **frammenti di memoria di processo**, incluse credenziali, token di autenticazione o chiavi di cifratura che erano in RAM nel momento in cui sono stati creati. In un'analisi offline (per esempio con un disco estratto o un'immagine forense), strumenti come Volatility possono estrarre segreti da `hiberfil.sys` o da un `MEMORY.DMP` esattamente come farebbero da un dump di memoria live.

## Le cartelle principali: cosa contengono e perché esistono

Su una installazione standard di Windows, la root del disco di sistema contiene sempre più o meno le stesse cartelle, ognuna con uno scopo preciso nell'architettura del sistema:

| Cartella                    | Perché esiste                                                                                                                                                                                           |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `C:\Windows`                | il sistema operativo vero e proprio: binari, driver, registro, componenti                                                                                                                               |
| `C:\Users`                  | profili personali, uno per ogni account che ha effettuato login almeno una volta                                                                                                                        |
| `C:\ProgramData`            | dati e configurazioni condivise tra tutti gli utenti della macchina, non legate a un profilo specifico                                                                                                  |
| `C:\Program Files`          | software a 64 bit installato per tutti gli utenti                                                                                                                                                       |
| `C:\Program Files (x86)`    | software a 32 bit, eseguito tramite il livello di compatibilità WOW64                                                                                                                                   |
| `C:\PerfLogs`               | log di performance raccolti dal sistema, poco usata in pratica                                                                                                                                          |
| `C:\Recovery`               | informazioni e file usati per il ripristino del sistema operativo                                                                                                                                       |
| `C:\Boot`                   | file di avvio per sistemi BIOS/MBR; sui sistemi UEFI moderni la EFI System Partition è una **partizione separata** (di solito FAT32, non la C:) montata su `\EFI` — non è una normale cartella di `C:\` |
| `System Volume Information` | dati interni di sistema: punti di ripristino, indicizzazione, dati di deduplicazione                                                                                                                    |
| `$Recycle.Bin`              | il Cestino, uno per ogni volume, con una sottocartella per ogni utente                                                                                                                                  |

> **Per il pentest:** `System Volume Information` è normalmente illeggibile anche da amministratore locale (di proprietà di SYSTEM), ma è dove risiedono i **Restore Point** creati dal ripristino configurazione di sistema e i dati del **Volume Shadow Copy Service (VSS)** — le snapshot automatiche che Windows crea prima di operazioni come gli aggiornamenti, utilissime per leggere hive di registro altrimenti bloccati, come vedremo. Nota: il database di Windows Search si trova invece sotto `C:\ProgramData\Microsoft\Search\Data\`, non qui.

## Dentro C:\Windows: il cuore del sistema operativo

`C:\Windows` da solo contiene una parte enorme della logica dell'intero sistema. Vale la pena conoscere le sue sottocartelle principali una per una.

**System32 e SysWOW64.** Su un Windows a 64 bit, `System32` contiene i binari a **64 bit** del sistema, mentre `SysWOW64` contiene quelli a **32 bit**, per compatibilità. Il nome inganna: "System32" fa pensare al contrario, ma è un residuo storico da quando Windows era ancora a 32 bit — Microsoft ha mantenuto il vecchio nome per non rompere migliaia di programmi con quel percorso scritto a mano, spostando i binari a 32 bit in una cartella nuova.

> **Per il pentest:** se esegui uno script a 32 bit da un processo a 64 bit, alcune chiamate di sistema vengono automaticamente reindirizzate da System32 a SysWOW64 (il **File System Redirector**) — se non ne sei consapevole, un file che sai esistere può sembrare sparito. Lo stesso meccanismo esiste anche per il registro (**Registry Redirector**): un processo a 32 bit che legge `HKLM\Software` vede in realtà `HKLM\Software\WOW6432Node`, una copia parallela pensata per evitare conflitti con chiavi scritte da software a 64 bit. Se hai bisogno di bypassare il redirector di file e accedere comunque a System32 da un processo a 32 bit, Windows espone anche il percorso speciale `C:\Windows\Sysnative`, che esiste solo virtualmente e non compare mai in un listing di cartelle.

**WinSxS.** La cartella `C:\Windows\WinSxS` ("Windows side-by-side") non è una semplice cache o cartella di backup: è il **Component Store** di Windows, la struttura che il sistema usa per installare, aggiornare, rimuovere e ripristinare i componenti del sistema operativo stesso. Contiene **più versioni della stessa libreria** installate contemporaneamente, permettendo a diverse applicazioni di usare la versione di una DLL con cui sono state testate, senza conflitti tra loro (il classico problema del "DLL Hell" che WinSxS risolve).

> **Per il pentest:** WinSxS mantiene più versioni di componenti di sistema, ma la presenza fisica di un file "vecchio" non implica automaticamente che venga caricato o sia sfruttabile — il loader usa i manifest per determinare quale versione attivare. Detto questo, quando stai investigando possibili scenari di DLL hijacking (un'applicazione carica una libreria dal percorso sbagliato), è qui che puoi trovare versioni precedenti di librerie di sistema; ma va sempre verificato se quella versione è quella effettivamente caricata e se il percorso di caricamento è controllabile.

**DriverStore.** `C:\Windows\System32\DriverStore` è il repository centrale dei pacchetti driver che Windows ha visto e installato, separato dai driver effettivamente attivi in `System32\drivers` (visti più avanti). Quando installi un dispositivo, Windows spesso copia prima il pacchetto driver qui, poi lo attiva.

> **Per il pentest:** una lista di driver storicamente installati (anche non più in uso) può rivelare hardware o software di terze parti che è stato collegato alla macchina in passato — utile in ricognizione, e talvolta un indizio di dispositivi USB o periferiche non più presenti fisicamente ma di cui resta traccia.

**Prefetch.** `C:\Windows\Prefetch` contiene file che Windows crea per velocizzare l'avvio dei programmi usati più di frequente, registrando quali file vengono caricati durante l'esecuzione.

> **Per il pentest e la forensics:** i file Prefetch rivelano **quali programmi sono stati eseguiti** sulla macchina, con che frequenza e quando l'ultima volta — una delle fonti più affidabili per ricostruire l'attività recente di un sistema, sia in un'analisi offensiva sia in un'indagine forense difensiva.

**SoftwareDistribution.** `C:\Windows\SoftwareDistribution` è dove Windows Update scarica e gestisce gli aggiornamenti prima e dopo l'installazione.

> **Per il pentest:** il contenuto di questa cartella e i relativi log danno indicazioni sullo stato degli aggiornamenti della macchina, ma non sono la fonte più affidabile per determinare se una CVE specifica sia sfruttabile: la cartella può essere ripulita e non riflette necessariamente i pacchetti effettivamente installati. Per un assessment serio servono la build e l'UBR (Update Build Revision) dal registro, i pacchetti installati via `dism /online /get-packages`, e il CBS.log.

**Panther.** Contiene gli answer file (`unattend.xml`, `Unattended.xml`) usati per automatizzare l'installazione di Windows — impostazioni di rete, partizionamento, e spesso un account amministratore locale con password codificata in Base64, pensata per il deploy automatico senza intervento manuale.

> **Per il pentest:** un file dimenticato qui, cosa che capita più spesso di quanto si pensi con immagini "golden" distribuite via strumenti di deploy centralizzato, equivale a una password di amministratore locale regalata. Metasploit ha un modulo dedicato: `post/windows/gather/enum_unattend`.

**Tasks / System32\Tasks.** Le attività pianificate vivono come file XML, ognuno con l'azione da eseguire e l'account con cui viene lanciata.

> **Per il pentest:** rivelano percorsi di script eseguiti con privilegi elevati — spesso scrivibili da utenti non privilegiati, un classico vettore di [privilege escalation](https://hackita.it/articoli/privilege-escalation-windows/) — e account di servizio usati per l'esecuzione. Ne parliamo in dettaglio nell'articolo dedicato alle [Scheduled Task](https://hackita.it/articoli/scheduled-task/).

**Logs, INF, Fonts, servicing, PolicyDefinitions.** Cartelle più di contorno ma con un ruolo preciso: `Logs` raccoglie i log di setup e manutenzione (CBS.log, DISM.log, setupact.log — utili per ricostruire il contesto della macchina, come nomi utente o condivisioni SMB coinvolte in operazioni passate); `INF` contiene i file che descrivono come installare driver e componenti; `Fonts` è autoesplicativa; `servicing` gestisce i pacchetti di aggiornamento dei componenti (strettamente legata a WinSxS); `PolicyDefinitions` contiene i file ADMX usati dalle Group Policy per definire quali impostazioni sono configurabili.

### Come Windows carica il codice: DLL, PE format e dove nasce il DLL hijacking

Un eseguibile Windows (`.exe`) e una libreria (`.dll`) condividono lo stesso formato binario, il **PE (Portable Executable)**: un **DOS Header** iniziale (residuo storico, mantenuto per compatibilità), seguito dal vero **PE Header**, e da una serie di **sezioni** con ruoli distinti — `.text` (il codice eseguibile), `.data` (dati inizializzati), `.rdata` (dati di sola lettura, tra cui le tabelle di import/export), `.reloc` (informazioni per rilocare il codice se caricato a un indirizzo diverso da quello previsto).

Le due tabelle più rilevanti dentro `.rdata` sono:

* **Import Table** — elenca quali funzioni, da quali DLL esterne, il programma userà
* **Export Table** — elenca quali funzioni una DLL mette a disposizione per essere usate da altri programmi

Quando un programma parte, Windows deve caricare in memoria tutte le DLL elencate nella sua Import Table, tramite funzioni come `LoadLibrary` e `GetProcAddress`. Il punto cruciale: se una DLL richiesta non specifica un percorso assoluto (cioè il percorso completo tipo `C:\Windows\System32\nome.dll`), Windows la cerca seguendo un ordine preciso di cartelle — il **DLL Search Order**. Tipicamente: prima la cartella dell'applicazione stessa, poi le **KnownDLLs** (un elenco di librerie di sistema considerate "sicure" e pre-caricate in memoria, che Windows protegge esplicitamente proprio per evitare che vengano sostituite), poi `System32`, `SysWOW64`, la cartella Windows, la cartella corrente, e infine le cartelle elencate in `%PATH%`.

> **Per il pentest:** il **DLL hijacking** sfrutta esattamente questo ordine di ricerca: se riesci a piazzare una DLL malevola con lo stesso nome in una cartella che Windows controlla *prima* di quella legittima (per esempio la cartella dell'applicazione, se scrivibile), il programma caricherà la tua DLL invece di quella originale, eseguendo il tuo codice con i privilegi di quel processo. È lo stesso principio per cui, come visto sopra, WinSxS conserva versioni vecchie di librerie: un'applicazione che dipende da una versione superata e vulnerabile di una DLL è un bersaglio concreto per questa tecnica.

![DLL Search Order: l'ordine con cui Windows cerca le librerie richieste da un programma](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgNzAwIDQwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPHJlY3Qgd2lkdGg9IjcwMCIgaGVpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiLz4KICA8dGV4dCB4PSIzNTAiIHk9IjMwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE2IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjMTExMTExIj5ETEwgU2VhcmNoIE9yZGVyOiBkb3ZlIFdpbmRvd3MgY2VyY2EgbGUgRExMPC90ZXh0PgogIDx0ZXh0IHg9IjM1MCIgeT0iNTAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTEiIGZpbGw9IiM1NTU1NTUiPnNlIGxhIERMTCBub24gw6ggc3BlY2lmaWNhdGEgY29uIHBlcmNvcnNvIGFzc29sdXRvLCBXaW5kb3dzIGNlcmNhIG5lbGwnb3JkaW5lOjwvdGV4dD4KCiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhMiIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iNiIgbWFya2VySGVpZ2h0PSI2IiBvcmllbnQ9ImF1dG8iPgogICAgICA8cGF0aCBkPSJNMCwwIEwxMCw1IEwwLDEwIHoiIGZpbGw9IiMxMTExMTEiLz4KICAgIDwvbWFya2VyPgogICAgPG1hcmtlciBpZD0iYTMiIHZpZXdCb3g9IjAgMCAxMCAxMCIgcmVmWD0iOSIgcmVmWT0iNSIgbWFya2VyV2lkdGg9IjYiIG1hcmtlckhlaWdodD0iNiIgb3JpZW50PSJhdXRvIj4KICAgICAgPHBhdGggZD0iTTAsMCBMMTAsNSBMMCwxMCB6IiBmaWxsPSIjZGMyNjI2Ii8+CiAgICA8L21hcmtlcj4KICA8L2RlZnM+CgogIDwhLS0gU3RlcCAxIC0gcmVkIChhdHRhY2tlciBvcHBvcnR1bml0eSkgLS0+CiAgPHJlY3QgeD0iMTUwIiB5PSI2NSIgd2lkdGg9IjQwMCIgaGVpZ2h0PSI0MiIgcng9IjYiIGZpbGw9IiNkYzI2MjYiLz4KICA8dGV4dCB4PSIzNTAiIHk9IjgyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj4xLiBDYXJ0ZWxsYSBkZWxsJ2FwcGxpY2F6aW9uZSBzdGVzc2E8L3RleHQ+CiAgPHRleHQgeD0iMzUwIiB5PSI5NyIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMCIgZmlsbD0iI2ZmY2NjYyI+4pqgIHNlIHNjcml2aWJpbGUsIHZldHRvcmUgZGkgRExMIGhpamFja2luZzwvdGV4dD4KCiAgPGxpbmUgeDE9IjM1MCIgeTE9IjEwNyIgeDI9IjM1MCIgeTI9IjEyMiIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYTIpIi8+CgogIDwhLS0gU3RlcCAyIC0tPgogIDxyZWN0IHg9IjE1MCIgeT0iMTIyIiB3aWR0aD0iNDAwIiBoZWlnaHQ9IjQyIiByeD0iNiIgZmlsbD0iIzExMTExMSIvPgogIDx0ZXh0IHg9IjM1MCIgeT0iMTQwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj4yLiBLbm93bkRMTHM8L3RleHQ+CiAgPHRleHQgeD0iMzUwIiB5PSIxNTYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTAiIGZpbGw9IiNhM2EzYTMiPmxpc3RhIHByb3RldHRhIHByZWNhcmljYXRhIOKAlCBub24gcHXDsiBlc3NlcmUgZGlyb3R0YXRhPC90ZXh0PgoKICA8bGluZSB4MT0iMzUwIiB5MT0iMTY0IiB4Mj0iMzUwIiB5Mj0iMTc5IiBzdHJva2U9IiMxMTExMTEiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhMikiLz4KCiAgPCEtLSBTdGVwIDMgLS0+CiAgPHJlY3QgeD0iMTUwIiB5PSIxNzkiIHdpZHRoPSI0MDAiIGhlaWdodD0iMzYiIHJ4PSI2IiBmaWxsPSIjMzMzMzMzIi8+CiAgPHRleHQgeD0iMzUwIiB5PSIyMDIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZpbGw9IiNmZmZmZmYiPjMuIEM6XFdpbmRvd3NcU3lzdGVtMzI8L3RleHQ+CgogIDxsaW5lIHgxPSIzNTAiIHkxPSIyMTUiIHgyPSIzNTAiIHkyPSIyMzAiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2EyKSIvPgoKICA8IS0tIFN0ZXAgNCAtLT4KICA8cmVjdCB4PSIxNTAiIHk9IjIzMCIgd2lkdGg9IjQwMCIgaGVpZ2h0PSIzNiIgcng9IjYiIGZpbGw9IiMzMzMzMzMiLz4KICA8dGV4dCB4PSIzNTAiIHk9IjI1MyIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZmlsbD0iI2ZmZmZmZiI+NC4gQzpcV2luZG93c1xTeXNXT1c2NDwvdGV4dD4KCiAgPGxpbmUgeDE9IjM1MCIgeTE9IjI2NiIgeDI9IjM1MCIgeTI9IjI4MSIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYTIpIi8+CgogIDwhLS0gU3RlcCA1IC0tPgogIDxyZWN0IHg9IjE1MCIgeT0iMjgxIiB3aWR0aD0iNDAwIiBoZWlnaHQ9IjM2IiByeD0iNiIgZmlsbD0iIzMzMzMzMyIvPgogIDx0ZXh0IHg9IjM1MCIgeT0iMzA0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmaWxsPSIjZmZmZmZmIj41LiBDOlxXaW5kb3dzPC90ZXh0PgoKICA8bGluZSB4MT0iMzUwIiB5MT0iMzE3IiB4Mj0iMzUwIiB5Mj0iMzMyIiBzdHJva2U9IiMxMTExMTEiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhMikiLz4KCiAgPCEtLSBTdGVwIDYgLSByZWQgLS0+CiAgPHJlY3QgeD0iMTUwIiB5PSIzMzIiIHdpZHRoPSI0MDAiIGhlaWdodD0iNDIiIHJ4PSI2IiBmaWxsPSIjZGMyNjI2Ii8+CiAgPHRleHQgeD0iMzUwIiB5PSIzNDkiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPjYuIENhcnRlbGxhIGNvcnJlbnRlICsgJVBBVEglPC90ZXh0PgogIDx0ZXh0IHg9IjM1MCIgeT0iMzY1IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEwIiBmaWxsPSIjZmZjY2NjIj7imqAgYWx0cm8gcHVudG8gZG92ZSB1biBhdHRhY2NhbnRlIHB1w7IgaW5zZXJpcmUgdW5hIERMTCBtYWxldm9sYTwvdGV4dD4KPC9zdmc+Cg==)

## Il profilo utente: struttura e logica

Sotto `C:\Users\<nome-utente>` trovi il profilo personale di ogni account che ha effettuato login almeno una volta. Le cartelle visibili di default seguono una logica pensata per l'utente finale: **Desktop, Documents, Downloads, Pictures, Music, Videos, Contacts, Saved Games, Searches** — ognuna con uno scopo dichiarato dal nome, pensate per organizzare i file personali in modo standard su ogni macchina Windows.

La parte più interessante dal punto di vista tecnico è **AppData**, divisa in tre cartelle con uno scopo preciso:

* **Roaming** — dati applicativi pensati per seguire l'utente da una macchina all'altra dello stesso dominio (in un ambiente aziendale con profili roaming configurati)
* **Local** — dati legati alla macchina specifica, mai sincronizzati altrove
* **LocalLow** — versione a permessi ridotti di Local, usata da processi eseguiti in modalità "sandboxed" (per esempio alcuni browser in modalità protetta)

Questa separazione esiste perché non tutti i dati applicativi hanno lo stesso senso ovunque: le impostazioni di un programma possono avere senso seguire l'utente (Roaming), mentre una cache locale legata all'hardware specifico no (Local).

> **Per il pentest:** AppData ospita molte delle credenziali salvate da applicazioni di terze parti (client FTP/VNC/SSH, browser, vault di password), spesso protette da [DPAPI](https://hackita.it/articoli/dpapi/) — il meccanismo di Windows che cifra dati legandoli all'account utente. Ma non è l'unico posto: altri segreti stanno nel registro, nel Credential Manager, in file di configurazione sparsi e in chiavi SSH. È un ottimo punto di partenza, non una lista esaustiva.

## Il registro: come gli hive su disco diventano HKLM, HKCU e gli altri

Il registro di Windows non è un file unico: è un insieme di **hive**, file binari su disco che il sistema carica e presenta come un'unica struttura gerarchica ad albero. Le radici principali che vedi in `regedit`:

* **HKEY\_LOCAL\_MACHINE (HKLM)** — impostazioni a livello di macchina, valide per tutti gli utenti; costruito unendo hive come SYSTEM, SOFTWARE, SAM, SECURITY, tutti fisicamente presenti sotto `C:\Windows\System32\config`
* **HKEY\_CURRENT\_USER (HKCU)** — impostazioni dell'utente attualmente loggato; è in realtà un collegamento dinamico all'hive `NTUSER.DAT` dentro il profilo di quell'utente
* **HKEY\_USERS (HKU)** — contiene gli hive di *tutti* gli utenti con un profilo caricato, non solo quello corrente; HKCU è di fatto un puntatore a una delle sottochiavi qui dentro
* **HKEY\_CLASSES\_ROOT (HKCR)** — associazioni tra estensioni file e programmi, oggetti COM; combina dati da HKLM e HKCU
* **HKEY\_CURRENT\_CONFIG (HKCC)** — informazioni sul profilo hardware attivo, meno rilevante nei sistemi moderni con un solo profilo hardware

Capire questa relazione tra hive-su-disco e radici-nel-registro è utile perché spiega perché, per esempio, modificare `NTUSER.DAT` di un utente offline (montandolo manualmente) equivale a modificare il suo HKCU quando farà login.

Una piccola tabella per fissare la corrispondenza tra hive logico e file fisico su disco:

| Hive logico   | File su disco                          |
| ------------- | -------------------------------------- |
| HKLM\SYSTEM   | `SYSTEM`                               |
| HKLM\SOFTWARE | `SOFTWARE`                             |
| HKLM\SAM      | `SAM`                                  |
| HKLM\SECURITY | `SECURITY`                             |
| HKCU          | `NTUSER.DAT` (nel profilo dell'utente) |

Tutti (tranne NTUSER.DAT, che sta nel profilo utente) vivono sotto `C:\Windows\System32\config`.

> **Per il pentest:** dentro **HKLM\SYSTEM\CurrentControlSet\Services**, ogni servizio ha una sottochiave con il valore **ImagePath**, che indica l'eseguibile lanciato dal servizio — se il percorso non è tra virgolette e contiene spazi, o se punta a un file scrivibile da un utente non privilegiato, hai un classico vettore di escalation. Le chiavi **Run**/**RunOnce** sotto `HKLM\Software\Microsoft\Windows\CurrentVersion` (e l'equivalente in HKCU) indicano cosa parte automaticamente al login. E dentro `System32\config` vivono gli hive **SAM**, **SYSTEM** e **SECURITY** — bloccati mentre Windows gira, estraibili con `reg save` o da una Volume Shadow Copy, e analizzabili con tool come [reg.py di Impacket](https://hackita.it/articoli/regpy/) o con [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege/) se disponibile.

### Comandi PowerShell per esplorare l'architettura vista finora

```powershell
Get-Volume                  # elenca i volumi montati, con filesystem e spazio libero
Get-ChildItem Env:           # mostra tutte le variabili d'ambiente disponibili
Get-Acl C:\percorso\file     # mostra owner e ACL di un file o cartella
fsutil fsinfo drives         # elenca le lettere di unità disponibili
mountvol                     # mostra i mount point e i volumi montati come cartella
```

Sono comandi di sola lettura, utili per orientarsi rapidamente sull'architettura reale di una macchina appena raggiunta, prima ancora di cercare vettori specifici di attacco.

## Variabili d'ambiente: le scorciatoie che Windows offre a ogni processo

Windows espone diversi percorsi tramite variabili d'ambiente, pensate per rendere gli script portabili tra macchine diverse senza scrivere percorsi assoluti:

| Variabile                   | Punta a                                                         |
| --------------------------- | --------------------------------------------------------------- |
| `%TEMP%` / `%TMP%`          | cartella temporanea dell'utente corrente                        |
| `%APPDATA%`                 | AppData\Roaming dell'utente corrente                            |
| `%LOCALAPPDATA%`            | AppData\Local dell'utente corrente                              |
| `%ProgramFiles%`            | Program Files (versione a 64 bit su sistema a 64 bit)           |
| `%ProgramData%`             | ProgramData                                                     |
| `%SystemRoot%` / `%WinDir%` | C:\Windows                                                      |
| `%USERPROFILE%`             | C:\Users\\<utente corrente>                                     |
| `%PUBLIC%`                  | C:\Users\Public, cartella condivisa tra tutti gli utenti        |
| `%HOMEDRIVE%`               | la lettera del disco che ospita il profilo utente (di norma C:) |
| `%HOMEPATH%`                | il percorso del profilo utente, relativo a HOMEDRIVE            |

> **Per il pentest:** queste variabili tornano continuamente in script di enumerazione e in exploit pubblici, proprio perché rendono un comando funzionante indipendentemente da dove Windows è installato (non sempre `C:\`) o da chi lo esegue — vale la pena abituarsi a leggerle al volo invece di doverle sempre espandere mentalmente.

## Permessi: ACL, owner, e perché "Administrator" non basta sempre

Ogni file e cartella su NTFS ha una **ACL** (Access Control List) che definisce chi può fare cosa, e un **owner** (proprietario) che per default ha sempre il controllo sui permessi di quel file, indipendentemente da cosa dice l'ACL stessa.

Gli account/gruppi più rilevanti da conoscere:

* **SYSTEM** — l'account con cui girano la maggior parte dei processi del kernel e dei servizi core; ha di fatto controllo completo sulla macchina
* **TrustedInstaller** — un account speciale, introdotto per proteggere i file di sistema più critici, che possiede molti file dentro `System32` e altre cartelle protette — **anche l'account Administrator non può modificarli senza prima prendersi esplicitamente la proprietà (`takeown`) e concedersi i permessi**, perché l'ACL di quei file non dà scrittura ad Administrator per design
* **Administrator** — privilegi ampi, ma non illimitati sui file di proprietà di TrustedInstaller
* **Users** — permessi minimi, tipicamente lettura ed esecuzione sulle cartelle di sistema
* **Everyone** — include tutti gli utenti autenticati; nelle configurazioni di default moderne **non include** gli utenti anonimi (questo dipende dalla policy "Network access: Let Everyone permissions apply to anonymous users", disabilitata per impostazione predefinita)

Una precisazione importante sull'owner: possedere un file non significa avere automaticamente "controllo completo" sul suo contenuto. L'owner ottiene implicitamente `WRITE_DAC`, cioè il diritto di **modificare la DACL** (la lista dei permessi) del file — il che indirettamente permette di concedersi qualsiasi permesso, ma è un passaggio in più, non automatico.

### Da dove viene davvero il controllo dei permessi: l'Access Token

Un dettaglio che spiega *perché* funziona un controllo ACL: quando un utente fa login, Windows gli assegna un **Access Token**, un oggetto che porta con sé la sua identità e i suoi diritti per tutta la sessione:

```
Utente → Logon → Access Token → SID → Privilegi → confronto con l'ACL dell'oggetto
```

Il token contiene il **SID** (Security Identifier, l'identificativo univoco dell'utente e dei gruppi a cui appartiene) e l'elenco dei **privilegi** assegnati (come [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege/) o [SeImpersonatePrivilege](https://hackita.it/articoli/seimpersonateprivilege/)). Ogni volta che quel processo prova ad accedere a un file, una chiave di registro o qualunque altra risorsa, Windows confronta il token con l'ACL della risorsa e decide se concedere l'accesso.

Questo è possibile perché, internamente, Windows non tratta file, chiavi di registro, processi e mutex come cose diverse tra loro: sono tutti **Object**, gestiti da un componente chiamato **Object Manager**, ognuno con un proprio **Security Descriptor** (che contiene l'ACL) e accessibile tramite un **Handle** — cioè un riferimento numerico che il processo riceve quando Windows gli concede accesso a quell'oggetto, valido solo per quella sessione. È la ragione per cui lo stesso concetto di permessi (proprietario, ACL, controllo di accesso) si applica in modo identico a un file su disco e, per esempio, a un processo in esecuzione.

![Come Windows decide se un utente può accedere a una risorsa: dal login all'Access Token al confronto ACL](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgNzYwIDIyMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPHJlY3Qgd2lkdGg9Ijc2MCIgaGVpZ2h0PSIyMjAiIGZpbGw9IiNmZmZmZmYiLz4KICA8dGV4dCB4PSIzODAiIHk9IjI4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjMTExMTExIj5Db21lIFdpbmRvd3MgZGVjaWRlIHNlIHB1b2kgYWNjZWRlcmUgYSB1biBmaWxlPC90ZXh0PgogIDxkZWZzPgogICAgPG1hcmtlciBpZD0iYXIiIHZpZXdCb3g9IjAgMCAxMCAxMCIgcmVmWD0iOSIgcmVmWT0iNSIgbWFya2VyV2lkdGg9IjYiIG1hcmtlckhlaWdodD0iNiIgb3JpZW50PSJhdXRvIj4KICAgICAgPHBhdGggZD0iTTAsMCBMMTAsNSBMMCwxMCB6IiBmaWxsPSIjMTExMTExIi8+CiAgICA8L21hcmtlcj4KICA8L2RlZnM+CgogIDwhLS0gQm94IDEgVXRlbnRlIC0tPgogIDxyZWN0IHg9IjIwIiB5PSI1MCIgd2lkdGg9IjExMCIgaGVpZ2h0PSI2MCIgcng9IjYiIGZpbGw9IiMxMTExMTEiLz4KICA8dGV4dCB4PSI3NSIgeT0iNzYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTIiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPlV0ZW50ZTwvdGV4dD4KICA8dGV4dCB4PSI3NSIgeT0iOTQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTAiIGZpbGw9IiNhM2EzYTMiPmZhIGxvZ2luPC90ZXh0PgoKICA8bGluZSB4MT0iMTMwIiB5MT0iODAiIHgyPSIxNTUiIHkyPSI4MCIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXIpIi8+CgogIDwhLS0gQm94IDIgVG9rZW4gLS0+CiAgPHJlY3QgeD0iMTU1IiB5PSI1MCIgd2lkdGg9IjEzMCIgaGVpZ2h0PSI2MCIgcng9IjYiIGZpbGw9IiNkYzI2MjYiLz4KICA8dGV4dCB4PSIyMjAiIHk9IjczIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEyIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5BY2Nlc3MgVG9rZW48L3RleHQ+CiAgPHRleHQgeD0iMjIwIiB5PSI4OSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMCIgZmlsbD0iI2ZmY2NjYyI+V2luZG93cyBsbyBjcmVhPC90ZXh0PgogIDx0ZXh0IHg9IjIyMCIgeT0iMTAzIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEwIiBmaWxsPSIjZmZjY2NjIj5lIGxvIHBvcnRhIG92dW5xdWU8L3RleHQ+CgogIDxsaW5lIHgxPSIyODUiIHkxPSI4MCIgeDI9IjMxMCIgeTI9IjgwIiBzdHJva2U9IiMxMTExMTEiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcikiLz4KCiAgPCEtLSBCb3ggMyBTSUQgKyBQcml2aWxlZ2kgLS0+CiAgPHJlY3QgeD0iMzEwIiB5PSI0MCIgd2lkdGg9IjE0MCIgaGVpZ2h0PSI4MCIgcng9IjYiIGZpbGw9IiMzMzMzMzMiLz4KICA8dGV4dCB4PSIzODAiIHk9IjYyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEyIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5Db250aWVuZTo8L3RleHQ+CiAgPHRleHQgeD0iMzgwIiB5PSI3OCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZmlsbD0iI2EzYTNhMyI+U0lEIHV0ZW50ZSArIFNJRCBncnVwcGk8L3RleHQ+CiAgPHRleHQgeD0iMzgwIiB5PSI5NCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZmlsbD0iI2EzYTNhMyI+UHJpdmlsZWdpIChTZURlYnVnLi4uKTwvdGV4dD4KICA8dGV4dCB4PSIzODAiIHk9IjExMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZmlsbD0iI2EzYTNhMyI+TGl2ZWxsbyBkaSBpbnRlZ3JpdMOgPC90ZXh0PgoKICA8bGluZSB4MT0iNDUwIiB5MT0iODAiIHgyPSI0NzUiIHkyPSI4MCIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXIpIi8+CgogIDwhLS0gQm94IDQgQ29uZnJvbnRvIEFDTCAtLT4KICA8cmVjdCB4PSI0NzUiIHk9IjUwIiB3aWR0aD0iMTMwIiBoZWlnaHQ9IjYwIiByeD0iNiIgZmlsbD0iIzExMTExMSIvPgogIDx0ZXh0IHg9IjU0MCIgeT0iNzMiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTIiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPkNvbmZyb250bzwvdGV4dD4KICA8dGV4dCB4PSI1NDAiIHk9Ijg5IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEwIiBmaWxsPSIjYTNhM2EzIj5Ub2tlbiB2cyBBQ0wgZGVsIGZpbGU8L3RleHQ+CiAgPHRleHQgeD0iNTQwIiB5PSIxMDMiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTAiIGZpbGw9IiNhM2EzYTMiPk9iamVjdCBNYW5hZ2VyPC90ZXh0PgoKICA8bGluZSB4MT0iNjA1IiB5MT0iODAiIHgyPSI2MzAiIHkyPSI4MCIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXIpIi8+CgogIDwhLS0gQm94IDUgRXNpdG8gLS0+CiAgPHJlY3QgeD0iNjMwIiB5PSI1MCIgd2lkdGg9IjExMCIgaGVpZ2h0PSIyOCIgcng9IjYiIGZpbGw9IiNkYzI2MjYiLz4KICA8dGV4dCB4PSI2ODUiIHk9IjY5IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEyIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj7inJMgQWNjZXNzbyBPSzwvdGV4dD4KICA8cmVjdCB4PSI2MzAiIHk9Ijg0IiB3aWR0aD0iMTEwIiBoZWlnaHQ9IjI2IiByeD0iNiIgZmlsbD0iIzMzMzMzMyIvPgogIDx0ZXh0IHg9IjY4NSIgeT0iMTAxIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjExIiBmaWxsPSIjYTNhM2EzIj7inJcgQWNjZXNzIERlbmllZDwvdGV4dD4KCiAgPCEtLSBCb3R0b20gbm90ZSAtLT4KICA8cmVjdCB4PSIyMCIgeT0iMTQ1IiB3aWR0aD0iNzIwIiBoZWlnaHQ9IjU1IiByeD0iNiIgZmlsbD0iI2Y1ZjVmNSIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjEiLz4KICA8dGV4dCB4PSIzODAiIHk9IjE2NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZmlsbD0iIzExMTExMSI+SWwgdG9rZW4gw6ggdmFsaWRvIHBlciB0dXR0YSBsYSBzZXNzaW9uZS4gU2UgaWwgdHVvIHRva2VuIGhhIFNlSW1wZXJzb25hdGVQcml2aWxlZ2UsIHB1b2kgInByZW5kZXJlIGluIHByZXN0aXRvIjwvdGV4dD4KICA8dGV4dCB4PSIzODAiIHk9IjE4MSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZmlsbD0iIzExMTExMSI+aWwgdG9rZW4gZGkgdW4gYWx0cm8gcHJvY2Vzc28g4oCUIGFuY2hlIHVubyBTWVNURU0g4oCUIGUgY29uIGVzc28gYWdpcmUgY29uIGkgc3VvaSBwcml2aWxlZ2kuPC90ZXh0PgogIDx0ZXh0IHg9IjM4MCIgeT0iMTk3IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjExIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZGMyNjI2Ij5RdWVzdG8gw6ggaWwgcHJpbmNpcGlvIGFsbGEgYmFzZSBkaSB0ZWNuaWNoZSBjb21lIHRva2VuIGltcGVyc29uYXRpb24gZSBwb3RhdG8gYXR0YWNrcy48L3RleHQ+Cjwvc3ZnPgo=)

> **Per il pentest:** `icacls` (o `Get-Acl`) è uno dei primi comandi da lanciare su file e servizi sospetti, ma attenzione: i permessi rilevanti sono su **quattro livelli distinti** che vanno controllati separatamente:

```
1. **ACL del file** — posso sovrascrivere o modificare l'eseguibile?
2. **ACL della directory padre** — posso creare, rinominare o cancellare file nella stessa cartella?
3. **ACL del servizio** — posso cambiare `ImagePath` o l'account? (`sc.exe sdshow <servizio>`)
4. **ACL della share SMB** — se il percorso è su una condivisione, i permessi NTFS e quelli della share si sommano (vince il più restrittivo tra i due)
```

> Per il PATH hijacking, vale la pena controllare quali directory del `%PATH%` sono scrivibili:

```powershell
$env:PATH -split ';' | Where-Object { $_ } | ForEach-Object {
    $acl = (Get-Acl $_ -ErrorAction SilentlyContinue).Access
    if ($acl -match "Write|Modify|FullControl") { $_ }
}
```

> Una directory scrivibile prima nel PATH di una DLL o di un eseguibile cercato senza percorso assoluto è un vettore di hijacking. Il dettaglio dello sfruttamento è nella guida [Windows Privilege Escalation](https://hackita.it/articoli/privilege-escalation-windows/) e in [SharpUp](https://hackita.it/articoli/sharpup/). L'abuso delle ACL su oggetti AD ha invece la sua guida dedicata sull'[acl-abuse](https://hackita.it/articoli/acl-abuse/).

## Servizi e driver: dal registro al kernel

I servizi Windows sono definiti nel registro (la chiave `Services` vista sopra) ma eseguiti concretamente in due modi: come processo dedicato, o ospitati dentro `svchost.exe`. Quest'ultimo è un processo host condiviso da molti servizi Windows: invece di avere un eseguibile separato per ogni singolo servizio (con il costo in termini di memoria e risorse che ne deriverebbe), Windows raggruppa più servizi correlati dentro una singola istanza di `svchost.exe`, riducendo il numero totale di processi in esecuzione. Su un Windows moderno vedrai spesso decine di istanze di `svchost.exe` in Task Manager, ciascuna con uno o più servizi al suo interno.

Un aspetto spesso semplificato: un **unquoted service path** (percorso dell'eseguibile con spazi e senza virgolette nel registro) non è sfruttabile in automatico. Perché diventi un vettore reale servono contemporaneamente: il servizio deve girare con privilegi elevati, il percorso deve avere spazi e nessuna virgoletta, tu devi avere accesso in scrittura su **uno dei percorsi candidati** che Windows proverebbe prima del binario legittimo, e devi poter avviare il servizio o aspettare che venga riavviato. Oltre ai permessi NTFS sul binario, vale la pena controllare anche i permessi sull'oggetto servizio stesso con `sc.exe sdshow <nome_servizio>`: `SERVICE_CHANGE_CONFIG` permette di modificare il percorso dell'eseguibile indipendentemente dai permessi NTFS.

I **driver** sono un caso particolare di servizio: file con estensione `.sys`, tipicamente sotto `C:\Windows\System32\drivers`, caricati direttamente nel kernel invece che come processo utente. Vale la pena distinguere due scenari distinti: sfruttare un driver **già caricato** con una vulnerabilità accessibile da un utente standard (tramite un device object o un'interfaccia IOCTL esposta senza controlli di privilegio adeguati) — che è uno dei vettori di escalation più gravi perché il codice gira in kernel mode; oppure il caricamento di un nuovo driver vulnerabile (**BYOVD**, Bring Your Own Vulnerable Driver), che richiede però già privilegi specifici per installare il driver e presuppone un contesto di attacco significativamente diverso.

## Avvio del sistema: BCD, bootmgr, EFI

Prima ancora che il kernel Windows si carichi, entra in gioco una catena di componenti di avvio: il firmware **EFI** (o il vecchio BIOS/MBR su sistemi più datati) individua il **bootmgr**, che legge il **BCD** (Boot Configuration Data, l'equivalente moderno del vecchio `boot.ini`) per sapere quale sistema operativo avviare e con quali opzioni. Da lì, **winload.efi** (o `winload.exe` su sistemi BIOS legacy) è il componente che carica effettivamente il kernel di Windows e i driver di avvio essenziali in memoria, prima di passargli definitivamente il controllo.

La timeline completa, dall'accensione al desktop, passa per una sequenza di processi ben precisa:

```
Accensione PC → UEFI → EFI Partition → bootmgfw.efi → BCD → winload.efi
   → ntoskrnl.exe (kernel) → HAL → smss.exe → csrss.exe → wininit.exe
   → services.exe → lsass.exe → winlogon.exe → explorer.exe
```

Ogni processo in questa catena ha un ruolo preciso, e diversi di questi tornano continuamente in un pentest o in un'analisi post-exploitation:

| Processo                                           | Ruolo                                                                                                    | Perché lo incontri in un pentest                                                                                                                                                      |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **smss.exe** (Session Manager)                     | avvia le prime sessioni di sistema, inizializza variabili d'ambiente                                     | raramente un bersaglio diretto, ma la sua terminazione anomala causa un crash di sistema — utile riconoscerlo nei log                                                                 |
| **csrss.exe** (Client/Server Runtime)              | gestisce processi e thread in user mode per il subsystem Windows                                         | un tempo bersaglio di tecniche di code injection, oggi fortemente protetto                                                                                                            |
| **wininit.exe**                                    | inizializza il subsystem in user mode, avvia services.exe e lsass.exe                                    | poco rilevante direttamente, ma è il "genitore" dei due processi seguenti                                                                                                             |
| **services.exe** (Service Control Manager)         | avvia e gestisce tutti i servizi Windows                                                                 | punto centrale per capire quali servizi girano e con quali privilegi — collegato alla chiave di registro Services vista sopra                                                         |
| **lsass.exe** (Local Security Authority Subsystem) | gestisce autenticazione, token di accesso, e tiene in memoria gli hash/credenziali delle sessioni attive | probabilmente il processo più importante in assoluto per un pentester: il suo dump di memoria è il modo classico per estrarre credenziali di sessioni attive (con tool come Mimikatz) |
| **winlogon.exe**                                   | gestisce il logon interattivo, la schermata di blocco, Ctrl+Alt+Canc                                     | punto di persistenza storico (sostituzione della shell di logon)                                                                                                                      |
| **explorer.exe**                                   | l'interfaccia grafica che l'utente vede — desktop, barra delle applicazioni                              | il processo con cui interagisce l'utente finale, spesso il bersaglio di attacchi lato client                                                                                          |
| **svchost.exe**                                    | host condiviso per molti servizi Windows, per ridurre l'overhead di un processo per servizio             | enumerare quali servizi girano dentro quale istanza di svchost è un passo comune di ricognizione                                                                                      |
| **dwm.exe** (Desktop Window Manager)               | gestisce la composizione grafica delle finestre                                                          | raramente rilevante offensivamente, ma la sua presenza conferma una sessione grafica attiva                                                                                           |

> **Per il pentest:** se dovessi ricordarti solo un processo da questa tabella, sarebbe **lsass.exe** — è il cuore di quasi ogni tecnica di [credential dumping](https://hackita.it/articoli/credential-dumping/), ed è il motivo per cui Windows moderno lo protegge con meccanismi come Credential Guard e Protected Process Light. Uno strumento che ne sfrutta direttamente il dump è [Mimikatz](https://hackita.it/articoli/mimikatz/).**Per il pentest fisico:** questi componenti di avvio sono raramente un bersaglio in un pentest da remoto, ma diventano rilevanti con accesso fisico (bypass della password tramite media alternativi, modifica del BCD per abilitare la modalità provvisoria). Il limite principale in questi scenari è **BitLocker**: se il volume di sistema è cifrato, l'accesso offline al disco è bloccato senza la chiave di ripristino, rendendo molte di queste tecniche inapplicabili senza quella chiave.

## Come Windows ragiona quando apri un file: tutto il capitolo in un unico flusso

Mettendo insieme quasi tutti i concetti visti finora, ecco cosa succede realmente quando un'applicazione apre un file — dal codice utente fino al disco fisico:

```
Applicazione
   ↓ (chiamata a un'API pubblica)
kernel32.dll
   ↓ (funzione di basso livello)
ntdll.dll → NtCreateFile
   ↓ (system call)
Kernel: I/O Manager
   ↓ (verifica ACL sul token dell'utente, poi inoltra)
Filesystem Driver (NTFS)
   ↓
Disco fisico
```

Ogni passaggio di questa catena è uno dei concetti spiegati in questo articolo: la separazione kernel/user mode, le syscall attraverso `ntdll.dll`, l'Object Manager che verifica il token contro l'ACL della risorsa, e infine NTFS che traduce la richiesta in blocchi fisici sul disco. Non è un dettaglio da manuale universitario: è la sequenza che rende comprensibile *perché* un permesso negato, un hook di sicurezza, o un file bloccato si comportano nel modo in cui li osservi durante un pentest.

## Struttura invariata, autenticazione diversa: il filesystem in un dominio Active Directory

Un'ultima precisazione utile se lavori spesso in ambienti aziendali: quando una macchina Windows fa parte di un dominio [Active Directory](https://hackita.it/articoli/active-directory/), la struttura del filesystem locale che abbiamo visto in questo articolo **resta identica** — stessi Program Files, stesso System32, stesso registro. Quello che cambia è tutto ciò che sta intorno: l'autenticazione passa per il dominio invece che per account locali, le Group Policy possono imporre configurazioni specifiche (comprese quelle distribuite via SYSVOL e NETLOGON), i profili possono essere roaming invece che legati a una singola macchina, e servizi come DNS, [Kerberos](https://hackita.it/articoli/kerberos/) e LDAP diventano parte integrante di come la macchina si comporta in rete. La mappa del disco non cambia; cambia chi decide cosa puoi farci.

## Namespace dei percorsi: `\\?\`, `\\.\`, Volume GUID e UNC

Un aspetto spesso ignorato ma rilevante sia per capire i tool che per comprendere certi bypass: Windows supporta più sintassi per esprimere un percorso, non solo `C:\cartella\file`.

* **Percorso normale** — `C:\Windows\System32\cmd.exe`: il solito, soggetto a canonicalizzazione e limiti di 260 caratteri
* **UNC** — `\\server\condivisione\file`: per accedere a risorse di rete; funziona anche in locale (`\\127.0.0.1\c$\file`). Questa sintassi è alla base di come funziona [SMB](https://hackita.it/articoli/smb/) per la condivisione di file e su cui si poggiano diverse tecniche di [lateral movement](https://hackita.it/articoli/lateral-movement/)
* **`\\?\`** (extended-length path) — bypassa canonicalizzazione e limite MAX\_PATH: `\\?\C:\percorso\molto\lungo\...`; molti tool di sicurezza e alcuni controlli antivirus non gestiscono correttamente questa sintassi
* **`\\.\`** (device namespace) — accesso diretto ai device object del kernel: `\\.\PhysicalDrive0`, `\\.\pipe\nome` per le named pipe, `\\.\C:` per il volume raw
* **Volume GUID** — `\\?\Volume{GUID}\file`: identifica un volume in modo univoco indipendentemente dalla lettera assegnata; utile in script quando la lettera può cambiare

> **Per il pentest:** la sintassi `\\?\` è stata usata storicamente per aggirare controlli su percorsi (path traversal, AV che non sanno normalizzarla, whitelist basate su pattern), e i device namespace permettono accesso a canali IPC e a raw disk che normalmente non sono raggiungibili tramite percorsi file normali.

## Comandi operativi: orientarsi su una macchina appena raggiunta

Una volta ottenuta una shell, questi comandi coprono i controlli iniziali senza installare nulla. Se vuoi automatizzare questo processo, [WinPEAS](https://hackita.it/articoli/winpeas/) e [Seatbelt](https://hackita.it/articoli/seatbelt/) coprono queste e molte altre verifiche con un singolo eseguibile:

```powershell
whoami /all                                    # utente, gruppi e TUTTI i privilegi del token
dir /r C:\Users\<utente>                        # elenca anche gli Alternate Data Stream nascosti
Get-Item -Path C:\file.txt -Stream *           # ADS su un file specifico (PowerShell)
fsutil reparsepoint query C:\percorso          # verifica se una cartella è un reparse point/junction
icacls C:\percorso\file.exe                    # permessi NTFS su file e cartelle
sc.exe qc <nome_servizio>                      # configurazione servizio: percorso eseguibile, account
sc.exe sdshow <nome_servizio>                  # Security Descriptor del servizio (chi può fare cosa)
schtasks /query /fo LIST /v                    # task pianificate con tutti i dettagli
vssadmin list shadows                          # Volume Shadow Copy disponibili
dism /online /get-packages                     # patch effettivamente installate (più affidabile di SoftwareDistribution)
```

## Artefatti forensi e di enumerazione: tabella rapida

Oltre alle cartelle principali, questi percorsi compaiono spesso in enumerazione e post-exploitation:

| Percorso                                                                                        | Cosa contiene                                           | Prerequisiti di accesso                                 |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------- |
| `%WINDIR%\Temp`                                                                                 | file temporanei di sistema                              | leggibile da chiunque per default                       |
| `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | cronologia comandi PowerShell                           | permessi del profilo utente                             |
| `%WINDIR%\System32\winevt\Logs\`                                                                | log eventi in formato EVTX                              | Administrator o SeSecurityPrivilege per il log Security |
| `%LOCALAPPDATA%\Microsoft\Windows\WER\`                                                         | Windows Error Reporting: crash dump e report di errori  | permessi del profilo utente                             |
| `C:\Windows\AppCompat\Programs\Amcache.hve`                                                     | traccia eseguibili e driver caricati (hive di registro) | Administrator                                           |
| `C:\Windows\System32\sru\SRUDB.dat`                                                             | SRUM: utilizzo rete, CPU, app negli ultimi 30-60 giorni | Administrator                                           |

Il **SRUM** (System Resource Usage Monitor) è particolarmente utile in scenari forensi: registra quale processo ha usato quanta rete e CPU, e può rivelare tool eseguiti che non lasciano altra traccia.

## Detection & Blue Team

* **Event 4656/4663** (Security log) — apertura handle e accesso a oggetti (file, registro): segnalano lettura di hive SAM/SECURITY; richiedono sia la audit policy abilitata sia una **SACL** sull'oggetto, altrimenti non vengono generati
* **Event 4670** — modifica dei permessi su un oggetto: utile per monitorare chi si prende la proprietà di file di sistema con `takeown`
* **Sysmon Event 6** — caricamento di un driver: fondamentale per rilevare driver caricati anomali o scenari di BYOVD (Bring Your Own Vulnerable Driver)
* **Sysmon Event 11** — creazione di file; **Event 12-14** — creazione/modifica/cancellazione di chiavi di registro; **Event 15** — creazione di Alternate Data Stream: quest'ultimo è specifico per rilevare ADS usati per nascondere payload
* Monitorare la creazione di junction o reparse point in percorsi sensibili da processi non di sistema
* Verificare periodicamente con `icacls` i permessi su binari eseguiti da servizi privilegiati: un servizio SYSTEM con eseguibile scrivibile da Users è un rischio immediato
* Rimuovere gli answer file (`Panther\Unattend.xml`) dopo il deploy
* Audit periodico delle chiavi Run/RunOnce e della cartella Tasks per persistenze non autorizzate

## Domande frequenti

**Qual è la differenza tra una junction e un symbolic link?**
Entrambe reindirizzano un percorso a un altro, ma la junction funziona solo sullo stesso computer ed è storicamente creabile anche da utenti non amministratori; il symbolic link è più flessibile (funziona anche su percorsi di rete) ma richiede in genere privilegi più alti per essere creato.

**Perché Administrator a volte non può modificare un file di sistema?**
Perché alcuni file critici sono di proprietà dell'account TrustedInstaller, non di Administrator: serve prima prendersi esplicitamente la proprietà del file per poterlo modificare.

**System32 contiene binari a 32 o 64 bit?**
A 64 bit, nonostante il nome. I binari a 32 bit stanno in SysWOW64 — uno dei dettagli più controintuitivi di Windows.

**A cosa serve WinSxS in pratica?**
Permette a più versioni della stessa libreria di coesistere sul sistema, evitando che l'aggiornamento di una DLL rompa un'altra applicazione che dipende da una versione precedente.

**HKCU è separato da HKLM?**
Sì: sono radici logiche distinte. HKCU viene mappato dinamicamente alla sottochiave dell'utente corrente dentro HKEY\_USERS — cioè `HKU\<SID_utente>` — che a sua volta viene costruita dal sistema caricando il file `NTUSER.DAT` del profilo. Quindi HKCU non "è" NTUSER.DAT, ma riflette il suo contenuto attraverso questa mappatura.

**Dove trovo la lista di cosa parte automaticamente all'avvio?**
Nelle chiavi di registro Run e RunOnce (sia in HKLM che in HKCU) e nella cartella delle Scheduled Task sotto System32\Tasks.

**Qual è la differenza tra kernel mode e user mode?**
Il kernel mode (Ring 0) ha accesso diretto e illimitato all'hardware — ci girano il kernel, l'HAL e i driver; lo user mode (Ring 3) è dove girano le applicazioni normali, con accesso mediato sempre dal kernel tramite system call.

**Perché lsass.exe è così importante in un pentest?**
Perché gestisce l'autenticazione e tiene in memoria hash e credenziali delle sessioni attive: un dump della sua memoria (con tool come Mimikatz) è il modo classico per estrarre credenziali senza toccare direttamente gli hive di registro.

**Cos'è il DLL hijacking, in breve?**
Sfrutta l'ordine con cui Windows cerca le DLL richieste da un programma: se riesci a piazzare una DLL malevola con lo stesso nome in una cartella controllata prima di quella legittima, il programma carica ed esegue il tuo codice al posto suo.

**Cos'è l'Object Manager di Windows?**
Il componente che tratta file, chiavi di registro, processi e altri elementi come un'unica categoria di "oggetti", ognuno con un Security Descriptor (che contiene l'ACL) e accessibile tramite un Handle — è il motivo per cui lo stesso modello di permessi si applica sia ai file sia, per esempio, ai processi.

***

## Per approfondire

Su Hackita, i naturali approfondimenti partendo da questo articolo:

* [Windows Privilege Escalation](https://hackita.it/articoli/privilege-escalation-windows/) — come trasformare la comprensione dell'architettura in vettori concreti di escalation
* [WinPEAS](https://hackita.it/articoli/winpeas/) — il tool che automatizza l'enumerazione su quasi tutto quello che abbiamo visto
* [Seatbelt](https://hackita.it/articoli/seatbelt/) — enumerazione più chirurgica, utile quando WinPEAS è troppo rumoroso
* [Credential Dumping](https://hackita.it/articoli/credential-dumping/) — cosa fare una volta localizzati gli hive SAM/SECURITY o lsass
* [DPAPI](https://hackita.it/articoli/dpapi/) — il meccanismo che protegge gran parte dei segreti dentro AppData

Risorse esterne:

* [PayloadsAllTheThings — Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md) — la raccolta più completa di tecniche, vettori e comandi su Windows privesc
* [Shard Security — Windows File System & Registry](https://shardsecurity.com/windows-file-system-registry-for-pentesters/) — buona guida compatta orientata al pentest pratico
* [Pentest Everything — Windows Privilege Escalation Checklist](https://pentesteverything.com/windows-privilege-escalation/) — checklist operativa da seguire dopo aver capito la struttura

***

*Articolo a scopo didattico. Tecniche testate su ambienti autorizzati come HackTheBox, VulnLab e lab personali.*
