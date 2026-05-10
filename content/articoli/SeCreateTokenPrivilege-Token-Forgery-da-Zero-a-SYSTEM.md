---
title: 'SeCreateTokenPrivilege: Token Forgery da Zero a SYSTEM'
slug: secreatetokenprivilege
description: Trovato SeCreateTokenPrivilege su un account non di sistema? Crea token con SID SYSTEM e Domain Admins da zero. NtCreateToken per shell SYSTEM. Tecnica Red Team.
image: /SeCreateTokenPrivilege.webp
draft: true
date: 2026-06-17T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - secreatetokenprivilege
  - ntcreatetoken
  - token-forgery
featured: true
---

Non rubi un token, non aspetti connessioni. Con SeCreateTokenPrivilege chiami `NtCreateToken()` e forgi un token con SID SYSTEM, gruppi Domain Admins e tutti i privilegi che vuoi — da zero. Se lo vedi su un account non di sistema: **finding critico P0**, documenta prima di tutto.

***

## Quick Exploit

```cmd
accesschk.exe -a SeCreateTokenPrivilege *
whoami /priv | findstr SeCreateToken
```

```cmd
CreateToken.exe -user S-1-5-18 -groups S-1-5-32-544 -privs SeDebugPrivilege,SeImpersonatePrivilege
RunAs.exe -token [handle] cmd.exe
```

Output atteso:

```
nt authority\system
```

***

## Attack Chain

```
SeCreateTokenPrivilege su account non-SYSTEM trovato
  → PRIMO: documenta come finding critico (misconfiguration o backdoor)
  → token-priv PoC: CreateToken.exe -user S-1-5-18 -groups S-1-5-32-544
  → RunAs.exe con handle token → shell SYSTEM
  OPPURE
  → token con SID Domain Admins → NTLM auth verso risorse di rete → DA
  (NON funziona via Kerberos — PAC validation blocca i SID forgiati)
```

***

## Tool Decision

| Obiettivo                  | Strumento                                                                                       |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| Token SYSTEM locale        | `CreateToken.exe -user S-1-5-18` da [hatRiot/token-priv](https://github.com/hatRiot/token-priv) |
| Token con Domain Admin SID | `CreateToken.exe` + SID `S-1-5-21-[DOMAIN]-512`                                                 |
| Verifica SID Domain Admins | `wmic group where "name='Domain Admins'" get SID`                                               |
| Token per NTLM laterale    | Forgi token + PTH / NTLM relay verso risorse di rete                                            |

***

## Cos'è SeCreateTokenPrivilege

Permette di chiamare `NtCreateToken()` — la syscall NT che crea oggetti token di sicurezza dal nulla. Un token creato con questa API può contenere:

* **SID utente arbitrario** — SYSTEM, Administrator, qualsiasi account AD
* **SID di gruppo arbitrari** — Domain Admins, Enterprise Admins, qualsiasi
* **Privilegi arbitrari** — tutti i SePrivilege della serie e oltre
* **Livello di integrità arbitrario**

Tutti gli altri privilegi di token lavorano con token **esistenti** — li catturano, ereditano o assegnano. Questo li crea da zero, senza dipendenza da nessuna condizione esterna.

**Normalmente esclusivo di:** `lsass.exe`, `services.exe`, `winlogon.exe`. Se lo trovi su un account non di sistema → **finding critico** da documentare immediatamente.

***

## Quando esiste

In un pentest normale, quasi mai su account non di sistema. Se appare:

* **Account di sistema core** — lsass.exe, services.exe (normale)
* **Misconfiguration grave** — assegnato esplicitamente per errore a un account utente o di servizio
* **Indicatore di compromissione precedente** — backdoor installata da un attaccante precedente

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeCreateTokenPrivilege    Create a token object    Enabled
```

Audit immediato nell'ambiente:

```cmd
accesschk.exe -a SeCreateTokenPrivilege *
```

Se compare un account non-SYSTEM → documenta e segnala come finding critico prima di procedere.

***

## Step 1 — Exploit con token-priv PoC

Usa la collection di PoC di hatRiot che include implementazioni per SeCreateTokenPrivilege. Scaricabile da [hatRiot/token-priv](https://github.com/hatRiot/token-priv):

```cmd
CreateToken.exe -user S-1-5-18 -groups S-1-5-32-544 -privs SeDebugPrivilege,SeImpersonatePrivilege
```

Il SID `S-1-5-18` è SYSTEM, `S-1-5-32-544` è il gruppo Administrators locale.

Poi avvia un processo con il token forgiato:

```cmd
RunAs.exe -token [handle] cmd.exe
```

Output:

```
nt authority\system
```

***

## Step 2 — Aggiungere Domain Admin SID al token

Il caso più utile in AD: crei un token per un account basso privilegio ma aggiungi il SID di Domain Admins:

```
Token forgiato:
  UserSID: SID dell'account corrente (basso privilegio)
  Groups:  aggiungi S-1-5-21-[DOMAIN]-512 (Domain Admins) con SE_GROUP_ENABLED
  Privs:   aggiungi i privilegi necessari
```

Con questo token, l'autenticazione NTLM verso risorse di dominio è accettata come Domain Admin.

**Limitazione critica:** Con **Kerberos**, il DC valida il PAC (Privilege Attribute Certificate) firmato con le chiavi del dominio. Il token forgiato funziona per:

* Risorse locali della macchina
* Autenticazione NTLM verso risorse di rete

Non funziona per autenticazione Kerberos verso risorse di rete (il PAC reale viene usato).

***

## Differenza con SeTcbPrivilege

|                    | SeCreateTokenPrivilege            | SeTcbPrivilege           |
| ------------------ | --------------------------------- | ------------------------ |
| API                | `NtCreateToken` (syscall diretta) | `LsaLogonUser` (via LSA) |
| Sessione logon LSA | ❌ Token standalone                | ✅ Sessione ufficiale     |
| Complessità        | Alta                              | Alta                     |

In pratica, entrambi portano allo stesso risultato. La distinzione è tecnica — rilevante per chi studia l'internals di Windows.

***

## Scenari reali

Trovare SeCreateTokenPrivilege su un account non-SYSTEM è quasi sempre:

1. **Misconfiguration grave** → assegnato per errore tramite policy. Finding critico da riportare.
2. **Indicatore di compromissione pregressa** → un attaccante precedente ha lasciato una backdoor su un service account con questo privilegio.

In entrambi i casi: documenta, fotografa, segnala come finding critico **prima** di sfruttarlo.

***

## Errori comuni

**`NtCreateToken` → `STATUS_PRIVILEGE_NOT_HELD`** — Privilegio non Enabled. Verifica: `whoami /priv | findstr SeCreateToken`.

**Token SYSTEM creato ma Kerberos blocca l'accesso alle risorse di rete** — Il PAC Kerberos è firmato dal DC con chiavi che non controlli. Usa il token forgiato per accesso locale o autenticazione NTLM verso risorse di rete — non funziona per Kerberos puro.

**Token non prende effetto nel processo** — Il token forgiato non è stato impostato come primario. Usa `ImpersonateLoggedOnUser` o `SetThreadToken` dopo la creazione, oppure usa `RunAs.exe -token [handle]`.

**Token con Domain Admin SID non accede a share di rete** — Il DC sta usando Kerberos e valida il PAC reale. Forza NTLM: aggiungi l'host a `LmCompatibilityLevel` basso o usa tool che forzano NTLM.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                        | Come lo bypassa il Red Team                                       |
| ----------------------------------------------- | ----------------------------------------------------------------- |
| Chiamate `NtCreateToken` da processi non SYSTEM | Difficile da nascondere — opera velocemente e rimuovi le tracce   |
| ETW logging su token creation anomala           | Disabilita ETW consumer con SeSecurityPrivilege prima             |
| Account non-SYSTEM con il privilegio in audit   | Questo è il finding — rimuovilo dopo aver completato l'operazione |

***

## Quando fallisce

* `NtCreateToken` → `STATUS_PRIVILEGE_NOT_HELD` → privilegio non Enabled
* Kerberos blocca risorse di rete → usa NTLM o PTH con hash reali
* Token non impostato come primario → verifica `SetThreadToken` / `ImpersonateLoggedOnUser`

***

## Mitigazioni

* Non assegnare mai SeCreateTokenPrivilege ad account non di sistema
* Audit periodico: `accesschk.exe -a SeCreateTokenPrivilege *`
* **Protected Users** per account privilegiati → forza Kerberos, disabilita NTLM fallback
* Kerberos PAC validation (default su AD moderno)

**Nota realistica:** Trovare questo privilegio su un account non-SYSTEM è quasi sempre sintomo di compromissione pregressa o misconfiguration grave. In entrambi i casi è un finding P0 da riportare prima ancora di sfruttarlo.

***

## FAQ

**Perché lsass.exe ha questo privilegio?**
Deve creare token di sessione durante l'autenticazione. Ogni login chiama `NtCreateToken` per costruire il token dell'utente. È un requisito funzionale del processo di autenticazione.

**Con il token forgiato divento Domain Admin sulla rete?**
Via NTLM sì. Via Kerberos no — il PAC è firmato dal DC e non è falsificabile senza KRBTGT.

**In un pentest vedrò mai questo privilegio su account non di sistema?**
Raramente. Se lo vedi: documenta, segnala come P0, poi sfrutta.

***

SeCreateTokenPrivilege su un account non di sistema è quasi certamente compromissione pregressa o misconfiguration critica — documenta prima di sfruttarlo.

***

**Articoli correlati:**

* [SeTcbPrivilege](https://hackita.it/articoli/setcbprivilege) — token creation via LSA invece di syscall diretta
* [SeImpersonatePrivilege](https://hackita.it/articoli/seimpersonateprivilege) — token capture reattivo, molto più comune

**Riferimenti:** [token-priv PoC](https://github.com/hatRiot/token-priv) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-a-token-object)
