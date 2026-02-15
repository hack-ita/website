---
title: 'Ldapsearch: Enumerazione LDAP e Active Directory da Linux'
slug: ldapsearch
description: >-
  Ldapsearch è il tool CLI per interrogare LDAP e Active Directory da Linux.
  Utile per enumerazione utenti, gruppi, SPN e oggetti di dominio.
image: /Gemini_Generated_Image_m1v8som1v8som1v8.webp
draft: false
date: 2026-02-16T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - ad
---

Ldapsearch è il client LDAP da linea di comando che interroga direttamente il database Active Directory. Ogni oggetto AD — utenti, computer, gruppi, GPO, OU — è accessibile via LDAP sulla porta 389 (o 636 per LDAPS). Con ldapsearch estrai attributi che [Rpcclient](https://hackita.it/articoli/rpcclient) non raggiunge: `description` (spesso contiene password), `servicePrincipalName` (target per Kerberoasting), `userAccountControl` (account disabilitati, no pre-auth), `memberOf` e molto altro.

Kill chain: **Enumeration / Credential Access** (MITRE ATT\&CK T1087.002).

***

## 1️⃣ Setup e Installazione

```bash
sudo apt install ldap-utils
```

Verifica: `ldapsearch -VV`. Requisiti: pacchetto `ldap-utils`, connettività porta 389/636.

***

## 2️⃣ Uso Base

**Query anonima (se permessa):**

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local"
```

**Autenticata:**

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "CN=user,CN=Users,DC=corp,DC=local" -w 'Password1' -b "DC=corp,DC=local"
```

**Con credenziali in formato UPN:**

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Password1' -b "DC=corp,DC=local"
```

**Parametri chiave:**

* `-x` → autenticazione semplice (no SASL)
* `-H ldap://host` → server LDAP
* `-D bindDN` → utente per bind
* `-w password` → password
* `-b baseDN` → base di ricerca
* `-s scope` → base, one, sub (default: sub)
* `(filter)` → filtro LDAP

***

## 3️⃣ Tecniche Operative

### Estrarre tutti gli utenti

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description memberOf
```

### Trovare utenti con password nella descrizione

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(description=*pass*)" sAMAccountName description
```

Classico quick win: admin che scrivono la password nel campo descrizione.

### Trovare account per Kerberoasting

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

Account con SPN impostato → target per Kerberoasting.

### Trovare account con pre-auth disabilitata (AS-REP Roasting)

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName
```

### Estrarre Domain Admins

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "CN=Domain Admins,CN=Users,DC=corp,DC=local" member
```

***

## 4️⃣ Tecniche Avanzate

### Enumerare GPO

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "CN=Policies,CN=System,DC=corp,DC=local" "(objectClass=groupPolicyContainer)" displayName gPCFileSysPath
```

### Trovare computer nel dominio

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(objectClass=computer)" dNSHostName operatingSystem
```

### LDAPS (SSL)

```bash
ldapsearch -x -H ldaps://10.10.10.10:636 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local"
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Password nella descrizione

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(description=*)" sAMAccountName description | grep -B1 -i pass
```

**Output atteso:** `description: Temp password: Welcome2025!`

**Timeline:** 3 secondi.

### Scenario 2: Kerberoasting target

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

**Output atteso:** service account con SPN → roastable.

### Scenario 3: Mappatura completa AD

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "user@corp.local" -w 'Pass' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName memberOf userAccountControl > ad_dump.txt
```

***

## 6️⃣ Toolchain Integration

**Flusso:** Nmap (389/636) → **Ldapsearch (AD enum)** → [Adfind](https://hackita.it/articoli/adfind) (enum avanzata) → Impacket (Kerberoast/AS-REP)

| Tool       | User enum | SPN enum | GPO | Filtri custom    |
| ---------- | --------- | -------- | --- | ---------------- |
| Ldapsearch | Sì        | Sì       | Sì  | Sì (LDAP filter) |
| Rpcclient  | Sì        | No       | No  | Limitato         |
| ADFind     | Sì        | Sì       | Sì  | Sì               |
| BloodHound | Sì        | Sì       | Sì  | No (graph)       |

***

## 7️⃣ Attack Chain Completa

**Fase 1:** Ldapsearch → utente con SPN (5 sec). **Fase 2:** Kerberoasting → TGS hash (10 sec). **Fase 3:** Hashcat crack → password (10 min). **Fase 4:** Account è DA → DCSync (1 min). **Timeline:** \~12 min.

***

## 8️⃣ Detection & Evasion

**Blue Team:** Event ID 1644 (expensive LDAP query), 4662 (object access). **Evasion:** 1) Query mirate con filtri specifici. 2) Paginazione per evitare query massive. 3) LDAPS per cifrare traffico.

***

## 9️⃣ Performance & Scaling

Query singola: istantanea. Dump completo AD 10K oggetti: 5-10 sec.

***

## 🔟 Tabelle Tecniche

### Filtri LDAP utili

| Filtro                                                 | Descrizione            |
| ------------------------------------------------------ | ---------------------- |
| `(objectClass=user)`                                   | Tutti gli utenti       |
| `(objectClass=computer)`                               | Tutti i computer       |
| `(objectClass=group)`                                  | Tutti i gruppi         |
| `(servicePrincipalName=*)`                             | Account con SPN        |
| `(description=*pass*)`                                 | Descrizioni con "pass" |
| `(adminCount=1)`                                       | Account protetti/admin |
| `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` | No pre-auth            |

***

## 11️⃣ Troubleshooting

| Problema                    | Fix                                            |
| --------------------------- | ---------------------------------------------- |
| `Can't contact LDAP server` | Porta 389 chiusa o firewall                    |
| `Invalid credentials`       | Formato bind DN errato — prova UPN             |
| Risultati troncati          | Aggiungi `-E pr=1000/noprompt` per paginazione |

***

## 12️⃣ FAQ

**Ldapsearch vs BloodHound?** Ldapsearch per query mirate. BloodHound per analisi relazionale e path to DA.

**Funziona senza credenziali?** Solo se anonymous bind è abilitato (raro su AD moderni).

***

## 13️⃣ Cheat Sheet

| Azione                  | Comando                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| Enum utenti             | `ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "DC=x,DC=y" "(objectClass=user)" sAMAccountName` |
| Password in description | `"(description=*pass*)" sAMAccountName description`                                                      |
| Kerberoastable          | `"(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName`                    |
| AS-REP roastable        | `"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"`                                                 |
| Domain Admins           | `-b "CN=Domain Admins,CN=Users,DC=x,DC=y" member`                                                        |
| Tutti i computer        | `"(objectClass=computer)" dNSHostName operatingSystem`                                                   |

***

**Disclaimer:** Ldapsearch per penetration test autorizzati. Repository: parte di OpenLDAP — `man ldapsearch`.

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
