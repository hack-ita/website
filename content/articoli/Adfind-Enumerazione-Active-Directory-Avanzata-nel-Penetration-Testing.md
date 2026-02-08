---
title: 'Adfind: Enumerazione Active Directory Avanzata nel Penetration Testing'
slug: adfind
description: AdFind è un tool per enumerare oggetti Active Directory tramite query LDAP da linea di comando. Guida pratica all’uso in fase di domain enumeration durante un penetration test.
image: /Gemini_Generated_Image_tupqq5tupqq5tupq.webp
draft: true
date: 2026-02-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - enum
---

AdFind è un tool Windows da linea di comando scritto da Joe Richards per query LDAP avanzate su Active Directory. Nel penetration testing è l'alternativa potente a [Ldapsearch](https://hackita.it/articoli/ldapsearch) per chi opera già su un host Windows compromesso: un singolo eseguibile portatile, nessuna installazione, query predefinite per gli scenari AD più comuni.

AdFind eccelle nel mappare trust relationship tra domini, enumerare GPO, trovare account con delegation configurata e identificare path di privilege escalation. È lo strumento che usi quando hai shell su un domain-joined machine e devi estrarre il massimo di informazioni dall'AD.

Kill chain: **Enumeration** (MITRE ATT\&CK T1087.002).

***

## 1️⃣ Setup e Installazione

AdFind è un singolo eseguibile — scaricalo e usalo:

```cmd
adfind.exe -h
```

Nessuna installazione. Funziona su qualsiasi Windows domain-joined. Il tool usa l'autenticazione integrata dell'utente corrente.

***

## 2️⃣ Uso Base

**Enumerare tutti gli utenti:**

```cmd
adfind.exe -f "(objectcategory=person)" -csv name sAMAccountName description memberOf
```

**Enumerare gruppi:**

```cmd
adfind.exe -f "(objectcategory=group)" -csv name member
```

**Enumerare computer:**

```cmd
adfind.exe -f "(objectcategory=computer)" -csv name operatingSystem dNSHostName
```

***

## 3️⃣ Tecniche Operative

### Domain Admins

```cmd
adfind.exe -f "(&(objectCategory=group)(cn=Domain Admins))" member
```

### Account con SPN (Kerberoasting)

```cmd
adfind.exe -f "(&(objectCategory=person)(servicePrincipalName=*))" -csv sAMAccountName servicePrincipalName
```

### Trust relationships

```cmd
adfind.exe -f "(objectclass=trustedDomain)" -csv cn trustDirection trustType
```

Mappa tutti i trust tra domini — fondamentale per cross-domain attack path.

### Subnet e siti AD

```cmd
adfind.exe -subnets -f "(objectCategory=subnet)" -csv cn siteObject
```

### Account con delegation

```cmd
adfind.exe -f "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))" -csv cn msDS-AllowedToDelegateTo
```

Account con constrained delegation → target per S4U attack.

***

## 4️⃣ Tecniche Avanzate

### Enumerazione GPO con path SYSVOL

```cmd
adfind.exe -f "(objectCategory=groupPolicyContainer)" -csv displayName gPCFileSysPath
```

### Password policy del dominio

```cmd
adfind.exe -default -f "(objectClass=domainDNS)" lockoutDuration lockoutThreshold pwdHistoryLength minPwdLength maxPwdAge
```

### Find stale computer accounts

```cmd
adfind.exe -f "(&(objectCategory=computer)(lastLogonTimestamp<=TIMESTAMP))" -csv cn lastLogonTimestamp
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Full AD enum da host compromesso

```cmd
adfind.exe -f "(objectcategory=person)" sAMAccountName description > users.txt
adfind.exe -f "(&(objectCategory=group)(adminCount=1))" name member > admin_groups.txt
adfind.exe -f "(objectclass=trustedDomain)" cn trustDirection > trusts.txt
```

**Timeline:** 10-15 secondi per tutto.

### Scenario 2: Trovare target Kerberoast e delegation

```cmd
adfind.exe -f "(&(objectCategory=person)(servicePrincipalName=*))" sAMAccountName servicePrincipalName > kerberoast.txt
adfind.exe -f "(msDS-AllowedToDelegateTo=*)" cn msDS-AllowedToDelegateTo > delegation.txt
```

### Scenario 3: Mappatura completa per BloodHound manual

```cmd
adfind.exe -f "(objectcategory=person)" sAMAccountName memberOf adminCount userAccountControl > bloodhound_users.txt
```

***

## 6️⃣ Toolchain Integration

**Flusso:** Shell su host → **AdFind (AD enum)** → Impacket (Kerberoast/DCSync) → [Smbmap](https://hackita.it/articoli/smbmap) (lateral movement)

| Tool       | Piattaforma | Auth integrata | Trust enum | Delegation |
| ---------- | ----------- | -------------- | ---------- | ---------- |
| AdFind     | Windows     | Sì             | Sì         | Sì         |
| Ldapsearch | Linux       | No (bind)      | Manuale    | Manuale    |
| BloodHound | Multi       | Sì (collector) | Sì         | Sì (graph) |
| PowerView  | Windows     | Sì             | Sì         | Sì         |

***

## 7️⃣ Attack Chain Completa

**Fase 1:** AdFind → SPN account (5 sec). **Fase 2:** Rubeus Kerberoast (10 sec). **Fase 3:** Hashcat crack (10 min). **Fase 4:** DA credentials → DCSync (1 min). **Timeline:** \~12 min.

***

## 8️⃣ Detection & Evasion

**Blue Team:** AV/EDR rileva `adfind.exe` (signature note). Event ID 4662 (Directory access). **Evasion:** 1) Rinomina binario. 2) Usa ldapsearch da Linux. 3) Query mirate, non dump completo.

***

## 9️⃣ Performance & Scaling

Query singola: 1-5 sec. Dump completo AD: 10-30 sec.

***

## 🔟 Tabelle Tecniche

| Query                              | Descrizione            |
| ---------------------------------- | ---------------------- |
| `-f "(objectcategory=person)"`     | Tutti gli utenti       |
| `-f "(objectcategory=computer)"`   | Tutti i computer       |
| `-f "(objectcategory=group)"`      | Tutti i gruppi         |
| `-f "(servicePrincipalName=*)"`    | Account con SPN        |
| `-f "(objectclass=trustedDomain)"` | Trust                  |
| `-f "(adminCount=1)"`              | Account protetti       |
| `-subnets`                         | Subnet AD              |
| `-default`                         | Default naming context |

***

## 11️⃣ Troubleshooting

| Problema             | Fix                                      |
| -------------------- | ---------------------------------------- |
| AV blocca esecuzione | Rinomina, usa ldapsearch                 |
| No output            | Non sei su host domain-joined            |
| Access denied        | Utente corrente senza permessi LDAP read |

***

## 12️⃣ FAQ

**AdFind vs PowerView?** AdFind è un exe portatile, PowerView è PowerShell (più soggetto a AMSI). Entrambi fanno enum AD ma con approach diverso.

**Funziona da Linux?** No, solo Windows. Su Linux usa ldapsearch.

***

## 13️⃣ Cheat Sheet

| Azione           | Comando                                                                        |
| ---------------- | ------------------------------------------------------------------------------ |
| Utenti           | `adfind -f "(objectcategory=person)" sAMAccountName`                           |
| Domain Admins    | `adfind -f "(&(objectCategory=group)(cn=Domain Admins))" member`               |
| SPN (Kerberoast) | `adfind -f "(servicePrincipalName=*)" sAMAccountName servicePrincipalName`     |
| Trust            | `adfind -f "(objectclass=trustedDomain)" cn trustDirection`                    |
| Delegation       | `adfind -f "(msDS-AllowedToDelegateTo=*)" cn msDS-AllowedToDelegateTo`         |
| GPO              | `adfind -f "(objectCategory=groupPolicyContainer)" displayName gPCFileSysPath` |

***

**Disclaimer:** AdFind per penetration test autorizzati. Website: [joeware.net/freetools](http://www.joeware.net/freetools/tools/adfind/).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
