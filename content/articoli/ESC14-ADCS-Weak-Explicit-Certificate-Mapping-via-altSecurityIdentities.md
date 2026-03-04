---
title: 'ESC14 ADCS: Weak Explicit Certificate Mapping via altSecurityIdentities'
slug: adesc14-adcs
description: ESC14 sfrutta configurazioni deboli di altSecurityIdentities in Active Directory. Un certificato può essere mappato a un account privilegiato e permettere impersonation.
image: /14.webp
draft: true
date: 2026-03-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ad
  - adcs
  - esc
  - ''
---

ESC14 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta configurazioni deboli dell’attributo **`altSecurityIdentities`** negli oggetti Active Directory. Questo attributo permette di creare **explicit certificate mapping**, cioè associare manualmente un certificato X.509 a un account AD per l’autenticazione.

Quando `altSecurityIdentities` è configurato, Active Directory può usare questa associazione **per autenticare direttamente l’utente tramite certificato**, bypassando i normali meccanismi di mapping basati su:

* SAN UPN
* DNS name
* SID security extension

Il problema nasce quando la stringa di mapping è **troppo generica o facilmente replicabile**. In questo caso un attaccante può ottenere o creare un certificato con gli stessi attributi e **impersonare l’account associato**.

***

# Come funziona ESC14

Il mapping esplicito avviene tramite stringhe come queste:

```
altSecurityIdentities
```

Esempi di mapping supportati:

```
X509:<I>IssuerDN<S>SubjectDN
X509:<S>CN=Username
X509:<RFC822>email@domain.com
X509:<SHA1-PUKEY>PublicKeyHash
```

Se il mapping usa attributi **non univoci**, un attaccante può creare un certificato che soddisfa la stessa condizione.

***

# Esempio di mapping debole

Esempio pericoloso:

```
X509:<S>CN=Administrator
```

Se un attaccante riesce a ottenere un certificato con:

```
Subject: CN=Administrator
```

Active Directory può mapparlo automaticamente all’account Administrator.

***

# Identificazione ESC14

Certipy non rileva ESC14 automaticamente perché l’attributo `altSecurityIdentities` è configurato sugli oggetti AD.

È necessario interrogare Active Directory.

### PowerShell

```powershell
Get-ADUser -Filter * -Properties altSecurityIdentities
```

### LDAP query

```
altSecurityIdentities=*
```

Strumenti utili:

* PowerShell
* LDAP tools
* BloodHound (analisi manuale)

***

# Esempio di mapping vulnerabile

```
altSecurityIdentities:
X509:<S>CN=DAUserBackupCert
```

Se un attaccante riesce a ottenere un certificato con:

```
CN=DAUserBackupCert
```

può autenticarsi come l’account associato.

***

# Exploitation ESC14

L’attacco ha tre fasi principali:

1. trovare mapping deboli
2. ottenere certificato compatibile
3. autenticarsi tramite certificato

***

## Step 1 — Ottenere certificato compatibile

Il certificato può provenire da:

* template AD CS vulnerabile (es. [ESC1](https://hackita.it/articoli/esc1-adcs))
* CA compromessa
* PKI esterna
* certificato autofirmato accettato dal sistema

***

## Step 2 — Autenticazione con Certipy

```bash
certipy auth \
-pfx malicious.pfx \
-dc-ip 10.0.0.100 \
-username administrator@corp.local \
-domain corp.local
```

Output tipico:

```
Got TGT
Saving credential cache
Got hash for administrator
```

L’attaccante ottiene:

* **Kerberos TGT**
* **NT hash**
* accesso come utente privilegiato

***

# Impatto ESC14

Se il mapping riguarda un account privilegiato:

* Domain Admin
* Enterprise Admin
* account Tier-0

l’attaccante ottiene **compromissione completa del dominio**.

ESC14 è particolarmente pericoloso perché **funziona anche con strong certificate binding attivo**.

***

# Detection ESC14

Indicatori utili:

* `altSecurityIdentities` popolato su account privilegiati
* mapping basati su **CN o email**
* mapping senza serial number o SKI

Audit consigliato:

```
altSecurityIdentities
```

su:

* Domain Admin
* Enterprise Admin
* Service Accounts
* Tier-0 accounts

***

# Mitigation ESC14

Le difese consistono nel rendere i mapping **univoci e crittograficamente forti**.

Formati raccomandati:

```
X509:<I>IssuerDN<SR>SerialNumber
```

oppure

```
X509:<SHA1-PUKEY>PublicKeyHash
```

Da evitare:

```
X509:<S>CN=username
X509:<RFC822>email
```

Misure consigliate:

* audit regolare di `altSecurityIdentities`
* usare mapping basati su **serial number**
* evitare mapping generici
* limitare explicit mapping agli account necessari

***

# FAQ — ESC14 ADCS

### Cos'è ESC14?

Una escalation basata su **explicit certificate mapping debole tramite altSecurityIdentities**.

### Qual è il problema principale?

Mapping troppo generici che possono essere replicati da un certificato controllato dall’attaccante.

### Serve compromettere la CA?

Non necessariamente. Basta ottenere un certificato che soddisfi il mapping.

### ESC14 funziona con strong certificate binding?

Sì, perché usa **explicit mapping**, non implicit mapping.

***

**Key Takeaway:** se `altSecurityIdentities` usa mapping deboli (come CN o email), un attaccante può creare un certificato compatibile e autenticarsi come qualsiasi account associato.

***

> ESC14 è spesso trascurato ma può portare a compromissione completa del dominio.
> Guida completa agli attacchi AD CS:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le tecniche successive:
> [https://hackita.it/articoli/esc15-adcs](https://hackita.it/articoli/esc15-adcs) · [https://hackita.it/articoli/esc16-adcs](https://hackita.it/articoli/esc16-adcs)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Pentest Active Directory o formazione offensiva:
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
