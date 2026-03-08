---
title: 'ESC12 ADCS: Compromissione della CA tramite YubiHSM2'
slug: esc12-adcs
description: >-
  ESC12 riguarda vulnerabilità nello stack YubiHSM2 usato da AD CS. Se la chiave
  privata della CA viene compromessa, un attaccante può forgiare Golden
  Certificates.
image: /12.webp
draft: false
date: 2026-03-09T00:00:00.000Z
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

ESC12 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che riguarda un caso molto specifico: l’uso di **YubiHSM2 per proteggere la chiave privata della Certificate Authority**. A differenza delle altre tecniche ESC, qui il problema non è una misconfiguration di AD CS ma una possibile **vulnerabilità nel software stack del dispositivo HSM** o nella sua integrazione con il server CA.

In alcune ricerche della community (in particolare quelle di **Hans-Joachim Knobloch**) è stato dimostrato che, in determinate condizioni, un attaccante con **accesso shell a basso privilegio sul server della CA** potrebbe riuscire a interagire con il **YubiHSM2 Key Storage Provider (KSP)** in modo non previsto.

Questo scenario potrebbe permettere di:

* forzare la CA a **firmare richieste di certificato arbitrarie**
* utilizzare l’HSM per **firmare dati controllati dall’attaccante**
* in casi estremi, ottenere accesso alla **chiave privata della CA**

Se la chiave della CA viene compromessa, l’attaccante può generare **Golden Certificates**, cioè certificati validi per qualsiasi account del dominio.

Per questo motivo ESC12 è spesso citato insieme agli altri certificate attacks, anche se tecnicamente è più vicino a una **vulnerabilità hardware/software post-compromise** che a una misconfiguration AD CS come [ESC5](https://hackita.it/articoli/esc5-adcs) o [ESC7](https://hackita.it/articoli/esc7-adcs).

***

# Prerequisiti per ESC12

Perché questo scenario sia possibile devono verificarsi diverse condizioni:

* la CA usa **YubiHSM2 per proteggere la chiave privata**
* l’attaccante ha **accesso shell sul server CA**
* il software YubiHSM2 o il KSP contiene una **vulnerabilità sfruttabile**
* l’attaccante riesce a interagire con il dispositivo HSM da un contesto non privilegiato

Questo significa che **ESC12 è quasi sempre un attacco post-compromise**.

***

# Identificazione ESC12

Certipy **non può rilevare ESC12 automaticamente**.

L’identificazione dipende da:

* configurazione della CA
* presenza di **YubiHSM2**
* audit della sicurezza del server CA
* vulnerabilità note nel software YubiHSM2

La ricerca originale che descrive questo scenario è disponibile qui:

[https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm/](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm/)

***

# Possibile Impatto

Se l’attaccante riesce a sfruttare una vulnerabilità nello stack YubiHSM2 può ottenere la capacità di **far firmare certificati alla CA**.

Questo porta a uno scenario simile a **CA compromise**.

In tal caso l’attaccante può creare certificati per qualsiasi account.

***

# Post-Exploitation con Certipy

Se la chiave privata della CA viene estratta o salvata come file `.pfx`, Certipy può essere usato per forgiare certificati.

### Forgiare certificato Administrator

```bash
certipy forge \
-ca-pfx 'CORP-CA.pfx' \
-upn 'administrator@corp.local' \
-sid 'S-1-5-21-...-500' \
-crl 'ldap:///'
```

Output:

```text
Saving forged certificate to administrator_forged.pfx
```

***

### Autenticazione con il certificato

```bash
certipy auth -pfx administrator_forged.pfx -dc-ip 10.0.0.100
```

Output tipico:

```text
Got TGT
Saving credential cache to administrator.ccache
Got hash for administrator
```

Risultato:

* **Kerberos TGT**
* **NT hash**
* controllo completo del dominio

***

# Scenario Alternativo

Se la chiave privata non può essere estratta ma la vulnerabilità permette comunque di **far firmare certificati alla CA**, l’attaccante può:

1. generare un CSR locale
2. farlo firmare dalla CA tramite la vulnerabilità
3. ottenere il certificato firmato

Una volta ottenuto il certificato (`.pfx`), può autenticarsi normalmente tramite PKINIT o TLS.

***

# Detection ESC12

Il rilevamento dipende da:

* audit della sicurezza del server CA
* accessi locali sospetti
* interazioni anomale con l’HSM

Indicatori utili:

* accesso shell non autorizzato sulla CA
* attività anomale nel software YubiHSM
* operazioni di firma certificate inattese

***

# Mitigation ESC12

Le difese principali riguardano la sicurezza del server CA e dell’HSM.

Misure raccomandate:

* mantenere aggiornati **firmware e software YubiHSM2**
* limitare l’accesso al server CA
* isolare la CA come **asset Tier-0**
* monitorare l’accesso locale e le operazioni HSM

Il server CA deve essere protetto con lo stesso livello di sicurezza di un **Domain Controller**.

***

# FAQ — ESC12 ADCS

### Cos'è ESC12?

Uno scenario in cui una vulnerabilità nello stack **YubiHSM2** permette a un attaccante con accesso locale alla CA di abusare della chiave privata.

### ESC12 è una misconfiguration AD CS?

Non necessariamente. È più una **vulnerabilità hardware/software post-compromise**.

### ESC12 permette Domain Admin?

Sì. Se la chiave della CA viene compromessa l’attaccante può generare certificati per qualsiasi utente.

### Qual è la differenza tra ESC12 e ESC5?

[ESC5](https://hackita.it/articoli/esc5-adcs) riguarda ACL PKI deboli.
ESC12 riguarda vulnerabilità nello **stack YubiHSM2**.

***

**Key Takeaway:** se un attaccante ottiene accesso alla chiave privata della CA — anche tramite vulnerabilità nello stack HSM — può generare certificati per qualsiasi account e compromettere completamente il dominio.

***

> ESC12 è uno scenario raro ma estremamente critico nella sicurezza delle PKI enterprise.
> Per vedere tutte le tecniche certificate attack consulta la guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le escalation successive:
> [https://hackita.it/articoli/esc13-adcs](https://hackita.it/articoli/esc13-adcs) · [https://hackita.it/articoli/esc14-adcs](https://hackita.it/articoli/esc14-adcs)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Vuoi imparare pentesting Active Directory o testare la sicurezza della tua infrastruttura?
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm/](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm/)
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
