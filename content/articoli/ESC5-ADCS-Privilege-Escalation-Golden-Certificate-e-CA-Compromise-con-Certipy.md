---
title: 'ESC5 AD CS: ACL PKI, CA Compromise e Golden Certificate'
slug: esc5-adcs
description: 'Scopri la privilege escalation ESC5 in Windows Active Directory (AD CS): enumera ACL PKI con Certipy e PowerShell, verifica NTAuthCertificates e mitigazioni.'
image: /esc5.webp
draft: false
date: 2026-03-07T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC5
  - AD CS
  - Certipy
  - NTAuthCertificates
---

# ESC5 AD CS: ACL Deboli sugli Oggetti PKI e Privilege Escalation

ESC5 non riguarda un singolo template o la CA in sé, ma tutto il resto dell'infrastruttura PKI che vive in Active Directory: container, oggetti di configurazione, e in alcuni casi anche il server della CA stesso. È una categoria più ampia e meno standardizzata delle altre tecniche ESC — non esiste un singolo comando che la rilevi, e il suo impatto dipende interamente da *quale* oggetto è controllabile e da *cosa* quel controllo permette realmente di fare.

Per questo motivo ESC5 va trattato diversamente da ESC4 (ACL sul singolo certificate template) ed ESC7 (permessi sulla CA): qui il bersaglio sono gli oggetti di supporto della PKI — primo fra tutti `NTAuthCertificates` — il cui abuso può alterare la catena di trust dell'intero dominio o, in certe condizioni documentate da SpecterOps, aprire una strada da Domain Admin di un dominio figlio a Enterprise Admin della foresta.

| Termine                                                  | Significato                                                                                                                                     |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **AD CS**                                                | Active Directory Certificate Services, il servizio che emette certificati nel dominio                                                           |
| **ESC5**                                                 | Categoria di privilege escalation basata su ACL deboli sugli oggetti PKI di supporto (non il template, non la CA stessa)                        |
| **Configuration naming context**                         | La partizione di AD replicata su tutta la foresta, dove vivono gli oggetti PKI                                                                  |
| **NTAuthCertificates**                                   | Oggetto che elenca le CA fidate per l'autenticazione di dominio (smart card, PKINIT)                                                            |
| **cACertificate**                                        | Attributo multivalore di `NTAuthCertificates` che contiene i certificati delle CA pubblicate come trusted                                       |
| **AIA / CDP**                                            | Container che ospitano, rispettivamente, i certificati delle CA (Authority Information Access) e i punti di distribuzione delle liste di revoca |
| **Enrollment Services**                                  | Container che ospita un oggetto `pKIEnrollmentService` per ogni CA enterprise registrata in AD                                                  |
| **pKIEnrollmentService**                                 | Oggetto, uno per CA, il cui attributo `certificateTemplates` elenca quali template quella CA ha pubblicato                                      |
| **certificateTemplates (attributo)**                     | Elenco dei nomi di template pubblicati su una CA — scriverlo equivale a pubblicare un template                                                  |
| **Golden Certificate**                                   | Certificato forgiato con la chiave privata della CA, valido per impersonare qualsiasi identità nel dominio                                      |
| **WriteDACL / WriteOwner / WriteProperty / FullControl** | Diritti ACL che, se posseduti sull'oggetto giusto, possono abilitare la modifica della configurazione PKI                                       |
| **Strong Certificate Mapping**                           | Requisito Microsoft (KB5014754) per cui il KDC deve poter legare in modo forte un certificato all'account, altrimenti può rifiutarlo            |

***

# Le superfici di ESC5

ESC5 non si limita agli oggetti sotto `CN=Public Key Services`. La ricerca SpecterOps distingue tre superfici diverse, con impatti e requisiti differenti:

| Superficie            | Oggetti/componenti                                                                        | Impatto possibile                                                                                  |
| --------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| **Oggetti PKI in AD** | NTAuthCertificates, AIA, CDP, Certificate Templates (container), Enrollment Services, OID | Alterazione della configurazione PKI, pubblicazione di template o CA non autorizzate               |
| **Server della CA**   | Account computer, sistema operativo, delega                                               | Compromissione del server che ospita il servizio CA                                                |
| **RPC/DCOM della CA** | Permessi sull'interfaccia di amministrazione esposta dalla CA                             | Controllo delle operazioni amministrative della CA, indipendente dagli ACL degli oggetti directory |

Questo articolo si concentra sulla prima superficie — quella che la maggior parte degli audit ACL copre davvero — distinguendo comunque, dove conta, il controllo del container da quello del singolo oggetto figlio: non è la stessa cosa.

Oggetti da includere nell'audit, sotto `CN=Public Key Services,CN=Services,CN=Configuration,DC=<dominio>,DC=<tld>`:

```
CN=NTAuthCertificates
CN=AIA
CN=CDP
CN=Certification Authorities
CN=Certificate Templates     ← container, distinto dagli ACL dei singoli template (ESC4)
CN=Enrollment Services       ← oggetti pKIEnrollmentService, uno per CA
CN=OID
```

***

# Quando conta un permesso

Avere `WriteDACL`, `WriteOwner`, `WriteProperty` o `FullControl` su uno di questi oggetti **non dimostra automaticamente** che ESC5 sia sfruttabile. Vanno distinti:

* chi possiede il diritto, direttamente o tramite un gruppo annidato;
* se il diritto è sul container o sull'oggetto figlio (controllare `CN=Certificate Templates` non equivale a controllare ogni template esistente — quello resta ESC4);
* se il diritto è ereditato o assegnato direttamente;
* se un eventuale `ObjectType` GUID limita l'ACE a un attributo specifico, invece che all'intero oggetto;
* se un `WriteProperty` apparentemente ampio consente davvero di scrivere l'attributo che serve all'attacco (es. `cACertificate` su NTAuth, `certificateTemplates` su un `pKIEnrollmentService`).

Un permesso sul container non implica controllo amministrativo sull'intera PKI, e un'ACE che sembra pericolosa può non abilitare nulla di utile se è limitata a un attributo irrilevante.

***

# Enumerazione

**Certipy non rileva ESC5.** La sua documentazione lo dichiara esplicitamente: `certipy find -vulnerable` analizza le ACL dei certificate template e della CA, non quelle degli altri oggetti PKI. Un risultato "pulito" da Certipy non esclude ESC5 — significa solo che quella categoria di controllo non è nel suo perimetro.

Alternative:

* **BloodHound**, con raccolta dati ADCS — utile ma completo solo quanto gli oggetti e le relazioni effettivamente raccolte.
* **PowerShell**, enumerando il Configuration naming context per intero (non un solo DN scritto a mano):

```powershell
Import-Module ActiveDirectory

$configNC = (Get-ADRootDSE).configurationNamingContext
$baseDN = "CN=Public Key Services,CN=Services,$configNC"

$targets = Get-ADObject -SearchBase $baseDN -SearchScope Subtree -LDAPFilter "(objectClass=*)" |
    Select-Object -ExpandProperty DistinguishedName

foreach ($dn in $targets) {
    try {
        $acl = Get-Acl -Path "AD:\$dn"
        $acl.Access | Select-Object `
            @{Name='ObjectDN'; Expression={$dn}},
            IdentityReference, ActiveDirectoryRights, AccessControlType,
            ObjectType, InheritedObjectType, IsInherited
    } catch {
        Write-Warning "ACL non leggibile per $dn : $($_.Exception.Message)"
    }
}
```

Questo elenca le ACE su ogni oggetto sotto Public Key Services — non è una valutazione automatica della sfruttabilità. I GUID in `ObjectType` vanno ricondotti all'attributo dello schema che rappresentano, i gruppi annidati vanno risolti, e un'ACE di "Deny" può annullare un permesso apparentemente concesso più in alto nella catena.

* **ADSIEdit / ldp.exe** per l'ispezione manuale di un singolo oggetto e del suo security descriptor.

***

# NTAuthCertificates: dall'ACL alla CA fidata

`NTAuthCertificates` (DN: `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local`) contiene, nell'attributo multivalore `cACertificate`, i certificati delle CA considerate fidate per l'autenticazione di dominio — smart card logon, certificati dei Domain Controller, PKINIT.

Se un attaccante può scrivere su quell'attributo (tipicamente via `WriteProperty` mirato su `msPKI-Certificates`/`cACertificate`, non un generico controllo del container), può pubblicarvi il certificato di una CA sotto il suo controllo. Da qui a un'autenticazione riuscita, però, restano condizioni separate da verificare una per una:

| Controllo          | Cosa verifica                                                                                 |
| ------------------ | --------------------------------------------------------------------------------------------- |
| ACL                | Si può davvero scrivere l'attributo necessario, non solo "qualcosa" sull'oggetto              |
| Certificato CA     | È disponibile la chiave privata corrispondente alla CA che si vuole pubblicare                |
| Trust              | La CA pubblicata è riconosciuta per l'uso specifico (autenticazione, non solo firma generica) |
| Certificato utente | SAN, SID e altre estensioni del certificato emesso sono coerenti con l'identità target        |
| KDC                | Il certificato viene accettato in fase di PKINIT, non solo generato correttamente             |
| Privilegi          | L'identità effettivamente autenticata e i suoi gruppi reali                                   |

La frase "pubblico una CA e ottengo certificati validi" è una sintesi concettuale: nella pratica serve controllare ognuna di queste condizioni, e la cache locale della NTAuth store (`HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates`) può anche ritardare rispetto alla modifica in AD, se la replica o il refresh di Group Policy non sono ancora avvenuti.

***

# La catena ESC5 → ESC1: da Domain Admin a Enterprise Admin

Questo è il percorso più rilevante documentato da SpecterOps, e nasce da una proprietà strutturale di Active Directory: il Configuration naming context è **forest-wide** e replicato su ogni DC scrivibile della foresta — incluso quello di un dominio figlio. Un Domain Admin di un dominio figlio ha SYSTEM sui DC di quel dominio, e SYSTEM ha pieno controllo sulla copia locale (ma replicata) del container `Public Key Services` del forest root.

La catena, nelle sue condizioni reali:

1. Da Domain Admin del dominio figlio, ottenere SYSTEM su un DC del dominio figlio.
2. Usare SYSTEM per concedersi il controllo del container `CN=Certificate Templates` — quella modifica replica verso il forest root.
3. Duplicare un template esistente e configurarlo come vulnerabile a [ESC1](https://hackita.it/articoli/esc1-adcs/): diritti di enrollment per il principal attaccante, EKU Client Authentication, SAN specificato dal richiedente, nessuna approvazione manager.
4. Scrivere il nuovo nome di template nell'attributo `certificateTemplates` dell'oggetto `pKIEnrollmentService` della CA enterprise — questo è l'atto di "pubblicazione" che la rende disponibile per l'enrollment.
5. Richiedere un certificato su quel template specificando come SAN un account Enterprise Admin.
6. Autenticarsi con quel certificato e ottenere un TGT per l'identità Enterprise Admin.

Punto chiave: questa catena **non deriva da una qualunque ACL debole** su un oggetto PKI. Richiede nello specifico la possibilità di scrivere nel container Certificate Templates (per creare un nuovo template) e nell'attributo `certificateTemplates` di un `pKIEnrollmentService` collegato a una CA che è — o fa risalire la catena di trust a — una CA del forest root riconosciuta per l'autenticazione di dominio. Senza AD CS distribuito nella foresta, o senza una CA root-trusted raggiungibile, la catena semplicemente non esiste.

***

# Compromissione della chiave privata della CA e Golden Certificates

Un percorso concettualmente diverso: qui non si sfrutta un'ACL su un oggetto AD, ma un controllo sufficiente sul **servizio CA** per estrarne la chiave privata. Con Certipy, l'operazione di backup richiede i diritti `ManageCA` e `ManageCertificates` sulla CA — **non** deriva automaticamente dal controllo di `NTAuthCertificates` o di un container PKI qualsiasi; sono due superfici distinte che possono anche non coincidere nello stesso attaccante.

```bash
certipy ca \
    -u 'administrator@corp.local' -p 'Passw0rd!' \
    -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -config 'CA.CORP.LOCAL\CORP-CA' -backup
```

Output:

```
[*] Creating new service for backup operation
[*] Creating backup
[*] Retrieving backup
[*] Got certificate and private key
[*] Backed up original PFX/P12 to 'pfx.p12'
[*] Saving certificate and private key to 'CORP-CA.pfx'
```

Con la chiave della CA si può forgiare un certificato per qualsiasi identità:

```bash
certipy forge \
    -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' \
    -sid 'S-1-5-21-...-500' -crl 'ldap:///'
```

`-crl 'ldap:///'` è un CRL distribution point fittizio, accettato perché il certificato forgiato non verrà verificato tramite revoca in questo scenario.

```bash
certipy auth -pfx 'administrator_forged.pfx' -dc-ip '10.0.0.100'
```

In caso di successo, Certipy mostra le identità nel certificato, ottiene un TGT e recupera l'hash NT. Ma "la chiave di una CA" non basta di per sé: deve trattarsi di una CA effettivamente rilevante per la catena di trust usata dal KDC per l'autenticazione — non ogni CA nella foresta può impersonare chiunque. Vanno verificati, prima di considerare l'attacco riuscito:

* **Subject/SAN/UPN** del certificato forgiato;
* **SID** e corrispondenza con l'oggetto AD target;
* **catena di trust** della CA usata per firmare;
* **strong certificate mapping**: dal 9 settembre 2025 Microsoft ha completato l'enforcement dei requisiti KB5014754, e `StrongCertificateBindingEnforcement` non è più un rollback supportato — un certificato forgiato senza un mapping forte verso l'account target può essere rifiutato dal KDC anche se firma e campi principali sono corretti.

Risultati da distinguere, non da dare per garantiti in sequenza: generazione del PFX → autenticazione Kerberos riuscita → rilascio del TGT → recupero dell'hash NT → accesso effettivo a una risorsa con quei privilegi. Ognuno di questi può fermarsi prima del successivo.

***

# Troubleshooting

| Sintomo                                                                                    | Causa possibile                                                                                                                                          |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `certipy ca -backup` fallisce con accesso negato                                           | Manca `ManageCA`/`ManageCertificates` — il controllo di un oggetto PKI in AD non basta                                                                   |
| `certipy forge` produce il PFX ma `certipy auth` fallisce con `KDC_ERR_CLIENT_NOT_TRUSTED` | La CA usata per firmare non è nella catena di trust riconosciuta per l'autenticazione, o il certificato non supera lo strong certificate mapping         |
| Il certificato forgiato viene rifiutato nonostante SID e UPN corretti                      | Manca la SID Security Extension o un mapping forte equivalente richiesto dal KDC aggiornato                                                              |
| ESC5 non appare mai nei risultati di `certipy find`                                        | Previsto — Certipy non analizza questa categoria di ACL; serve un audit manuale/BloodHound separato                                                      |
| Il template pubblicato nella catena ESC5→ESC1 non è utilizzabile                           | L'attributo `certificateTemplates` del `pKIEnrollmentService` non è stato scritto correttamente, o la replica verso il forest root non è ancora avvenuta |

***

# Detection

* **Event ID 5136** — modifica di un oggetto directory, incluse le modifiche agli oggetti PKI sotto Public Key Services. Richiede una SACL configurata su quell'oggetto per essere generato: l'auditing non è attivo di default.
* Eventi di **Certificate Services** relativi a cambiamenti di configurazione e permessi del servizio CA.
* Monitoraggio specifico su:
  * modifiche a `cACertificate` (NTAuthCertificates);
  * modifiche a `certificateTemplates` sugli oggetti `pKIEnrollmentService`;
  * cambi di security descriptor sui container PKI.
* Replica e configurazione: una modifica malevola nel dominio figlio replica verso il forest root — la correlazione va fatta a livello di foresta, non solo sul singolo dominio.

***

# Mitigazioni

* **Least privilege sugli ACL PKI**: solo gruppi come Enterprise Admins o un gruppo dedicato di PKI Admins dovrebbero avere diritti di scrittura su NTAuthCertificates, Enrollment Services, Certificate Templates (container) e gli altri oggetti sotto Public Key Services.
* **Audit periodico** delle ACL su `CN=Public Key Services` e dei suoi figli, con attenzione a `Authenticated Users`/`Domain Users` con diritti di scrittura, diretti o ereditati.
* **Monitoraggio dedicato su NTAuthCertificates**: ogni modifica a `cACertificate` è un evento ad alto impatto.
* **Separazione dei ruoli CA**: `ManageCA` e `ManageCertificates` non dovrebbero coincidere con chi ha anche diritti estesi sugli oggetti PKI in AD, per evitare che le due superfici si somminino in un unico attaccante.
* **Dopo un incidente**: revocare/rimuovere trust, certificati e chiavi compromesse, e verificare la replica su tutti i DC della foresta prima di considerare chiuso l'incidente.

***

# FAQ — ESC5 ADCS

### Cos'è ESC5?

ACL deboli su oggetti PKI di supporto in Active Directory (NTAuthCertificates, AIA, CDP, Enrollment Services, container Certificate Templates) — distinti dal singolo template (ESC4) e dai permessi sulla CA (ESC7).

### Qual è la differenza tra ESC4, ESC5 ed ESC7?

[ESC4](https://hackita.it/articoli/esc4-adcs/) riguarda l'ACL di un singolo certificate template. ESC5 riguarda gli altri oggetti PKI in AD (container, NTAuth, Enrollment Services). [ESC7](https://hackita.it/articoli/esc7-adcs/) riguarda i permessi `ManageCA`/`ManageCertificates` sulla CA stessa — una superficie diversa, non sovrapponibile automaticamente a ESC5.

### Perché `certipy find -vulnerable` non basta a escludere ESC5?

Perché Certipy analizza le ACL dei template e della CA, non quelle degli altri oggetti PKI in AD. L'assenza di un risultato ESC5 non dimostra l'assenza della vulnerabilità — serve un audit ACL dedicato (BloodHound con raccolta ADCS, PowerShell, o ispezione manuale).

### ESC5 porta sempre a Domain Admin o Enterprise Admin?

No. L'impatto dipende da quale oggetto è controllabile e da cosa quel controllo permette concretamente di scrivere. Il percorso verso Enterprise Admin via ESC5→ESC1 è condizionale: richiede AD CS distribuito nella foresta, controllo del container Certificate Templates e dell'attributo `certificateTemplates` di un `pKIEnrollmentService` collegato a una CA root-trusted.

### Perché un certificato forgiato con la chiave della CA può comunque fallire l'autenticazione?

Perché dal 9 settembre 2025 i Domain Controller aggiornati applicano l'enforcement dello strong certificate mapping (KB5014754): un certificato senza un mapping forte verso l'account target può essere rifiutato dal KDC anche se la firma e i campi principali sono corretti.

***

> Guida completa alle tecniche ESC1–ESC16: [AD CS Privilege Escalation con Certipy](https://hackita.it/articoli/adcs-esc1-esc16/).Tecniche collegate: [ESC4 ADCS](https://hackita.it/articoli/esc4-adcs/) (ACL sul singolo template) e [ESC7 ADCS](https://hackita.it/articoli/esc7-adcs/) (permessi sulla CA) coprono le due superfici più vicine a ESC5 ma distinte da essa.

**Fonti tecniche:**

* [Certipy — GitHub Wiki, Privilege Escalation (ESC5)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
* [SpecterOps — From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
* [Microsoft Learn — Import Third-Party CA to Enterprise NTAuth Store](https://learn.microsoft.com/en-US/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store)
