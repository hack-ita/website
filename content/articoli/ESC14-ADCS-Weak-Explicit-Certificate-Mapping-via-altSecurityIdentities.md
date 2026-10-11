---
title: 'ESC14 AD CS: Privesc con altSecurityIdentities e Certipy'
slug: adesc14-adcs
description: 'Privilege escalation in Active Directory: ESC14 sfrutta mapping X.509 deboli in altSecurityIdentities per impersonare account Windows tramite certificati.'
image: /14.webp
draft: false
date: 2026-03-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC14
  - AD CS
  - Active Directory
  - Certipy
---

# ESC14 in Active Directory Certificate Services: weak explicit certificate mapping via altSecurityIdentities

ESC14 **non è una tecnica sola**: SpecterOps, che l'ha documentata, distingue quattro scenari distinti (A, B, C, D) con prerequisiti, attributi coinvolti e comportamento del KDC diversi tra loro. Trattarla come "trovi un mapping debole, crei un certificato, ti autentichi" — in tre comandi — è impreciso e, su un dominio aggiornato, spesso semplicemente non funziona. Questa guida separa i quattro scenari, dice cosa serve per ciascuno e cosa fare quando non va.

Glossario prima di entrare nel merito — qui più che altrove serve, perché il tema è denso:

| Termine                               | Cos'è, in una riga                                                                                                                                                                                                                |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **altSecurityIdentities**             | Un attributo AD multi-valore che permette di associare manualmente ("explicit mapping") un certificato a un account, per bypassare il mapping automatico.                                                                         |
| **Explicit mapping**                  | Un'associazione certificato→account impostata a mano in `altSecurityIdentities`, diversa dal mapping "implicito" che il KDC deduce dai campi standard del certificato (SAN UPN, SID security extension).                          |
| **PKINIT**                            | L'estensione Kerberos che permette di autenticarsi con un certificato invece che con una password.                                                                                                                                |
| **Schannel**                          | Il componente Windows che gestisce TLS, usato ad esempio da LDAPS — è una via di autenticazione alternativa a PKINIT, con regole di mapping proprie.                                                                              |
| **S4U2Self**                          | Un'estensione Kerberos che permette a un servizio di ottenere un ticket per conto di un utente — qui entra in gioco in alcuni percorsi di autenticazione via Schannel.                                                            |
| **Strong / weak mapping**             | Forte = basato su identificatori non riutilizzabili (serial number, hash della chiave pubblica). Debole = basato su campi replicabili (nome, email).                                                                              |
| **Victim / Target**                   | Nel linguaggio di questa tecnica: il "target" è l'account che l'attaccante vuole impersonare (ha il mapping debole); il "victim" è l'account/attributo che l'attaccante riesce a controllare per costruire il certificato giusto. |
| **CT\_FLAG\_NO\_SECURITY\_EXTENSION** | Un flag di un certificate template che fa sì che i certificati emessi **non** portino la SID security extension — condizione necessaria per alcuni degli scenari qui sotto.                                                       |

***

# In cosa consiste il problema (con una correzione importante)

`altSecurityIdentities` permette di associare esplicitamente un certificato a un account. Non è corretto dire — come si legge spesso — che questo "bypassa sempre" il mapping basato su SAN UPN, DNS o SID: **il comportamento dipende dal contenuto del certificato, dal tipo di mapping, e dalle impostazioni del Domain Controller**. In alcuni casi un certificato con SAN UPN viene prima valutato con il mapping implicito, e se quel tentativo fallisce l'autenticazione può essere semplicemente rifiutata, senza mai arrivare al mapping esplicito.

Il problema reale: quando il mapping esplicito configurato è **debole** (basato su campi facilmente replicabili, come un nome o un indirizzo email), un attaccante che riesce a ottenere un certificato con quegli stessi valori può farlo accettare come corrispondenza valida.

### Formati di mapping: deboli vs forti

| Formato                            | Forza  | Perché                                                            |
| ---------------------------------- | ------ | ----------------------------------------------------------------- |
| `X509:<I>IssuerDN<S>SubjectDN`     | Debole | Issuer e Subject sono stringhe replicabili                        |
| `X509:<S>SubjectDN`                | Debole | Il Subject da solo è ancora più facile da replicare               |
| `X509:<RFC822>EmailAddress`        | Debole | Un indirizzo email è un attributo scrivibile in molti ambienti    |
| `X509:<I>IssuerDN<SR>SerialNumber` | Forte  | Il serial number di un certificato è univoco e non riutilizzabile |
| `X509:<SKI>SubjectKeyIdentifier`   | Forte  | Identifica una chiave pubblica specifica                          |
| `X509:<SHA1-PUKEY>PublicKeyHash`   | Forte  | Hash della chiave pubblica, non riproducibile a piacere           |

La distinzione è sulla **possibilità di replicare/riutilizzare** l'identificatore, non sulla lunghezza della stringa.

### Un dettaglio tecnico che si sbaglia spesso

Costruire a mano un mapping `<I>IssuerDN<SR>SerialNumber` richiede due trasformazioni, non una sola:

* i componenti del Distinguished Name vanno scritti **in ordine inverso** — `CN=corp-CA, DC=corp, DC=local` diventa `DC=local,DC=corp,CN=corp-CA`;
* nel serial number va invertito l'ordine delle **coppie di byte**, non delle singole cifre esadecimali — `A1B2C3` diventa `C3B2A1`, non `3C2B1A`. Esempio reale: `6c0000002559f904dbc638e8a5000000000025` diventa `250000000000a5e838c6db04f959250000006c`.

Sbagliare questo passaggio è la causa più comune di "il certificato è giusto ma il mapping non corrisponde comunque".

***

# Prerequisiti comuni a tutti gli scenari

* l'attaccante controlla un account ("victim") da cui può richiedere certificati;
* esiste un certificate template che concede Enroll al victim, con EKU di client authentication, ed emette senza requisiti che il victim non può soddisfare;
* la CA è un'Enterprise CA fidata per l'autenticazione, con catena di trust valida e template effettivamente pubblicato.

Da qui, i quattro scenari divergono completamente.

***

# Scenario A — Scrivi tu stesso il mapping del target

**Questo è lo scenario più diretto, e l'unico che funziona anche con strong certificate binding attivo** — perché l'attaccante stesso scrive un mapping forte, non sfrutta una debolezza preesistente.

**Prerequisito chiave:** avere un permesso che consenta di scrivere `altSecurityIdentities` sul target (Write property su quell'attributo, GenericWrite, GenericAll o equivalenti).

**Target tipico:** un computer account, spesso perché porta sessioni admin locali interessanti o perché le sue credenziali sono comode da impersonare.

**Template usato:** `Machine` (default — `Domain Computers` ha Enroll).

### Passaggi

1. Richiedi un certificato come il tuo stesso account macchina:

```bash
Certify.exe request /template:Machine /machine
```

1. Estrai issuer e serial number dal certificato ottenuto:

```cmd
certutil -dump certificato.cer
```

1. Costruisci il mapping forte (con le due inversioni spiegate sopra) e scrivilo su `altSecurityIdentities` del target. SpecterOps fornisce cmdlet dedicati per questo:

```powershell
Add-AltSecIDMapping -DistinguishedName "CN=TargetComputer,..." -Mapping "X509:<I>...<SR>..."
```

1. Autenticati come il target con PKINIT:

```bash
Rubeus.exe asktgt /user:TARGET$ /certificate:tuo-certificato.pfx /ptt
```

### Se non funziona

* **Scrittura rifiutata su `altSecurityIdentities`** → il permesso che pensavi di avere non è quello giusto; verifica con uno strumento di analisi ACL (es. BloodHound) che il tipo di diritto sia effettivamente sufficiente (GenericWrite non sempre equivale a poter scrivere un attributo protetto specifico);
* **TGT richiesto ma rifiutato** → controlla di aver invertito correttamente DN e byte del serial, è l'errore più comune;
* **Via Schannel invece che PKINIT** → serve che il flag S4U2Self (`0x8`) sia attivo sul DC — di norma lo è di default, ma vale la pena verificarlo se PKINIT fallisce per altri motivi.

Ripristina sempre il valore originale di `altSecurityIdentities` dopo l'uso, come faresti con un UPN temporaneo in altre tecniche ESC — altrimenti lasci una backdoor visibile a chiunque legga quell'attributo.

***

# Scenario B — Mapping debole via email (`X509:<RFC822>`)

**Target:** un utente che ha già un mapping `X509:<RFC822>EmailAddress` in `altSecurityIdentities`.

**Victim (quello che devi controllare tu):** l'attributo `mail` di un account da cui puoi richiedere un certificato.

**Requisiti del template:** deve avere `CT_FLAG_NO_SECURITY_EXTENSION` nel `msPKI-Enrollment-Flag` (non è il default — va cercato esplicitamente) e richiedere l'email nel Subject Alternative Name (`CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL`).

### Passaggi

1. Imposta l'attributo `mail` del tuo account sullo stesso valore presente nel mapping del target (via ADSI o `Set-ADUser -EmailAddress`).
2. Richiedi un certificato dal template che include l'email nel SAN:

```bash
Certify.exe request /template:ExtMail
```

1. Autenticati — ma qui arriva il punto critico.

### Perché oggi questo scenario è quasi sempre bloccato su PKINIT

Via PKINIT, questo percorso richiede che il DC sia ancora in **modalità compatibile** (non Full Enforcement) rispetto allo strong certificate binding. Dal 9 settembre 2025 Microsoft ha reso l'enforcement forte **permanente**, senza più possibilità di tornare a Compatibility Mode: su un DC aggiornato a quella data, questo scenario via PKINIT **non funziona più**.

Resta teoricamente percorribile via **Schannel**, ma solo se quel servizio ha un proprio mapping debole configurato in modo permissivo (vedi anche [ESC10](https://hackita.it/articoli/esc10-adcs/), che tratta esattamente questa superficie) — non darlo per scontato, verificalo.

### Se non funziona

* **Certificato ottenuto ma rifiutato in autenticazione** → quasi certamente il DC è in Full Enforcement: questo scenario via Kerberos è chiuso su ambienti aggiornati, non è un errore di configurazione tuo;
* **`mail` non modificabile sul tuo account** → serve un permesso di scrittura su quell'attributo, che potresti non avere di default sul tuo stesso account in ambienti con policy restrittive.

***

# Scenario C — Mapping debole via Issuer+Subject (`X509:<I>...<S>...`)

**Target:** un utente o computer con un mapping `X509IssuerSubject` in `altSecurityIdentities`.

**Victim:** se il target da impersonare è un utente, devi controllare gli attributi `cn` e `name` (un rename li aggiorna insieme); se è un computer, l'attributo `dNSHostName`.

> Attenzione a un caso limite: se target e victim sono utenti nello stesso container e il mapping contiene già il CN del target, il rename può risultare impossibile (collisione di nome) — se ti capita, non è un errore di comando, è che quella particolare via è bloccata in quell'ambiente.

**Requisiti del template:** `CT_FLAG_NO_SECURITY_EXTENSION`, più `CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME` o `DNS_AS_CN`, e il Subject **senza** directory path né email.

**CA:** deve essere esattamente quella indicata nell'IssuerName del mapping — non una CA qualsiasi del dominio.

### Passaggi

1. Rinomina il victim (cn/name o dNSHostName, a seconda del caso) per farlo coincidere con il Subject atteso dal mapping.
2. Richiedi il certificato:

```bash
Certify.exe request /template:ExtMail
```

1. Autenticazione — qui la via più praticabile oggi è **Schannel**, non PKINIT:

```bash
certipy auth -pfx certificato.pfx -dc-ip 10.0.0.100 -ldap-shell
```

Via PKINIT serve ancora la modalità compatibile del KDC (quindi, come per lo Scenario B, oggi spesso non disponibile). Via Schannel serve invece un flag specifico, il **Subject/Issuer flag (`0x1`)**, che **non è attivo di default** — va verificato, non assunto.

### Se non funziona

* **Rename bloccato** → vedi il caso limite sopra, può essere una collisione di nome nello stesso container;
* **`certipy auth -ldap-shell` rifiuta l'autenticazione** → verifica che il flag Subject/Issuer sia davvero attivo su quel DC; se non lo è, questo scenario specifico non è sfruttabile lì;
* **Certificato emesso ma CA "sbagliata"** → ricontrolla che l'IssuerName nel mapping corrisponda esattamente alla CA da cui hai richiesto il certificato.

***

# Scenario D — Mapping debole via Subject soltanto (`X509:<S>...`)

Stessa logica dello Scenario C, ma con un mapping ancora più permissivo (solo il Subject, senza Issuer).

**Victim:** stessi requisiti dello Scenario C (cn/name o dNSHostName controllabili).

**Template:** stessi requisiti dello Scenario C.

### Passaggi

```bash
Certify.exe request /template:MachineNoSec /machine
```

Autenticazione via PKINIT in modalità compatibile, o — più realisticamente oggi — da verificare via Schannel con gli stessi vincoli dello Scenario C.

### Se non funziona

Stesse cause dello Scenario C: verifica prima lo stato di enforcement del DC (quasi sempre la causa reale su ambienti aggiornati) prima di sospettare un errore nei tuoi comandi.

***

# Matrice di compatibilità (aggiornata a oggi)

| Scenario                            | Via PKINIT (Kerberos)                                     | Via Schannel                                                        |
| ----------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------- |
| A — mapping scritto dall'attaccante | ✅ Funziona anche con Full Enforcement                     | ✅ (serve S4U2Self, default attivo)                                  |
| B — mapping email debole            | ❌ Bloccato dal Full Enforcement permanente (dal 9/9/2025) | Possibile solo se Schannel ha un mapping debole configurato a parte |
| C — mapping issuer+subject          | ❌ Bloccato dal Full Enforcement permanente                | Possibile solo col flag Subject/Issuer (`0x1`), non default         |
| D — mapping subject soltanto        | ❌ Bloccato dal Full Enforcement permanente                | Come C                                                              |

In pratica: su un dominio con i DC aggiornati, **lo Scenario A è quello su cui vale davvero la pena concentrarsi** in un pentest — gli altri tre dipendono da configurazioni di compatibilità che Microsoft ha eliminato come default.

***

# Identificazione

Occhio: cercare solo tra gli utenti si perde metà del problema, perché anche i computer possono avere `altSecurityIdentities` valorizzato.

### PowerShell — utenti e computer

```powershell
Get-ADObject -LDAPFilter "(altSecurityIdentities=*)" `
  -SearchBase "DC=corp,DC=local" `
  -Properties altSecurityIdentities,objectClass |
  Select-Object objectClass,DistinguishedName,altSecurityIdentities
```

### LDAP

```
(altSecurityIdentities=*)
```

Questo è solo il primo passo: trovati gli oggetti con l'attributo popolato, vanno classificati i mapping (debole/forte dalla tabella sopra) e va data priorità agli account Tier-0 e privilegiati.

Certipy **non copre ESC14**: non enumera `altSecurityIdentities` e non ha comandi dedicati a scriverlo o abusarlo — compare solo per l'autenticazione finale via Schannel (`-ldap-shell`), non per il resto del flusso.

Un certificato autofirmato **non** è un'opzione universalmente valida per nessuno di questi scenari: deve comunque rispettare i requisiti di trust e gli EKU dell'ambiente — avere il Subject giusto da solo non basta se la catena di fiducia non regge.

***

# Detection

| Controllo                                    | Obiettivo                                                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `altSecurityIdentities` su utenti E computer | Trovare mapping deboli su account privilegiati                                                                |
| ACL sull'attributo                           | Chi può scriverlo su ciascun target                                                                           |
| Attributi `mail`, `cn`, `dNSHostName`        | Capire su quali account un attaccante potrebbe avere controllo sufficiente a costruire un mapping compatibile |
| Certificate template                         | Enroll, EKU, campi Subject/SAN richiesti                                                                      |
| Log Domain Controller                        | Autenticazioni rifiutate per assenza di mapping forte                                                         |
| Log modifica AD                              | Correlare modifiche ad `altSecurityIdentities` con certificati emessi e autenticazioni successive             |

Due eventi Windows utili, con i loro limiti:

* **5136** — modifica a un oggetto AD, utile per beccare un cambio di `altSecurityIdentities`, se l'auditing è configurato;
* **39** — associato ai casi in cui il KDC non trova un mapping forte per un'autenticazione via certificato.

Nessuno dei due, da solo, copre tutti e quattro gli scenari: vanno correlati tra loro e con l'enumerazione periodica dell'attributo.

***

# Mitigation

* usa sempre mapping **forti** (`<SR>`, `<SKI>`, `<SHA1-PUKEY>`), mai basati su nome o email;
* verifica chi ha **permessi di scrittura** su `altSecurityIdentities` per ogni account privilegiato — è il prerequisito reale dello Scenario A, il più pericoloso oggi;
* rimuovi i mapping deboli non strettamente necessari, specialmente su account Tier-0;
* se sospetti una compromissione: oltre a correggere il mapping, verifica i certificati ottenuti nel periodo sospetto, le autenticazioni effettuate con essi, e l'eventuale persistenza tramite un mapping esplicito aggiunto senza autorizzazione.

***

# FAQ — ESC14 ADCS

### Cos'è ESC14?

Un abuso dell'attributo `altSecurityIdentities`, che si articola in quattro scenari distinti (A-D) con prerequisiti diversi, non una singola tecnica.

### Qual è la differenza tra ESC14-A e gli altri?

ESC14-A richiede di poter **scrivere** il mapping del target — e funziona anche con strong certificate binding attivo. B, C e D sfruttano mapping **già deboli** preesistenti, e dipendono dal comportamento di compatibilità del KDC o di Schannel.

### ESC14 è sfruttabile con Full Enforcement attivo?

Lo Scenario A sì. Gli scenari B, C, D via Kerberos/PKINIT no, dal momento che il Compatibility Mode è stato rimosso in modo permanente dal 9 settembre 2025 — restano teoricamente percorribili solo via Schannel, e solo se quel servizio ha una propria configurazione debole.

### Serve compromettere la CA per fare ESC14?

No. Basta ottenere un certificato legittimo che soddisfi il mapping — il problema è nel mapping, non nella CA.

***

Per il quadro completo delle escalation vedi la [guida ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/). Continua con [ESC15](https://hackita.it/articoli/esc15-adcs/) (EKUwu, CVE-2024-49019) o [ESC16](https://hackita.it/articoli/esc16-adcs/).

Ricerca originale di riferimento: [ADCS ESC14 Abuse Technique — SpecterOps](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/). Tool usati in questa guida: Certify, Rubeus, [Certipy](https://github.com/ly4k/Certipy).
