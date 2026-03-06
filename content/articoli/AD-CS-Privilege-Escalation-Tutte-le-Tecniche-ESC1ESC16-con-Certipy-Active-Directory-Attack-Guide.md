---
title: 'AD CS Privilege Escalation: Tutte le Tecniche ESC1–ESC16 con Certipy (Active Directory Attack Guide)'
slug: adcs-esc1-esc16
description: 'AD CS Privilege Escalation su Active Directory: guida completa alle tecniche ESC1–ESC16 con Certipy. Scopri come ottenere Domain Admin sfruttando certificate template e CA misconfigurate.'
image: /Copilot_20260304_203545.webp
draft: false
date: 2026-03-06T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ad
  - adcs
  - esc
  - certipy
---

Active Directory Certificate Services (**AD CS**) è uno dei vettori più potenti di **privilege escalation in Active Directory**. Una singola misconfiguration nei certificate template o nella Certificate Authority può permettere a un utente di dominio di autenticarsi come **Domain Admin** — spesso con un solo comando.

Le tecniche **ESC1–ESC16** sfruttano errori di configurazione nei template di certificato, nella CA e nel certificate mapping dei Domain Controller. In molti ambienti aziendali queste debolezze restano presenti per anni senza essere auditate, rendendo AD CS una delle superfici di attacco più efficaci nei penetration test interni.

Questa guida raccoglie **tutte le tecniche AD CS ESC1–ESC16** con spiegazioni operative, impatto reale e comandi usati nei pentest. Ogni tecnica ha una guida dedicata con exploitation tramite [Certipy](https://hackita.it/articoli/certipy), condizioni di vulnerabilità e mitigazioni. Qui trovi la panoramica completa degli attacchi AD CS su [Active Directory](https://hackita.it/articoli/active-directory).

## AD CS Privilege Escalation: Quick Start Con Certipy

Tre comandi. Da utente standard a Domain Admin in meno di 60 secondi.

**1 — Trova i template vulnerabili**

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

**2 — Richiedi certificato come Administrator**

```bash
certipy req -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -target CA.CORP.LOCAL -ca 'CORP-CA' -template 'VulnTemplate' -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
```

**3 — Autenticati e ottieni TGT + NT hash**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip 10.0.0.100
```

Questo è [ESC1](https://hackita.it/articoli/esc1-adcs) — il certificate attack più comune. Le altre 15 tecniche ESC hanno percorsi diversi, ma lo stesso risultato finale: **privileged access nel dominio**.

***

## Cos'è AD CS e Perché È Vulnerabile Ai Certificate Attack

Active Directory Certificate Services è il ruolo Windows Server che gestisce la PKI aziendale: emette certificati digitali usati per autenticazione, firma e crittografia. In un dominio [Active Directory](https://hackita.it/articoli/active-directory), i certificati possono essere usati per autenticarsi via [Kerberos](https://hackita.it/articoli/kerberos) PKINIT — chi possiede un certificato valido per un utente può ottenerne il **TGT** e spesso anche il **NT hash**. Questo meccanismo di certificate-based authentication è alla base di ogni AD CS attack.

Il problema è che molte installazioni di AD CS vengono configurate con impostazioni troppo permissive: template con enrollment aperto a **Domain Users**, Subject Alternative Name specificabile dall'utente, EKU troppo ampi, web enrollment senza protezioni, flag CA pericolosi, mapping deboli sui Domain Controller. Ogni misconfiguration può diventare un percorso diretto verso **Domain Admin**.

Fino al 2021 quasi nessuno testava AD CS nei pentest interni. Oggi è una delle superfici di attacco più studiate e più produttive nella ricerca offensiva su Active Directory.

***

## Cosa Sono Le ESC (AD CS Escalation Techniques)

Le **ESC** sono 16 tecniche di Active Directory Privilege Escalation documentate che sfruttano misconfiguration o vulnerabilità in AD CS. Ogni ESC colpisce un livello diverso della PKI:

* **Template di certificato** → ESC1–4, ESC9, ESC13, ESC15
* **Certificate Authority** → ESC5–8, ESC11–12, ESC16
* **Domain Controller / certificate mapping** → ESC10, ESC14

L'impatto resta quasi sempre lo stesso: un utente con bassi privilegi ottiene un certificato che gli permette di autenticarsi come **Domain Admin** o come qualsiasi altro utente del dominio. Alcune ESC richiedono prerequisiti come **GenericWrite**, accesso alla CA o coercion NTLM; altre funzionano con un semplice account di dominio.

In pratica ogni certificate attack segue la stessa logica:

**ottenere un certificato valido → autenticarsi come un utente privilegiato → compromettere il dominio**

### Mappa rapida ESC1–ESC16

| ESC   | Tipo                                   | Livello  |
| ----- | -------------------------------------- | -------- |
| ESC1  | Enrollee supplies subject + auth EKU   | Template |
| ESC2  | Any Purpose / no EKU                   | Template |
| ESC3  | Enrollment Agent abuse                 | Template |
| ESC4  | Template hijacking                     | Template |
| ESC5  | PKI object ACL abuse                   | CA / PKI |
| ESC6  | SAN arbitrari via CA flag              | CA       |
| ESC7  | Dangerous permissions on CA            | CA       |
| ESC8  | NTLM relay a web enrollment            | CA       |
| ESC9  | No security extension                  | Template |
| ESC10 | Weak certificate mapping               | DC       |
| ESC11 | NTLM relay a RPC                       | CA       |
| ESC12 | YubiHSM2 / CA key abuse                | CA       |
| ESC13 | Issuance policy linked to group        | Template |
| ESC14 | Weak explicit certificate mapping      | DC       |
| ESC15 | Arbitrary application policy injection | Template |
| ESC16 | Security extension disabled CA-wide    | CA       |

***

## Tool Principali Per AD CS Exploitation

### Certipy

Tool Python per Linux/Kali di Oliver Lyak. Supporta tutte e 16 le ESC: enumeration, exploitation, relay, shadow credentials, certificate forging, LDAP shell. È lo standard per ogni AD CS attack nei pentest.

👉 [Certipy guida completa](https://hackita.it/articoli/certipy)

### Certify

Tool C#/.NET di SpecterOps per ambienti Windows. Supporta enumeration e exploitation delle tecniche classiche, soprattutto ESC1–8. Non copre bene gli scenari più recenti come ESC15/ESC16. Utile quando Python non è disponibile nel contesto dell'AD CS exploitation.

👉 [Certify guida completa](https://hackita.it/articoli/certify)

### Rubeus

Tool C# per Kerberos ticket manipulation. Non attacca AD CS direttamente, ma è essenziale per la fase di autenticazione PKINIT e post-exploitation quando si lavora da Windows.

👉 [Rubeus guida completa](https://hackita.it/articoli/rubeus)

***

## Tutte Le Tecniche ESC: Da ESC1 a ESC16

### ESC1 — Enrollee Supplies Subject

Il template permette all'utente di specificare il Subject Alternative Name (SAN) con un EKU di autenticazione. Qualsiasi utente di dominio può richiedere un certificato come Administrator. È la tecnica più diretta e più frequente nei pentest.

👉 [ESC1 ADCS guida completa](https://hackita.it/articoli/esc1-adcs)

### ESC2 — Any Purpose / No EKU

Il template ha EKU **Any Purpose** o nessun EKU definito. Il certificato può funzionare come Enrollment Agent e aprire la catena **on-behalf-of** per richiedere certificati come qualsiasi utente. Spesso viene chainato con [ESC3](https://hackita.it/articoli/esc3-adcs).

👉 [ESC2 ADCS guida completa](https://hackita.it/articoli/esc2-adcs)

### ESC3 — Enrollment Agent Abuse

Un template con EKU **Certificate Request Agent** permette richieste on-behalf-of. Due passaggi: ottenere l'Enrollment Agent e poi richiedere un certificato come utente privilegiato. È la versione esplicita della logica vista in [ESC2](https://hackita.it/articoli/esc2-adcs).

👉 [ESC3 ADCS guida completa](https://hackita.it/articoli/esc3-adcs)

### ESC4 — Template Hijacking (ACL Abuse)

L'attaccante ha permessi di scrittura su un oggetto template AD. Modifica il template, lo trasforma in un ESC1, lo sfrutta e poi lo ripristina. Certipy automatizza quasi tutta la catena.

👉 [ESC4 ADCS guida completa](https://hackita.it/articoli/esc4-adcs)

### ESC5 — PKI Object ACL Abuse

ACL deboli sugli oggetti PKI nel Configuration Naming Context: **NTAuthCertificates**, container **AIA/CDP**, oggetti OID, trust PKI e computer account della CA. È una tecnica più rara ma molto più strategica, perché può portare al controllo persistente della PKI del dominio.

👉 [ESC5 ADCS guida completa](https://hackita.it/articoli/esc5-adcs)

### ESC6 — EDITF\_ATTRIBUTESUBJECTALTNAME2

Un flag a livello CA che permette SAN arbitrari in qualsiasi richiesta. Dopo le patch del 2022 da solo non basta più sui DC patchati, ma combinato con [ESC9](https://hackita.it/articoli/esc9-adcs) o [ESC16](https://hackita.it/articoli/esc16-adcs) torna a essere molto potente.

👉 [ESC6 ADCS guida completa](https://hackita.it/articoli/esc6-adcs)

### ESC7 — ManageCA Permission Abuse

Chi ha il permesso **ManageCA** sulla CA può aggiungersi come officer, abilitare template sensibili, approvare richieste e forzare emissioni di certificati privilegiati. È una compromissione diretta della Certificate Authority.

👉 [ESC7 ADCS guida completa](https://hackita.it/articoli/esc7-adcs)

### ESC8 — NTLM Relay a Web Enrollment

Il web enrollment della CA accetta NTLM senza **EPA**. Un attaccante forza un DC o un utente privilegiato ad autenticarsi, relaya verso il web enrollment e ottiene un certificato come vittima. Storicamente una delle tecniche più impattanti. Se il web enrollment non è esposto, prova [ESC11](https://hackita.it/articoli/esc11-adcs) via RPC.

👉 [ESC8 ADCS guida completa](https://hackita.it/articoli/esc8-adcs)

### ESC9 — No Security Extension

Il template ha il flag `CT_FLAG_NO_SECURITY_EXTENSION`: il certificato non contiene il SID dell'utente. Combinato con manipolazione UPN e mapping deboli, permette impersonation. È la variante template-level di [ESC16](https://hackita.it/articoli/esc16-adcs).

👉 [ESC9 ADCS guida completa](https://hackita.it/articoli/esc9-adcs)

### ESC10 — Weak Certificate Mapping (Registry)

La debolezza è nel registry dei DC, non nel template. `StrongCertificateBindingEnforcement = 0` per Kerberos o `CertificateMappingMethods` con UPN bit per Schannel possono rendere sfruttabili certificati apparentemente innocui.

👉 [ESC10 ADCS guida completa](https://hackita.it/articoli/esc10-adcs)

### ESC11 — NTLM Relay a RPC (MS-ICPR)

Come [ESC8](https://hackita.it/articoli/esc8-adcs), ma verso l'interfaccia RPC della CA. Se il flag `IF_ENFORCEENCRYPTICERTREQUEST` non è attivo, il relay può funzionare e portare allo stesso risultato: certificato come DC o come altro account privilegiato.

👉 [ESC11 ADCS guida completa](https://hackita.it/articoli/esc11-adcs)

### ESC12 — YubiHSM2 Key Leak

Scenario specifico in cui una CA protetta da YubiHSM2 può comunque essere abusata in presenza di una vulnerabilità o di una debole integrazione software sul server CA. Se la chiave CA viene esposta o usata in modo improprio, si arriva al **Golden Certificate**.

👉 [ESC12 ADCS guida completa](https://hackita.it/articoli/esc12-adcs)

### ESC13 — OID-to-Group Link

Un template include una issuance policy il cui oggetto OID in AD punta a un gruppo privilegiato. Chiunque si autentichi con un certificato di quel template riceve il SID del gruppo nel PAC senza esserne membro. Privilege escalation estremamente elegante e spesso sottovalutata.

👉 [ESC13 ADCS guida completa](https://hackita.it/articoli/esc13-adcs)

### ESC14 — Weak altSecurityIdentities Mapping

Mapping deboli nell'attributo `altSecurityIdentities` permettono di associare certificati a utenti privilegiati tramite valori troppo generici o facilmente replicabili. È una forma di explicit certificate mapping abuse.

👉 [ESC14 ADCS guida completa](https://hackita.it/articoli/esc14-adcs)

### ESC15 — EKUwu (CVE-2024-49019)

I template **Schema V1** su CA non patchate permettono di iniettare **Application Policies** arbitrarie nel certificato. In pratica l'attaccante aggiunge EKU che il template non dovrebbe concedere, come **Client Authentication** o **Certificate Request Agent**.

👉 [ESC15 ADCS guida completa](https://hackita.it/articoli/esc15-adcs)

### ESC16 — Security Extension Disabled CA-Wide

La CA disabilita globalmente la SID security extension in tutti i certificati tramite `DisableExtensionList`. È la versione CA-wide di [ESC9](https://hackita.it/articoli/esc9-adcs): qualsiasi template emesso da quella CA torna a usare mapping legacy.

👉 [ESC16 ADCS guida completa](https://hackita.it/articoli/esc16-adcs)

***

## Enumerazione AD CS Con Certipy

Il primo passo in ogni pentest AD CS è l'enumerazione. Un singolo comando [Certipy](https://hackita.it/articoli/certipy) identifica gran parte delle ESC presenti nell'ambiente:

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Certipy interroga LDAP per estrarre template, CA, permessi, issuance policies e configurazioni note, poi le confronta con le condizioni di exploit delle tecniche AD CS più comuni.

Rileva automaticamente soprattutto:

* [ESC1](https://hackita.it/articoli/esc1-adcs)
* [ESC2](https://hackita.it/articoli/esc2-adcs)
* [ESC3](https://hackita.it/articoli/esc3-adcs)
* [ESC4](https://hackita.it/articoli/esc4-adcs)
* [ESC6](https://hackita.it/articoli/esc6-adcs)
* [ESC7](https://hackita.it/articoli/esc7-adcs)
* [ESC8](https://hackita.it/articoli/esc8-adcs)
* [ESC9](https://hackita.it/articoli/esc9-adcs)
* [ESC11](https://hackita.it/articoli/esc11-adcs)
* [ESC13](https://hackita.it/articoli/esc13-adcs)
* [ESC15](https://hackita.it/articoli/esc15-adcs)
* [ESC16](https://hackita.it/articoli/esc16-adcs)

Le ESC non rilevate automaticamente — come [ESC5](https://hackita.it/articoli/esc5-adcs), [ESC10](https://hackita.it/articoli/esc10-adcs), [ESC12](https://hackita.it/articoli/esc12-adcs) e [ESC14](https://hackita.it/articoli/esc14-adcs) — richiedono invece audit manuali su registry, ACL PKI, `altSecurityIdentities` o sicurezza del server CA.

***

## Catena Di Attacco AD CS Reale: Da Utente Standard a Domain Admin

Un pentest AD CS tipico segue questa progressione:

**Enumeration** → `certipy find -vulnerable` identifica un template [ESC1](https://hackita.it/articoli/esc1-adcs) con enrollment aperto a Domain Users.

**Exploitation** → `certipy req -upn administrator@corp.local -sid S-1-5-21-...-500` richiede un certificato come Administrator.

**Authentication** → `certipy auth -pfx administrator.pfx` esegue PKINIT e restituisce il TGT + NT hash di Administrator.

**Domain Dominance** → con l'NT hash di Administrator si esegue DCSync per estrarre tutte le credenziali del dominio, incluso l'hash di `krbtgt` per un Golden Ticket.

Tempo totale: spesso meno di 60 secondi tra il primo comando e la compromissione amministrativa. Nessun exploit software, nessun memory corruption, nessun RCE tradizionale. Solo una misconfiguration PKI.

Nei casi più complessi, le ESC si concatenano:

* [ESC4](https://hackita.it/articoli/esc4-adcs) → [ESC1](https://hackita.it/articoli/esc1-adcs)
* coercion NTLM → [ESC8](https://hackita.it/articoli/esc8-adcs) → certificato DC → DCSync
* [ESC6](https://hackita.it/articoli/esc6-adcs) + [ESC9](https://hackita.it/articoli/esc9-adcs)
* [ESC6](https://hackita.it/articoli/esc6-adcs) + [ESC16](https://hackita.it/articoli/esc16-adcs)
* [ESC2](https://hackita.it/articoli/esc2-adcs) → [ESC3](https://hackita.it/articoli/esc3-adcs)

È qui che AD CS diventa davvero pericoloso: non una singola vulnerabilità, ma una **superficie di attacco componibile**.

***

## FAQ — AD CS Privilege Escalation

### Cosa sono le ESC in Active Directory?

Le ESC sono 16 tecniche di Active Directory Privilege Escalation che sfruttano misconfiguration in Active Directory Certificate Services. Ogni ESC colpisce un aspetto diverso della PKI: template, CA o configurazione dei Domain Controller. Tutte possono portare a certificate abuse e dominio compromesso.

### Qual è la ESC più comune nei pentest?

[ESC1](https://hackita.it/articoli/esc1-adcs) è la più frequente: template con **Supply in the request** + EKU di autenticazione + enrollment aperto. Subito dopo arrivano spesso [ESC8](https://hackita.it/articoli/esc8-adcs) e [ESC4](https://hackita.it/articoli/esc4-adcs).

### Serve Certipy per sfruttare le ESC?

[Certipy](https://hackita.it/articoli/certipy) è lo strumento più completo per AD CS exploitation: enumeration, req, auth, relay, forge, shadow credentials, LDAP shell. In ambienti Windows si può lavorare anche con [Certify](https://hackita.it/articoli/certify) e [Rubeus](https://hackita.it/articoli/rubeus), ma per il panorama moderno AD CS Certipy resta il riferimento.

### Le ESC sono comuni nei pentest reali?

Sì. Le configurazioni AD CS sono spesso legacy, poco documentate e raramente auditate. Per questo AD CS è ormai parte standard di ogni pentest interno serio su Active Directory.

### Come proteggersi da tutte le ESC?

Tre livelli:

* **Template** → disabilita "Supply in the request", restringi enrollment, evita EKU permissivi, riduci V1
* **CA** → rimuovi flag pericolosi, abilita EPA, non disabilitare SID security extension, proteggi i permessi
* **DC** → imposta `StrongCertificateBindingEnforcement = 2`, usa mapping forti, controlla Schannel e `altSecurityIdentities`

Esegui `certipy find -vulnerable` regolarmente e tratta la CA come asset **Tier-0**.

### Qual è la differenza tra ESC a livello template e ESC a livello CA?

Le ESC template ([ESC1](https://hackita.it/articoli/esc1-adcs), [ESC2](https://hackita.it/articoli/esc2-adcs), [ESC3](https://hackita.it/articoli/esc3-adcs), [ESC4](https://hackita.it/articoli/esc4-adcs), [ESC9](https://hackita.it/articoli/esc9-adcs), [ESC13](https://hackita.it/articoli/esc13-adcs), [ESC15](https://hackita.it/articoli/esc15-adcs)) sfruttano configurazioni del singolo template.
Le ESC CA ([ESC5](https://hackita.it/articoli/esc5-adcs), [ESC6](https://hackita.it/articoli/esc6-adcs), [ESC7](https://hackita.it/articoli/esc7-adcs), [ESC8](https://hackita.it/articoli/esc8-adcs), [ESC11](https://hackita.it/articoli/esc11-adcs), [ESC12](https://hackita.it/articoli/esc12-adcs), [ESC16](https://hackita.it/articoli/esc16-adcs)) sfruttano la CA o la PKI forest-wide.
Le ESC DC ([ESC10](https://hackita.it/articoli/esc10-adcs), [ESC14](https://hackita.it/articoli/esc14-adcs)) sfruttano mapping e autenticazione lato controller di dominio.

***

## Riassunto: AD CS Privilege Escalation in 5 Punti

**AD CS è uno dei vettori più efficaci di Active Directory Privilege Escalation** — 16 tecniche documentate, molte delle quali portano direttamente a Domain Admin.

**Certipy copre gran parte dell’intero ciclo di attacco AD CS** — enumeration, exploitation, authentication, relay, forging e post-exploitation.

**Le ESC non sono tutte uguali** — alcune dipendono dai template, altre dalla CA, altre dal mapping sui Domain Controller.

**Il rischio reale non è solo la singola tecnica, ma la concatenazione** — ESC4 → ESC1, ESC6 + ESC9, ESC6 + ESC16, ESC2 → ESC3, ESC8 → dominio.

**La misura difensiva più importante lato DC resta `StrongCertificateBindingEnforcement = 2`** — ma da sola non basta se template, CA e mapping restano deboli.

***

> AD CS è una delle superfici di **certificate attack più produttive nei pentest Active Directory**. Se questo contenuto ti è utile puoi supportare il progetto su [Supporta HackIta](https://hackita.it/supporto).
> Vuoi imparare **Active Directory exploitation e offensive security 1:1**? Vai su [Servizi HackIta](https://hackita.it/servizi).
> Se invece vuoi **testare la sicurezza del tuo sito web o della tua infrastruttura aziendale**, richiedi un [penetration test](https://hackita.it/servizi).Continua con le guide operative:
> [ESC1](https://hackita.it/articoli/esc1-adcs) · [ESC8](https://hackita.it/articoli/esc8-adcs) · [ESC15](https://hackita.it/articoli/esc15-adcs) · [Certipy](https://hackita.it/articoli/certipy) · [Active Directory pentesting](https://hackita.it/articoli/active-directory)Riferimenti tecnici:
> [Certified Pre-Owned – SpecterOps](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
> [Certipy – GitHub](https://github.com/ly4k/Certipy)
> [Microsoft AD CS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)

```
```
