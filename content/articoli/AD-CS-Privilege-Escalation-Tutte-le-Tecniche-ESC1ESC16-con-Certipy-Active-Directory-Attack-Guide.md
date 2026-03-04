---
title: 'AD CS Privilege Escalation: Tutte le Tecniche ESC1–ESC16 con Certipy (Active Directory Attack Guide)'
slug: adcs-esc1-esc16
description: 'AD CS Privilege Escalation su Active Directory: guida completa alle tecniche ESC1–ESC16 con Certipy. Scopri come ottenere Domain Admin sfruttando certificate template e CA misconfigurate.'
image: /Copilot_20260304_203545.webp
draft: true
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

Active Directory Certificate Services (**AD CS)** è uno dei vettori più potenti di **privilege escalation** in Active Directory. Una singola misconfiguration nei certificate template o nella Certificate Authority può permettere a un utente di dominio di autenticarsi come Domain Admin — spesso con un solo comando.

Le tecniche ESC (Escalation) da ESC1 a ESC16 sfruttano errori di configurazione nei template di certificato, nella CA e nel certificate mapping dei Domain Controller. In molti ambienti aziendali queste configurazioni sono presenti senza che nessuno le controlli, rendendo AD CS una delle superfici di attacco più efficaci nei penetration test interni.

#### Questa guida raccoglie **tutte le tecniche AD CS ESC1–ESC16** con spiegazioni operative e comandi reali. Ogni tecnica ha una guida dedicata con exploitation tramite [Certipy](https://hackita.it/articoli/certipy), condizioni di vulnerabilità e mitigazioni. Qui trovi la panoramica completa degli attacchi AD CS su Active Directory.

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

Questo è [ESC1](https://hackita.it/articoli/esc1-adcs) — il certificate attack più comune. Le altre 15 tecniche ESC hanno percorsi diversi ma lo stesso risultato: Domain Admin.

***

## Cos'è AD CS e Perché È Vulnerabile Ai Certificate Attack

Active Directory Certificate Services è il ruolo Windows Server che gestisce la PKI aziendale: emette certificati digitali usati per autenticazione, firma, crittografia. In un dominio [Active Directory](https://hackita.it/articoli/active-directory), i certificati possono essere usati per autenticarsi via [Kerberos](https://hackita.it/articoli/kerberos) PKINIT — chi ha un certificato valido per un utente ottiene il suo TGT e il suo NT hash. Questo meccanismo di certificate-based authentication è alla base di ogni AD CS attack.

Il problema: le configurazioni di default di AD CS sono permissive. Template con enrollment aperto a Domain Users, Subject Alternative Name specificabile dall'utente, EKU troppo ampi, web enrollment senza protezioni. Ogni misconfiguration è un percorso diretto verso Domain Admin attraverso AD CS exploitation. Fino al 2021, quasi nessuno testava AD CS nei pentest. Oggi è la superficie di attacco più attiva nella ricerca offensiva su Active Directory.

***

## Cosa Sono Le ESC (AD CS Escalation Techniques)

Le ESC sono 16 tecniche di Active Directory Privilege Escalation documentate che sfruttano misconfiguration o vulnerabilità in AD CS. Ogni ESC colpisce un livello diverso: template di certificato (ESC1–4, ESC9, ESC13, ESC15), Certificate Authority (ESC5–8, ESC11–12, ESC16), o configurazione dei Domain Controller (ESC10, ESC14).

L'impatto è sempre lo stesso: un utente con bassi privilegi ottiene un certificato che gli permette di autenticarsi come Domain Admin — o qualsiasi altro utente del dominio. Alcune ESC richiedono prerequisiti (GenericWrite, accesso alla CA), altre funzionano con un semplice account di dominio. Ogni certificate-based authentication attack segue la stessa logica: richiedere un certificato → autenticarsi come un utente privilegiato → compromettere il dominio.

***

## Tool Principali Per AD CS Exploitation

### Certipy

Tool Python per Linux/Kali di Oliver Lyak. Supporta tutte e 16 le ESC: enumeration, exploitation, relay, shadow credentials, certificate forging, LDAP shell. È lo standard per ogni AD CS attack nei pentest.

👉 [Certipy guida completa](https://hackita.it/articoli/certipy)

### Certify

Tool C#/.NET di SpecterOps per ambienti Windows. Enumeration e exploitation di ESC1–8. Non supporta relay, forging, ESC15/ESC16. Utile quando Python non è disponibile nel contesto dell'AD CS exploitation.

👉 [Certify guida completa](https://hackita.it/articoli/certify)

### Rubeus

Tool C# per Kerberos ticket manipulation. Non attacca AD CS direttamente, ma è essenziale per l'autenticazione PKINIT dopo aver ottenuto un certificato con Certify su Windows — completa la catena del certificate attack.

👉 [Rubeus guida completa](https://hackita.it/articoli/rubeus)

***

## Tutte Le Tecniche ESC: Da ESC1 a ESC16

### ESC1 — Enrollee Supplies Subject

Il template permette all'utente di specificare il Subject Alternative Name (SAN) con un EKU di autenticazione. Qualsiasi utente di dominio richiede un certificato come Administrator. La ESC più comune e più diretta — un singolo certificate attack per Domain Admin.

👉 [ESC1 ADCS guida completa](https://hackita.it/articoli/esc1-adcs)

### ESC2 — Any Purpose / No EKU

Il template ha EKU "Any Purpose" o nessun EKU definito. Il certificato funziona come Enrollment Agent, aprendo la catena on-behalf-of per richiedere certificati come qualsiasi utente. Spesso chainato con [ESC3](https://hackita.it/articoli/esc3-adcs) per completare l'AD CS exploitation.

👉 [ESC2 ADCS guida completa](https://hackita.it/articoli/esc2-adcs)

### ESC3 — Enrollment Agent Abuse

Un template con EKU "Certificate Request Agent" permette richieste on-behalf-of. Due passaggi: ottenere l'Enrollment Agent, poi richiedere un certificato come Domain Admin. È la catena naturale dopo [ESC2](https://hackita.it/articoli/esc2-adcs).

👉 [ESC3 ADCS guida completa](https://hackita.it/articoli/esc3-adcs)

### ESC4 — Template Hijacking (ACL Abuse)

L'attaccante ha permessi di scrittura su un oggetto template AD. Riscrive il template rendendolo vulnerabile a [ESC1](https://hackita.it/articoli/esc1-adcs), lo sfrutta, e lo ripristina. Certipy automatizza l'intera catena di AD CS attack.

👉 [ESC4 ADCS guida completa](https://hackita.it/articoli/esc4-adcs)

### ESC5 — PKI Object ACL Abuse

ACL deboli sugli oggetti PKI nel Configuration Naming Context: NTAuthCertificates, container AIA/CDP, oggetti OID, computer account della CA. La compromissione della CA porta al Golden Certificate — la forma più persistente di certificate-based authentication attack.

👉 [ESC5 ADCS guida completa](https://hackita.it/articoli/esc5-adcs)

### ESC6 — EDITF\_ATTRIBUTESUBJECTALTNAME2

Un flag a livello CA che permette SAN arbitrari in qualsiasi richiesta. Dopo la patch di maggio 2022 va combinato con [ESC9](https://hackita.it/articoli/esc9-adcs) o [ESC16](https://hackita.it/articoli/esc16-adcs) per funzionare su DC patchati.

👉 [ESC6 ADCS guida completa](https://hackita.it/articoli/esc6-adcs)

### ESC7 — ManageCA Permission Abuse

Chi ha il permesso ManageCA sulla CA può aggiungersi come officer, abilitare il template SubCA (presente su ogni CA), richiedere un certificato negato, e approvarselo. Sei step di AD CS exploitation per Domain Admin.

👉 [ESC7 ADCS guida completa](https://hackita.it/articoli/esc7-adcs)

### ESC8 — NTLM Relay a Web Enrollment

Il web enrollment della CA accetta NTLM senza EPA. Un attaccante forza un DC ad autenticarsi (PetitPotam), relaya verso il web enrollment, ottiene un certificato come DC → DCSync → dominio compromesso. Il certificate attack che ha fatto storia. Se il web enrollment non è esposto, prova [ESC11](https://hackita.it/articoli/esc11-adcs) via RPC.

👉 [ESC8 ADCS guida completa](https://hackita.it/articoli/esc8-adcs)

### ESC9 — No Security Extension

Il template ha il flag `CT_FLAG_NO_SECURITY_EXTENSION`: il certificato non contiene il SID dell'utente. Combinato con manipolazione UPN e weak certificate mapping, permette impersonation di qualsiasi utente. Variante template-level di [ESC16](https://hackita.it/articoli/esc16-adcs).

👉 [ESC9 ADCS guida completa](https://hackita.it/articoli/esc9-adcs)

### ESC10 — Weak Certificate Mapping (Registry)

La debolezza è nel registry dei DC, non nel template. `StrongCertificateBindingEnforcement = 0` (Kerberos) o `CertificateMappingMethods` con UPN bit (Schannel). Qualsiasi template con Client Authentication diventa sfruttabile per un certificate-based authentication attack.

👉 [ESC10 ADCS guida completa](https://hackita.it/articoli/esc10-adcs)

### ESC11 — NTLM Relay a RPC (MS-ICPR)

Come [ESC8](https://hackita.it/articoli/esc8-adcs) ma verso l'interfaccia RPC della CA. Se il flag `IF_ENFORCEENCRYPTICERTREQUEST` non è attivo, il relay funziona. Stesso risultato: certificato come DC.

👉 [ESC11 ADCS guida completa](https://hackita.it/articoli/esc11-adcs)

### ESC12 — YubiHSM2 Key Leak

La CA usa YubiHSM2 e la password dell'HSM è in chiaro nel registry Windows. Shell sul server CA → password → chiave privata CA → Golden Certificate. Come [ESC5](https://hackita.it/articoli/esc5-adcs), porta a persistenza indefinita.

👉 [ESC12 ADCS guida completa](https://hackita.it/articoli/esc12-adcs)

### ESC13 — OID-to-Group Link

Un template ha una issuance policy il cui oggetto OID in AD punta a un gruppo privilegiato. Chiunque si autentichi con un certificato di quel template riceve il SID del gruppo nel PAC — senza essere membro. Active Directory Privilege Escalation senza cambiare identità.

👉 [ESC13 ADCS guida completa](https://hackita.it/articoli/esc13-adcs)

### ESC14 — Weak altSecurityIdentities Mapping

Mapping deboli nell'attributo `altSecurityIdentities` (basati su email, subject, issuer+subject). Un attaccante con GenericWrite manipola attributi per matchare il mapping di un account privilegiato. Meccanismo diverso da [ESC9](https://hackita.it/articoli/esc9-adcs), stessa logica di certificate mapping abuse.

👉 [ESC14 ADCS guida completa](https://hackita.it/articoli/esc14-adcs)

### ESC15 — EKUwu (CVE-2024-49019)

I template Schema V1 non hanno l'attributo Application Policy. L'attaccante inietta "Client Authentication" come Application Policy — il DC la onora al posto dell'EKU. Il template WebServer è il target principale di questo AD CS attack.

👉 [ESC15 ADCS guida completa](https://hackita.it/articoli/esc15-adcs)

### ESC16 — Security Extension Disabled CA-Wide

La CA disabilita globalmente la security extension SID in tutti i certificati tramite `DisableExtensionList`. Versione CA-wide di [ESC9](https://hackita.it/articoli/esc9-adcs): ogni template diventa sfruttabile per impersonation via manipolazione UPN. L'ultima tecnica ESC documentata (maggio 2025).

👉 [ESC16 ADCS guida completa](https://hackita.it/articoli/esc16-adcs)

***

## Enumerazione AD CS Con Certipy

Il primo passo in ogni pentest AD CS è l'enumerazione. Un singolo comando [Certipy](https://hackita.it/articoli/certipy) identifica tutte le ESC presenti nell'ambiente:

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Certipy interroga LDAP per estrarre tutti i template, le CA, i permessi, e li analizza contro le condizioni di ogni AD CS attack. L'output mostra esattamente quali template sono vulnerabili, a quale ESC, e perché. Rileva automaticamente ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC9, ESC11, ESC13, ESC15 e ESC16.

Le ESC non rilevate automaticamente (ESC5, ESC10, ESC12, ESC14) richiedono ispezione manuale — registry dei DC, ACL sugli oggetti PKI, o accesso al server CA.

***

## Catena Di Attacco AD CS Reale: Da Utente Standard a Domain Admin

Un pentest AD CS tipico segue questa progressione di Active Directory Privilege Escalation:

**Enumeration** → `certipy find -vulnerable` identifica un template [ESC1](https://hackita.it/articoli/esc1-adcs) con enrollment aperto a Domain Users.

**Exploitation** → `certipy req -upn administrator@corp.local -sid S-1-5-21-...-500` richiede un certificato come Administrator.

**Authentication** → `certipy auth -pfx administrator.pfx` esegue PKINIT e restituisce il TGT + NT hash di Administrator.

**Domain Dominance** → con l'NT hash di Administrator si esegue DCSync per estrarre tutte le credenziali del dominio, incluso l'hash di krbtgt per un Golden Ticket.

Tempo totale: meno di 60 secondi dal primo comando all'ultimo. Nessun exploit. Nessuna vulnerabilità software. Solo una misconfiguration in un template di certificato — un singolo certificate attack per il dominio completo.

Nei casi più complessi, le ESC si concatenano: [ESC4](https://hackita.it/articoli/esc4-adcs) (template hijacking) → [ESC1](https://hackita.it/articoli/esc1-adcs) (SAN abuse), oppure coercizione NTLM → [ESC8](https://hackita.it/articoli/esc8-adcs) (relay) → certificato DC → DCSync. L'AD CS exploitation avanzata combina più tecniche dove una singola non basta.

***

## FAQ — AD CS Privilege Escalation

### Cosa sono le ESC in Active Directory?

Le ESC (Escalation) sono 16 tecniche di Active Directory Privilege Escalation che sfruttano misconfiguration in Active Directory Certificate Services. Ogni ESC colpisce un aspetto diverso della PKI: template, CA, o configurazione dei DC. Tutte portano potenzialmente a Domain Admin attraverso certificate attack.

### Qual è la ESC più comune nei pentest?

[ESC1](https://hackita.it/articoli/esc1-adcs) è la più frequente: template con "Supply in the request" + EKU di autenticazione + enrollment aperto. Presente nella maggior parte degli ambienti enterprise. Subito dopo: [ESC8](https://hackita.it/articoli/esc8-adcs) (NTLM relay al web enrollment) e [ESC4](https://hackita.it/articoli/esc4-adcs) (ACL deboli sui template).

### Serve Certipy per sfruttare le ESC?

[Certipy](https://hackita.it/articoli/certipy) è lo strumento più completo per AD CS exploitation: supporta tutte e 16 le ESC, include relay, forging, shadow credentials e LDAP shell. Su Windows si può usare [Certify](https://hackita.it/articoli/certify) + [Rubeus](https://hackita.it/articoli/rubeus) per le ESC1–8. Per ESC15/ESC16, Certipy è l'unica opzione.

### Le ESC sono comuni nei pentest reali?

Molto comuni. La ricerca SpecterOps stima che oltre l'80% degli ambienti AD con Certificate Services ha almeno una ESC sfruttabile. Il motivo: le configurazioni di default sono permissive e quasi nessuno audita i template di certificato regolarmente. L'AD CS attack è ormai parte standard di ogni pentest interno.

### Come proteggersi da tutte le ESC?

Tre livelli: **template** (disabilita "Supply in the request", restringi enrollment, clona V1 a V2+), **CA** (rimuovi EDITF flag, abilita EPA, non disabilitare la security extension), **DC** (imposta `StrongCertificateBindingEnforcement = 2`, usa solo mapping forti). Esegui `certipy find -vulnerable` regolarmente e tratta la CA come asset Tier-0.

### Qual è la differenza tra ESC a livello template e ESC a livello CA?

Le ESC template (1–4, 9, 13, 15) sfruttano configurazioni di singoli template: EKU, flag, ACL. Le ESC CA (5–8, 11–12, 16) sfruttano la CA stessa: permessi, flag globali, endpoint esposti. Le ESC DC (10, 14) sfruttano il registry e il certificate mapping dei Domain Controller.

***

## Riassunto: AD CS Privilege Escalation in 5 Punti

**AD CS è il vettore di Active Directory Privilege Escalation più efficace nei pentest moderni** — 16 tecniche ESC documentate, ognuna con un percorso reale verso Domain Admin.

**Certipy rileva e sfrutta automaticamente 12 ESC su 16** — un singolo comando di enumerazione mappa l'intera superficie di AD CS attack nell'ambiente.

**L'80%+ degli ambienti con Certificate Services ha almeno una ESC sfruttabile** — le configurazioni di default sono permissive e raramente auditate.

**Le ESC si dividono in tre livelli: template, CA, DC** — la difesa richiede hardening su tutti e tre, non su uno solo.

**La singola azione più efficace è impostare StrongCertificateBindingEnforcement = 2 su tutti i DC** — neutralizza ESC9, ESC10, e ESC16 Scenario A simultaneamente.

***

> AD CS è una delle superfici di **certificate attack più produttive nei pentest Active Directory**. Se questo contenuto ti è utile puoi supportare il progetto su [Supporta HackIta](https://hackita.it/supporto).\
> Vuoi imparare penetration testing **Active Directory e offensive security 1:1**? Vai su [Formazione HackIta](https://hackita.it/servizi).\
> Se invece vuoi **testare la sicurezza del tuo sito web o della tua infrastruttura aziendale**, richiedi un [penetration test](https://hackita.it/servizi).Continua con le guide operative:\
> [ESC1](https://hackita.it/articoli/esc1-adcs) · [ESC8](https://hackita.it/articoli/esc8-adcs) · [ESC15](https://hackita.it/articoli/esc15-adcs) · [Certipy](https://hackita.it/articoli/certipy) · [Active Directory pentesting](https://hackita.it/articoli/active-directory)Riferimenti tecnici:\
> [https://specterops.io/blog/2021/06/17/certified-pre-owned/](https://specterops.io/blog/2021/06/17/certified-pre-owned/)\
> [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)\
> [https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
