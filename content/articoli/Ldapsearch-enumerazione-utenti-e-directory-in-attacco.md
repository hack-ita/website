---
title: 'ldapsearch: Comandi LDAP per Enumerare Utenti, Gruppi e AD'
slug: ldapsearch
description: 'ldapsearch su Kali Linux: RootDSE, Base DN, bind LDAP, utenti, gruppi, computer, SPN, LDAPS e troubleshooting per l''enumerazione di Active Directory.'
image: /LDAPSEARCH.webp
draft: false
date: 2026-01-23T00:00:00.000Z
lastmod: 2026-09-16T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - ldapsearch
  - active directory
---

# ldapsearch: Enumerazione LDAP e Active Directory da Kali Linux

`ldapsearch` è il client CLI di OpenLDAP per interrogare un server LDAP generico. Non è uno strumento "AD" in senso stretto — è un client LDAP puro che, applicato ad Active Directory, permette di leggere Base DN, utenti, gruppi, computer e attributi con un controllo su bind, filtri e scope che i tool AD "opinionated" non danno. In questa guida: RootDSE → bind → search scope → filtri → enumerazione utenti/gruppi/computer/SPN → performance e paging → troubleshooting → confronto con NetExec/BloodHound.

## Cos'è ldapsearch e Dove si Incastra nel Workflow

`ldapsearch` sta bene tra recon e AD enumeration: prima valida raggiungibilità e TLS, poi interroga la RootDSE per capire i naming context, infine esegue query mirate per costruire una mappa di utenti/gruppi/computer. Quando vuoi ragionare in termini di percorsi di attacco (sessioni, ACL, deleghe) piuttosto che di singoli record, il passo successivo naturale è [BloodHound](https://hackita.it/articoli/bloodhound/) — `ldapsearch` resta comunque utile lì come verifica puntuale ("questa OU è visibile con queste credenziali?").

## Installazione e Verifica

```bash
sudo apt update && sudo apt install -y ldap-utils
ldapsearch -VV
```

## Sintassi ldapsearch

```text
ldapsearch [opzioni] -b <base> [-s <scope>] "<filtro>" [attributi]
```

| Opzione | Funzione                                         |
| ------- | ------------------------------------------------ |
| `-H`    | LDAP URI (`ldap://` o `ldaps://`)                |
| `-x`    | Simple authentication                            |
| `-D`    | Bind DN                                          |
| `-W`    | Password interattiva                             |
| `-b`    | Search base                                      |
| `-s`    | Search scope                                     |
| `-LLL`  | Output LDIF pulito (no header/commenti)          |
| `-ZZ`   | StartTLS obbligatorio                            |
| `-Y`    | Meccanismo SASL (es. `GSSAPI` per bind Kerberos) |
| `-E`    | LDAP control (es. paging)                        |
| `-l`    | Time limit                                       |
| `-z`    | Size limit                                       |

## RootDSE e Base DN

Uno degli errori più comuni è partire da un Base DN sbagliato. La RootDSE risponde anche senza autenticazione nella maggior parte dei casi e dice quali naming context esistono:

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" namingContexts defaultNamingContext
```

```ldif
dn:
namingContexts: DC=example,DC=com
defaultNamingContext: DC=example,DC=com
```

In Active Directory `defaultNamingContext` indica il naming context di dominio, mentre `namingContexts` elenca tutti quelli pubblicati dal server (schema, configuration, ecc.) — non tutti gli ambienti LDAP espongono `defaultNamingContext`, è un attributo tipico di AD.

**Global Catalog:** oltre a 389/636, Active Directory pubblica un Global Catalog su porte 3268 (LDAP) e 3269 (LDAPS), utile quando serve interrogare più domini della stessa foresta con un solo bind.

### LDAP vs LDAPS vs StartTLS

| Trasporto       | Porta tipica | TLS                               |
| --------------- | ------------ | --------------------------------- |
| LDAP            | 389          | No                                |
| LDAP + StartTLS | 389          | Upgrade a TLS dopo la connessione |
| LDAPS           | 636          | TLS fin dall'inizio               |

## Bind: Anonymous, Simple, SASL/Kerberos

**RootDSE accessibile non implica enumerazione completa**: molti server rispondono alla RootDSE senza autenticazione ma bloccano la lettura di utenti/gruppi/computer non appena provi a interrogare il Base DN reale.

### Anonymous bind

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=example,DC=com" -s sub "(objectClass=*)" dn
```

Se ottieni DN/OU senza credenziali, è un leak strutturale utile per orientare le query successive. Se vedi `Insufficient access`, è normale: passa a bind autenticato.

### Simple bind

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W -b "DC=example,DC=com" -s sub "(objectClass=*)" dn
```

Un account low-priv spesso può leggere più del previsto, ma quanto dipende interamente dalle ACL configurate sul directory service — non è una garanzia universale.

`Invalid credentials (49)` è spesso un problema di formato: prova il DN completo invece dello UPN.

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "CN=John Doe,OU=Users,DC=example,DC=com" -W -b "DC=example,DC=com" "(sAMAccountName=jdoe)" dn
```

### Bind Kerberos (SASL/GSSAPI)

Se hai già un TGT valido (es. via `kinit`), puoi autenticarti senza passare la password in chiaro sulla riga di comando:

```bash
ldapsearch -Y GSSAPI -H ldap://10.10.10.10 -b "DC=example,DC=com" -s sub "(objectClass=*)" dn
```

Utile anche quando il bind simple è bloccato da policy (vedi la nota su LDAP signing più sotto).

### StartTLS / LDAPS

```bash
ldapsearch -x -H ldap://10.10.10.10 -ZZ -D "jdoe@example.com" -W -b "DC=example,DC=com" "(objectClass=*)" dn
```

Se il certificato non è trusted, la soluzione è importare la CA corretta nel trust store della macchina attacker o usare esplicitamente il certificato previsto dal lab — non ignorare la verifica del certificato.

```bash
ldapsearch -x -H ldaps://10.10.10.10:636 -D "jdoe@example.com" -W -b "DC=example,DC=com" "(objectClass=*)" dn
```

## Search Scope

* **`base`** — solo l'entry indicata da `-b`.
* **`one`** — solo i figli diretti dell'entry.
* **`sub`** — l'intero sottoalbero a partire dall'entry.

È lo scope sbagliato, più spesso del filtro sbagliato, la causa di query che tornano 0 risultati quando ti aspetti migliaia (o viceversa).

## LDAP Filter Cheatsheet

```text
(objectClass=user)                                    # tutti gli oggetti di classe user
(&(objectClass=user)(sAMAccountName=jdoe))             # AND: utente specifico
(!(userAccountControl=514))                            # NOT: esclude account disabilitati con quel flag esatto
(|(cn=admin*)(cn=*admin*))                              # OR + wildcard
(servicePrincipalName=*)                                # presenza attributo: account con almeno uno SPN
```

`(&(objectCategory=person)(objectClass=user))` è la combinazione tipica per isolare gli utenti "reali" in Active Directory — `objectCategory` è un attributo fortemente legato allo schema AD, non un filtro LDAP universale.

## Enumerazione Active Directory

### Utenti

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(&(objectCategory=person)(objectClass=user))" \
dn sAMAccountName cn
```

### Gruppi

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(objectClass=group)" dn cn member
```

`member` può mancare anche quando il gruppo esiste: non tutti i gruppi espongono i membri a low-priv. In quel caso interroga `memberOf` direttamente sugli utenti target.

### Computer

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(objectClass=computer)" dn cn dNSHostName operatingSystem
```

### Attributi Interessanti

| Attributo              | Perché interessa                                                  |
| ---------------------- | ----------------------------------------------------------------- |
| `sAMAccountName`       | Nome account                                                      |
| `userPrincipalName`    | Identità UPN                                                      |
| `memberOf`             | Gruppi di appartenenza                                            |
| `servicePrincipalName` | Servizi associati (SPN)                                           |
| `userAccountControl`   | Flag account (bitmask, non un valore singolo da leggere a occhio) |
| `pwdLastSet`           | Ultima modifica password                                          |
| `lastLogonTimestamp`   | Attività recente dell'account                                     |
| `dNSHostName`          | Hostname del computer                                             |
| `operatingSystem`      | OS dichiarato dal computer object                                 |

`userAccountControl` è un bitmask: un valore come `512` va interpretato per flag, non letto come "account normale" a colpo d'occhio — più flag combinati producono valori diversi.

### Account con SPN

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
dn sAMAccountName servicePrincipalName
```

La presenza di uno SPN non è di per sé una vulnerabilità: identifica un account associato a un servizio, che può meritare una verifica successiva nel percorso di assessment (tipicamente [Kerberoasting](https://hackita.it/articoli/kerberoasting/)) — non un risultato exploitabile da solo.

## Output Pulito e Performance

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -b "DC=example,DC=com" "(sAMAccountName=jdoe)" dn cn memberOf
```

`-LLL` toglie header/commenti, `-o ldif-wrap=no` evita che le righe lunghe vengano spezzate — indispensabile se poi vuoi parsare con grep/awk.

Se il server tronca i risultati (size limit lato server), aggiungi il controllo di paging:

```bash
-E pr=1000/noprompt
```

Se vedi `control not supported`, il server non implementa i paged results: in quel caso l'unica via è restringere la query (OU specifica, meno attributi), il paging non risolve sempre i size limit.

Per query lente o OU enormi, limita tempo e numero di entry invece di lasciare il terminale bloccato:

```bash
-l 10 -z 500 -o nettimeout=5
```

## Troubleshooting

**`Invalid credentials (49)`** — password sbagliata, formato bind DN non accettato (UPN vs DN completo), o account bloccato/disabilitato.

**`No such object (32)`** — Base DN inesistente, oppure scope sbagliato (`base` invece di `sub` o viceversa). Riparti dalla RootDSE.

**`Confidentiality required`** — il server rifiuta bind in chiaro. Usa `-ZZ` o `ldaps://`. **Nota per il 2026:** da Windows Server 2025 in poi il comportamento di default dei DC per LDAP signing tende a "Require Signing", quindi è sempre più comune incontrare questo rifiuto anche in ambienti che prima accettavano simple bind non protetto — non è più solo una policy configurata manualmente.

**`Can't contact LDAP server`** — porta chiusa o routing/firewall. Verifica reachability prima di sospettare TLS:

```bash
nc -vz 10.10.10.10 389
```

**`Size limit exceeded`** — il server ha troncato i risultati: usa paging o restringi la query.

**`Insufficient access`** — le credenziali usate non hanno i permessi per quella specifica ricerca, anche se il bind è riuscito.

## ldapsearch vs NetExec vs BloodHound vs enum4linux-ng

| Tool                                                        | Quando usarlo                                                        |
| ----------------------------------------------------------- | -------------------------------------------------------------------- |
| `ldapsearch`                                                | Precisione: controllo totale su bind, scope, filtri, attributi       |
| [NetExec](https://hackita.it/articoli/netexec/)             | Enumeration operativa rapida SMB/LDAP, validazione credenziali       |
| [BloodHound](https://hackita.it/articoli/bloodhound/)       | Relazioni e attack path (ACL, sessioni, deleghe), non singoli record |
| [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) | Enumerazione SMB/RPC quando LDAP è limitato o chiuso                 |
| [rpcclient](https://hackita.it/articoli/rpcclient/)         | Informazioni RPC/SAM/dominio via SMB                                 |

NetExec supporta anche l'enumerazione LDAP con null bind, utile come verifica rapida prima di scrivere query `ldapsearch` mirate:

```bash
netexec ldap 10.10.10.10 -u '' -p '' --query "(objectClass=*)" ""
```

`ldapsearch` resta la scelta quando serve leggere esattamente un attributo su un DN preciso o validare un'ACL puntuale — NetExec e BloodHound sono più veloci per una vista d'insieme, ma non sostituiscono il controllo fine che dà un client LDAP diretto.

## Scenario Pratico: ldapsearch su una Macchina HTB/PG

Ambiente: DC `10.10.10.10`, credenziali low-priv `jdoe@example.com`.

```bash
# 1. Base DN dalla RootDSE
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" defaultNamingContext

# 2. Utenti con paging e output pulito
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -E pr=1000/noprompt \
-b "DC=example,DC=com" -s sub "(&(objectCategory=person)(objectClass=user))" \
sAMAccountName cn memberOf

# 3. Gruppi
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -b "DC=example,DC=com" -s sub "(objectClass=group)" cn dn
```

Risultato atteso: Base DN confermato, dump LDIF pulito di utenti e gruppi visibili con quell'account — materiale grezzo da correlare poi con BloodHound o con test SMB mirati.

## Checklist Operativa

* Verifica reachability su 389/636 (e 3268/3269 se serve il Global Catalog) prima di tutto.
* RootDSE con `-b "" -s base` per ricavare i naming context.
* Preferisci TLS (`-ZZ` o `ldaps://`) invece di simple bind in chiaro.
* Chiedi attributi specifici, non `*`: meno rumore, meno detection.
* `No such object (32)` → Base DN sbagliato; `Invalid credentials (49)` → formato bind DN.
* Se i risultati sono troncati, prova il paging prima di assumere un problema di permessi.

## Concetti Controintuitivi

* **"Se RootDSE risponde, posso enumerare tutto il dominio"** — no, RootDSE accessibile non implica accesso alle directory entries: sono due livelli di visibilità diversi.
* **"`*` è più comodo, quindi lo uso sempre"** — genera output enorme e più rumoroso in detection; parti con pochi attributi mirati.
* **"LDAPS e StartTLS sono intercambiabili"** — operativamente simili, ma in ambienti reali spesso uno funziona e l'altro no (certificati, policy, middlebox).
* **"Il paging risolve sempre i size limit"** — solo se il server supporta il controllo; altrimenti l'unica via è restringere la query.

## Hardening

* Disabilita o limita l'anonymous bind: se un utente non autenticato legge OU/utenti, la mappa del dominio è già regalata.
* Applica ACL granulari: un account low-priv non dovrebbe leggere attributi sensibili per default.
* Forza LDAP signing e channel binding sui DC — è la direzione presa da Microsoft di default sui controller più recenti, non solo una best practice facoltativa.
* Blocca simple bind non protetto da TLS.
* Monitora pattern di enumerazione: filtri larghi tipo `(objectClass=*)`, raffiche di query in poco tempo, bind falliti ripetuti.

## FAQ

**Qual è la differenza tra `-s base`, `-s one` e `-s sub`?**
`base` interroga solo l'entry indicata, `one` i suoi figli diretti, `sub` l'intero sottoalbero. È la causa più comune di query che tornano risultati inattesi.

**Come uso ldapsearch con LDAPS?**
`-H ldaps://host:636` invece di `ldap://`, oppure `-ZZ` su porta 389 per forzare StartTLS. Se il certificato non è trusted, importa la CA corretta invece di bypassare la verifica.

**Cosa significa l'errore LDAP 49?**
Invalid credentials: quasi sempre password sbagliata o formato del bind DN non accettato (prova DN completo invece di UPN, o viceversa).

**Cosa significa l'errore LDAP 32?**
No such object: il Base DN che hai passato non esiste sul server. Riparti dalla RootDSE per ricavare quello corretto.

***

Tutto quanto descritto vale esclusivamente su sistemi di tua proprietà o in ambienti autorizzati (lab, CTF, HTB, PG).
