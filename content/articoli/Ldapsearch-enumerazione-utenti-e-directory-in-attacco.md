---
title: 'Ldapsearch: enumerazione utenti e directory in attacco'
slug: ldapsearch
description: >-
  Scopri come utilizzare ldapsearch per raccogliere informazioni su utenti,
  gruppi e strutture AD. Tecniche di enumeration reali per Red Team e pentester.
image: /LDAPSEARCH.webp
draft: false
date: 2026-01-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - ldapsearch
  - active directory
---

# Ldapsearch: enumerazione utenti e directory in attacco

Se `ldapsearch` ti sputa “No such object” o non trovi il Base DN, qui lo sistemi in 10 minuti **con comandi ripetibili in lab**.

## Intro

`ldapsearch` è un client CLI che interroga un server LDAP e stampa i risultati in LDIF: perfetto per fare enumeration “chirurgica” su directory (OpenLDAP o Active Directory) quando vuoi controllo totale su bind, filtri e attributi.

In un workflow offensivo da lab lo usi per:

* scoprire il Base DN e la struttura (OU/CN)
* enumerare utenti, gruppi, computer e attributi utili
* verificare permessi/ACL e quanto “leaka” un account low-priv
* fare troubleshooting di TLS/LDAPS, timeouts e size limit

Cosa farai in questa guida:

* impari 3 pattern che userai sempre (RootDSE → bind → query mirate)
* costruisci filtri LDAP “da pentest” (utenti/gruppi/computer/SPN)
* pulisci output e gestisci paging/limit
* eviti gli errori classici (49/32/TLS)

Nota etica: tutto ciò che segue è **solo per sistemi di tua proprietà o ambienti autorizzati** (lab/CTF/HTB/PG).

***

## Cos’è ldapsearch e dove si incastra nel workflow

> **In breve:** `ldapsearch` è la tua “lente” su LDAP: meno automatico di tool AD dedicati, ma più preciso quando devi controllare bind, base DN, filtri e attributi restituiti.

In pratica, `ldapsearch` sta bene in mezzo tra recon e AD enumeration:

* prima: validi raggiungibilità e TLS/LDAPS
* poi: RootDSE per capire naming contexts e capability
* infine: query mirate per costruire una mappa di utenti/gruppi/computer

Se dopo l’enumerazione vuoi “ragionare” in termini di percorsi di attacco (sessioni, ACL, deleghe), passa a strumenti più “graph oriented” come [mappare Active Directory con BloodHound](/articoli/bloodhound/) e usa `ldapsearch` come verifica puntuale (es. “questa OU è visibile?”).

Quando NON usarlo: se ti serve “tutto e subito” con parsing già pronto (JSON/CSV) e moduli AD specifici, spesso è più veloce un tool dedicato (vedi sezione Alternative).

***

## Installazione / verifica versione / quick sanity check

> **In breve:** su Kali di solito è già presente (pacchetti OpenLDAP client). Il sanity check è: help/versione + test rete su 389/636.

Perché: confermi che stai usando il client giusto e che non stai impazzendo per un binario mancante.

Cosa aspettarti: `ldapsearch -VV` stampa versione e build; `-h` mostra opzioni principali.

Comando:

```bash
ldapsearch -VV
```

Esempio di output (può variare):

```text
ldapsearch: @(#) $OpenLDAP: ldapsearch 2.6.x ...
```

Interpretazione: se hai una versione “strana” o wrapper, tienilo a mente per TLS e default auth.

Errore comune + fix: `command not found` → installa client OpenLDAP.

Comando:

```bash
sudo apt update && sudo apt install -y ldap-utils
```

***

## RootDSE e Base DN: da dove parti davvero

> **In breve:** prima scopri il Base DN interrogando la RootDSE (`-b "" -s base`). Se sbagli il Base DN, finirai nel classico errore “No such object (32)”.

Il 90% dei fail su `ldapsearch` è “stai cercando nel posto sbagliato”.

Perché: RootDSE ti dice “quali naming contexts esistono” e spesso qual è quello di default.

Cosa aspettarti: un entry senza DN “normale” (spesso `dn:` vuoto) con attributi tipo `namingContexts` (e in AD spesso `defaultNamingContext`).

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" namingContexts defaultNamingContext
```

Esempio di output (può variare):

```ldif
dn:
namingContexts: DC=example,DC=com
defaultNamingContext: DC=example,DC=com
```

Interpretazione: il tuo Base DN tipico sarà `DC=example,DC=com`. Da lì userai quasi sempre `-s sub`.

Errore comune + fix: `Can't contact LDAP server` → porta/host errati o firewall; prova `-H ldaps://...:636` o StartTLS (vedi TLS più sotto).

***

## Bind & transport: anonymous, simple, SASL, StartTLS e LDAPS

> **In breve:** in lab “operativo” userai spesso bind simple (`-x -D ... -W`) su canale protetto (StartTLS `-ZZ` o `ldaps://`). Se il server richiede confidenzialità, senza TLS vedrai errori tipo “Confidentiality required”.

### Pattern 1: anonymous bind (solo per capire cosa leaka)

Perché: scopri immediatamente se l’LDAP espone info senza credenziali (misconfig comune in lab).

Cosa aspettarti: o ti risponde con dati “basics”, o ti taglia fuori con access denied.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=example,DC=com" -s sub "(objectClass=*)" dn
```

Esempio di output (può variare):

```ldif
dn: DC=example,DC=com
dn: CN=Users,DC=example,DC=com
dn: OU=Workstations,DC=example,DC=com
```

Interpretazione: se ottieni DN/OU senza auth, hai già leak strutturale utile per pivotare le query.

Errore comune + fix: se vedi “Insufficient access”, è normale: passa a bind autenticato.

### Pattern 2: simple bind con credenziali (il classico da pentest interno)

Qui spesso conviene legare `ldapsearch` all’ecosistema AD: dopo che hai credenziali, puoi correlare con tool di dominio come [attacchi rapidi su Active Directory con CrackMapExec](/articoli/crackmapexec/) per testare accessi e poi tornare a `ldapsearch` per query mirate.

Perché: un account low-priv spesso può leggere moltissimo (utenti, gruppi, attributi).

Cosa aspettarti: bind OK e risultati coerenti con ACL.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W -b "DC=example,DC=com" -s sub "(objectClass=*)" dn
```

Esempio di output (può variare):

```ldif
dn: CN=John Doe,OU=Users,DC=example,DC=com
dn: CN=HR Printer,OU=Devices,DC=example,DC=com
```

Interpretazione: se il bind passa, sei “dentro” e puoi stringere i filtri.

Errore comune + fix: `Invalid credentials (49)` → DN/UPN errato o password sbagliata. In AD prova una forma diversa di bind DN (DN completo vs UPN). Esempio DN completo:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "CN=John Doe,OU=Users,DC=example,DC=com" -W -b "DC=example,DC=com" "(sAMAccountName=jdoe)" dn
```

### Pattern 3: StartTLS / LDAPS (evita credenziali in chiaro)

Perché: molti server bloccano simple bind senza TLS o rispondono con errori di confidenzialità.

Cosa aspettarti: handshake TLS; se il cert non è trusted potresti avere failure (dipende da client/CA).

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -ZZ -D "jdoe@example.com" -W -b "DC=example,DC=com" "(objectClass=*)" dn
```

Esempio di output (può variare):

```text
# Output LDIF...
```

Interpretazione: `-ZZ` richiede StartTLS riuscito: se continua, il trasporto è ok.

Errore comune + fix: TLS fail per certificati → in lab importa la CA corretta nel trust store della macchina attacker o usa LDAPS esplicito:

```bash
ldapsearch -x -H ldaps://10.10.10.10:636 -D "jdoe@example.com" -W -b "DC=example,DC=com" "(objectClass=*)" dn
```

***

## Sintassi base + 3 pattern che userai sempre

> **In breve:** `-H` (URI) + `-b` (base) + `-s` (scope) + filtro LDAP. Se non specifichi attributi, torna “tanti” attributi: meglio chiedere solo quelli utili.

### Pattern A: “dimmi solo se esiste” (ritorna solo DN)

Perché: validi velocemente filtri e base DN senza portarti dietro 200 attributi.

Cosa aspettarti: un elenco di `dn:`.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=example,DC=com" -s sub "(sAMAccountName=jdoe)" dn
```

Esempio di output (può variare):

```ldif
dn: CN=John Doe,OU=Users,DC=example,DC=com
```

Interpretazione: il filtro è giusto e l’utente esiste.

Errore comune + fix: nessun output → utente non esiste o non è visibile con quelle ACL. Prova a cercare per `cn` o restringi/espandi base.

### Pattern B: “dammi attributi mirati” (utente/gruppi/flags)

Perché: estrai solo ciò che serve davvero (membro di gruppi, flag account, SPN).

Cosa aspettarti: pochi attributi “operativi”.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(sAMAccountName=jdoe)" \
cn memberOf userAccountControl pwdLastSet lastLogonTimestamp servicePrincipalName
```

Esempio di output (può variare):

```ldif
dn: CN=John Doe,OU=Users,DC=example,DC=com
cn: John Doe
memberOf: CN=IT,OU=Groups,DC=example,DC=com
userAccountControl: 512
```

Interpretazione: ora hai “telemetria” utile per capire ruolo e superficie (gruppi, flag, SPN).

Errore comune + fix: attributi vuoti → non sempre sono settati o non visibili; prova `*` e poi affina.

### Pattern C: “RootDSE capability check” (controlli/estensioni supportate)

Perché: capisci se il server supporta paging, sorting, meccanismi SASL, ecc.

Cosa aspettarti: attributi come `supportedControl`, `supportedSASLMechanisms`, `supportedLDAPVersion`.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" \
supportedLDAPVersion supportedControl supportedSASLMechanisms
```

Esempio di output (può variare):

```ldif
dn:
supportedLDAPVersion: 3
supportedSASLMechanisms: GSSAPI
```

Interpretazione: se non vedi controlli, non dare per scontato paging/sorting.

Errore comune + fix: output “vuoto” → alcuni server limitano RootDSE; prova con credenziali o con TLS.

***

## Enumerazione / discovery / leakage tipici in lab

> **In breve:** i filtri “killer” sono per utenti, gruppi e computer. In AD, aggiungi query per account con SPN (utile per attacchi di tipo Kerberoasting in lab) ma ricordati sempre detection/hardening.

### Enumerare utenti (solo quelli “person/user”)

Perché: lista “chi esiste” e poi pivot su attributi.

Cosa aspettarti: `dn`, `sAMAccountName`, `cn`.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(&(objectCategory=person)(objectClass=user))" \
dn sAMAccountName cn
```

Esempio di output (può variare):

```ldif
dn: CN=John Doe,OU=Users,DC=example,DC=com
sAMAccountName: jdoe
cn: John Doe
```

Interpretazione: hai una lista base. Da qui puoi filtrare per OU o per attributi specifici.

Errore comune + fix: troppi risultati e tagliati dal server → usa paging (vedi sezione performance).

### Enumerare gruppi e membership

Perché: i gruppi sono “privilegi in forma di testo”.

Cosa aspettarti: nome gruppo + membri (se visibili).

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(objectClass=group)" \
dn cn member
```

Esempio di output (può variare):

```ldif
dn: CN=IT,OU=Groups,DC=example,DC=com
cn: IT
member: CN=John Doe,OU=Users,DC=example,DC=com
```

Interpretazione: `member` può essere enorme o nascosto: spesso conviene query per “memberOf” sull’utente.

Errore comune + fix: `member` mancante → non tutti i gruppi espongono i membri a low-priv; usa `memberOf` sugli utenti target.

### Enumerare computer (workstation/server)

Perché: ti costruisci l’inventario e puoi correlare con altre fonti.

Cosa aspettarti: `dn`, `cn`, `dNSHostName`.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(objectClass=computer)" \
dn cn dNSHostName operatingSystem
```

Esempio di output (può variare):

```ldif
dn: CN=WS-023,OU=Workstations,DC=example,DC=com
cn: WS-023
dNSHostName: ws-023.example.com
operatingSystem: Windows 10 Pro
```

Interpretazione: se hai `dNSHostName`, poi validi reachability e servizi con tool di rete e SMB; in lab spesso conviene incrociare con [Smbclient per condivisioni Windows](/articoli/smbclient/) quando trovi host “interesting”.

Errore comune + fix: `dNSHostName` vuoto → non sempre popolato; usa `cn` e DNS/NetBIOS enumeration separata.

### Account con SPN (lab-only, utile per valutare esposizione)

Perché: trovare `servicePrincipalName` aiuta a identificare servizi account-based.

Cosa aspettarti: utenti con almeno uno SPN.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-b "DC=example,DC=com" -s sub "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
dn sAMAccountName servicePrincipalName
```

Esempio di output (può variare):

```ldif
dn: CN=svc_sql,OU=ServiceAccounts,DC=example,DC=com
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sql01.example.com:1433
```

Interpretazione: non è “exploit” da solo, è intelligence. In lab la validazione è: l’account è visibile? quali SPN? quali gruppi?

Errore comune + fix: nessun risultato → non ci sono service account con SPN o non li vedi con quelle ACL.

***

## Output pulito e performance: LDIF, wrap, paging, timeouts

> **In breve:** per lavorare bene devi “pulire” LDIF (`-LLL`, no wrapping) e gestire limiti (paging `-E pr=...`, `-l` timelimit, `-z` sizelimit, `-o nettimeout=...`).

### Output pulito: meno rumore, più parsing

Perché: l’output default può essere “verbose” e wrap-ato, pessimo da greppare.

Cosa aspettarti: LDIF senza commenti e senza “version: 1” (con `-LLL`), e linee non spezzate.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -b "DC=example,DC=com" "(sAMAccountName=jdoe)" \
dn cn memberOf
```

Esempio di output (può variare):

```ldif
dn: CN=John Doe,OU=Users,DC=example,DC=com
cn: John Doe
memberOf: CN=IT,OU=Groups,DC=example,DC=com
```

Interpretazione: ora puoi parsare con grep/awk senza bestemmiare.

Errore comune + fix: output enorme → chiedi solo attributi utili, non `*` a caso.

### Paging: quando il server tronca i risultati

Perché: molti server applicano size limit e ti restituiscono solo una parte.

Cosa aspettarti: risultati “a pagine” gestiti dal client (se supportato dal server).

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -E pr=1000/noprompt \
-b "DC=example,DC=com" -s sub "(&(objectCategory=person)(objectClass=user))" \
dn sAMAccountName
```

Esempio di output (può variare):

```ldif
dn: CN=Alice,OU=Users,DC=example,DC=com
sAMAccountName: alice
dn: CN=Bob,OU=Users,DC=example,DC=com
sAMAccountName: bob
```

Interpretazione: se vedi che la lista ora è completa, il tuo collo di bottiglia era il limite.

Errore comune + fix: “control not supported” → il server non supporta paged results; in quel caso filtra per OU o usa query più strette.

### Timeouts e limiti “difensivi” (per non impiccarsi)

Perché: in lab capita di colpire query lente (OU enormi, filtri larghi).

Cosa aspettarti: abort controllato invece di terminale bloccato.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-l 10 -z 500 -o nettimeout=5 \
-b "DC=example,DC=com" -s sub "(objectClass=computer)" dn
```

Esempio di output (può variare):

```text
# risultati parziali o terminazione per timelimit/sizelimit
```

Interpretazione: `-l` limita tempo, `-z` limita numero entry, `nettimeout` limita handshake/rete.

Errore comune + fix: tagli troppo aggressivi → alza `-l` e usa paging invece di `-z`.

***

## Errori comuni e troubleshooting (quelli che ti capitano davvero)

> **In breve:** se vedi errori 49/32 o TLS, quasi sempre è: bind DN sbagliato, Base DN sbagliato, o canale non “confidential”.

### “Invalid credentials (49)”

Cause tipiche:

* password sbagliata
* formato bind DN non accettato (UPN vs DN completo)
* account lockout/disabled (dipende dal lab)

Fix rapido: valida l’utente con filtro su una base corretta e riprova con DN completo.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=example,DC=com" -s sub "(sAMAccountName=jdoe)" dn
```

### “No such object (32)”

Cause tipiche:

* `-b` punta a una base che non esiste (OU sbagliata, DC sbagliati)
* stai usando `-s base` quando volevi `-s sub` (o viceversa)

Fix rapido: RootDSE e poi riparti dal namingContext corretto.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" namingContexts
```

### “Confidentiality required” / bind bloccato senza TLS

Cause tipiche:

* policy che richiede TLS per simple bind
* stai passando credenziali su `ldap://` e il server rifiuta

Fix rapido: StartTLS obbligatorio.

Comando:

```bash
ldapsearch -x -H ldap://10.10.10.10 -ZZ -D "jdoe@example.com" -W -b "DC=example,DC=com" "(objectClass=*)" dn
```

### “Can’t contact LDAP server”

Cause tipiche:

* porta chiusa (389/636)
* routing/firewall
* TLS handshake che fallisce

Fix rapido: valida reachability e poi sniffa in lab.

Comando:

```bash
nc -vz 10.10.10.10 389
```

Quando NON usarlo: se devi debuggare handshake TLS a livello basso, spesso ti conviene usare strumenti TLS dedicati o catture di traffico (vedi link utili).

***

## Alternative e tool correlati (quando preferirli)

> **In breve:** `ldapsearch` è precisione e controllo. Tool AD “opinionated” sono più veloci per output pronto e workflow completi.

Usa alternative quando:

* vuoi enumerazione AD “a colpo d’occhio” (sessioni, ACL, relazioni): BloodHound (graph)
* vuoi test credenziali + moduli AD/SMB rapidi: CME
* vuoi enumerare SMB/RPC (utenti, share, SID) quando LDAP è limitato: enum4linux-ng, rpcclient

Se ti serve enumerazione Windows via SMB/RPC in parallelo a LDAP, guarda [enumerazione avanzata con enum4linux-ng](/articoli/enum4linux-ng/) e incrocia i risultati con quello che vedi via directory.

***

## Hardening & detection (cosa deve fare chi difende)

> **In breve:** riduci la superficie LDAP con: meno anonymous bind, meno attributi sensibili visibili, TLS obbligatorio, logging e alert su pattern di enumeration.

In un lab “blue team aware”, questi sono i punti che fanno davvero differenza:

* Disabilita o limita l’anonymous bind: se un utente non autenticato può leggere OU/utenti, stai regalando la mappa.
* Forza TLS per bind e query (StartTLS/LDAPS) e blocca simple bind in chiaro.
* Applica ACL: un account low-priv non dovrebbe leggere attributi sensibili “gratis”.
* Logging: monitora picchi di search con filtri larghi tipo `(objectClass=*)`, richieste massive su `CN=Users`, e “spray” di bind falliti.
* Rate-limit e alert: enumeration spesso è “molte query in poco tempo”, soprattutto con paging.

Nota: i dettagli precisi di audit/eventi cambiano tra OpenLDAP e Active Directory e tra versioni; in lab verifica sul server quali log vengono prodotti e quali controlli sono supportati.

***

## Scenario pratico: ldapsearch su una macchina HTB/PG

> **In breve:** in un lab con DC `10.10.10.10`, l’obiettivo è ottenere Base DN dalla RootDSE e enumerare utenti/gruppi “useful” con output pulito e paging.

Ambiente: target LDAP/AD su `10.10.10.10` (lab). Credenziali low-priv: `jdoe@example.com`.

Obiettivo: identificare `defaultNamingContext` e ottenere una lista utenti + gruppi principali visibili con quell’account.

Azione 1 (RootDSE → Base DN):

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" defaultNamingContext namingContexts
```

Azione 2 (Enumerazione utenti con paging e output pulito):

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -E pr=1000/noprompt \
-b "DC=example,DC=com" -s sub "(&(objectCategory=person)(objectClass=user))" \
sAMAccountName cn memberOf
```

Azione 3 (Estrarre solo gruppi “grossi” e nomi):

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -b "DC=example,DC=com" -s sub "(objectClass=group)" \
cn dn
```

Risultato atteso concreto: ottieni `DC=example,DC=com` e un dump LDIF pulito da cui ricavi utenti e gruppi visibili per quella ACL.

Detection + hardening: un SOC dovrebbe vedere una raffica di query subtree e, se presenti, controlli di paging; mitigazioni tipiche sono ACL più strette, TLS obbligatorio e alert su filtri larghi ripetuti.

***

## Playbook 10 minuti: ldapsearch in un lab

> **In breve:** sequenza minima: reachability → RootDSE → bind → query utenti/gruppi/computer → hardening notes.

### Step 1 – Verifica porta LDAP/LDAPS

Se non arrivi a 389/636, `ldapsearch` non è il problema.

```bash
nc -vz 10.10.10.10 389
```

### Step 2 – RootDSE per Base DN

Prendi subito `defaultNamingContext` o `namingContexts`.

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" namingContexts defaultNamingContext
```

### Step 3 – Bind autenticato (low-priv) e query di test

Conferma che le credenziali funzionano e che leggi qualcosa.

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W -b "DC=example,DC=com" "(sAMAccountName=jdoe)" dn
```

### Step 4 – Dump utenti “light” con paging

Tira fuori solo gli attributi utili e evita size limit.

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W \
-LLL -o ldif-wrap=no -E pr=1000/noprompt \
-b "DC=example,DC=com" "(&(objectCategory=person)(objectClass=user))" \
sAMAccountName cn memberOf
```

### Step 5 – Gruppi e computer

Costruisci inventario base (gruppi e host).

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W -LLL -o ldif-wrap=no \
-b "DC=example,DC=com" "(objectClass=computer)" cn dNSHostName operatingSystem
```

### Step 6 – Se TLS è richiesto, forza StartTLS

Se vedi confidenzialità richiesta, usa `-ZZ`.

```bash
ldapsearch -x -H ldap://10.10.10.10 -ZZ -D "jdoe@example.com" -W -b "DC=example,DC=com" "(objectClass=*)" dn
```

### Step 7 – Annotazioni difensive

Segna cosa hai potuto leggere da low-priv e quali query erano “rumorose” (subtree + paging): è materiale perfetto per hardening in lab.

***

## Checklist operativa

> **In breve:** lista corta di controlli che evitano l’80% dei fail su `ldapsearch`.

* Verifica reachability su `389` e `636` prima di tutto.
* Interroga RootDSE con `-b "" -s base` per ricavare `namingContexts`.
* Usa `-x` per simple bind quando non stai facendo SASL.
* Preferisci TLS: `-ZZ` (StartTLS) o `ldaps://`.
* Usa `-LLL` per LDIF pulito e `-o ldif-wrap=no` per evitare line wrapping.
* Chiedi attributi specifici invece di `*` (meno rumore, meno detection).
* Se taglia i risultati, prova paging con `-E pr=1000/noprompt`.
* Se una query è lenta, imposta `-l` (timelimit) e `-o nettimeout=...`.
* Se `No such object (32)`, il Base DN è sbagliato: riparti da RootDSE.
* Se `Invalid credentials (49)`, cambia formato bind DN (UPN vs DN completo).
* Se devi validare “esistenza”, chiedi solo `dn`.
* Documenta cosa leaka anonymous vs autenticato (è un finding difensivo reale).

***

## Riassunto 80/20

> **In breve:** questi comandi ti portano da “zero” a “enumerazione utile” con pochissimo rumore.

| Obiettivo              | Azione pratica          | Comando/Strumento                                                                                                |
| ---------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Scoprire Base DN       | RootDSE naming contexts | `ldapsearch -x -H ldap://10.10.10.10 -b "" -s base "(objectClass=*)" namingContexts`                             |
| Verificare credenziali | Query su utente singolo | `ldapsearch -x -H ldap://10.10.10.10 -D "jdoe@example.com" -W -b "DC=example,DC=com" "(sAMAccountName=jdoe)" dn` |
| Dump utenti pulito     | Output + paging         | `ldapsearch -x -LLL -o ldif-wrap=no -E pr=1000/noprompt ... "(&(objectCategory=person)(objectClass=user))"`      |
| Enumerare gruppi       | `objectClass=group`     | `ldapsearch -x ... "(objectClass=group)" cn dn`                                                                  |
| Enumerare computer     | `objectClass=computer`  | `ldapsearch -x ... "(objectClass=computer)" cn dNSHostName`                                                      |
| Forzare TLS            | StartTLS required       | `ldapsearch -x -H ldap://10.10.10.10 -ZZ ...`                                                                    |

***

## Concetti controintuitivi

> **In breve:** sono gli “inganni” che fanno perdere tempo anche a chi sa usare LDAP.

* **“Se non vedo risultati, il filtro è sbagliato”**
  Non sempre: potresti non avere permessi su quella OU o stai cercando sotto una base errata. In lab valida prima il Base DN via RootDSE e prova una query “dn-only”.
* **“`*` è più comodo, quindi lo uso”**
  È comodo ma rumoroso e spesso inutile: ti genera output enorme e aumenta detection. In lab parti con 3–6 attributi e amplia solo se serve.
* **“LDAPS e StartTLS sono intercambiabili”**
  Operativamente sì, ma nei lab reali spesso uno funziona e l’altro no (cert, policy, middlebox). Se `-ZZ` fallisce, prova `ldaps://:636` e viceversa.
* **“Paging risolve sempre i size limit”**
  No: se il server non supporta il controllo, `-E pr=...` non ti salva. In quel caso devi filtrare meglio (OU specifica) o cambiare approccio.

***

## FAQ

D: Come trovo il Base DN se non lo conosco?

R: Interroga RootDSE con `-b "" -s base` e leggi `namingContexts` (o `defaultNamingContext` in alcuni ambienti). Poi usa quel valore in `-b`.

D: Posso bindare con `utente@dominio` invece del DN completo?

R: In molti lab AD sì, ma non è garantito. Se `Invalid credentials (49)`, prova il DN completo `CN=...,OU=...,DC=...,DC=...`.

D: Perché il server tronca la lista utenti?

R: Size limit server-side. Prova paging `-E pr=1000/noprompt` se supportato, oppure restringi la query per OU e chiedi meno attributi.

D: Perché mi dice “Confidentiality required”?

R: Il server rifiuta simple bind in chiaro. Usa StartTLS `-ZZ` o `ldaps://` e riprova.

D: Come rendo l’output “parsabile”?

R: Usa `-LLL` e `-o ldif-wrap=no`, e chiedi solo attributi necessari (es. `dn cn memberOf`).

***

## Link utili su HackIta.it

> **In breve:** risorse correlate per completare l’enumerazione (SMB/RPC, sniffing, recon) e incrociare i dati LDAP.

* [Rpcclient: attacco e enum SMB su Active Directory](/articoli/rpcclient/)
* [Inveigh: rubare hash NTLM via LLMNR, NBNS e WPAD](/articoli/inveigh/)
* [NBTScan: scansione silenziosa NetBIOS su reti Windows](/articoli/nbtscan/)
* [Netcat: il coltellino svizzero dell’hacking di rete](/articoli/netcat/)
* [Tcpdump: analizzare il traffico di rete da terminale](/articoli/tcpdump/)
* [TShark: analizzare il traffico di rete da terminale](/articoli/tshark/)

Inoltre (pagine istituzionali):

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

***

## Riferimenti autorevoli

* [OpenLDAP man page: ldapsearch(1)](https://www.openldap.org/software/man.cgi?query=ldapsearch\&sektion=1)
* [OpenLDAP Admin Guide: common causes of LDAP errors](/doc/admin25/appendix-common-errors.html)

***

## CTA finale HackITA

Se questa guida ti ha fatto risparmiare tempo in lab, puoi supportare il progetto qui: /supporto/

Vuoi una formazione 1:1 orientata a OSCP/AD lab e playbook realmente usabili? Trovi i pacchetti qui: /servizi/

Se sei un’azienda e vuoi assessment, hardening o simulazioni Red Team (sempre in perimetro autorizzato), trovi tutto qui: /servizi/
