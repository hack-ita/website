---
title: 'Rpcclient: attacco e enum SMB su Active Directory'
slug: rpcclient
description: >-
  Rpcclient consente di interrogare AD via SMB per ottenere utenti, SID e
  informazioni critiche. Tecniche offensive per pentest e Red Team.
image: /Gemini_Generated_Image_qeb7nqeb7nqeb7nq.webp
draft: false
date: 2026-01-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - rpcclient
---

# Rpcclient: attacco e enum SMB su Active Directory

Se hai la 445 aperta ma l’enumerazione “classica” ti dà poco, `rpcclient` ti fa tirare fuori utenti, gruppi, SID e policy in modo chirurgico (sempre in lab/CTF/VM autorizzate).

## Intro

`rpcclient` è un client MS-RPC/DCE-RPC della suite Samba che ti permette di interrogare servizi Windows/AD (SAMR, LSA, SRVSVC) passando spesso da SMB (named pipes).

In un workflow offensivo da lab è utile quando vuoi trasformare “porta 445 aperta” in intelligence di dominio: utenti, gruppi, membership, SID/RID, policy password, share enumerate via RPC.

Cosa farai (in pratica):

* connetterti in modalità anonima (se possibile) o con credenziali low-priv
* dumpare utenti/gruppi e correlare RID/SID
* estrarre policy password e share info via RPC
* gestire errori comuni (logon failure, access denied, signing)

Nota etica: usa tutto solo su sistemi tuoi o esplicitamente autorizzati (HTB/PG/lab AD).

## Cos’è rpcclient e dove si incastra nel workflow

> **In breve:** `rpcclient` interroga servizi interni Windows/AD via MS-RPC (spesso su SMB), quindi è perfetto per enumerazione “di dominio”, non per browsing file.

`rpcclient` non nasce per “sfogliare share” (quello è più da SMB file access), ma per chiamare procedure remote: query su utenti/gruppi, mapping SID, policy e informazioni server.

Dove lo metti nella catena (lab):

* Recon: 445/139 trovate aperte, capisci se c’è AD/SMB sensato.
* Accesso: provi anonymous/null session solo per disclosure; altrimenti usi credenziali anche basse.
* Intel: estrai userlist, gruppi, policy, mapping SID/RID.
* Correlazione: passi i risultati a tool di post-enum e pathing.

Quando NON usarlo: se ti serve solo scaricare file da share o fare triage rapido su più host (meglio strumenti più diretti).

## Installazione, versione e quick sanity check

> **In breve:** su Kali spesso è già presente (Samba client). Prima valida versione e connettività verso 445/139 nel lab.

Perché: ti assicuri di avere `rpcclient` e riduci “bug fantasma” dovuti a tool mancanti/vecchi.
Cosa aspettarti: una versione stampata e il binario disponibile.
Comando:

```
rpcclient --version
```

Interpretazione: se il comando risponde, sei a posto; se manca, installa i client Samba.
Errore comune + fix: `command not found` → installa il pacchetto Samba client.

Perché: installare in modo pulito su Kali.
Cosa aspettarti: `rpcclient` disponibile nel PATH.
Comando:

```
sudo apt update && sudo apt install -y samba-common-bin smbclient
```

Interpretazione: su alcune distro il pacchetto può variare, ma l’obiettivo è ottenere i binari Samba client.
Errore comune + fix: repository/apt rotti → verifica mirror o usa una repo Kali corretta.

## Connessione e autenticazione: le 3 modalità che userai sempre

> **In breve:** `rpcclient` può entrare in shell interattiva oppure eseguire comandi one-shot con `-c`; l’accesso anonimo è raro ma va testato.

### 1) Test “null session” (anonimo) in lab

Perché: se passa, hai information disclosure senza credenziali (finding serio).
Cosa aspettarti: se consentito, arrivi al prompt `rpcclient $>`; se negato, access denied.
Comando:

```
rpcclient -U '' -N 10.10.10.10
```

Esempio di output (può variare):

```
rpcclient $>
```

Interpretazione: se entri, prova subito comandi “safe” tipo `srvinfo` o `querydominfo`.
Errore comune + fix: `NT_STATUS_ACCESS_DENIED` → non è un problema: significa che anonimo è bloccato (normale su ambienti moderni).

### 2) Connessione con credenziali (domain o local)

Perché: con credenziali low-priv spesso ottieni comunque tantissima intel di dominio.
Cosa aspettarti: prompt interattivo `rpcclient $>` oppure errore di logon.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10
```

Interpretazione: se il dominio è richiesto e non lo metti, potresti autenticarti contro contesti non attesi.
Errore comune + fix: `NT_STATUS_LOGON_FAILURE` → credenziali errate o dominio sbagliato; prova a specificare `-W LAB` se serve.

### 3) One-liner non interattiva (perfetta per scripting)

Perché: esegui una mini-sequenza e salvi output pulito.
Cosa aspettarti: output testuale dei comandi richiesti (o errori per i comandi non permessi).
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; enumdomusers'
```

Interpretazione: ottimo per dump iniziale “fast”.
Errore comune + fix: comandi separati male → usa `;` tra comandi e virgolette singole attorno alla stringa.

## Enumerazione base: dominio, server, utenti e gruppi

> **In breve:** parti sempre da `querydominfo` e `srvinfo`, poi passa a `enumdomusers` e `enumdomgroups` per costruire la tua mappa.

### Capire “dove sei finito”: domain + server

Perché: vuoi sapere se stai parlando con un DC, un member server o una macchina standalone.
Cosa aspettarti: info su dominio e server (dipende dai permessi).
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; srvinfo'
```

Esempio di output (può variare):

```
Domain: LAB
Server: DC01
Users: 128
Groups: 54
OS: Windows Server (build info may vary)
```

Interpretazione: se ottieni nome dominio e conteggi, hai già un buon segnale di visibilità RPC.
Errore comune + fix: output vuoto/errore → prova in modalità interattiva per vedere messaggi più chiari.

### Dump utenti: la userlist “grezza” che serve sempre

Perché: la lista utenti alimenta qualunque fase successiva (validazione credenziali, pathing, triage).
Cosa aspettarti: righe con `user:[Nome] rid:[0x...]`.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'enumdomusers'
```

Esempio di output (può variare):

```
user:[Administrator] rid:[0x1f4]
user:[svc_sql] rid:[0x45a]
user:[m.rossi] rid:[0x5c1]
```

Interpretazione: il RID ti permette query mirate (`queryuser`, `queryusergroups`) senza ambiguità.
Errore comune + fix: `NT_STATUS_ACCESS_DENIED` → l’utente non ha permessi per enumerare; prova altre fonti (LDAP/SMB) o credenziali diverse in lab.

### Enumerare gruppi e membership (dove nasce l’escalation)

Perché: l’escalation in AD è spesso “gruppi → privilegi → path”.
Cosa aspettarti: lista gruppi e poi membri per RID del gruppo.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'enumdomgroups'
```

Interpretazione: prendi un RID interessante e interroga i membri.
Errore comune + fix: se non sai quale RID usare, prova prima a listare e poi query.

Perché: capire chi sta dentro un gruppo target.
Cosa aspettarti: lista di RID membri (poi li risolvi in nomi).
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querygroupmem 0x200'
```

Interpretazione: se ottieni RID, poi fai `queryuser` o risolvi SID/nomi.
Errore comune + fix: gruppo RID diverso nel tuo lab → non assumere “0x200 = Domain Admins” come legge: verifica sempre.

Per collegare rapidamente utenti/gruppi a path reali di escalation, passa i dati a [BloodHound: mappa l’Active Directory come un hacker](/articoli/bloodhound/).

## Profilazione mirata: queryuser, gruppi dell’utente e segnali utili

> **In breve:** una volta trovato un account interessante (service account, admin, “strano”), approfondisci con `queryuser` e `queryusergroups`.

Perché: vuoi dettagli operativi (descrizioni, stato account, last logon, flags) e membership.
Cosa aspettarti: campi testuali con attributi (variano per versione/permessi).
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'queryuser svc_sql'
```

Interpretazione: guarda “description” e campi simili: in lab spesso contengono hint o leak (da trattare come finding).
Errore comune + fix: nome utente non risolto → usa `enumdomusers` e prendi il RID, poi `queryuser 0x...`.

Perché: trovare i gruppi dell’utente in modo diretto.
Cosa aspettarti: lista di gruppi (come RID) legati all’utente.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'queryusergroups 0x45a'
```

Interpretazione: se vedi gruppi “operativi” (backup, server operators, custom), è un candidato escalation in lab.
Errore comune + fix: confondere RID utente con RID gruppo → annota sempre cosa stai interrogando.

Se ti serve un confronto “file-centric” (share e contenuti), usa invece [Smbclient: accesso e attacco alle condivisioni Windows](/articoli/smbclient/).

## SID, RID e risoluzione nomi: evitare ambiguità

> **In breve:** `lookupnames` e `lookupsids` ti permettono di passare tra nomi e SID; è fondamentale quando lavori con output di più tool.

Perché: normalizzare identità (nome ↔ SID) e correlare dataset.
Cosa aspettarti: un SID e un tipo associato (user/group).
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'lookupnames Administrator'
```

Interpretazione: ottieni il SID e capisci se stai parlando di un account built-in o di dominio.
Errore comune + fix: `NT_STATUS_NONE_MAPPED` → nome errato o contesto diverso; verifica il dominio/realm.

Perché: risolvere SID in nome “umano”.
Cosa aspettarti: mapping SID → account.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'lookupsids S-1-5-21-1111111111-2222222222-3333333333-500'
```

Interpretazione: utile quando trovi SID in log, ACL o output di altri strumenti.
Errore comune + fix: SID incompleto o locale → assicurati che il SID sia corretto e riferito al dominio del lab.

## Casi d’uso offensivi “da lab”: disclosure utile senza exploit

> **In breve:** con `rpcclient` puoi ottenere policy password e share info via RPC; sono dati “tattici” che impattano direttamente il rischio.

### Policy password: getdompwinfo

Perché: ti serve per valutare rischio (min length, lockout/age se esposti) e fare report sensato in lab.
Cosa aspettarti: parametri della policy (variano per configurazione).
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'getdompwinfo'
```

Esempio di output (può variare):

```
min_password_length: 8
password_history: 24
password_properties: 0x00000001
```

Interpretazione: non “attacchi” nulla: misuri posture e impatti possibili (se la policy è debole, è un finding).
Errore comune + fix: access denied → non tutte le credenziali possono leggere tutto; valida con un account che nel lab ha permessi adeguati.

### Share enumerate via RPC: netshareenumall

Perché: vedi share e descrizioni anche quando non vuoi ancora fare browsing file.
Cosa aspettarti: lista share e commenti; i nomi spesso indicano dati sensibili.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'netshareenumall'
```

Interpretazione: prendi i nomi share e poi decidi se passare a strumenti file-centric.
Errore comune + fix: share non visibili via RPC → usa alternative (SMB listing) o cambia account nel lab.

Validazione in lab: crea un mini dominio con share “IT-Deploy” e un service account; verifica quanto un low-priv vede via RPC e documenta il gap.
Segnali di detection: picchi di autenticazioni di rete e chiamate RPC ripetute verso DC/member server in finestre brevi.
Hardening/mitigazione: disabilita anonymous/guest, limita la visibilità di enumeration per utenti non privilegiati e applica auditing coerente su accessi di rete e RPC.

Per validare velocemente credenziali e visibilità su più host (sempre in lab), molti usano tool “bulk” come [CrackMapExec: attacchi rapidi su Active Directory](/articoli/crackmapexec/).

## Errori comuni e troubleshooting (quelli che ti fanno perdere tempo)

> **In breve:** la maggior parte dei problemi è: credenziali/contesto dominio, policy che blocca enumeration, o trasporto/negoziazione SMB.

### `NT_STATUS_LOGON_FAILURE`

Perché: indica credenziali errate o contesto sbagliato.
Cosa aspettarti: fallimento immediato in connessione.
Comando:

```
rpcclient -U 'LAB/user1%WrongPass' 10.10.10.10 -c 'srvinfo'
```

Interpretazione: non stai “rompendo” nulla: stai autenticando male.
Errore comune + fix: dominio errato → prova `-U 'LAB/user1%Passw0rd!'` e, se serve, aggiungi `-W LAB`.

### `NT_STATUS_ACCESS_DENIED` su comandi specifici

Perché: hai sessione valida, ma quel comando richiede permessi più alti.
Cosa aspettarti: alcuni comandi funzionano, altri negati.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; enumdomusers'
```

Interpretazione: se `querydominfo` funziona ma `enumdomusers` no, è un limite di permessi/policy.
Errore comune + fix: non “insistere”: cambia fonte dati (LDAP, SMB, DNS) o usa un account autorizzato nel lab.

### Timeout / server non raggiungibile

Perché: firewall, routing lab (VPN), o porte chiuse.
Cosa aspettarti: timeout e nessun output utile.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'srvinfo'
```

Interpretazione: se va in timeout, prima verifica connettività e che 445/139 siano raggiungibili.
Errore comune + fix: target risolve male → usa IP diretto (non hostname) e controlla la reachability in lab.

## Alternative e tool correlati (quando preferirli)

> **In breve:** `rpcclient` è “manuale e preciso”; se vuoi automation, bulk-check o fonti dati diverse, scegli lo strumento giusto.

* Se vuoi enumerazione “one-shot” e report rapido: [Enum4linux-ng: enumerazione avanzata su reti Windows](/articoli/enum4linux-ng/) spesso ti dà una fotografia iniziale utile.
* Se devi lavorare su file e share (download/upload, recursion, loot): passa a `smbclient` e mantieni `rpcclient` per la parte “dominio”.
* Se la tua fonte principale è LDAP (directory-centric) invece di RPC: `ldapsearch` è spesso più coerente e scriptabile.
* Se devi trasformare enumerazione in path d’escalation realistici: BloodHound è lo standard de-facto in lab AD.

Quando NON usarle: se ti serve una query “chirurgica” su un oggetto specifico (utente/gruppo/SID), `rpcclient` resta una delle scelte più pulite.

## Hardening & detection: cosa guarda un defender quando usi rpcclient

> **In breve:** `rpcclient` genera attività di autenticazione di rete e chiamate RPC; la difesa si basa su auditing, riduzione dell’enumerazione e policy “no anonymous”.

Detection (lab blu team):

* Correlazione di autenticazioni di rete ripetute verso DC/member server in burst brevi.
* Sequenze di query RPC “enumerative” (pattern: query dominio → enum utenti → enum gruppi) da host non amministrativi.
* Anomalie temporali: enumerazione massiva fuori dalle finestre di amministrazione.

Hardening:

* Disabilita anonymous/guest e limita “information disclosure” via RPC per utenti standard.
* Segrega gli asset AD: riduci chi può parlare con DC su SMB/RPC.
* Applica auditing coerente su logon di rete e accessi remoti amministrativi, e alert su comportamenti enumerativi.

## Scenario pratico: rpcclient su una macchina HTB/PG

Ambiente: attacker Kali su VPN lab, target `10.10.10.10` (Windows/AD lab).
Obiettivo: ottenere userlist e policy password in modo ripetibile e “reportabile”.

Azione 1 (test anonimo):

```
rpcclient -U '' -N 10.10.10.10 -c 'srvinfo'
```

Azione 2 (dump iniziale con credenziali low-priv del lab):

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; enumdomusers; enumdomgroups'
```

Azione 3 (policy password per valutazione rischio):

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'getdompwinfo'
```

Risultato atteso concreto: ottieni una lista utenti (con RID) e parametri base policy password da riportare come evidenza.

Detection + hardening: se la rete è ben configurata, l’accesso anonimo fallisce e i comandi enumerativi sono limitati a ruoli autorizzati. Un defender dovrebbe alertare su burst di chiamate RPC e autenticazioni di rete da host non admin.

## Playbook 10 minuti: rpcclient in un lab

### Step 1 – Verifica contesto e obiettivo

Perché: definisci cosa vuoi estrarre (utenti, gruppi, policy) e con quali credenziali lab.
Cosa aspettarti: un target IP e un set minimo di comandi.
Comando:

```
echo "Target: 10.10.10.10 | Goal: users+groups+pwpolicy" > notes_rpcclient.txt
```

### Step 2 – Prova anonymous/null session (solo disclosure)

Perché: se passa, hai un finding immediato di information disclosure.
Cosa aspettarti: prompt o access denied.
Comando:

```
rpcclient -U '' -N 10.10.10.10 -c 'srvinfo'
```

### Step 3 – Login con credenziali low-priv del lab

Perché: molte enumerazioni funzionano anche con account standard.
Cosa aspettarti: output dei comandi o access denied su quelli più sensibili.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; srvinfo'
```

### Step 4 – Dump utenti + gruppi (baseline)

Perché: ti serve la mappa base per qualunque analisi successiva.
Cosa aspettarti: userlist con RID e gruppi disponibili.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'enumdomusers; enumdomgroups'
```

### Step 5 – Profilazione di un account “interessante”

Perché: i dettagli dell’account spesso guidano la prossima mossa in lab.
Cosa aspettarti: attributi e/o gruppi associati.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'queryuser svc_sql'
```

### Step 6 – Policy password + share info (report-ready)

Perché: sono evidenze “difendibili” nel report (posture, exposure).
Cosa aspettarti: parametri policy e nomi share.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'getdompwinfo; netshareenumall'
```

### Step 7 – Salva output e annota limiti

Perché: senza evidence salvata, non hai ripetibilità.
Cosa aspettarti: file di output consultabile.
Comando:

```
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; enumdomusers; enumdomgroups; getdompwinfo' > rpcclient_dump.txt
```

## Checklist operativa

* Ho confermato che il target è lab/CTF/VM autorizzata.
* Ho provato `-U '' -N` solo per verificare disclosure anonima.
* Ho usato `-c` per dump ripetibili e salvabili.
* Ho eseguito `querydominfo` e `srvinfo` prima delle enum massicce.
* Ho estratto `enumdomusers` e annotato i RID.
* Ho eseguito `enumdomgroups` e scelto gruppi da approfondire.
* Ho profilato almeno 1 account con `queryuser`.
* Ho controllato `getdompwinfo` per valutazione postura.
* Ho enumerato share via `netshareenumall` (se permesso).
* Ho salvato output in file con timestamp e note.
* Ho annotato comandi che tornano `ACCESS_DENIED` (limiti di permesso).
* Ho definito detection/hardening nel report (no anonymous, auditing, segmentation).

## Riassunto 80/20

| Obiettivo                      | Azione pratica                | Comando/Strumento                      |         |
| ------------------------------ | ----------------------------- | -------------------------------------- | ------- |
| Entrare e capire contesto      | Domenio + server info         | `rpcclient -c 'querydominfo; srvinfo'` |         |
| Costruire userlist             | Enumerare utenti dominio      | `rpcclient -c 'enumdomusers'`          |         |
| Capire la superficie “gruppi”  | Enumerare gruppi e membership | `rpcclient -c 'enumdomgroups'`         |         |
| Profilare un account target    | Query dettagli utente         | \`rpcclient -c 'queryuser \<user       | rid>'\` |
| Valutare postura password      | Leggere policy                | `rpcclient -c 'getdompwinfo'`          |         |
| Individuare share interessanti | Enum share via RPC            | `rpcclient -c 'netshareenumall'`       |         |

## Concetti controintuitivi

* **“Se ho 445 aperta allora posso enumerare tutto”**
  No: molte enum richiedono permessi e policy; `ACCESS_DENIED` non è “errore tool”, è hardening (o permessi insufficienti in lab).
* **“Il nome utente basta, non mi servono RID/SID”**
  In ambienti AD reali i RID/SID evitano ambiguità e ti permettono query affidabili anche quando i nomi non risolvono bene.
* **“Null session è sempre possibile”**
  Su ambienti moderni spesso è bloccata; va testata, documentata e poi si passa a credenziali autorizzate nel lab.
* **“rpcclient è un tool da file share”**
  No: è dominio/RPC-centric. Per file e loot su share usa strumenti SMB file-centric e tieni rpcclient per identity/policy.

## FAQ

D: `rpcclient -U '' -N` non entra, è normale?

R: Sì, su ambienti moderni l’anonymous è spesso disabilitato. In lab documentalo come “null session non consentita” e usa credenziali autorizzate.

D: Posso usare `rpcclient` senza shell interattiva?

R: Sì: usa `-c 'cmd1; cmd2'` per eseguire comandi one-shot e salvare output in file (`> dump.txt`).

D: `enumdomusers` mi dà `ACCESS_DENIED`, che faccio?

R: Significa che l’account non ha permessi o che la policy limita l’enumerazione. In lab cambia fonte (LDAP/SMB) o usa un account esplicitamente autorizzato.

D: Quando preferisco strumenti alternativi?

R: Se vuoi automation/report rapido usa strumenti di enum “bulk”; se vuoi file browsing usa tool SMB file-centric; se vuoi pathing di escalation usa un graph tool AD.

D: `rpcclient` è utile anche su host non-DC?

R: Sì: puoi interrogare servizi RPC disponibili sul target, ma l’enumerazione “di dominio” dipende dal ruolo della macchina e dai permessi.

## Link utili su HackIta.it

* [Enum4linux-ng: enumerazione avanzata su reti Windows](/articoli/enum4linux-ng/)
* [Smbclient: accesso e attacco alle condivisioni Windows](/articoli/smbclient/)
* [CrackMapExec: attacchi rapidi su Active Directory](/articoli/crackmapexec/)
* [Responder: attacco LLMNR/NBT-NS/WPAD per hash NTLM](/articoli/responder/)
* [NBTScan: scansione NetBIOS per info sensibili](/articoli/nbtscan/)
* [Rpcinfo: enumerazione dei servizi RPC in ambienti Unix](/articoli/rpcinfo/)

Pagine istituzionali:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

* [https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)

## CTA finale HackITA

Se questo contenuto ti è utile, supporta il progetto: trovi tutto su /supporto/ per tenere HackIta indipendente e pieno di guide operative.

Se vuoi accelerare davvero su AD/RPC/SMB con lab guidati e correzione degli errori “da esame”, trovi la formazione 1:1 su /servizi/.

Per aziende e team: assessment, hardening e simulazioni di attacco in ambienti autorizzati sono su /servizi/.
