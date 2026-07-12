---
title: 'samrdump.py Impacket: Enumerare Utenti Windows via SAMR'
slug: samrdump
description: 'Guida a samrdump.py di Impacket per enumerare utenti Windows via MS-SAMR su SMB, ottenere RID e attributi account con password, hash NTLM o Kerberos.'
image: /samrdump-enumerazione-utenti-gruppi-share-samr.webp
draft: true
date: 2026-07-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - samrdump
  - samr
  - windows-enumeration
  - active-directory
---

# Come enumerare account Windows via SAMR con samrdump.py

`samrdump.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e sfrutta il protocollo MS-SAMR per enumerare account utente e i loro attributi su un sistema Windows, via SMB. Interroga il **primo dominio SAM restituito** dal target, elenca i suoi utenti e per ognuno recupera un set di attributi (nome completo, commenti, contatore password errate, stato dell'account). **Non enumera gruppi, alias, membri di gruppo, né condivisioni** — nonostante alcune guide online (anche note) lo diano per scontato, il codice attuale non chiama nessuna funzione per farlo.

A differenza di [GetADUsers.py](https://hackita.it/articoli/getadusers/) che usa LDAP e deve puntare al DC, samrdump funziona contro qualsiasi host Windows — workstation, member server, DC — purché l'account con cui ti autentichi sia autorizzato a fare chiamate SAMR remote su quel target. Non è automatico: dipende dalla policy `RestrictRemoteSAM` del target, di cui parliamo più sotto.

Riferimento ufficiale: [fortra/impacket — samrdump.py](https://github.com/fortra/impacket/blob/master/examples/samrdump.py)

## Come funziona davvero

```
1. Connessione SMB (porta 445 o 139) verso la named pipe \pipe\samr
2. Bind sull'interfaccia MS-SAMR
3. hSamrConnect → apre l'handle al server SAM
4. hSamrEnumerateDomainsInSamServer → elenca TUTTI i domini SAM trovati (li stampa tutti)
5. hSamrOpenDomain sul PRIMO dominio della lista → apre solo quello
6. hSamrEnumerateUsersInDomain → elenca gli utenti di quel dominio
7. Per ogni utente:
   hSamrOpenUser → apre il contesto utente
   hSamrQueryInformationUser2 (UserAllInformation) → recupera gli attributi
8. Stampa i risultati (tabella o CSV)
```

Nessuna chiamata a funzioni di enumerazione alias/gruppi, nessuna interazione con share. Se vedi un output con `Found alias: Domain Admins, rid = 512` da qualche parte online, non viene da questa versione del tool.

**Differenza chiave rispetto a GetADUsers.py:**

|                           | `samrdump.py`                                       | `GetADUsers.py`                                    |
| ------------------------- | --------------------------------------------------- | -------------------------------------------------- |
| Protocollo                | MS-SAMR via SMB (445/139)                           | LDAP (389)                                         |
| Target                    | Qualsiasi host Windows raggiungibile via SAMR       | Solo Domain Controller                             |
| Mostra account locali     | Sì                                                  | No                                                 |
| Mostra account di dominio | Sì, se punti al DC                                  | Sì, sempre                                         |
| Attributi mostrati        | RID, nome completo, commenti, contatori, stato base | `sAMAccountName`, email, `pwdLastSet`, `lastLogon` |
| Gruppi/OU                 | No                                                  | No (nessuno dei due)                               |

## Sintassi e opzioni reali

```bash
impacket-samrdump [opzioni] [[dominio/]utente[:password]@]target
```

| Opzione           | Descrizione                                                              |
| ----------------- | ------------------------------------------------------------------------ |
| `-csv`            | Output in formato CSV (vero CSV, separato da virgole)                    |
| `-dc-ip IP`       | IP del Domain Controller                                                 |
| `-target-ip IP`   | IP del target — utile quando il target è un nome NetBIOS non risolvibile |
| `-port {139,445}` | Porta SMB (default: 445) — solo questi due valori sono accettati         |
| `-hashes LM:NT`   | Pass-the-Hash                                                            |
| `-aesKey KEY`     | Chiave AES per Kerberos — impostarla forza automaticamente `-k`          |
| `-k`              | Autenticazione Kerberos                                                  |
| `-no-pass`        | Non chiedere la password                                                 |
| `-ts`             | Timestamp nei log                                                        |
| `-debug`          | Output verboso                                                           |

**Non esiste** un argomento posizionale tipo `139/SMB` o `445/SMB` in coda al target — è un errore che gira in alcune guide. La porta si imposta solo con `-port`.

## Utilizzo pratico

### Base — con password

```bash
# Domain Controller — utenti di dominio
impacket-samrdump corp.local/user:Password123@10.10.10.5

# Workstation — account locali (Administrator, utenti locali)
impacket-samrdump ./administrator:Password123@10.10.10.50
```

### Pass-the-Hash

```bash
impacket-samrdump -hashes :NThash corp.local/administrator@10.10.10.5
```

### Kerberos, con hostname e IP separati

```bash
export KRB5CCNAME=/path/to/ticket.ccache

impacket-samrdump \
  -k -no-pass \
  -dc-ip 10.10.10.5 \
  -target-ip 10.10.10.50 \
  corp.local/user@WS01.corp.local
```

`-target-ip` conta quando usi un hostname come target (necessario per Kerberos) ma vuoi forzare la connessione verso un IP specifico — se lo ometti, il tool usa lo stesso valore del target.

### Output CSV — per analisi offline

```bash
impacket-samrdump -csv corp.local/user:pass@10.10.10.5 > samrdump_output.csv
```

### Via porta 139 (fallback se 445 è bloccata)

```bash
impacket-samrdump -port 139 corp.local/user:'Password123!'@10.10.10.5
```

## Output e come leggerlo

**Formato normale (senza `-csv`):**

```
Found domain(s):
 . CORP
 . Builtin
Found user: Administrator, uid = 500
Administrator (500)/FullName:
Administrator (500)/AdminComment: Account amministrativo predefinito
Administrator (500)/UserComment:
Administrator (500)/PrimaryGroupId: 513
Administrator (500)/BadPasswordCount: 0
Administrator (500)/LogonCount: 47
Administrator (500)/PasswordLastSet: 2024-01-15 10:23:11
Administrator (500)/PasswordDoesNotExpire: True
Administrator (500)/AccountIsDisabled: False
Administrator (500)/ScriptPath:
```

Nota: il tool stampa `uid` nell'output, ma tecnicamente quel numero è il **RID** (Relative Identifier).

**Formato CSV (`-csv`), header reale:**

```
#Name,RID,FullName,PrimaryGroupId,BadPasswordCount,LogonCount,PasswordLastSet,PasswordDoesNotExpire,AccountIsDisabled,AdminComment,UserComment,ScriptPath
Administrator,500,,513,0,47,2024-01-15 10:23:11,True,False,Account amministrativo predefinito,,
svc_sql,1104,SQL Service,513,0,12,2019-03-10 12:00:00,False,False,,,
```

**Come interpretare i campi reali:**

| Campo                          | Significato                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------ |
| `RID` (`uid` in output)        | Identificatore relativo dell'account, ultima parte del SID                                       |
| `FullName`                     | Nome completo impostato sull'account                                                             |
| `PrimaryGroupId`               | RID del gruppo primario dell'utente                                                              |
| `BadPasswordCount`             | Contatore tentativi falliti, riportato dal target interrogato                                    |
| `LogonCount`                   | Numero di logon registrati                                                                       |
| `PasswordLastSet`              | Ultima impostazione password — vecchia non equivale automaticamente a debole, solo a non ruotata |
| `PasswordDoesNotExpire`        | La password è configurata per non scadere — non significa che sia debole o nota                  |
| `AccountIsDisabled`            | Stato disabilitato dell'account                                                                  |
| `AdminComment` / `UserComment` | Commenti testuali — a volte contengono credenziali dimenticate                                   |
| `ScriptPath`                   | Script di logon associato                                                                        |

**Il tool NON restituisce:** gruppi, membri di gruppo, share, `msDS-SupportedEncryptionTypes` (RC4/AES supportati), flag `PasswordNotRequired`, stato di lock dell'account, o data di scadenza.

## RID — cosa sono e cosa non dimostrano

Il RID identifica l'account all'interno del dominio; unito al SID del dominio forma il SID completo (`S-1-5-21-X-Y-Z-RID`). Alcuni RID sono fissi per convenzione:

```
500 = Administrator incorporato
501 = Guest
502 = krbtgt (solo su DC, in un dominio Active Directory)
```

**Attenzione:** questi sono RID di account **utente**. `samrdump.py` non enumera gruppi, quindi non aspettarti di vedere RID di gruppo (512 = Domain Admins, 519 = Enterprise Admins, ecc.) nel suo output.

**Un RID 501 (Guest) presente e non disabilitato non equivale ad accesso anonimo possibile.** Verifica separatamente la configurazione SMB prima di concludere che l'accesso anonimo funzioni.

```bash
# Per ottenere il SID del dominio, serve un altro tool
impacket-lookupsid corp.local/user:pass@10.10.10.5 | head -5
```

Con RID e SID del dominio puoi poi costruire ticket Kerberos forgiati (vedi [Golden Ticket](https://hackita.it/articoli/golden-ticket/)).

## samrdump.py funziona senza credenziali?

Le **null session** erano il modo classico per fare enumerazione SAMR senza credenziali. Su sistemi moderni dipendono da diversi fattori configurabili indipendentemente: `RestrictAnonymous`, accesso anonimo a share/named pipe, e soprattutto la policy `RestrictRemoteSAM`.

```bash
impacket-samrdump ''@10.10.10.5
impacket-samrdump 10.10.10.5
```

Da Windows 10 1607 / Server 2016 in poi, il descrittore di sicurezza predefinito per `RestrictRemoteSAM` limita l'accesso SAM remoto ai soli amministratori locali sui sistemi **non-DC**; sui Domain Controller invece il default resta più permissivo (storicamente `Everyone`), anche se può essere ristretto tramite policy. Un buon riferimento pratico è [questo articolo su SAM Remote access enumeration](https://itworldjd.wordpress.com/2022/04/29/ad-sam-remote-access-enumeration/), oltre alla [documentazione Microsoft su RestrictRemoteSAM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls).

## Differenza tra workstation, member server e Domain Controller

| Target                    | Account generalmente enumerati                                                |
| ------------------------- | ----------------------------------------------------------------------------- |
| Workstation standalone    | Account locali                                                                |
| Member workstation/server | Account del SAM locale, se l'account che usi passa `RestrictRemoteSAM`        |
| Domain Controller         | Account del dominio AD esposti via SAMR (default storicamente più permissivo) |
| Samba o compatibili       | Dipende interamente dall'implementazione e configurazione                     |

## Confronto con tool alternativi

| Tool                                                     | Protocollo  | Info principali                                                          |
| -------------------------------------------------------- | ----------- | ------------------------------------------------------------------------ |
| `samrdump.py`                                            | SAMR/SMB    | RID, nome completo, commenti, gruppo primario, contatori, stato base     |
| [rpcclient](https://hackita.it/articoli/rpcclient/)      | RPC/SMB     | Utenti, gruppi, membri — più flessibile ma richiede sessione interattiva |
| [lookupsid.py](https://hackita.it/articoli/lookupsid/)   | MS-LSAT/SMB | RID bruteforce, utile per costruire il SID completo                      |
| [GetADUsers.py](https://hackita.it/articoli/getadusers/) | LDAP        | `sAMAccountName`, email, `pwdLastSet`, `lastLogon`                       |
| BloodHound                                               | LDAP+SMB    | Relazioni, gruppi, sessioni, attack path                                 |

```bash
# Alternativa con rpcclient (più flessibile per gruppi, richiede autenticazione)
rpcclient -U "corp.local/user%Password123" 10.10.10.5 -c "enumdomusers"
rpcclient -U "corp.local/user%Password123" 10.10.10.5 -c "enumdomgroups"

# Alternativa con netexec
nxc smb 10.10.10.5 -u user -p pass --users
```

**Quando samrdump.py restituisce `STATUS_ACCESS_DENIED` sull'intera enumerazione**, puoi comunque provare a interrogare singoli RID uno per uno — la policy `RestrictRemoteSAM` a volte blocca l'enumerazione di massa ma non le query puntuali:

```bash
# RID cycling manuale con rpcclient (funziona anche con null session su target permissivi)
for i in $(seq 500 1100); do
  rpcclient -N -U "" 10.10.10.5 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""
done

# Stesso concetto automatizzato con netexec
nxc smb 10.10.10.5 -u '' -p '' --rid-brute
```

**Quando usare samrdump.py invece delle alternative:** vuoi specificamente gli attributi esposti da `SamrQueryInformationUser2` (commenti, contatori, PrimaryGroupId) su un host preciso, o ti serve un CSV pronto da processare senza passare da rpcclient interattivo.

## Workflow tipico

```
samrdump.py
│
├── Ottieni username e RID
│   ├── userlist per controlli autorizzati (password spraying, solo dopo aver verificato lockout policy)
│   └── correlazione con lookupsid.py per il SID completo
│
├── Account con AdminComment/UserComment sospetti
│   └── a volte contengono credenziali dimenticate in chiaro
│
├── Nomi che sembrano service account (svc_*)
│   └── verifica reale con GetUserSPNs.py — il nome da solo non dimostra nulla
│
├── Account di dominio ottenuti da un DC
│   ├── GetNPUsers.py per verificare no-preauth reale
│   └── BloodHound/LDAP per gruppi e privilegi (samrdump non li mostra)
│
└── Account locali ottenuti da un member server
    └── verifica separata di gruppi locali e diritti (rpcclient, nxc)
```

## Detection

Non esistono Event ID "dedicati" a samrdump specifico — quello che si osserva è traffico SAMR generico, indistinguibile da altri tool che usano la stessa interfaccia:

* Autenticazione SMB e logon di rete verso il target
* Connessione a `IPC$` e accesso alla named pipe `\pipe\samr`
* Traffico DCE/RPC su interfaccia MS-SAMR — molte chiamate `SamrOpenUser`/`SamrQueryInformationUser` in sequenza sono un pattern enumerativo
* Sorgenti non amministrative che interrogano un numero elevato di account
* Event ID `5145` se è abilitato il Detailed File Share Auditing
* Telemetria EDR/NDR su SMB e RPC resta il segnale più affidabile, più della singola voce di log

Non esiste una regola generale per cui un tool di enumerazione sia "sempre più silenzioso" di un altro.

## Errori comuni

| Errore                           | Causa probabile                                                              | Verifica                                                         |
| -------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `STATUS_LOGON_FAILURE`           | Credenziali o dominio errati                                                 | Controlla formato e materiale di autenticazione                  |
| `STATUS_ACCESS_DENIED`           | Account escluso dalle ACL SAMR o dalla policy `RestrictRemoteSAM` sul target | Non presumere serva sempre un admin                              |
| `STATUS_PIPE_NOT_AVAILABLE`      | Named pipe SAMR non disponibile                                              | Controlla SMB, `IPC$` e firewall                                 |
| Timeout                          | Porta 139/445 filtrata o routing errato                                      | Verifica connettività, prova `-target-ip`                        |
| Errore hostname/KDC con Kerberos | Target indicato solo tramite IP                                              | Usa FQDN come target e `-target-ip` per la connessione effettiva |
| Nessuna entry ricevuta           | Dominio SAM aperto ma nessun utente recuperato                               | Attiva `-debug` e verifica il tipo di target                     |

## Cheat Sheet

```bash
# Base con credenziali
impacket-samrdump corp.local/user:pass@TARGET

# Workstation — account locali
impacket-samrdump ./administrator:pass@WORKSTATION

# Pass-the-Hash
impacket-samrdump -hashes :NThash corp.local/user@TARGET

# Output CSV per analisi
impacket-samrdump -csv corp.local/user:pass@TARGET > output.csv

# Kerberos con hostname/IP separati
export KRB5CCNAME=ticket.ccache
impacket-samrdump -k -no-pass -dc-ip DC_IP -target-ip TARGET_IP corp.local/user@WS01.corp.local

# Via porta 139 (fallback)
impacket-samrdump -port 139 corp.local/user:pass@TARGET

# Null session (riesce solo se la policy lo permette)
impacket-samrdump ''@TARGET

# Cerca account con password che non scade
impacket-samrdump -csv corp.local/user:pass@TARGET | awk -F, '$8=="True"'
```

## Articoli correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [SMB](https://hackita.it/articoli/smb/)
* [rpcdump.py](https://hackita.it/articoli/rpcdump/)
* [rpcclient](https://hackita.it/articoli/rpcclient/)
* [lookupsid.py](https://hackita.it/articoli/lookupsid/)
* [GetADUsers.py](https://hackita.it/articoli/getadusers/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)
* [Golden Ticket](https://hackita.it/articoli/golden-ticket/)

> Uso esclusivo in ambienti autorizzati.
