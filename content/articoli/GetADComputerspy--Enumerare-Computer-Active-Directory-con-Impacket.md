---
title: GetADComputers.py — Enumerare Computer Active Directory con Impacket
slug: getadcomputers
description: 'Guida a impacket-GetADComputers per enumerare computer Active Directory via LDAP, -resolveIP ,auth con password, hash NTLM, Kerberos, ccache o chiavi AES.'
image: /getadcomputers-py-enumerazione-computer-active-directory.webp
draft: true
date: 2026-07-28T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - impacket
  - getadcomputers
  - ldap
  - computer-account
  - network-discovery
---

# GetADComputers.py: enumerazione dei computer Active Directory via LDAP

`GetADComputers.py` interroga un Domain Controller tramite LDAP e restituisce gli oggetti computer del dominio con `sAMAccountName`, hostname DNS, sistema operativo e versione. L’opzione corretta per aggiungere un indirizzo IPv4 è `-resolveIP`. Il tool supporta password, hash NTLM, Kerberos, ccache e chiavi AES, ma non mostra `PasswordLastSet`, `LastLogon`, stato dell’account, ruoli, servizi o vulnerabilità.

`GetADComputers.py` è uno degli script inclusi in [Impacket](https://hackita.it/articoli/impacket/) e serve a costruire rapidamente un inventario LDAP dei computer presenti in un dominio Active Directory.

A differenza di scanner di rete e framework più estesi, non effettua una scansione delle porte e non verifica se le macchine siano accese. Interroga il database di Active Directory e stampa soltanto gli attributi richiesti dal proprio parser.

Questa guida è stata verificata sul codice di:

* **Impacket 0.13.1**, release stabile corrente;
* branch **`master`**, identificato dal progetto come versione di sviluppo 0.14.0-dev;
* helper LDAP e Kerberos condivisi in `impacket/examples/utils.py`.

Nelle sezioni rilevanti non risultano differenze funzionali tra la release stabile e `master`: parser, filtro LDAP, attributi richiesti, output e risoluzione DNS coincidono.

Riferimenti ufficiali:

* [GetADComputers.py — release Impacket 0.13.1](https://github.com/fortra/impacket/blob/impacket_0_13_1/examples/GetADComputers.py)
* [GetADComputers.py — branch master](https://github.com/fortra/impacket/blob/master/examples/GetADComputers.py)
* [Helper LDAP e Kerberos di Impacket](https://github.com/fortra/impacket/blob/master/impacket/examples/utils.py)
* [Release ufficiali Impacket](https://github.com/fortra/impacket/releases)

***

## Cosa fa realmente GetADComputers.py

Il tool costruisce il Base DN dal dominio fornito e invia al Domain Controller questo filtro LDAP:

```text
(&(objectCategory=computer)(objectClass=computer))
```

La ricerca è paginata in blocchi da 100 risultati e richiede soltanto quattro attributi:

```text
sAMAccountName
dNSHostName
operatingSystem
operatingSystemVersion
```

Con `-resolveIP`, per ogni valore `dNSHostName` viene inoltre effettuata una query DNS di tipo `A` verso il Domain Controller specificato con `-dc-ip`.

In pratica, il tool può restituire:

| Campo          | Significato                                                             |
| -------------- | ----------------------------------------------------------------------- |
| `SAM AcctName` | Nome SAM del computer account, normalmente terminante con `$`           |
| `DNS Hostname` | FQDN registrato nell’attributo `dNSHostName`                            |
| `OS Version`   | Valore di `operatingSystemVersion`                                      |
| `OS`           | Valore di `operatingSystem`                                             |
| `IPAddress`    | Un indirizzo IPv4 ottenuto con una query DNS `A`, solo con `-resolveIP` |

`GetADComputers.py` è quindi utile per:

* ottenere un inventario iniziale dei computer account;
* identificare convenzioni di naming;
* distinguere indicativamente client e server tramite gli attributi del sistema operativo;
* ricavare FQDN da usare in successive verifiche;
* risolvere gli hostname in IPv4 tramite il DNS del DC;
* preparare liste per strumenti complementari.

Non fornisce invece una mappa completa e verificata dell’infrastruttura. Un oggetto presente in Active Directory può essere disabilitato, obsoleto, non più esistente, spento o associato a un record DNS non aggiornato.

***

## Cosa non restituisce

La versione verificata **non richiede e non stampa**:

* indirizzo e-mail;
* `pwdLastSet` o `PasswordLastSet`;
* `lastLogon`;
* `lastLogonTimestamp`;
* stato abilitato o disabilitato;
* `userAccountControl`;
* Distinguished Name e OU;
* Service Principal Name;
* delegazioni Kerberos;
* ACL dell’oggetto;
* sessioni utente;
* porte aperte;
* servizi attivi;
* livello di patch;
* vulnerabilità;
* presenza di LAPS;
* privilegi locali o di dominio.

Di conseguenza, non è corretto dedurre dall’output che:

* una password macchina sia vecchia o debole;
* un computer account sia vulnerabile a takeover;
* un sistema sia raggiungibile;
* Windows Server 2016 sia automaticamente vulnerabile a EternalBlue o PrintNightmare;
* un host con edizione “Datacenter” sia un Domain Controller;
* un computer possa essere sfruttato tramite RBCD o Shadow Credentials.

Queste verifiche richiedono attributi LDAP aggiuntivi o strumenti differenti.

***

## Prerequisiti e privilegi richiesti

Il target posizionale deve contenere almeno il dominio:

```text
dominio[/utente[:password]]
```

Il tool non usa la sintassi `utente@target` tipica di altri script Impacket. Il Domain Controller viene indicato separatamente tramite `-dc-ip` e, quando utile, `-dc-host`.

In un dominio configurato normalmente, un utente autenticato a basso privilegio può generalmente leggere gli attributi non riservati richiesti dal tool. Non sono necessari privilegi Domain Admin, ma ACL personalizzate o policy di hardening possono limitare la visibilità.

`-no-pass` non equivale a una modalità anonima: evita soltanto il prompt della password ed è pensato soprattutto per Kerberos e ccache. Lo script non espone un’opzione specifica per l’anonymous bind e non va presentato come strumento affidabile di enumerazione senza credenziali.

***

## Porte, protocolli e traffico generato

| Porta      | Protocollo | Quando viene usata                                                                             |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------- |
| TCP 389    | LDAP       | Connessione iniziale al Domain Controller                                                      |
| TCP 636    | LDAPS      | Fallback automatico se LDAP restituisce `strongerAuthRequired`                                 |
| TCP 53     | DNS        | Query `A` con `-resolveIP`                                                                     |
| TCP/UDP 88 | Kerberos   | Acquisizione o utilizzo dei ticket quando necessario                                           |
| TCP 445    | SMB        | Può essere contattata dall’helper condiviso per ricavare il nome macchina in modalità Kerberos |

Il tool non utilizza named pipe e non interroga direttamente workstation o member server. La query LDAP e, con `-resolveIP`, le query DNS vengono inviate al Domain Controller.

### Attenzione al traffico SMB con Kerberos

Nella versione verificata, `GetADComputers.py` usa l’helper condiviso `ldap_login()`. Quando `-k` è attivo, l’helper chiama `_get_machine_name()` e apre una connessione SMB verso il DC per ricavarne il nome NetBIOS.

Per questo motivo non bisogna descrivere la modalità Kerberos come esclusivamente LDAP/Kerberos o come priva di traffico SMB.

L’opzione `-dc-host` è comunque importante per indicare il Domain Controller corretto e mantenere coerenti hostname, SPN e risoluzione. Nel percorso di codice attuale, però, la modalità Kerberos richiama comunque `_get_machine_name()` sul target selezionato.

***

## Sintassi corretta

```bash
impacket-GetADComputers [opzioni] dominio[/utente[:password]]
```

Il nome del file Python è:

```bash
GetADComputers.py
```

Nelle distribuzioni che installano i wrapper Impacket, come Kali Linux, il comando è normalmente:

```bash
impacket-GetADComputers
```

Controlla sempre il parser della versione installata:

```bash
impacket-GetADComputers -h
```

***

## Opzioni realmente presenti nel parser

| Opzione                 | Descrizione reale                                                                |
| ----------------------- | -------------------------------------------------------------------------------- |
| `-user username`        | Presente nel parser, ma non applicata al filtro LDAP nella versione verificata   |
| `-resolveIP`            | Risolve il record DNS `A` dei valori `dNSHostName` interrogando il DC            |
| `-dc-ip IP`             | Indirizzo IP del Domain Controller                                               |
| `-dc-host HOST`         | Hostname del Domain Controller                                                   |
| `-hashes LMHASH:NTHASH` | Autenticazione NTLM tramite hash                                                 |
| `-k`                    | Autenticazione Kerberos, con possibile uso della ccache indicata da `KRB5CCNAME` |
| `-no-pass`              | Evita il prompt della password                                                   |
| `-aesKey HEX`           | Chiave AES-128 o AES-256 per Kerberos                                            |
| `-ts`                   | Aggiunge timestamp ai messaggi di log                                            |
| `-debug`                | Abilita informazioni diagnostiche aggiuntive                                     |

Queste opzioni **non esistono** nel parser corrente:

```text
-all
-resolve
-outputfile
-o
-ldaps
-target-ip
```

LDAP viene già usato per enumerare tutti gli oggetti che corrispondono al filtro. Non serve quindi alcuna opzione `-all`.

Per salvare l’output bisogna usare la redirezione della shell, perché `-outputfile` non è supportata.

***

## La limitazione dell’opzione -user

Il parser dichiara:

```text
-user username
```

e il valore viene assegnato internamente a:

```python
self.__requestUser
```

Nella release 0.13.1 e nel branch `master`, però, questa variabile non viene utilizzata per modificare il filtro LDAP:

```text
(&(objectCategory=computer)(objectClass=computer))
```

Di conseguenza:

```bash
impacket-GetADComputers corp.local/user:pass \
  -dc-ip 10.10.10.5 \
  -user WS01$
```

non limita realmente la ricerca a `WS01$`.

L’opzione è presente nell’help ma, nel codice verificato, non produce il filtro specifico descritto dalla propria help string.

Per interrogare un singolo computer è preferibile usare `ldapsearch`, una query LDAP raw di NetExec oppure PowerShell.

***

## Utilizzo con password

### Password richiesta in modo interattivo

Evitare la password nella command line riduce la possibilità che rimanga visibile nella cronologia o nell’elenco dei processi:

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5
```

Il tool richiederà la password tramite prompt.

### Password nella stringa target

```bash
impacket-GetADComputers 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5
```

Le virgolette sono importanti quando la password contiene caratteri interpretati dalla shell.

***

## Pass-the-Hash

`GetADComputers.py` supporta l’autenticazione NTLM tramite `-hashes`.

```bash
impacket-GetADComputers corp.local/user \
  -hashes :NTHASH \
  -dc-ip 10.10.10.5
```

Formato completo:

```bash
impacket-GetADComputers corp.local/user \
  -hashes LMHASH:NTHASH \
  -dc-ip 10.10.10.5
```

Quando l’LM hash non è disponibile, la forma `:NTHASH` è normalmente sufficiente. Per il funzionamento generale di questa modalità consulta anche la guida al [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/).

Il successo dipende dalle policy del dominio e dai meccanismi di autenticazione consentiti dal Domain Controller.

***

## Kerberos con ccache

Esporta il ticket cache:

```bash
export KRB5CCNAME=/path/to/user.ccache
```

Esegui quindi:

```bash
impacket-GetADComputers corp.local/user \
  -k \
  -no-pass \
  -dc-host DC01.corp.local \
  -dc-ip 10.10.10.5
```

Requisiti importanti:

* il dominio deve essere corretto;
* il principal nella ccache deve essere coerente con l’utente indicato;
* l’orario del client deve essere sincronizzato con il dominio;
* hostname e DNS devono essere coerenti con gli SPN;
* il KDC deve essere raggiungibile;
* nella versione corrente viene effettuata anche una connessione SMB al DC per il machine-name discovery.

Controlla i ticket disponibili con:

```bash
klist
```

***

## Kerberos con chiave AES

Il parser supporta chiavi Kerberos AES-128 e AES-256:

```bash
impacket-GetADComputers corp.local/user \
  -aesKey AES256_HEX_KEY \
  -dc-host DC01.corp.local \
  -dc-ip 10.10.10.5
```

Non è obbligatorio aggiungere manualmente `-k`: il parser condiviso di Impacket abilita automaticamente Kerberos quando viene fornita `-aesKey`.

La chiave deve appartenere al principal specificato e deve avere formato e lunghezza corretti.

***

## Risolvere gli indirizzi IPv4 con -resolveIP

L’opzione corretta è:

```bash
-resolveIP
```

Esempio:

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -resolveIP
```

Nella versione verificata, il codice sostituisce il resolver DNS predefinito e imposta come nameserver il valore di `-dc-ip`.

Per questo motivo devi fornire esplicitamente un indirizzo DC valido quando usi `-resolveIP`. Senza `-dc-ip`, il valore assegnato alla lista dei nameserver può essere assente e la risoluzione può fallire.

Il tool:

1. legge `dNSHostName` dall’oggetto computer;
2. invia una query DNS `A` su TCP;
3. stampa un IPv4 se la risoluzione riesce;
4. lascia vuoto il campo in caso di eccezione.

Limitazioni:

* non interroga record `AAAA`;
* non restituisce IPv6;
* non verifica se l’host risponde;
* se esistono più record `A`, il ciclo interno sovrascrive il valore e l’output mostra soltanto l’ultimo indirizzo elaborato;
* un record DNS valido non dimostra che l’host sia acceso;
* un errore DNS non dimostra che l’oggetto sia inutilizzabile.

***

## Salvare l’output

`-outputfile` non esiste. Usa la redirezione:

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -resolveIP > /tmp/getadcomputers.txt
```

Per separare stdout e messaggi di errore:

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -resolveIP \
  > /tmp/getadcomputers.txt \
  2> /tmp/getadcomputers-errors.txt
```

Il file può contenere informazioni sensibili sull’infrastruttura interna.

***

## Output reale e interpretazione

Senza `-resolveIP`, le intestazioni generate dal codice sono:

```text
SAM AcctName    DNS Hostname                        OS Version      OS
--------------- ----------------------------------- --------------- --------------------
```

Un output rappresentativo del formato è:

```text
SAM AcctName    DNS Hostname                        OS Version      OS
--------------- ----------------------------------- --------------- -----------------------------------
DC01$           DC01.corp.local                     10.0 (20348)    Windows Server 2022 Standard
WS01$           WS01.corp.local                     10.0 (22631)    Windows 11 Pro
SRV-SQL$        SRV-SQL.corp.local                  10.0 (17763)    Windows Server 2019 Standard
LEGACY01$       LEGACY01.corp.local                 6.3 (9600)      Windows Server 2012 R2 Standard
```

Con `-resolveIP` viene aggiunta la colonna `IPAddress`:

```text
SAM AcctName    DNS Hostname                        OS Version      OS                                  IPAddress
--------------- ----------------------------------- --------------- ----------------------------------- --------------------
DC01$           DC01.corp.local                     10.0 (20348)    Windows Server 2022 Standard        10.10.10.5
WS01$           WS01.corp.local                     10.0 (22631)    Windows 11 Pro                      10.10.10.20
OLD-PC$         OLD-PC.corp.local                   10.0 (19045)    Windows 10 Pro
```

L’output è una tabella a larghezza fissa destinata alla lettura umana, non CSV o JSON. Stringhe molto lunghe possono rendere fragile il parsing con `awk`.

### Come leggere correttamente i campi

#### `SAM AcctName`

È il `sAMAccountName` dell’oggetto computer. Normalmente termina con `$`.

Non indica:

* che il computer sia abilitato;
* che il sistema sia online;
* che il secure channel funzioni;
* che l’oggetto non sia obsoleto.

#### `DNS Hostname`

È il valore memorizzato in `dNSHostName`.

Può essere:

* vuoto;
* non aggiornato;
* non risolvibile;
* associato a un record DNS obsoleto;
* differente dal nome con cui il sistema è raggiungibile da una determinata rete.

#### `OS` e `OS Version`

Sono attributi dichiarativi conservati nell’oggetto computer. Sono utili per prioritizzare verifiche, ma non sostituiscono il fingerprinting attivo.

Un sistema operativo precedente o fuori supporto non prova da solo:

* l’assenza di patch;
* la presenza di SMBv1;
* l’esposizione dello spooler;
* la vulnerabilità a uno specifico CVE;
* la raggiungibilità del servizio interessato.

***

## Estrarre FQDN e indirizzi IP

### Estrarre gli FQDN

```bash
awk '$1 ~ /\$$/ && $2 ~ /\./ {print $2}' \
  /tmp/getadcomputers.txt \
  > /tmp/computers-fqdn.txt
```

### Estrarre gli IPv4

```bash
awk '$NF ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ {print $NF}' \
  /tmp/getadcomputers.txt \
  > /tmp/computers-ipv4.txt
```

### Eliminare duplicati

```bash
sort -u /tmp/computers-fqdn.txt -o /tmp/computers-fqdn.txt
sort -u /tmp/computers-ipv4.txt -o /tmp/computers-ipv4.txt
```

Questi filtri dipendono dal formato corrente dell’output. Dopo un aggiornamento di Impacket, verifica nuovamente intestazioni e colonne.

***

## Query LDAP equivalente con ldapsearch

Per ottenere gli stessi attributi con una query manuale:

```bash
ldapsearch -LLL -x \
  -H ldap://DC01.corp.local \
  -D 'user@corp.local' \
  -W \
  -b 'DC=corp,DC=local' \
  '(&(objectCategory=computer)(objectClass=computer))' \
  sAMAccountName \
  dNSHostName \
  operatingSystem \
  operatingSystemVersion
```

Questa alternativa permette di modificare liberamente filtro e attributi. Consulta anche la guida Hackita a [ldapsearch](https://hackita.it/articoli/ldapsearch/).

***

## Interrogare un computer specifico

Poiché `-user` non applica realmente un filtro nella versione verificata, usa una query mirata:

```bash
ldapsearch -LLL -x \
  -H ldap://DC01.corp.local \
  -D 'user@corp.local' \
  -W \
  -b 'DC=corp,DC=local' \
  '(&(objectCategory=computer)(sAMAccountName=WS01$))' \
  sAMAccountName \
  dNSHostName \
  operatingSystem \
  operatingSystemVersion
```

Per evitare che la shell interpreti `$`, racchiudi il filtro tra apici singoli.

***

## Identificare realmente i Domain Controller

`GetADComputers.py` non richiede `userAccountControl`, quindi non può classificare con certezza i Domain Controller.

Il nome `DC01` è solo una convenzione. Anche la stringa “Datacenter” indica un’edizione di Windows Server, non il ruolo AD DS.

Microsoft definisce il flag `SERVER_TRUST_ACCOUNT` con valore decimale `8192` come indicatore di un computer account appartenente a un Domain Controller.

Query LDAP:

```bash
ldapsearch -LLL -x \
  -H ldap://DC01.corp.local \
  -D 'user@corp.local' \
  -W \
  -b 'DC=corp,DC=local' \
  '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' \
  sAMAccountName \
  dNSHostName \
  operatingSystem \
  userAccountControl
```

La matching rule OID:

```text
1.2.840.113556.1.4.803
```

esegue un confronto LDAP bitwise AND e verifica la presenza del flag specificato.

***

## Escludere i computer account disabilitati

Il flag `ACCOUNTDISABLE` vale `2`.

```bash
ldapsearch -LLL -x \
  -H ldap://DC01.corp.local \
  -D 'user@corp.local' \
  -W \
  -b 'DC=corp,DC=local' \
  '(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' \
  sAMAccountName \
  dNSHostName \
  operatingSystem \
  userAccountControl
```

`GetADComputers.py` importa internamente `UF_ACCOUNTDISABLE`, ma nel codice verificato non utilizza la costante per filtrare o contrassegnare i risultati.

***

## Analizzare computer potenzialmente obsoleti

Per un’analisi separata puoi richiedere attributi aggiuntivi:

```bash
ldapsearch -LLL -x \
  -H ldap://DC01.corp.local \
  -D 'user@corp.local' \
  -W \
  -b 'DC=corp,DC=local' \
  '(&(objectCategory=computer)(objectClass=computer))' \
  sAMAccountName \
  dNSHostName \
  distinguishedName \
  userAccountControl \
  pwdLastSet \
  lastLogonTimestamp
```

Questi valori richiedono una corretta conversione e interpretazione:

* `pwdLastSet` non dimostra che la password macchina sia debole;
* una data vecchia può indicare un host spento, isolato, dismesso o con problemi di secure channel;
* `lastLogonTimestamp` è replicato ma approssimativo;
* `lastLogon` è specifico di ciascun DC e non rappresenta automaticamente l’ultimo accesso globale.

Non collegare automaticamente queste date a RBCD, Shadow Credentials o computer account takeover: tali tecniche dipendono da ACL, flag e configurazioni specifiche.

***

## Alternativa con NetExec

[NetExec](https://hackita.it/articoli/netexec/) supporta query LDAP raw:

```bash
nxc ldap 10.10.10.5 \
  -d corp.local \
  -u user \
  -p 'Password123!' \
  --query '(&(objectCategory=computer)(objectClass=computer))' \
  'sAMAccountName dNSHostName operatingSystem operatingSystemVersion'
```

Le query raw restituiscono i valori LDAP senza applicare il formato tabellare di `GetADComputers.py`.

Controlla sempre l’help della versione installata:

```bash
nxc ldap --help
```

### Pre-created computer account

Il modulo NetExec `pre2k` appartiene a un workflow differente:

```bash
nxc ldap DC01.corp.local \
  -d corp.local \
  -u user \
  -p 'Password123!' \
  -M pre2k
```

Il modulo cerca computer account pre-creati con combinazioni specifiche di flag `userAccountControl` e può tentare di richiedere un TGT usando la password macchina predefinita derivata dal nome del computer.

Non è una funzione di `GetADComputers.py` e non deve essere eseguita soltanto perché un sistema appare vecchio nell’attributo `operatingSystem`.

È una verifica più attiva, da effettuare esclusivamente in ambienti autorizzati e dopo averne compreso l’impatto.

***

## Alternativa da Windows con PowerShell

Con il modulo ActiveDirectory:

```powershell
Get-ADComputer -Filter * `
  -Properties DNSHostName,
              OperatingSystem,
              OperatingSystemVersion,
              Enabled,
              PasswordLastSet,
              LastLogonTimestamp,
              UserAccountControl |
  Select-Object Name,
                DNSHostName,
                OperatingSystem,
                OperatingSystemVersion,
                Enabled,
                PasswordLastSet,
                LastLogonTimestamp,
                UserAccountControl
```

Questa soluzione restituisce più attributi rispetto a `GetADComputers.py`, ma richiede il modulo ActiveDirectory e un ambiente Windows o PowerShell compatibile.

***

## GetADComputers.py, GetADUsers.py e BloodHound

### GetADComputers.py

È adatto a un inventario rapido e minimale dei computer account:

* nome SAM;
* FQDN;
* sistema operativo;
* versione;
* IPv4 opzionale.

### GetADUsers.py

[GetADUsers.py](https://hackita.it/articoli/getadusers/) è focalizzato sugli account utente e usa attributi differenti.

Le opzioni dei due script non sono intercambiabili: `GetADComputers.py`, per esempio, non possiede `-all` né `-outputfile`.

### BloodHound

[BloodHound](https://hackita.it/articoli/bloodhound/) non è un semplice sostituto della tabella generata da `GetADComputers.py`.

Raccoglie relazioni, ACL, delegazioni, gruppi, sessioni e percorsi di attacco che il tool Impacket non analizza.

Usa `GetADComputers.py` per una ricognizione rapida; usa BloodHound quando servono relazioni e attack path.

***

## Workflow operativo corretto

### 1. Enumerare gli oggetti computer

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5
```

Obiettivi:

* conoscere i computer account;
* raccogliere gli FQDN;
* individuare convenzioni di naming;
* osservare gli attributi OS disponibili.

### 2. Aggiungere la risoluzione IPv4

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -resolveIP \
  > /tmp/getadcomputers.txt
```

### 3. Estrarre FQDN e IP

```bash
awk '$1 ~ /\$$/ && $2 ~ /\./ {print $2}' \
  /tmp/getadcomputers.txt |
  sort -u > /tmp/computers-fqdn.txt

awk '$NF ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ {print $NF}' \
  /tmp/getadcomputers.txt |
  sort -u > /tmp/computers-ipv4.txt
```

### 4. Verificare quali host siano realmente raggiungibili

Una verifica di rete è separata dalla query LDAP:

```bash
nmap -Pn -sT \
  -p 135,445,3389,5985,5986 \
  --open \
  -iL /tmp/computers-ipv4.txt
```

Il risultato di Nmap non va attribuito a `GetADComputers.py`.

### 5. Verificare SMB signing con uno strumento complementare

```bash
nxc smb /tmp/computers-ipv4.txt \
  --gen-relay-list /tmp/relay-targets.txt
```

Questa è una verifica SMB attiva svolta da NetExec, non da Impacket `GetADComputers.py`.

Il risultato deve essere validato con la versione corrente dello strumento e, quando necessario, con controlli manuali.

### 6. Approfondire soltanto i target rilevanti

Esempi:

* query LDAP aggiuntive per SPN e delegazioni;
* BloodHound per ACL e attack path;
* NetExec per servizi e configurazioni;
* Nmap per fingerprinting;
* verifica delle patch con strumenti dedicati;
* enumerazione SMB soltanto sugli host autorizzati.

L’attributo OS deve servire a decidere cosa verificare, non a dichiarare automaticamente una vulnerabilità.

***

## Pivot e proxychains

In presenza di un pivot, il percorso di rete deve permettere di raggiungere i servizi effettivamente usati:

```text
TCP 389    LDAP
TCP 636    LDAPS, in caso di fallback
TCP 53     DNS con -resolveIP
TCP/UDP 88 Kerberos
TCP 445    machine-name discovery in modalità Kerberos
```

Esempio generico:

```bash
proxychains4 impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5
```

La compatibilità dipende dal tipo di proxy:

* un SOCKS TCP può trasportare LDAP, LDAPS, DNS TCP e SMB;
* non tutti i proxy supportano UDP Kerberos;
* `-resolveIP` usa DNS su TCP nella versione verificata;
* la risoluzione locale del dominio e del DC deve essere coerente;
* una semplice forward della sola porta 389 può non essere sufficiente per Kerberos o `-resolveIP`.

In ambienti con DNS interno non raggiungibile può essere necessario configurare `/etc/hosts`, un resolver interno o un tunnel appropriato.

***

## Errori comuni e troubleshooting

### `unrecognized arguments: -resolve`

Causa:

```text
-resolve
```

non esiste.

Soluzione:

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -resolveIP
```

***

### `unrecognized arguments: -all`

Causa: l’opzione appartiene ad altri script o a guide non aggiornate.

Soluzione: rimuoverla. `GetADComputers.py` usa già un filtro che enumera tutti gli oggetti computer visibili.

***

### `unrecognized arguments: -outputfile`

Causa: il parser non supporta l’opzione.

Soluzione:

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  > computers.txt
```

***

### `Domain should be specified!`

Il target non contiene un dominio valido.

Errato:

```bash
impacket-GetADComputers user:pass \
  -dc-ip 10.10.10.5
```

Corretto:

```bash
impacket-GetADComputers corp.local/user:pass \
  -dc-ip 10.10.10.5
```

***

### Colonna IP vuota

Possibili cause:

* `dNSHostName` non ha un record `A`;
* il record è scaduto o rimosso;
* `-dc-ip` è errato o assente;
* TCP 53 è filtrata;
* il DNS del DC non è raggiungibile dal pivot;
* la risposta DNS non è valida;
* l’hostname è presente in AD ma non è più utilizzato.

Non significa necessariamente che il computer account sia disabilitato o che l’host non esista.

***

### Output con sole intestazioni

Possibili cause:

* nel dominio non sono presenti oggetti computer visibili;
* ACL personalizzate limitano la lettura;
* il dominio indicato genera un Base DN errato;
* è stato interrogato il dominio sbagliato;
* la ricerca LDAP non restituisce entry compatibili.

Gli errori di autenticazione o connessione vengono generalmente mostrati come eccezioni, non come una semplice tabella vuota.

Usa:

```bash
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -debug
```

***

### Campi DNS o OS vuoti

Il computer object può non avere valorizzati:

```text
dNSHostName
operatingSystem
operatingSystemVersion
```

Il tool stampa stringhe vuote. Non è una prova automatica di compromissione o malfunzionamento.

***

### `strongerAuthRequired`

L’helper LDAP condiviso tenta inizialmente LDAP e, quando riceve questo errore, riprova automaticamente con LDAPS.

`GetADComputers.py` non espone un’opzione `-ldaps`.

Se anche il fallback fallisce, controlla:

* TCP 636;
* certificato e configurazione LDAPS del DC;
* LDAP signing;
* channel binding;
* compatibilità della versione Impacket;
* policy NTLM e Kerberos.

***

### Errore durante il machine-name discovery con Kerberos

L’helper apre una connessione SMB e tenta un accesso vuoto per ricavare il nome del server. Anche quando l’autenticazione anonima non viene concessa, la negoziazione può permettere a Impacket di leggere il nome del server.

In ambienti con NTLM disabilitato, SMB filtrato o risposta non compatibile, la procedura può fallire.

Verifica:

* `-dc-host DC01.corp.local`;
* risoluzione DNS;
* raggiungibilità di TCP 445;
* SPN LDAP;
* sincronizzazione temporale;
* validità della ccache;
* output di `-debug`.

***

### `KRB_AP_ERR_SKEW`

Client e Domain Controller hanno orari troppo distanti.

Controlla:

```bash
timedatectl
```

e sincronizza l’orario con una sorgente autorizzata.

***

### Il parametro `-user` non riduce l’output

È il comportamento della versione verificata: l’argomento viene parsato e memorizzato, ma non viene inserito nel filtro LDAP.

Usa una query LDAP specifica tramite `ldapsearch`, NetExec o PowerShell.

***

## Detection

L’esecuzione non crea un evento Windows chiamato “GetADComputers.py”.

Dal punto di vista del Domain Controller appare come:

1. una connessione e autenticazione LDAP;
2. una ricerca LDAP paginata sul dominio;
3. eventuali query DNS `A`;
4. in modalità Kerberos, una connessione SMB preliminare per ricavare il nome del server.

L’attività è coerente con **MITRE ATT\&CK T1018 — Remote System Discovery**, che include l’uso di query LDAP per individuare sistemi nel dominio.

### Fonti di telemetria utili

* autenticazioni NTLM o Kerberos verso il DC;
* connessioni LDAP 389 o LDAPS 636;
* filtro LDAP sugli oggetti `computer`;
* attributi richiesti;
* query DNS `A` in sequenza verso il DC;
* connessione SMB 445 in modalità Kerberos;
* processo Python o wrapper Impacket sull’endpoint sorgente;
* scansioni Nmap o NetExec successive;
* Defender for Identity o telemetria di rete equivalente.

### Evento 4662

L’evento Security **4662** può registrare operazioni sugli oggetti Active Directory, ma viene generato soltanto quando:

* è abilitato `Audit Directory Service Access`;
* sull’oggetto è configurata una SACL appropriata;
* l’operazione corrisponde alla SACL.

Non va indicato come evento garantito per ogni query LDAP.

### Evento 1644

L’evento Directory Service **1644** è destinato principalmente a query LDAP costose, inefficienti o lente e dipende dalla configurazione diagnostica del Domain Controller.

Il filtro usato da `GetADComputers.py` può essere normale e indicizzato. Non è corretto promettere che ogni esecuzione generi automaticamente un evento 1644.

### Microsoft Defender for Identity

Defender for Identity monitora le attività LDAP e può rilevare query sospette associate a reconnaissance o strumenti conosciuti.

Una singola lettura di attributi comuni può avere anche spiegazioni amministrative legittime: origine, frequenza, identità e attività successive devono essere correlate per ridurre i falsi positivi.

***

## Mitigazioni

Le letture LDAP di computer, utenti e gruppi sono comuni nel funzionamento ordinario di Active Directory. Bloccarle indiscriminatamente può compromettere applicazioni e attività amministrative.

Controlli più efficaci:

* limitare l’accesso ai Domain Controller dalle reti non necessarie;
* segmentare workstation, server amministrativi e sistemi Tier 0;
* applicare LDAP signing e channel binding;
* preferire Kerberos e ridurre progressivamente NTLM;
* monitorare query LDAP anomale per volume, origine e identità;
* rilevare sequenze LDAP → DNS → SMB, WinRM o RDP;
* rimuovere o disabilitare computer account obsoleti dopo verifica;
* mantenere corretti DNS e attributi computer;
* usare account amministrativi separati;
* installare sensori Defender for Identity o strumenti equivalenti;
* controllare processi Python e tool offensivi sugli endpoint;
* definire baseline per applicazioni che interrogano normalmente Active Directory.

Non esiste una mitigazione sicura basata soltanto sul negare a tutti gli utenti la lettura degli oggetti computer.

***

## Cleanup

`GetADComputers.py` esegue una query di lettura e non modifica Active Directory. Non serve quindi alcun cleanup lato dominio.

Devono però essere rimossi o protetti gli artefatti locali:

```bash
rm -f \
  /tmp/getadcomputers.txt \
  /tmp/getadcomputers-errors.txt \
  /tmp/computers-fqdn.txt \
  /tmp/computers-ipv4.txt \
  /tmp/relay-targets.txt
```

Rimuovi la variabile ccache quando non serve più:

```bash
unset KRB5CCNAME
```

Gestisci i ticket secondo le procedure del laboratorio:

```bash
kdestroy
```

Non lasciare password in chiaro nella cronologia shell o in file leggibili da altri utenti.

***

## Cheat Sheet

```bash
# Help e parser reale
impacket-GetADComputers -h

# Autenticazione con prompt password
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5

# Password inline
impacket-GetADComputers 'corp.local/user:Password123!' \
  -dc-ip 10.10.10.5

# Risoluzione IPv4 tramite il DNS del DC
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -resolveIP

# Pass-the-Hash
impacket-GetADComputers corp.local/user \
  -hashes :NTHASH \
  -dc-ip 10.10.10.5

# Kerberos con ccache
export KRB5CCNAME=/path/to/user.ccache

impacket-GetADComputers corp.local/user \
  -k \
  -no-pass \
  -dc-host DC01.corp.local \
  -dc-ip 10.10.10.5

# Kerberos con chiave AES
impacket-GetADComputers corp.local/user \
  -aesKey AES256_HEX_KEY \
  -dc-host DC01.corp.local \
  -dc-ip 10.10.10.5

# Timestamp e debug
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -ts \
  -debug

# Salva output
impacket-GetADComputers corp.local/user \
  -dc-ip 10.10.10.5 \
  -resolveIP > /tmp/getadcomputers.txt

# Estrai FQDN
awk '$1 ~ /\$$/ && $2 ~ /\./ {print $2}' \
  /tmp/getadcomputers.txt |
  sort -u > /tmp/computers-fqdn.txt

# Estrai IPv4
awk '$NF ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ {print $NF}' \
  /tmp/getadcomputers.txt |
  sort -u > /tmp/computers-ipv4.txt

# Query equivalente con ldapsearch
ldapsearch -LLL -x \
  -H ldap://DC01.corp.local \
  -D 'user@corp.local' \
  -W \
  -b 'DC=corp,DC=local' \
  '(&(objectCategory=computer)(objectClass=computer))' \
  sAMAccountName \
  dNSHostName \
  operatingSystem \
  operatingSystemVersion

# Query equivalente con NetExec
nxc ldap 10.10.10.5 \
  -d corp.local \
  -u user \
  -p 'Password123!' \
  --query '(&(objectCategory=computer)(objectClass=computer))' \
  'sAMAccountName dNSHostName operatingSystem operatingSystemVersion'
```

***

## Errori da non ripetere

```text
-resolve              → errato, usare -resolveIP
-all                  → inesistente
-outputfile           → inesistente, usare >
LastLogon             → non restituito
PasswordLastSet       → non restituito
Datacenter = DC       → falso
OS vecchio = CVE      → falso senza verifica
DNS risolto = online  → falso
-user filtra computer → falso nella versione verificata
```

***

## Articoli Hackita correlati

* [Impacket: suite e strumenti](https://hackita.it/articoli/impacket/)
* [GetADUsers.py: enumerazione utenti Active Directory](https://hackita.it/articoli/getadusers/)
* [ldapsearch: query LDAP da Linux](https://hackita.it/articoli/ldapsearch/)
* [NetExec: enumerazione e verifica dei servizi](https://hackita.it/articoli/netexec/)
* [BloodHound: relazioni e attack path Active Directory](https://hackita.it/articoli/bloodhound/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)
* [SMB: protocollo e porta 445](https://hackita.it/articoli/smb/)
* [Active Directory: guida generale](https://hackita.it/articoli/active-directory/)

***

## Fonti tecniche

### Fonti primarie

* [Fortra Impacket — repository ufficiale](https://github.com/fortra/impacket)
* [GetADComputers.py — Impacket 0.13.1](https://github.com/fortra/impacket/blob/impacket_0_13_1/examples/GetADComputers.py)
* [GetADComputers.py — branch master](https://github.com/fortra/impacket/blob/master/examples/GetADComputers.py)
* [Helper LDAP e Kerberos di Impacket](https://github.com/fortra/impacket/blob/master/impacket/examples/utils.py)
* [Microsoft — flag UserAccountControl](https://learn.microsoft.com/it-it/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
* [Microsoft — evento 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)
* [Microsoft — analisi delle query LDAP con evento 1644](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/event1644reader-analyze-ldap-query-performance)
* [MITRE ATT\&CK T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
* [NetExec — query LDAP raw](https://www.netexec.wiki/ldap-protocol/query-ldap)
* [NetExec — pre2k computer account abuse](https://www.netexec.wiki/ldap-protocol/pre2k)

### Fonti operative di confronto

* [HackTricks — Active Directory Methodology](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html)
* [The Hacker Recipes — LDAP reconnaissance](https://www.thehacker.recipes/ad/recon/ldap)
* [InternalAllTheThings — Active Directory Enumeration](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/)
* [Hackviser — LDAP Pentesting](https://hackviser.com/tactics/pentesting/services/ldap)

> Utilizza queste tecniche esclusivamente su sistemi di tua proprietà o per i quali possiedi un’autorizzazione esplicita.
