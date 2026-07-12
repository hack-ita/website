---
title: 'SharpHound per BloodHound CE: Guida alla Raccolta Dati AD'
slug: sharphound
description: >-
  SharpHound per BloodHound CE: raccolta dati Active Directory, flag principali,
  opzioni stealth e importazione per mappare i path di escalation.
image: /sharphound-active-directory.webp
draft: false
date: 2026-07-13T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - sharphound
  - ldap
  - attack paths
---

# SharpHound per BloodHound CE: Raccolta Dati Active Directory e Attack Path

SharpHound CE è il collector ufficiale di BloodHound per gli ambienti Active Directory. Eseguito nel contesto di un utente di dominio, utilizza LDAP e le API native di Windows per raccogliere informazioni su utenti, gruppi, computer, sessioni, ACL e relazioni privilegiate.

I risultati vengono salvati in file JSON, normalmente compressi in un archivio ZIP, da importare in [BloodHound](https://hackita.it/articoli/bloodhound) CE. La piattaforma trasforma questi dati in un grafo di nodi e relazioni, permettendo di individuare configurazioni rischiose e attack path verso obiettivi ad alto valore, inclusi i gruppi Domain Admin.

In questa guida vedrai come eseguire SharpHound, scegliere i metodi di raccolta, utilizzare i flag principali, ridurre l’impatto dell’enumerazione e importare correttamente i dati in BloodHound CE.

***

Senza dati, BloodHound è uno schermo vuoto. SharpHound è quello che popola quel grafo: interroga il Domain Controller via LDAP, enumera sessioni, ACL, group membership, trust e oggetti ADCS, e comprime tutto in un archivio pronto per l'importazione. È scritto in C# e gira su qualsiasi macchina Windows con credenziali di dominio — non serve essere Domain Admin.

> SharpHound non richiede privilegi elevati. Qualsiasi account di dominio autenticato può raccogliere la maggior parte dei dati. I path di escalation esistono indipendentemente da chi li enumera.

***

## Perché SharpHound Prima di Qualsiasi Altra Cosa

In un engagement AD, SharpHound è il primo tool da eseguire dopo aver ottenuto credenziali di dominio — prima di qualsiasi exploit, prima di qualsiasi movement. Il motivo è semplice: senza il grafo BloodHound sei cieco. Con il grafo hai visibilità immediata su tutti i path verso Domain Admin, le misconfigurazioni ACL, i delegation abuse, le sessioni degli admin.

Il tempo medio per raccogliere dati con `DCOnly` su un dominio enterprise è sotto il minuto. Il tempo che ti fa risparmiare in ricerca manuale è ore.

***

SharpHound usa due canali principali:

* **LDAP/LDAPS** verso il Domain Controller per enumerare utenti, gruppi, computer, ACL, GPO, trust e oggetti ADCS
* **SMB (named pipe)** verso le singole macchine del dominio per raccogliere sessioni utente attive e local group membership

I dati vengono serializzati in file JSON e compressi in uno ZIP con timestamp. Quel file viene importato in BloodHound CE per la visualizzazione e l'analisi.

***

## Collection Methods

SharpHound supporta diversi metodi di raccolta configurabili con il flag `-c` o `--CollectionMethods`:

| Metodo        | Cosa raccoglie                                                                      |
| ------------- | ----------------------------------------------------------------------------------- |
| `Default`     | Group membership, trust, ACL, OU structure, GPO, LocalGroups, Sessions, ObjectProps |
| `All`         | Tutto quanto — incluso ADCS, RDP, DCOM, PSRemote, SPNTargets                        |
| `DCOnly`      | Solo dati dal DC via LDAP — nessun contatto con le macchine del dominio. Stealthier |
| `Session`     | Solo sessioni utente attive sulle macchine                                          |
| `ACL`         | Solo ACL degli oggetti AD                                                           |
| `Trusts`      | Solo trust tra domini                                                               |
| `ObjectProps` | Proprietà degli oggetti (utenti, computer, gruppi)                                  |
| `LoggedOn`    | Utenti attualmente loggati (richiede admin locale sulle macchine)                   |
| `ADCS`        | Oggetti e configurazioni AD Certificate Services                                    |

***

## Utilizzo Base

### Da macchina joined al dominio

```powershell
# Default — raccoglie i dati più utili senza troppo rumore
.\SharpHound.exe

# All — tutto disponibile incluso ADCS
.\SharpHound.exe -c All

# DCOnly — solo LDAP, nessun contatto con le macchine (più stealth)
.\SharpHound.exe -c DCOnly

# Combinazione selettiva — ACL + ObjectProps + Trusts senza session enumeration
.\SharpHound.exe -c ACL,ObjectProps,Trusts
```

### Da macchina non joined (con credenziali)

```powershell
# runas /netonly — esegui nel contesto delle credenziali del dominio
runas /netonly /user:corp.local\utente "powershell.exe"
# Nella nuova shell:
.\SharpHound.exe -c All -d corp.local

# Con flag LDAP diretti (senza runas)
.\SharpHound.exe -c All --LdapUsername utente --LdapPassword 'Password123!' -d corp.local
```

### Via PowerShell (Invoke-BloodHound)

```powershell
# Import del modulo SharpHound PS
Import-Module .\SharpHound.ps1

# Raccolta completa
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp\bh

# DCOnly via PS
Invoke-BloodHound -CollectionMethod DCOnly -OutputDirectory C:\Windows\Temp\bh
```

***

## Flag Utili

```powershell
# Specifica dominio target
.\SharpHound.exe -c All -d corp.local

# Output in directory specifica
.\SharpHound.exe -c All --outputdirectory C:\Windows\Temp

# Proteggi lo ZIP con password (utile per exfiltration)
.\SharpHound.exe -c All --zippassword 'p@ssword123' --outputprefix 'PENTEST'

# Esclude un dominio dalla raccolta
.\SharpHound.exe -c All --ExcludeDomains otherdomain.local

# Limita a una specifica OU
.\SharpHound.exe -c All --SearchBase 'OU=Servers,DC=corp,DC=local'

# DC specifico (utile se il default non è raggiungibile)
.\SharpHound.exe -c All --DomainController DC01.corp.local

# Stealth mode — session collection solo sulle macchine più probabili
.\SharpHound.exe --CollectionMethods Session --Stealth

# Loop collection — raccoglie sessioni ogni N minuti per X ore
.\SharpHound.exe --CollectionMethods Session --Loop --LoopDuration 02:00:00 --LoopInterval 00:05:00
```

***

## Loop Collection — Perché è Importante

Le sessioni utente in AD sono dinamiche — un utente logga e slogga nel corso della giornata. Una singola raccolta snapshot spesso manca sessioni critiche. Il loop collection risolve questo:

```powershell
# Raccoglie sessioni ogni 5 minuti per 2 ore
# Costruisce una mappa molto più completa delle sessioni attive
.\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00 --LoopInterval 00:05:00
```

Questo è particolarmente utile per trovare path del tipo: "l'utente `svc_admin` è loggato su `WORKSTATION01` ogni mattina tra le 9 e le 10" — un'informazione che una singola raccolta notturna non cattura.

***

## BloodHound.py — Da Linux

Quando non hai accesso a una macchina Windows ma hai credenziali di dominio, usa il collector Python (community edition):

```bash
# Installazione
pip install bloodhound

# Raccolta completa da Linux
bloodhound-python -u utente -p 'Password123!' -d corp.local \
  -ns <DC_IP> -c All

# Con hash NTLM (pass-the-hash)
bloodhound-python -u utente --hashes :NThash -d corp.local \
  -ns <DC_IP> -c All

# Specifica DC esplicitamente
bloodhound-python -u utente -p 'Password123!' -d corp.local \
  -ns <DC_IP> -c All --zip
```

> **Nota:** bloodhound-python nella versione community non supporta nativamente BloodHound CE (Community Edition). Usa la versione aggiornata del repo o verifica la compatibilità con la tua versione di BloodHound prima dell'importazione.

***

## File di Output Generati

SharpHound produce uno ZIP con file JSON separati per categoria. Conoscerli è utile per capire cosa importare e cosa cercare:

| File                 | Contiene                                                      |
| -------------------- | ------------------------------------------------------------- |
| `users.json`         | Utenti AD: attributi, group membership, SPNs, password policy |
| `groups.json`        | Gruppi e nested membership                                    |
| `computers.json`     | Computer, OS, sessioni, delegation                            |
| `domains.json`       | Info dominio, trust, policy                                   |
| `gpos.json`          | Group Policy Objects                                          |
| `ous.json`           | Organizational Units e ACL                                    |
| `containers.json`    | Container AD e permessi                                       |
| `sessions.json`      | Sessioni utente attive sulle macchine                         |
| `acls.json`          | ACL degli oggetti AD                                          |
| `cas.json`           | Certificate Authority (con `-c ADCS`)                         |
| `certtemplates.json` | Template ADCS vulnerabili (con `-c ADCS`)                     |

Il file più pesante è quasi sempre `acls.json` — su domini grandi può arrivare a centinaia di MB.

***

## SharpHound vs PowerView

|                  | SharpHound                            | PowerView                                    |
| ---------------- | ------------------------------------- | -------------------------------------------- |
| Uso              | Raccolta dati in massa per BloodHound | Query manuali e operazioni puntuali          |
| Output           | File JSON per Neo4j                   | PowerShell objects                           |
| Velocità         | Molto veloce su tutto il dominio      | Selettivo ma più lento su scala              |
| Visibilità grafo | Sì (via BloodHound)                   | No (output testuale)                         |
| Modifiche AD     | No                                    | Sì (Set-DomainObject, Add-DomainGroupMember) |
| Stealth          | Meno (query LDAP massive)             | Più (query selettive)                        |

**In pratica:** SharpHound per la mappa d'insieme, [PowerView](https://hackita.it/articoli/powerview/) per le query specifiche e le modifiche agli oggetti AD.

***

## Errori Comuni

### Access Denied su sessioni/local group

```
[-] Error getting sessions for WORKSTATION01: Access is denied
```

Causa: Remote Registry disabilitato o SMB bloccato. Soluzione: usa `DCOnly` per saltare le query SMB sulle macchine.

### LDAP Bind Failed

```
[-] LDAP connection failed
```

Cause: credenziali errate, DC non raggiungibile su porta 389, LDAPS obbligatorio. Prova:

```powershell
.\SharpHound.exe -c All --LdapPort 636 --SecureLdap
```

### Empty sessions.json

Il file c'è ma è vuoto. Significa che non hai trovato sessioni attive nel momento della raccolta. Soluzione: loop collection durante orari di punta.

### Zip file corrotto all'importazione in BloodHound

Spesso causato da output directory su share di rete. Usa sempre path locale come `C:\Windows\Temp`.

***

```bash
# Avvia BloodHound CE con Docker (se non già attivo)
docker-compose up -d

# Accedi a http://localhost:8080
# Credenziali default: admin / bloodhoundcommunityedition
```

Una volta nel pannello:

1. Clicca **Upload Data** (icona in alto a destra)
2. Seleziona lo ZIP generato da SharpHound
3. Attendi l'elaborazione
4. Usa il tab **Pathfinding** o le query predefinite per iniziare l'analisi

***

## OPSEC

* **`DCOnly`** è il metodo più stealth: nessun contatto SMB con le macchine del dominio, solo query LDAP verso il DC. Genera molto meno rumore rispetto a `All`
* Il flag `--Stealth` per la session collection riduce il numero di macchine contattate a quelle con maggiore probabilità di avere sessioni attive
* Rinomina il binario prima di trasferirlo sulla macchina target — `SharpHound.exe` è un nome ovvio per qualsiasi EDR
* Usa `--zippassword` per cifrare l'output prima dell'exfiltration
* Evita di eseguire `All` in orari di bassa attività — paradossalmente è più anomalo. Esegui durante le ore lavorative quando il traffico LDAP è normale
* Il loop collection di sessioni genera traffico SMB ripetuto — valuta se il beneficio informativo vale il rischio di detection

***

## Scenario Reale

Hai appena compromesso un account utente di dominio. Prima di fare qualsiasi altra cosa:

1. Trasferisci SharpHound sulla macchina (rinominato come `svchost_updater.exe`)
2. Esegui `DCOnly` per avere subito il grafo ACL senza toccare le macchine
3. Importa in BloodHound CE e cerca il path più corto verso Domain Admin
4. Se il path passa per sessioni, esegui un loop collection breve durante le ore di punta
5. Con il grafo completo, pianifica l'escalation

Questo approccio minimizza il rumore nelle prime fasi e ti dà visibilità completa prima di muoverti.

***

## Detection

**🔴 HIGH:**

* Processo `SharpHound.exe` o `SharpHound.ps1` visibile su endpoint (nome originale)
* Burst di query LDAP verso il DC da un singolo host in finestre di pochi minuti — centinaia di query in breve tempo è anomalo

**🟡 MEDIUM:**

* Connessioni SMB ripetute dallo stesso host verso molte macchine del dominio in sequenza (session enumeration)
* Accesso al registro remoto (`RemoteRegistry` service) su molte macchine in breve tempo

***

## Mitigazione

* Limitare l'accesso in lettura a certi attributi LDAP sensibili non è banale in AD — la maggior parte dei dati raccolti da SharpHound è leggibile da qualsiasi utente autenticato per design
* Abilitare **LDAP signing e LDAPS** riduce la superficie di alcune enumerazioni
* Monitorare i burst di query LDAP con SIEM — un utente normale non fa centinaia di query LDAP in 30 secondi
* Microsoft Defender for Identity ha signature specifiche per SharpHound e BloodHound.py

***

## FAQ

**SharpHound richiede privilegi elevati?**
No per la maggior parte dei dati (group membership, ACL, ObjectProps, Trusts). La session enumeration via SMB su alcune macchine può richiedere admin locale, ma `DCOnly` funziona con qualsiasi account di dominio.

**Qual è la differenza tra SharpHound e bloodhound-python?**
SharpHound è il collector ufficiale supportato da SpecterOps, gira solo su Windows, ed è più completo. bloodhound-python è un porting community per Linux, pratico quando non hai accesso a una macchina Windows, ma può avere limitazioni di compatibilità con BloodHound CE.

**Quanto tempo impiega una raccolta completa?**
Dipende dalla dimensione del dominio. Su domini piccoli (\<500 oggetti) meno di un minuto. Su domini enterprise con migliaia di macchine, `All` può richiedere ore — `DCOnly` è sempre molto più rapido.

***

## Conclusione

SharpHound è il primo tool da eseguire dopo aver ottenuto un foothold autenticato in un dominio Active Directory. Senza la mappa del grafo, ti muovi alla cieca. Con il grafo, ogni path di escalation — ACL abuse, Kerberoasting, RBCD, Shadow Credentials — diventa visibile e pianificabile.

La scelta del collection method dipende dal contesto: `DCOnly` per velocità e stealth nelle prime fasi, `All` quando vuoi il quadro completo, loop session per ambienti dove le sessioni sono il vettore principale.

***

**Risorse:**

* [SpecterOps – SharpHound Flags Reference](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags)
* [HackTricks – BloodHound](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/bloodhound.html)
