---
title: 'Showmount: scopri le condivisioni NFS esposte in rete'
description: >-
  Showmount è il tool perfetto per enumerare condivisioni NFS. Usato nei recon
  per identificare risorse accessibili e punti d’ingresso in ambienti
  Unix/Linux.
image: /showmount.webp
draft: true
date: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - showmount
  - nfs
---

## Introduzione

Showmount è un’utility a riga di comando usata per interrogare il demone mountd di un server NFS remoto.
Il suo scopo è mostrare quali directory vengono esportate dal server e quindi quali percorsi possono essere montati.

Dal punto di vista offensivo, un servizio NFS esposto rappresenta spesso una fonte diretta di dati sensibili.
Backup, configurazioni, home directory e codice applicativo vengono frequentemente condivisi tramite NFS.

Showmount non trasferisce file.
Serve a capire dove colpire.

## Setup e verifica del servizio

Showmount è normalmente presente su Kali Linux.

```
which showmount
```

Prima di utilizzarlo è necessario verificare la presenza del servizio NFS.
Le porte di riferimento sono 111 e 2049.

```
sudo nmap -p 111,2049 -sS -sU 10.10.20.5 --open
```

Se entrambe le porte risultano aperte, l’enumerazione NFS è possibile.

## Enumerazione degli export

```
showmount -e 10.10.20.5
```

Output tipico:

```
/home/backup    10.10.0.0/16
/var/www/html   (everyone)
/data/conf      (everyone)
```

Questo comando elenca le directory esportate e i client autorizzati.
La dicitura `(everyone)` indica che l’export non è limitato a specifici host.

Directory come backup o conf sono target ad alto valore.

Showmount funziona solo con NFS versione 2 e 3.
Se il server utilizza solo NFSv4, il comando può fallire.

## Enumerazione dei client che montano NFS

```
showmount -a 10.10.20.5
```

Output tipico:

```
10.10.30.22:/home/backup
10.10.30.45:/var/www/html
```

Questa informazione permette di identificare sistemi interni che dipendono dalle share NFS.
Spesso questi host sono pivot ideali.

## Quando showmount fallisce

Errore comune:

```
RPC: Program not registered
```

In questo caso è necessario interrogare rpcbind.

```
rpcinfo -p 10.10.20.5
```

Se mountd è in ascolto su porte alte, un firewall può bloccarlo.
Se mountd non è presente ma NFS è disponibile su 2049, il server usa probabilmente solo NFSv4.

In entrambi i casi, il passo successivo è tentare il montaggio diretto.

## Montaggio e verifica dei permessi

```
sudo mkdir -p /mnt/nfs_test
sudo mount -t nfs -o ro,vers=3 10.10.20.5:/var/www/html /mnt/nfs_test
```

Esplorazione:

```
ls -la /mnt/nfs_test
find /mnt/nfs_test -name ".env" -o -name "config*" 2>/dev/null
```

Il montaggio consente di verificare i permessi reali.
File di configurazione e backup sono spesso il punto di rottura.

Smontaggio:

```
sudo umount /mnt/nfs_test
```

## Scenario di attacco

Durante un test autorizzato viene individuato un server con NFS esposto.

```
showmount -e 10.10.20.5
```

Risultato:

```
/opt/app_backups (everyone)
```

Montaggio:

```
sudo mount -t nfs -o ro,vers=3,nolock 10.10.20.5:/opt/app_backups /mnt/backups
```

All’interno è presente un archivio di backup applicativo.
Il contenuto include credenziali di database riutilizzate su altri sistemi.

Le credenziali permettono accesso laterale e successiva escalation.

## Considerazioni finali

Showmount è uno strumento di enumerazione rapida.
Non sfrutta vulnerabilità ma configurazioni deboli.

Il suo fallimento indica spesso NFSv4 o filtraggio firewall.
In questi casi è necessario cambiare tattica, non fermarsi.

## Riferimenti tecnici

[https://man7.org/linux/man-pages/man5/exports.5.html](https://man7.org/linux/man-pages/man5/exports.5.html)
[https://nfs.sourceforge.net/](https://nfs.sourceforge.net/)

## Supporta HackITA

[https://hackita.it/supporto/](https://hackita.it/supporto/)

## Formazione e servizi

[https://hackita.it/servizi/](https://hackita.it/servizi/)

## Note legali

Le tecniche descritte devono essere utilizzate esclusivamente in ambienti autorizzati.

HackITA – Excellence in Offensive Security
