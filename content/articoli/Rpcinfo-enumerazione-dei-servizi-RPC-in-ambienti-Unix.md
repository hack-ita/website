---
title: 'Rpcinfo: enumerazione dei servizi RPC in ambienti Unix'
description: >-
  Rpcinfo permette di identificare i servizi RPC attivi su host Unix/Linux.
  Fondamentale per il recon e l’analisi di potenziali vettori di attacco remoti.
image: /rpcinfo.webp
draft: true
date: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - rpcinfo
  - rpc
---

## Rpcinfo: enumerazione dei servizi RPC in ambienti Unix

Rpcinfo è un comando a riga di comando utilizzato per interrogare un server rpcbind, noto anche come portmapper.
Il suo compito è mostrare quali servizi RPC sono registrati su un host remoto e su quali porte reali sono in ascolto.

Dal punto di vista offensivo, rpcinfo è uno strumento chiave per individuare servizi di backend che utilizzano porte dinamiche.
Un semplice scan che mostra la porta 111 aperta non dice nulla su cosa stia realmente girando dietro.

Rpcinfo trasforma quella singola porta in una mappa completa dei servizi RPC attivi.

## Setup e verifica iniziale

Rpcinfo è normalmente già presente su Kali Linux.

```
which rpcinfo
```

Se non è disponibile, può essere installato dal pacchetto rpcbind.

```
sudo apt update
sudo apt install rpcbind
```

Prima di usare rpcinfo è necessario verificare che la porta 111 sia raggiungibile.

```
sudo nmap -sS -p 111 10.10.20.5 -n -Pn
sudo nmap -sU -p 111 10.10.20.5 -n -Pn
```

RPC utilizza spesso UDP, quindi il controllo su entrambe le modalità è fondamentale.

## Enumerazione completa dei servizi RPC

```
rpcinfo -p 10.10.20.5
```

Output tipico:

```
program vers proto   port  service
100000    4   tcp    111  portmapper
100005    3   udp  20048  mountd
100003    3   tcp   2049  nfs
```

Questo comando elenca tutti i programmi RPC registrati, le versioni supportate, il protocollo e la porta reale.

La presenza di mountd e nfs indica immediatamente un server NFS attivo.
La porta mostrata per mountd è spesso dinamica e non standard.

## Vista rapida e compatta dei servizi

```
rpcinfo -s 10.10.20.5
```

Output tipico:

```
program version(s) netid(s) service
100000 2,3,4 udp,tcp rpcbind
100003 2,3 udp,tcp nfs
100005 1,2,3 udp,tcp mountd
```

Questo formato è utile per una valutazione rapida.
Conferma la presenza dei servizi senza concentrarsi sulle porte.

È il comando ideale per decidere velocemente se passare a showmount o al montaggio diretto NFS.

## Verifica attiva di un servizio RPC

```
rpcinfo -t 10.10.20.5 mountd
```

Oppure usando il program number:

```
rpcinfo -u 10.10.20.5 100005
```

Se il servizio risponde, rpcinfo mostrerà le versioni disponibili.
Questo step verifica che il servizio sia realmente attivo e non solo registrato.

È utile prima di tentare montaggi o attacchi più invasivi.

## Individuare servizi RPC meno comuni

```
rpcinfo -p 10.10.20.5 | grep 100007
```

Output possibile:

```
100007    2   udp  32779  ypbind
```

La presenza di ypbind indica NIS, spesso associato a configurazioni legacy e potenzialmente molto deboli.
Rpcinfo permette di individuare rapidamente questi servizi senza scansioni rumorose.

## Scenario di attacco

Durante un test autorizzato viene individuata la porta 111 aperta su un server interno.

```
rpcinfo -p 10.10.30.15
```

L’output mostra mountd e nfs attivi.

```
rpcinfo -t 10.10.30.15 mountd
```

Il servizio risponde correttamente.
Si procede quindi con l’enumerazione NFS.

```
showmount -e 10.10.30.15
```

Viene individuato un export accessibile a chiunque.
Il mount rivela script di backup con credenziali in chiaro.

Da lì parte il movimento laterale verso database e sistemi interni fino all’escalation.

Rpcinfo è stato il primo anello della catena.

## Considerazioni finali

Rpcinfo non è un exploit.
È uno strumento di visibilità.

Il suo valore sta nel rendere evidenti servizi che altrimenti resterebbero nascosti dietro porte dinamiche.
Dopo la scoperta della porta 111, rpcinfo dovrebbe essere sempre il primo comando eseguito.

In ambienti NFS moderni basati solo su NFSv4 può mostrare informazioni limitate, ma anche questo è un segnale utile.

## Riferimenti tecnici

[https://man7.org/linux/man-pages/man8/rpcinfo.8.html](https://man7.org/linux/man-pages/man8/rpcinfo.8.html)
[https://linux.die.net/man/8/rpcinfo](https://linux.die.net/man/8/rpcinfo)

## Supporta HackITA

[https://hackita.it/supporto/](https://hackita.it/supporto/)

## Formazione e servizi

[https://hackita.it/servizi/](https://hackita.it/servizi/)

## Note legali

Le tecniche descritte devono essere utilizzate esclusivamente in ambienti autorizzati.

HackITA – Excellence in Offensive Security
