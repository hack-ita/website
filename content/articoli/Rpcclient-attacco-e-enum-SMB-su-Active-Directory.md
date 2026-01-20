---
title: 'Rpcclient: attacco e enum SMB su Active Directory'
description: >-
  Rpcclient consente di interrogare AD via SMB per ottenere utenti, SID e
  informazioni critiche. Tecniche offensive per pentest e Red Team.
draft: true
date: 2026-01-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - rpcclient
---

# Rpcclient: il canale diretto per interrogare Active Directory via MS-RPC

**Report Red Team – ambiente controllato e autorizzato**

Quando trovi la porta **445** aperta in una rete Windows, la reazione istintiva è lanciarsi su SMB alla ricerca di share esposte. Ma esiste una via più diretta, silenziosa e spesso molto più informativa: **MS-RPC (Remote Procedure Call)**.

`rpcclient`, parte della suite Samba, è il tuo accesso diretto ai servizi interni di Windows e Active Directory. Non lavora sulle cartelle: interroga **utenti, gruppi, SID, policy e relazioni di dominio**, usando gli stessi meccanismi nativi di Windows.

Se sai usarlo bene, `rpcclient` trasforma un accesso SMB “banale” in **intelligence strutturata di dominio**.

***

## Cos’è rpcclient e perché è uno strumento di enumerazione chirurgica

`rpcclient` è un client **MS-RPC / DCE-RPC**. In pratica, ti permette di chiamare procedure remote su un sistema Windows come se fossi un componente interno del sistema operativo.

I principali servizi RPC interrogabili sono:

* **SAMR (Security Account Manager Remote)**
  Utenti di dominio, account locali, gruppi e relazioni.
* **LSARPC (Local Security Authority Remote)**
  SID, privilegi, policy di sicurezza.
* **SRVSVC (Server Service)**
  Informazioni sul server e condivisioni di rete.

Il valore per un red teamer non è “fare rumore”, ma **fare domande precise**: partire da un nome utente e arrivare a gruppi, privilegi e policy senza exploit.

***

## Connessione e autenticazione

Prima di enumerare, devi aprire una sessione RPC valida. `rpcclient` supporta più modalità, ognuna utile in una fase diversa dell’attacco.

### Connessione con credenziali valide

Scenario classico dopo credential harvesting o password spraying riuscito.

```bash
rpcclient -U 'DOMINIO/NomeUtente%Password' 192.168.1.10
```

Se l’accesso riesce, entri nella shell interattiva:

```
rpcclient $>
```

***

### Test di null session (accesso anonimo)

In ambienti legacy o mal configurati, l’accesso anonimo può ancora funzionare.

```bash
rpcclient -U '' -N 192.168.1.10
```

Se va a buon fine, hai **information disclosure senza credenziali**. Anche solo questo è già un finding serio.

***

### Modalità non interattiva (one-liner)

Fondamentale per scripting e automazione.

```bash
rpcclient -U 'DOMINIO/NomeUtente%Password' 192.168.1.10 -c 'comando1; comando2'
```

***

## Enumerazione di base: capire dove sei finito

Prima di scavare, serve contesto.

### Informazioni sul dominio

```bash
rpcclient $> querydominfo
```

Restituisce:

* nome dominio
* numero utenti
* numero gruppi
* stato generale del dominio

### Informazioni sul server

```bash
rpcclient $> srvinfo
```

Utile per farsi un’idea del ruolo e della versione del sistema.

***

## Enumerazione utenti di dominio

Questo è quasi sempre il primo vero obiettivo.

```bash
rpcclient $> enumdomusers
```

Output tipico:

```
user:[Administrator] rid:[0x1f4]
user:[Giovanni.Rossi] rid:[0x3f2]
user:[SRV_SQL$] rid:[0x452]
```

I **RID** sono fondamentali: servono per query mirate e correlazioni con altri tool.

***

## Profilazione avanzata dell’utente

Una volta identificato un account interessante, puoi interrogarlo in profondità.

```bash
rpcclient $> queryuser 0x3f2
```

oppure:

```bash
rpcclient $> queryuser Giovanni.Rossi
```

Qui trovi spesso:

* descrizioni (a volte contengono password…)
* orari di logon
* stato account
* gruppi di appartenenza

***

## Enumerazione gruppi e relazioni

La vera escalation passa quasi sempre dai gruppi.

### Elenco gruppi di dominio

```bash
rpcclient $> enumdomgroups
```

### Membri di un gruppo specifico

```bash
rpcclient $> querygroupmem 0x200
```

(RID tipico per **Domain Admins**, ma verifica sempre)

### Gruppi di un utente

```bash
rpcclient $> queryusergroups 0x3f2
```

Qui capisci **chi può diventare chi**.

***

## Enumerazione delle share via RPC

Alternativa (e complemento) a smbclient.

```bash
rpcclient $> netshareenumall
```

Dettagli di una share specifica:

```bash
rpcclient $> netsharegetinfo "CondivisioneInterna"
```

***

## Politiche password del dominio

Informazione tattica chiave per spraying e brute-force.

```bash
rpcclient $> getdompwinfo
```

Ti dice:

* lunghezza minima
* complessità
* durata password

***

## Lavorare con SID e nomi

Conversioni utilissime in ambienti AD.

### Nome → SID

```bash
rpcclient $> lookupnames Administrator
```

### SID → nome

```bash
rpcclient $> lookupsids S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-500
```

### Enumerazione SID noti

```bash
rpcclient $> lsaenumsid
```

***

## Automazione e raccolta rapida di intelligence

### Dump iniziale di dominio

```bash
rpcclient -U 'DOMINIO/NomeUtente%Password' 192.168.1.10 \
-c 'querydominfo; srvinfo; enumdomusers; enumdomgroups; getdompwinfo' \
> enum_initial.txt
```

### Generare una userlist pulita

```bash
rpcclient -U 'DOMINIO/NomeUtente%Password' 192.168.1.10 -c 'enumdomusers' \
| grep -oP '\[.*?\]' | tr -d '[]' > userlist.txt
```

***

## Scenario red team realistico (kill chain)

1. Nmap mostra **445 aperta**.
2. Nessuna null session.
3. Recuperi credenziali low-priv da file o spray.
4. Usi `rpcclient` per enumerare dominio e gruppi.
5. Scopri account di servizio in gruppi interessanti.
6. Movimento laterale.
7. Dump credenziali.
8. Torni a `rpcclient` con privilegi superiori.
9. Completi escalation.

rpcclient non è il colpo finale: è **la mappa**.

***

## rpcclient vs altri strumenti

* **vs smbclient**
  smbclient lavora sui file. rpcclient lavora sul dominio.
* **vs enum4linux-ng**
  enum4linux-ng automatizza; rpcclient ti dà controllo chirurgico.
* **vs Nmap NSE**
  NSE è veloce; rpcclient è profondo e persistente.

***

## Conclusione

`rpcclient` non è il tool più immediato, ma è uno dei più potenti per chi ragiona da red team.
Ti permette di passare dal “vedo una porta aperta” al **comprendere struttura, fiducia e privilegi di un dominio Active Directory**.

In ambienti autorizzati, padroneggiarlo significa smettere di andare a tentativi e iniziare a **muoverti con metodo**.

***

## HackITA – supporto, formazione e servizi

Se questo contenuto ti è utile:

* **[Supporta](https://hackita.it/supporto/) HackITA** per mantenere attivi contenuti tecnici indipendenti.
* [**Formazione 1:1** ](https://hackita.it/servizi/)per red teamer e pentester che vogliono capire davvero AD, RPC e movimento laterale.
* **Servizi per aziende**: assessment, hardening e simulazioni di attacco in ambienti autorizzati.

**Non limitarti a usare i tool. Comprendi il dominio. Domina la catena.**
