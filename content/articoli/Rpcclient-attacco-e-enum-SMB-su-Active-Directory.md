---
title: 'rpcclient Kali Linux: Enumerazione SMB, AD e SID/RID'
slug: rpcclient
description: 'Guida a rpcclient su Kali Linux per enumerare utenti, gruppi, SID/RID, trust, policy password e share SMB tramite SAMR, LSARPC e SRVSVC, con comandi pratici.'
image: /Gemini_Generated_Image_qeb7nqeb7nqeb7nq.webp
draft: false
date: 2026-01-23T00:00:00.000Z
lastmod: 2026-09-17T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - rpcclient
---

# rpcclient: Enumerazione SMB e Active Directory da Kali Linux

`rpcclient` è il client MS-RPC della suite Samba: interroga interfacce Windows/AD come SAMR, LSARPC e SRVSVC — tipicamente attraverso named pipe SMB, anche se il protocollo supporta altri transport DCERPC. In un workflow offensivo trasforma "porta 445 esposta" in intelligence di dominio: utenti, gruppi, SID/RID, policy password, share, trust.

**In 30 secondi:**

* **A cosa serve rpcclient?** Interroga interfacce RPC su Windows/AD per ottenere utenti, gruppi, SID/RID, policy password e share, quando i permessi lo consentono.
* **Serve un account?** Non necessariamente — una null session va sempre testata, ma su sistemi moderni l'anonimo è spesso bloccato.
* **rpcclient enumera i file dentro le share?** No: enumera solo l'esistenza e i metadati delle share. Per il contenuto serve un client file-centric come [smbclient](https://hackita.it/articoli/smbclient/).

## Cos'è rpcclient e Come Funziona

`rpcclient` è un client MS-RPC della suite Samba. Su Windows/AD usa più spesso named pipe via SMB (`ncacn_np`) per raggiungere interfacce come SAMR, LSARPC e SRVSVC, ma il protocollo DCE/RPC supporta anche altri transport (es. `ncacn_ip_tcp`) — non è quindi corretto pensare a "rpcclient = SMB" in senso stretto, solo il percorso più comune in pratica.

### Interfacce RPC Principali

| Interfaccia | Cosa trovi                                       |
| ----------- | ------------------------------------------------ |
| SAMR        | Utenti, gruppi, membership, RID, policy password |
| LSARPC      | SID, privilegi, trust di dominio                 |
| SRVSVC      | Info server, share                               |
| WKSSVC      | Informazioni workstation/dominio                 |
| SPOOLSS     | Informazioni relative allo spooler di stampa     |

```text
rpcclient
  |
  +-- SAMR: enumdomusers, enumdomgroups, queryuser, queryusergroups, querygroupmem, getdompwinfo
  |
  +-- LSARPC: lookupnames, lookupsids, lookupdomain, lsaquery, dsenumdomtrusts
  |
  +-- SRVSVC: srvinfo, netshareenumall
```

Se il target espone SMB sulla 445, `rpcclient` può diventare una fonte importante di informazioni — ma quanto ottieni dipende da servizi RPC disponibili, autenticazione e permessi, non dalla sola porta aperta.

## Installazione e Verifica

```bash
sudo apt update && sudo apt install -y samba-common-bin smbclient
rpcclient --version
```

## Connessione e Autenticazione

### Null session (anonima)

```bash
rpcclient -U '' -N 10.10.10.10
```

Se entri, hai un finding di information disclosure senza credenziali — prova subito comandi "safe" come `srvinfo`. Su ambienti moderni `NT_STATUS_ACCESS_DENIED` qui è normale, non un problema di sintassi: l'anonimo è spesso disabilitato di default.

### Credenziali (dominio o locali)

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10
```

`NT_STATUS_LOGON_FAILURE` è quasi sempre credenziali o dominio sbagliati — prova a specificare esplicitamente il dominio con `-W LAB` se il formato `DOMAIN/user` non basta.

### Comandi One-Shot con `-c`

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; enumdomusers'
```

Utile per dump ripetibili e salvabili su file (`> dump.txt`), senza restare in shell interattiva.

## Enumerazione Iniziale

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; srvinfo'
```

`srvinfo` dà informazioni sul server, `querydominfo` sul dominio, quando l'endpoint espone SAMR con permessi sufficienti — l'output da solo non è una prova assoluta del ruolo della macchina (DC vs member server), solo un forte indizio da confermare con altre fonti.

## Enumerazione Utenti e Gruppi

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'enumdomusers'
```

```text
user:[Administrator] rid:[0x1f4]
user:[svc_sql] rid:[0x45a]
```

`enumdomusers` restituisce username e RID; usa il RID per interrogazioni mirate invece del nome, è più affidabile:

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'queryuser 0x45a'
```

Gruppi e membership:

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'enumdomgroups'
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querygroupmem 0x200'
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'queryusergroups 0x45a'
```

Non assumere quale RID corrisponda a quale gruppo built-in (es. "0x200 = Domain Admins") senza verificarlo nel tuo lab — varia.

Per correlare rapidamente utenti/gruppi con path di escalation reali, passa i dati a [BloodHound](https://hackita.it/articoli/bloodhound/).

## RID Cycling: Enumerare Utenti Senza Permessi su enumdomusers

Se `enumdomusers` è negato ma una null session (o un account low-priv) può comunque interrogare singoli RID, puoi forzare l'enumerazione tentando un range di RID tipico degli account utente:

```bash
for i in $(seq 500 1100); do
  rpcclient -N -U '' 10.10.10.10 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid"
done
```

È una tecnica di fallback, non il metodo primario: se `enumdomusers` funziona, è sempre più veloce e completo. Il RID cycling serve quando l'enumerazione diretta è bloccata ma la risoluzione di un singolo RID no — una distinzione di permessi che càpita più spesso di quanto sembri.

## SID e RID

```text
SID di dominio:  S-1-5-21-1111111111-2222222222-3333333333
RID:             500
SID completo:    S-1-5-21-1111111111-2222222222-3333333333-500
```

Il RID identifica l'account all'interno del dominio (il SID authority); il SID completo è univoco nell'intera foresta.

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'lookupnames Administrator'
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'lookupsids S-1-5-21-1111111111-2222222222-3333333333-500'
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'lookupdomain LAB'
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'lsaquery'
```

`lsaquery` dà nome e SID di dominio in un colpo solo — spesso il primo comando utile quando non conosci ancora nulla del target. `NT_STATUS_NONE_MAPPED` su `lookupnames`/`lookupsids` indica quasi sempre nome/SID sbagliato o dominio/contesto diverso da quello atteso.

### Trust di Dominio

Se il target fa parte di una foresta con più domini, LSARPC-DS espone anche le relazioni di trust:

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'dsenumdomtrusts'
```

Utile per capire se esistono altri domini raggiungibili prima di restringere l'assessment a uno solo.

## Password Policy

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'getdompwinfo'
```

```text
min_password_length: 8
password_history: 24
```

Restituisce le informazioni sulla password policy esposte da SAMR — i campi disponibili variano per sistema e permessi, non aspettarti sempre l'intero set (lockout, age, ecc.).

## Enumerazione SMB via RPC

```bash
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'netshareenumall'
```

Enumerare una share non significa avere accesso automatico al suo contenuto: RPC ti dice cosa esiste, per leggerne dentro serve un client file-centric come [smbclient](https://hackita.it/articoli/smbclient/).

## Errori e Troubleshooting

**`NT_STATUS_LOGON_FAILURE`** — credenziali o dominio sbagliati. Prova a specificare `-W LAB` esplicitamente.

**`NT_STATUS_ACCESS_DENIED` su comandi specifici** — la sessione è valida ma quel comando richiede permessi più alti. Non insistere: cambia fonte dati (LDAP, SMB) o account.

**Null session negata** — normale su ambienti moderni, documentalo come finding ("anonimo bloccato") invece di considerarlo un errore del tool.

**Timeout / target non raggiungibile** — verifica reachability su 445/139 prima di sospettare altro:

```bash
nc -vz 10.10.10.10 445
```

**Comportamento diverso per signing/transport** — se il server richiede SMB signing e il client non lo negozia correttamente, la connessione può fallire prima ancora del bind RPC: verifica con [smbclient](https://hackita.it/articoli/smbclient/) se la sessione SMB di base funziona.

## rpcclient vs smbclient vs ldapsearch vs NetExec vs BloodHound

| Tool                                                  | Focus                             |
| ----------------------------------------------------- | --------------------------------- |
| rpcclient                                             | RPC diretto: SAMR, LSARPC, SRVSVC |
| smbclient                                             | Share e file                      |
| [ldapsearch](https://hackita.it/articoli/ldapsearch/) | Directory LDAP/AD                 |
| [NetExec](https://hackita.it/articoli/netexec/)       | Automation e bulk check SMB/AD    |
| [BloodHound](https://hackita.it/articoli/bloodhound/) | Relazioni e attack path           |

`rpcclient` non sostituisce `ldapsearch`: sono fonti dati diverse (RPC vs directory LDAP) che spesso confermano o completano a vicenda le stesse informazioni. Per enumerazione SMB/RPC quando LDAP è limitato, [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) resta una buona prima fotografia prima di scendere nel dettaglio con `rpcclient`.

## Scenario Pratico: rpcclient su una Macchina HTB/PG

```bash
# 1. Test anonimo
rpcclient -U '' -N 10.10.10.10 -c 'srvinfo'

# 2. Dump iniziale con credenziali low-priv
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'querydominfo; enumdomusers; enumdomgroups'

# 3. Password policy per valutazione rischio
rpcclient -U 'LAB/user1%Passw0rd!' 10.10.10.10 -c 'getdompwinfo'
```

Risultato atteso: userlist con RID, gruppi disponibili, parametri base della policy password — materiale grezzo da riportare come evidenza e correlare con [BloodHound](https://hackita.it/articoli/bloodhound/) o [smbclient](https://hackita.it/articoli/smbclient/).

## Playbook Rapido

1. Test anonymous.
2. Identifica domain/server (`querydominfo`, `srvinfo`).
3. Enumera utenti/gruppi (o RID cycling se `enumdomusers` è negato).
4. Profila account interessanti (`queryuser`, `queryusergroups`).
5. Mappa SID/RID (`lookupnames`, `lookupsids`, `lsaquery`).
6. Enumera share (`netshareenumall`) e policy (`getdompwinfo`).
7. Correla con LDAP/SMB/BloodHound.

## Checklist Operativa

* 445/139 verificati raggiungibili.
* Anonymous testato (solo per disclosure, non come metodo principale atteso).
* Domain/server identificati con `querydominfo`/`srvinfo`.
* Utenti e gruppi enumerati (o RID cycling se necessario).
* SID/RID e account interessanti approfonditi.
* Share e policy password correlate con quanto trovato via SMB/LDAP.

## Concetti Controintuitivi

* **"Se ho la 445 aperta posso enumerare tutto"** — no, dipende da servizi RPC esposti, autenticazione e permessi; `ACCESS_DENIED` spesso è hardening che funziona, non un errore del tool.
* **"Il nome utente basta, non servono RID/SID"** — in AD reale i RID/SID evitano ambiguità quando i nomi non risolvono o sono duplicati tra contesti.
* **"La null session è sempre possibile"** — su ambienti moderni è spesso bloccata: va testata e documentata, non assunta.
* **"rpcclient è per file share"** — no, è dominio/RPC-centric: per contenuti di file usa uno strumento SMB file-centric e tieni rpcclient per identity/policy.

## FAQ

**Come enumero utenti AD con rpcclient?**
`enumdomusers` per la lista diretta; se è negato, il RID cycling su un range tipico (500-1100) spesso funziona anche in null session.

**Come uso rpcclient senza credenziali?**
`rpcclient -U '' -N <target>` per la null session. Su ambienti moderni fallisce spesso, ma va sempre testata come primo passo.

**Qual è la differenza tra rpcclient e smbclient?**
rpcclient interroga interfacce RPC (SAMR, LSARPC, SRVSVC) per identity e policy; smbclient accede a share e file. Non sono intercambiabili: enumerare una share via rpcclient non dà accesso al suo contenuto.

**Qual è la differenza tra rpcclient e ldapsearch?**
Fonti dati diverse — RPC contro directory LDAP. Spesso danno risultati sovrapponibili su utenti e gruppi, ma con superficie di permessi e dettaglio diversi: quando uno è bloccato, vale la pena provare l'altro.

**Cosa significa `NT_STATUS_ACCESS_DENIED` con rpcclient?**
La sessione è valida ma l'account non ha permessi per quel comando specifico. Non è un errore di sintassi: prova altri comandi meno privilegiati o un'altra fonte.

***

Tutto quanto descritto vale esclusivamente su sistemi di tua proprietà o in ambienti autorizzati (lab, CTF, HTB, PG).
