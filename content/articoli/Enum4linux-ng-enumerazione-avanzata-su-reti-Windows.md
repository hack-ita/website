---
title: 'enum4linux-ng: Enumerazione SMB e Active Directory'
slug: enum4linux-ng
description: 'Guida completa a enum4linux-ng per l''enumerazione SMB e Active Directory: utenti, gruppi, share, policy, SID/RID, autenticazione e comandi pratici.'
image: /enum4linux.webp
draft: false
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - enum4linux-ng
  - Windows Enumeration
  - RPC Enumeration
  - SMB Enumeration
featured: true
---

# enum4linux-ng: Enumerazione SMB, RPC e Active Directory

**A cosa serve enum4linux-ng?** Automatizza l'enumerazione di sistemi Windows e Samba raccogliendo dati via SMB, RPC, NetBIOS e — sui domain controller — anche LDAP/LDAPS: utenti, gruppi, share, password policy, info di sistema e di dominio, con export in JSON/YAML per riuso in pipeline o report. Risolve il classico "445 aperta ma non so cosa tirarci fuori" con un unico comando ripetibile — **solo in lab/CTF/HTB/PG/VM autorizzate**.

## Cos'è enum4linux-ng e Come Funziona

È un wrapper attorno ai tool Samba `nmblookup`, `net`, `rpcclient` e `smbclient` — ma non solo: `ldapsearch` e `polenum` sono reimplementati nativamente in Python, il che gli permette di parlare LDAP/LDAPS direttamente sui DC senza dipendere dal binario esterno, oltre a esportare tutti i risultati in JSON/YAML per riuso.

```text
enum4linux-ng
  |
  +-- SMB/RPC: utenti, gruppi, share, policy, OS info, servizi, stampanti
  |
  +-- NetBIOS: nomi, workgroup
  |
  +-- LDAP/LDAPS: info di dominio aggiuntive (solo su DC)
```

L'enumerazione è "smart": il tool verifica prima se SMB o LDAP sono raggiungibili e salta automaticamente i check che fallirebbero comunque (es. LDAP se non è in ascolto), e si ferma subito se non riesce a stabilire una sessione SMB.

## Installazione e Verifica

```bash
sudo apt update && sudo apt install enum4linux-ng -y
enum4linux-ng -h
```

## Sintassi e Opzioni Fondamentali

```text
enum4linux-ng [opzioni] <host>
```

| Opzione           | Funzione                                                                                           |
| ----------------- | -------------------------------------------------------------------------------------------------- |
| `-A`              | Enumerazione completa: `-U -G -S -P -O -N -I -L` (nessun'altra opzione = comportamento di default) |
| `-As`             | Come `-A` ma senza NetBIOS names lookup: `-U -G -S -P -O -I -L`                                    |
| `-U`              | Utenti via RPC                                                                                     |
| `-G`              | Gruppi via RPC                                                                                     |
| `-Gm`             | Gruppi **con membri** via RPC (non incluso di default, nemmeno in `-A`)                            |
| `-S`              | Share via RPC                                                                                      |
| `-C`              | Servizi via RPC                                                                                    |
| `-P`              | Password policy via RPC                                                                            |
| `-O`              | Info sistema operativo via RPC                                                                     |
| `-I`              | Info stampanti via RPC                                                                             |
| `-L`              | Info di dominio aggiuntive via LDAP/LDAPS (solo DC)                                                |
| `-R [BULK_SIZE]`  | RID cycling — **non incluso in `-A`**, va richiesto esplicitamente                                 |
| `-r RANGES`       | Range RID da testare (default `500-550,1000-1050`)                                                 |
| `-u/-p/-w`        | Utente / password / dominio                                                                        |
| `-H NTHASH`       | Autenticazione con NT hash                                                                         |
| `-K TICKET_FILE`  | Autenticazione Kerberos                                                                            |
| `-t TIMEOUT`      | Timeout connessione (default 10s)                                                                  |
| `-oJ / -oY / -oA` | Export JSON / YAML / entrambi                                                                      |

**Attenzione:** `-A` non include il RID cycling — è una delle differenze principali rispetto al vecchio `enum4linux.pl`. Se ti aspetti RID cycling nell'output di `-A` e non lo vedi, non è un bug: serve `-R` esplicito.

## Enumerazione SMB/RPC

### Utenti

```bash
enum4linux-ng -U -d 10.10.10.10
```

```text
[+] Users (RPC)
  LAB\Administrator
  LAB\svc_backup
  LAB\jdoe
```

`-d` aggiunge dettagli extra per utenti e gruppi. Un account `svc_*` è quasi sempre un candidato di interesse offensivo (service account, spesso con permessi più larghi del previsto).

### Gruppi e Membership

```bash
enum4linux-ng -G 10.10.10.10
enum4linux-ng -Gm 10.10.10.10
```

I membri dei gruppi **non** vengono enumerati di default: serve `-Gm` esplicito per correlare direttamente gruppo → membri, senza passare a query [rpcclient](https://hackita.it/articoli/rpcclient/) manuali.

### Share

```bash
enum4linux-ng -S 10.10.10.10
```

Share non standard (oltre a `IPC$`/`NETLOGON`/`SYSVOL`) sono spesso la fonte di leak più concreta. `NT_STATUS_ACCESS_DENIED` su questo modulo significa che serve autenticazione o che la share è protetta — passa ad auth o valida accesso diretto con [smbclient](https://hackita.it/articoli/smbclient/).

### Password Policy

```bash
enum4linux-ng -P 10.10.10.10
```

Minlen e lockout deboli sono un segnale reale per la priorità di eventuali test di credenziali nel perimetro autorizzato dell'engagement.

### Servizi e Stampanti

```bash
enum4linux-ng -C 10.10.10.10
enum4linux-ng -I 10.10.10.10
```

`-C` enumera servizi via RPC, `-I` informazioni sulle stampanti — sono due moduli distinti, non un'unica opzione combinata.

### Info Dominio via LDAP (solo DC)

```bash
enum4linux-ng -L 10.10.10.10
```

Attivo solo se il target espone LDAP — su un member server (non DC) questo modulo viene saltato automaticamente dalla logica "smart" del tool.

## RID Cycling

```bash
enum4linux-ng -R 10.10.10.10 -r 500-550,1000-1050
```

`-R` abilita il RID cycling, `-r` definisce i range (il default è già `500-550,1000-1050`, coincide quasi sempre con gli account "core" di un dominio piccolo). Non è un fallback universale: è un metodo di discovery alternativo che funziona quando il servizio RPC permette di risolvere singoli RID anche se la user enumeration diretta (`-U`) è bloccata — dipende comunque da cosa il target consente di interrogare.

## Autenticazione

```bash
# Credenziali di dominio
enum4linux-ng -A 10.10.10.10 -u jdoe -p 'Password123!' -w LAB

# Account locale
enum4linux-ng -S 10.10.10.10 -u localuser -p 'LocalPass!' --local-auth

# NT hash
enum4linux-ng -U 10.10.10.10 -u Administrator -H <NTHASH>

# Ticket Kerberos (solo ambienti AD, DNS deve essere configurato correttamente)
enum4linux-ng -A 10.10.10.10 -K /tmp/krb5cc_1000
```

Anche un account low-priv spesso sblocca molto più di quanto ottieni in anonimo — confronta sempre i due run per capire cosa era davvero limitato da permessi. `-H` vuole l'NT hash nel formato atteso dalla versione installata: verifica con `-h` se hai dubbi, non assumere un formato combinato LM:NT per default.

## Troubleshooting

**"No session can be set up"** — il tool si ferma se SMB è raggiungibile ma non riesce ad aprire sessione:

```bash
enum4linux-ng -As 10.10.10.10 -t 10
```

`-As` rimuove la dipendenza dal lookup NetBIOS; se persiste, serve autenticazione (`-u/-p` o `--local-auth`) o verificare che il session setup completi davvero, non solo che la porta risulti aperta.

**Debug puntuale:**

```bash
enum4linux-ng -U 10.10.10.10 -v
```

`-v` stampa i comandi Samba effettivamente eseguiti (net, rpcclient, smbclient): utile per riprodurre manualmente il punto esatto in cui fallisce.

## Hardening & Detection

L'enumerazione più ricca avviene quando: anonymous/null session sono permissive, RPC consente il listing di utenti/gruppi/share, LDAP risponde con info di dominio senza restrizioni.

**Segnali di detection:** spike di connessioni su 445/139 con richieste RPC ravvicinate, pattern di RID cycling (query ripetute su RID sequenziali), enumerazioni share/policy in sequenza rapida da un host non amministrativo.

**Mitigazioni:** limita l'enumerazione anonima e l'accesso alle pipe RPC, segmenta SMB (445 solo dove serve), applica auditing sugli accessi a share sensibili (SYSVOL/NETLOGON), riduci gli account privilegiati esposti a query di dominio non necessarie.

## enum4linux-ng vs rpcclient vs smbclient vs ldapsearch vs NetExec vs BloodHound

| Tool                                                  | Focus                                                 |
| ----------------------------------------------------- | ----------------------------------------------------- |
| enum4linux-ng                                         | Enumerazione automatizzata SMB/RPC/NetBIOS/LDAP       |
| [rpcclient](https://hackita.it/articoli/rpcclient/)   | Query MS-RPC granulari (SAMR/LSARPC/SRVSVC)           |
| [smbclient](https://hackita.it/articoli/smbclient/)   | Share e file                                          |
| [ldapsearch](https://hackita.it/articoli/ldapsearch/) | Directory LDAP/AD con controllo fine su bind e filtri |
| [NetExec](https://hackita.it/articoli/crackmapexec/)  | Automation/azioni SMB-AD su più host                  |
| [BloodHound](https://hackita.it/articoli/bloodhound/) | Relazioni e attack path AD                            |

enum4linux-ng è il primo comando quando arrivi su un target SMB e vuoi una fotografia completa senza scrivere query manuali; quando serve granularità su un singolo oggetto (RID, filtro LDAP specifico) o operare su molti host insieme, passi agli strumenti dedicati sopra.

## Workflow HTB/PG

```bash
# 1. Conferma il servizio
nmap -p 139,445 --open -sV 10.10.10.10

# 2. Fotografia completa (fallback -As se NetBIOS crea attrito)
enum4linux-ng -A 10.10.10.10

# 3. Se la sessione anonima è limitata, ripeti con credenziali low-priv
enum4linux-ng -A 10.10.10.10 -u jdoe -p 'Password123!' -w LAB

# 4. Se enumdomusers/-U non basta, RID cycling mirato
enum4linux-ng -R 10.10.10.10 -r 500-550,1000-1050

# 5. Congela i risultati per report e correlazione con BloodHound/LDAP
enum4linux-ng -A 10.10.10.10 -oA e4lng_10.10.10.10
```

Se vedi `SYSVOL`/`NETLOGON` o share custom al passo 2, è già una priorità concreta per il listing successivo con smbclient; se `-A` anonimo non ritorna quasi nulla ma con credenziali low-priv cambia drasticamente, hai la conferma che era un limite di sessione, non assenza di dati.

## Checklist Operativa

* 139/445 raggiungibili verificati prima di lanciare `-A`.
* `-As` provato se il lookup NetBIOS crea attrito o timeout.
* Sessione confermata: se fallisce, passa subito ad auth invece di insistere con l'anonimo.
* Utenti/gruppi/share/policy enumerati; `-R` come alternativa se `-U` è bloccato.
* Risultati esportati (`-oJ`/`-oA`) per riuso e confronto tra run.
* Trovate share interessanti? Valida l'accesso reale con smbclient prima di assumere sia solo listing.

## Riassunto 80/20

| Obiettivo               | Comando                                             |
| ----------------------- | --------------------------------------------------- |
| Fotografia completa     | `enum4linux-ng -A 10.10.10.10`                      |
| Evitare attrito NetBIOS | `enum4linux-ng -As 10.10.10.10`                     |
| Gruppi con membri       | `enum4linux-ng -Gm 10.10.10.10`                     |
| RID cycling mirato      | `enum4linux-ng -R 10.10.10.10 -r 500-550,1000-1050` |
| Congelare risultati     | `enum4linux-ng -A 10.10.10.10 -oA nome_output`      |

## Concetti Controintuitivi

* **"`-A` fa anche RID cycling"** — no, `-A` copre `-U -G -S -P -O -N -I -L`, il RID cycling resta escluso di default e va richiesto con `-R`.
* **"445 aperta = posso enumerare tutto"** — il tool si ferma subito se non riesce a stabilire sessione: la porta aperta non garantisce niente da sola.
* **"I membri dei gruppi si vedono sempre con `-G`"** — no, servono membri espliciti solo con `-Gm`.
* **"Il RID cycling è sempre la soluzione quando `-U` fallisce"** — dipende comunque da cosa il servizio RPC permette di risolvere: non è garanzia automatica di risultati.

## FAQ

**Cosa fa `-A`?**
Esegue l'enumerazione completa standard (`-U -G -S -P -O -N -I -L`); è anche il comportamento di default se non specifichi altre opzioni. Non include il RID cycling.

**Qual è la differenza tra `-A` e `-As`?**
`-As` esegue lo stesso set di `-A` ma senza il lookup dei nomi NetBIOS (niente `-N`) — utile quando 137/138 sono filtrate o rumorose.

**Come enumero i membri di un gruppo?**
Con `-Gm`, non con `-G` da solo: i membri non sono inclusi nell'enumerazione base dei gruppi.

**Come funziona l'autenticazione con hash?**
`-H` accetta l'NT hash nel formato atteso dalla versione installata — verifica con `-h` prima di assumere un formato specifico.

**enum4linux-ng sostituisce rpcclient o ldapsearch?**
No: è un buon primo passo automatizzato, ma per query granulari su un singolo oggetto o filtri LDAP specifici restano più precisi gli strumenti dedicati.

***

Fonte primaria per opzioni e comportamento: [repository ufficiale su GitHub](https://github.com/cddmp/enum4linux-ng). Tutto quanto descritto vale esclusivamente su sistemi di tua proprietà o in ambienti autorizzati (lab, CTF, HTB, PG).
