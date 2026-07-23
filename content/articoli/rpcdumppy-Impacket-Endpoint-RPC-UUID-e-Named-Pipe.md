---
title: 'rpcdump.py Impacket: Endpoint RPC, UUID e Named Pipe'
slug: rpcdump
description: 'Guida a rpcdump.py di Impacket per enumerare endpoint RPC Windows, UUID, named pipe e porte dinamiche. Comandi pratici e analisi per il pentesting.'
image: /rpcdump-enumerazione-endpoint-rpc.webp
draft: false
date: 2026-07-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - rpcdump
  - endpoint-mapper
  - ms-rpc
  - uuid-rpc
---

# rpcdump.py: Enumerare Endpoint RPC, UUID e Named Pipe su Windows

`rpcdump.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e interroga l'**Endpoint Mapper** di Windows ([porta 135](https://hackita.it/articoli/porta-135-rpc/)) per farsi restituire la lista di tutte le interfacce RPC registrate sull'host: UUID, protocollo, binding (porta dinamica o named pipe). Non esegue comandi sul target — è pura enumerazione, complementare a quella che fai con [rpcclient](https://hackita.it/articoli/rpcclient/) sulle stesse named pipe. Il risultato è una mappa di cosa gira sull'host e su quali canali è raggiungibile.

**Attenzione fin da subito:** la presenza di un'interfaccia nell'output non equivale a una vulnerabilità. Dimostra solo che quell'interfaccia è registrata sull'Endpoint Mapper. Perché diventi realmente sfruttabile servono altre condizioni: il binding deve essere raggiungibile da remoto (`ncacn_ip_tcp` o `ncacn_np`, non `ncalrpc` che è solo locale), il bind RPC deve completarsi, l'utente deve avere i privilegi richiesti, e il servizio deve avere una configurazione debole o una vulnerabilità applicabile.

Riferimento ufficiale: [fortra/impacket — rpcdump.py](https://github.com/fortra/impacket/blob/master/examples/rpcdump.py)
Documentazione protocollo: [MS-RPCE — Microsoft RPC Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)

## A cosa serve rpcdump.py?

L'**Endpoint Mapper** (porta TCP/135) è il servizio Windows che mappa i client RPC ai servizi registrati. Quando un servizio RPC si avvia, si registra comunicando il proprio **UUID** (identificatore dell'interfaccia), il **protocollo** (`ncacn_ip_tcp`, `ncacn_np`, `ncalrpc`) e la **porta o named pipe** su cui ascolta.

`rpcdump.py` interroga questo registro e restituisce tutto, poi tenta di abbinare ogni UUID a un servizio noto per renderlo leggibile. Si usa tipicamente in fase di [enumeration](https://hackita.it/articoli/enumeration/), dopo aver identificato la porta 135 aperta con [Nmap](https://hackita.it/articoli/nmap/), per capire quali servizi (Task Scheduler, SAM, Service Control Manager, WMI) sono esposti e quindi potenzialmente attaccabili — con la riserva vista sopra sulla differenza tra presenza e sfruttabilità.

## rpcdump richiede credenziali?

Dipende dalla porta. Guardando il codice sorgente attuale:

* **Porta 135 e 593:** nessuna autenticazione — l'Endpoint Mapper risponde senza credenziali su questi due canali
* **Porta 139 e 445:** le credenziali (password o [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)) vengono applicate per l'autenticazione SMB, necessaria per raggiungere l'Endpoint Mapper via `\pipe\epmapper`
* **Porta 443:** le credenziali vengono usate solo per l'autenticazione al proxy RPC (RPC-over-HTTP), non a livello MSRPC

`rpcdump.py` **non implementa Kerberos** — non esistono flag `-k` o `-no-pass` in questa versione del tool.

## Sintassi e opzioni

```bash
impacket-rpcdump [opzioni] [dominio/utente:password@]target
```

| Opzione                       | Descrizione                                      |
| ----------------------------- | ------------------------------------------------ |
| `-target-ip IP`               | IP target — utile se il nome non risolve via DNS |
| `-port {135,139,443,445,593}` | Porta su cui connettersi (default: 135)          |
| `-hashes LM:NT`               | Pass-the-Hash — si applica solo su porta 139/445 |
| `-debug`                      | Output verboso per troubleshooting               |
| `-ts`                         | Aggiunge timestamp a ogni riga di log            |

## Quali porte usa rpcdump.py?

```bash
# Anonymous su 135 (default) — nessuna credenziale possibile né richiesta
impacket-rpcdump 10.10.10.5

# Con credenziali di dominio — autenticazione SMB su porta 445
impacket-rpcdump -port 445 corp.local/user:Password123@10.10.10.5

# Pass-the-Hash su porta 445
impacket-rpcdump -hashes :NThash -port 445 corp.local/administrator@10.10.10.5

# Via RPC over HTTP (593) — credenziali solo per il proxy
impacket-rpcdump -port 593 corp.local/user:pass@10.10.10.5

# IP separato dal nome (NetBIOS senza DNS)
impacket-rpcdump -target-ip 10.10.10.5 corp.local/user:pass@DC01
```

**Quando 135 è filtrato:** `rpcdump` raggiunge specificamente l'Endpoint Mapper attraverso `\pipe\epmapper` via [SMB](https://hackita.it/articoli/smb/) (porta 445), autenticando con [NTLM](https://hackita.it/articoli/ntlm/). Questo non rende automaticamente raggiungibili tutte le altre interfacce RPC dell'host — ogni servizio ha comunque il proprio binding (dinamico o su named pipe specifica) che va verificato separatamente.

## Output e come leggerlo

```
Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol
Provider: samsrv.dll
UUID    : 12345778-1234-ABCD-EF00-0123456789AC
Bindings:
          ncacn_np:\\DC01[\pipe\samr]
          ncacn_ip_tcp:10.10.10.5[49155]

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol
Provider: services.exe
UUID    : 367ABB81-9844-35F1-AD32-98F038001003
Bindings:
          ncacn_np:\\DC01[\pipe\svcctl]
```

Un binding `ncalrpc` (visibile spesso per interfacce come Task Scheduler moderno) indica comunicazione RPC **locale** — da solo non è una superficie raggiungibile dalla rete. Cerca invece `ncacn_ip_tcp` o `ncacn_np` per capire cosa è davvero esposto da remoto.

## IOXIDResolver — enumerare interfacce di rete senza autenticazione

Tra le interfacce che `rpcdump.py` elenca c'è spesso `IObjectExporter` (DCOM). Il suo metodo `ServerAlive2` risponde **senza richiedere alcuna autenticazione** e restituisce tutte le interfacce di rete della macchina, incluse quelle su reti interne o IPv6 non visibili da un semplice scan. È la tecnica che ha reso nota la box HTB "APT": interrogando questo metodo si scopriva un indirizzo IPv6 altrimenti invisibile.

```bash
# Con Impacket (script community IOXIDResolver.py, non incluso di default)
python3 IOXIDResolver.py -t 10.10.10.5

# Con rpcmap.py, forzando i binding numeri di opnum bassi sull'interfaccia DCOM
rpcmap.py -brute-opnums -opnum-max 5 ncacn_ip_tcp:10.10.10.5
```

Utile in due scenari: quando l'host ha più schede di rete (pivoting verso segmenti che nmap non vede da fuori) o quando esiste una configurazione IPv6 che l'attaccante non conosceva.

## Quali UUID RPC sono più importanti durante un pentest?

Durante un penetration test autorizzato, gli endpoint da controllare con priorità più alta sono quelli legati a movimento laterale, coercizione dell'autenticazione e replica AD.

### Interfacce ad alta priorità offensiva

| UUID                                                                            | Interfaccia                               | Binding tipico                                           | Rilevanza                                                                                                                      | Cosa NON dimostra                                           |
| ------------------------------------------------------------------------------- | ----------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| `E3514235-4B06-11D1-AB04-00C04FC2DCD2`                                          | MS-DRSR / DRSUAPI                         | TCP dinamico (nessuna named pipe)                        | Replica AD, percorso [DCSync](https://hackita.it/articoli/dcsync/)                                                             | Non dimostra il possesso dei diritti di replica             |
| `91AE6020-9E3C-11CF-8D7C-00AA00C091BE`                                          | MS-ICPR / ICertPassage                    | `\pipe\cert` o TCP dinamico                              | Interfaccia RPC di una CA AD CS, verificabile poi con [Certipy](https://hackita.it/articoli/certipy/)                          | Non dimostra che relay o ESC siano sfruttabili              |
| `367ABB81-9844-35F1-AD32-98F038001003`                                          | MS-SCMR                                   | `\pipe\svcctl` o TCP                                     | Gestione servizi remoti — [psexec.py](https://hackita.it/articoli/psexec/), [smbexec.py](https://hackita.it/articoli/smbexec/) | Non dimostra privilegi amministrativi                       |
| `86D35949-83C9-4044-B424-DB363231FD0C`                                          | MS-TSCH / ITaskSchedulerService (moderno) | TCP dinamico                                             | Task Scheduler moderno, usato da [atexec.py](https://hackita.it/articoli/atexec/) anche via `\pipe\atsvc` su SMB               | Non dimostra il diritto di creare o avviare task            |
| `1FF70682-0A51-30E8-076D-740BE8CEE98B`                                          | MS-TSCH / ATSvc legacy                    | `\pipe\atsvc`                                            | Task Scheduler legacy (comando AT), usato solo da at.exe                                                                       | Non indica che il sistema supporti ancora operazioni legacy |
| `378E52B0-C0A9-11CF-822D-00AA0051E40F`                                          | MS-TSCH / SASec                           | `\pipe\atsvc`                                            | Gestione sicurezza dei task legacy                                                                                             | Non dimostra accesso amministrativo                         |
| `12345678-1234-ABCD-EF00-0123456789AB`                                          | MS-RPRN (Print Spooler)                   | `\pipe\spoolss`                                          | Superficie coercizione — PrinterBug/SpoolSample                                                                                | Non dimostra che PrintNightmare sia presente                |
| `76F03F96-CDFD-44FC-A22C-64950A001209`                                          | MS-PAR (asincrona, stessa pipe spoolss)   | `\pipe\spoolss` o TCP dinamico                           | Interfaccia asincrona del print system, usata anche in PrintNightmare                                                          | Non va confuso con l'UUID principale MS-RPRN                |
| `C681D488-D850-11D0-8C52-00C04FD90F7E` / `DF1941C5-FE89-4E79-BF10-463657ACF44D` | MS-EFSR / EFSRPC                          | `\pipe\efsrpc` (anche via lsarpc, samr, lsass, netlogon) | Coercizione autenticazione — tecnica PetitPotam                                                                                | Non dimostra che il metodo RPC necessario sia accettato     |
| `4FC742E0-4A10-11CF-8273-00AA004AE673`                                          | MS-DFSNM                                  | `\pipe\netdfs`                                           | Gestione DFS — superficie DFSCoerce                                                                                            | Non dimostra che la chiamata coercitiva sia autorizzata     |
| `12345678-1234-ABCD-EF00-01234567CFFB`                                          | MS-NRPC / Netlogon                        | `\pipe\netlogon` o TCP dinamico                          | Secure channel, Zerologon (CVE-2020-1472)                                                                                      | Non dimostra vulnerabilità su sistemi patchati              |

### Interfacce utili per enumerazione e post-exploitation

| UUID                                   | Interfaccia                   | Endpoint                                  | Utilità                                                                                                                                                                          |
| -------------------------------------- | ----------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `338CD001-2244-31F1-AAAA-900038001003` | MS-RRP (Remote Registry)      | `\pipe\winreg`                            | Lettura/modifica remota del registro con permessi adeguati                                                                                                                       |
| `3DDE7C30-165D-11D1-AB8F-00805F14DB40` | MS-BKRP (BackupKey)           | `\pipe\protected_storage`, `\pipe\ntsvcs` | Chiavi di backup DPAPI del dominio                                                                                                                                               |
| `12345778-1234-ABCD-EF00-0123456789AC` | MS-SAMR                       | `\pipe\samr` o TCP                        | Enumerazione utenti, gruppi, alias                                                                                                                                               |
| `12345778-1234-ABCD-EF00-0123456789AB` | MS-LSAT / MS-LSAD             | `\pipe\lsarpc`                            | Traduzione SID-nome, policy LSA, trust                                                                                                                                           |
| `4B324FC8-1670-01D3-1278-5A47BF6EE188` | MS-SRVS (Server Service)      | `\pipe\srvsvc`                            | Share, sessioni, connessioni                                                                                                                                                     |
| `6BFFD098-A112-3610-9833-46C3F87E345A` | MS-WKST (Workstation Service) | `\pipe\wkssvc`                            | Info su workstation, dominio, utenti connessi                                                                                                                                    |
| `82273FDC-E32A-18C3-3F78-827929DC23EA` | MS-EVEN (Eventlog Remoting)   | `\pipe\eventlog`                          | Lettura remota degli event log — utile per enumerare sessioni utente pregresse (vedi tool community LogHunter). Oggetto di CVE-2025-29969 (scrittura file arbitraria via TOCTOU) |
| `9556DC99-828C-11CF-A37E-00AA003240C7` | MS-WMI / IWbemServices        | DCOM, TCP dinamico                        | Query WMI e gestione remota — è l'interfaccia sfruttata da [wmiexec.py](https://hackita.it/articoli/wmiexec/)                                                                    |
| `F309AD18-D86A-11D0-A075-00C04FB68820` | MS-WMI / IWbemLevel1Login     | DCOM, TCP dinamico                        | Login e inizializzazione sessioni WMI                                                                                                                                            |

**Nota su WMI:** `8BC3F05E-D86B-11D0-A075-00C04FB68820` che vedi spesso citato non è l'UUID dell'interfaccia `IWbemServices` — è il **CLSID** usato per l'attivazione WMI via DCOM (`WbemLevel1Login`). L'interfaccia che esegue effettivamente le query è `IWbemServices`, UUID `9556DC99-828C-11CF-A37E-00AA003240C7`.

### UUID facili da confondere

Una sola cifra sbagliata cambia completamente il protocollo identificato:

| UUID                                   | Protocollo              |
| -------------------------------------- | ----------------------- |
| `12345678-1234-ABCD-EF00-0123456789AB` | MS-RPRN (Print Spooler) |
| `12345778-1234-ABCD-EF00-0123456789AB` | MS-LSAT/MS-LSAD         |
| `12345778-1234-ABCD-EF00-0123456789AC` | MS-SAMR                 |
| `12345678-1234-ABCD-EF00-01234567CFFB` | MS-NRPC (Netlogon)      |

## Grep per filtrare l'output

```bash
# Trova solo named pipe
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep "pipe\\"

# Cerca Print Spooler (coercizione)
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep -i "spool\|12345678-1234-ABCD-EF00-0123456789AB"

# Cerca NTDS Replication (percorso DCSync)
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep "E3514235"

# Cerca Netlogon (Zerologon)
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep "12345678-1234-ABCD-EF00-01234567CFFB"

# Export completo per analisi
impacket-rpcdump corp.local/user:pass@10.10.10.5 > rpcdump_output.txt
grep -E "Protocol:|UUID|ncacn_np|ncacn_ip_tcp" rpcdump_output.txt
```

## Qual è la differenza tra rpcdump.py e rpcmap.py?

`rpcmap.py` è il complemento di rpcdump: testa binding diretti su interfacce specifiche senza passare dall'Endpoint Mapper. È utile quando l'epmapper è filtrato ma conosci già una porta alta aperta (trovata con Nmap) o vuoi verificare un binding via named pipe specifico.

```bash
# Enumera interfacce sulla porta 135
rpcmap.py ncacn_ip_tcp:10.10.10.5[135]

# Su porta alta specifica (trovata con nmap)
rpcmap.py ncacn_ip_tcp:10.10.10.5[49155]

# Via named pipe, con autenticazione SMB (transport) diversa dall'auth RPC
rpcmap.py -auth-transport corp.local/user:pass 'ncacn_np:10.10.10.5[\pipe\samr]'

# Pass-the-Hash sia a livello RPC che di trasporto
rpcmap.py -hashes-rpc :NThash -hashes-transport :NThash ncacn_ip_tcp:10.10.10.5[135]
```

**Quando il server richiede client autenticati** (policy "Restrict Unauthenticated RPC Clients"), la chiamata di enumerazione standard (MGMT) fallisce. In quel caso `rpcmap.py` ha un database interno di UUID noti e prova a fare il bind di ognuno singolarmente per capire quali interfacce esistono davvero:

```bash
# Forza il tentativo di bind su ogni UUID noto, ignorando l'MGMT bloccato
rpcmap.py -auth-level 1 ncacn_ip_tcp:10.10.10.5[135]

# Con livello di autenticazione più alto e credenziali
rpcmap.py -auth-level 6 -auth-rpc corp.local/user:pass ncacn_ip_tcp:10.10.10.5[135]
```

## rpcdump in un workflow di enumerazione

```
1. nmap -sV -p 135 10.10.10.0/24 → identifica host con RPC esposto
2. rpcdump.py → mappa i servizi esposti e le named pipe
3. rpcclient -U '' -N target → prova sessione null diretta sulle pipe trovate (samr, lsarpc)
4. Identifica vettori da approfondire (verificando SEMPRE binding e privilegi reali):
   \pipe\samr → enumerazione SAM
   \pipe\svcctl → psexec/smbexec (se hai creds admin)
   \pipe\atsvc → atexec.py
   \pipe\spoolss → verifica coercizione (PrinterBug/SpoolSample)
   E3514235 (DRSUAPI) → percorso DCSync, se sei DA
5. rpcmap.py → approfondimento su porte/pipe specifiche, o bypass se l'MGMT è bloccato
6. IObjectExporter / ServerAlive2 → se serve scoprire altre interfacce di rete (IPv6, altre schede)
```

## Detection: cosa vede davvero chi ti monitora

**Cos'è un opnum, in una riga:** ogni interfaccia RPC espone diverse funzioni (es. "crea un servizio", "leggi il registro"); l'**opnum** è semplicemente il numero che identifica QUALE funzione hai chiamato — un po' come il numero di un'opzione in un menu telefonico. Sapere l'opnum ti dice esattamente quale azione hai fatto, non solo con quale servizio hai parlato.

Sapere non solo quale UUID triggera un alert, ma quale opnum lo fa, ti dice esattamente cosa rende un tool rumoroso rispetto a un altro — utile per capire le scelte OPSEC, non solo per il blue team.

| Interfaccia | UUID                                   | Opnum critico                                      | Cosa rileva                                                                  |
| ----------- | -------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------- |
| MS-SCMR     | `367ABB81-9844-35F1-AD32-98F038001003` | `0xC` (RCreateServiceW) / `0x18` (RCreateServiceA) | Creazione servizio remoto — [psexec.py](https://hackita.it/articoli/psexec/) |
| MS-TSCH     | `86D35949-83C9-4044-B424-DB363231FD0C` | `0x1` (SchRpcRegisterTask)                         | Registrazione task — [atexec.py](https://hackita.it/articoli/atexec/)        |
| MS-EFSR     | `C681D488-D850-11D0-8C52-00C04FD90F7E` | `0x0` / `0x4`                                      | Chiamate coercizione PetitPotam                                              |
| MS-RRP      | `338CD001-2244-31F1-AAAA-900038001003` | — (l'intera interfaccia è sensibile)               | Accesso remoto al registro                                                   |

In pratica: un tool che chiama solo `SchRpcRegisterTask` genera un evento specifico e riconoscibile a prescindere dal nome del task (random o no) — la firma è sull'opnum, non sui dettagli superficiali.

**Cosa usano i difensori per bloccare, non solo loggare:** oltre agli Event ID nativi, esistono soluzioni come **RPC Firewall** (Zero Networks) che si iniettano nel processo RPC server e permettono di bloccare per UUID+opnum+IP sorgente — ad esempio bloccando `367ABB81-...` da qualunque host che non sia un jump box autorizzato, neutralizzando psexec/smbexec senza toccare il resto del servizio. Sapere che esiste ti aiuta a spiegare un fallimento anomalo ("access denied" pur con credenziali corrette) durante un assessment.

Sul fronte opposto, chi fa ricerca su queste interfacce usa tool come **MS-RPC-Fuzzer** (basato su NtObjectManager) per bombardare ogni procedura RPC con input mutati e scoprire crash o comportamenti anomali — un approccio complementare a rpcdump, orientato a trovare vulnerabilità piuttosto che enumerare superficie esistente.

## Errori comuni

| Errore                                         | Causa                                                                 | Soluzione                                                                                                                  |
| ---------------------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `Connection refused`                           | Porta 135 filtrata                                                    | Prova `-port 445`                                                                                                          |
| `MSRPC SessionError: access_denied`            | Autenticazione SMB fallita o negata                                   | Verifica credenziali, prova un altro utente                                                                                |
| `DCE/RPC connection failed`                    | Firewall blocca porte alte dinamiche                                  | Usa `-port 445` per passare da SMB                                                                                         |
| Output vuoto                                   | Host non ha Endpoint Mapper attivo                                    | Verifica con nmap che 135/445 siano aperte                                                                                 |
| Nessuna interfaccia utile su target aggiornati | Sessioni null disabilitate (default da Windows 10 Anniversary in poi) | Prova con credenziali valide anche minime, o verifica `\pipe\samr` con [rpcclient](https://hackita.it/articoli/rpcclient/) |

## Domande frequenti

**A cosa serve rpcdump.py?**
Enumera tutti i servizi RPC registrati su un host Windows tramite l'Endpoint Mapper (porta 135), mostrando UUID, protocollo e binding (porta o named pipe) di ognuno. Non esegue comandi, solo enumerazione.

**rpcdump.py richiede credenziali?**
Solo su porta 139/445 (autenticazione SMB) e parzialmente su 443 (solo per il proxy RPC). Su 135 e 593 funziona senza credenziali, nessuna autenticazione è prevista.

**Quali porte usa rpcdump.py?**
135 (default), 139, 443, 445, 593. Quando 135 è filtrato, passa da 445 raggiungendo l'Endpoint Mapper via `\pipe\epmapper`.

**La presenza di un UUID significa che il servizio è vulnerabile?**
No. Dimostra solo che l'interfaccia è registrata. Serve poi verificare che il binding sia raggiungibile da remoto, che il bind RPC vada a buon fine, che tu abbia i privilegi giusti e che il servizio abbia una configurazione debole o vulnerabile.

**Qual è la differenza tra rpcdump.py e rpcmap.py?**
rpcdump interroga l'Endpoint Mapper e ti dà la lista completa. rpcmap testa un binding specifico che già conosci (porta o pipe), utile quando l'epmapper è filtrato o quando l'MGMT è bloccato da policy.

**Perché rpcdump mostra un binding ncalrpc?**
`ncalrpc` è comunicazione RPC solo locale, sulla stessa macchina — non è raggiungibile dalla rete. Se vedi solo `ncalrpc` per un'interfaccia, quella non è una superficie di attacco remota.

## Cheat Sheet

```bash
# Base (anonymous su 135, nessuna credenziale possibile)
impacket-rpcdump 10.10.10.5

# Con credenziali (autenticazione SMB su 445)
impacket-rpcdump -port 445 corp.local/user:pass@10.10.10.5

# Pass-the-Hash (solo su 139/445)
impacket-rpcdump -hashes :NThash -port 445 corp.local/user@10.10.10.5

# Via RPC over HTTP
impacket-rpcdump -port 593 corp.local/user:pass@10.10.10.5

# Filtra named pipe
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep "pipe\\"

# Cerca Print Spooler (coercizione)
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep -i "spool\|12345678-1234-ABCD-EF00-0123456789AB"

# Cerca DRSUAPI (percorso DCSync)
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep "E3514235"

# Cerca Netlogon (Zerologon)
impacket-rpcdump corp.local/user:pass@10.10.10.5 | grep "12345678-1234-ABCD-EF00-01234567CFFB"

# rpcmap su porta o pipe specifica
rpcmap.py ncacn_ip_tcp:10.10.10.5[49155]
rpcmap.py 'ncacn_np:10.10.10.5[\pipe\samr]'
```

> Uso esclusivo in ambienti autorizzati.
