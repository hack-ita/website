---
title: 'Enum4linux-ng: Enumerazione Avanzata su reti Windows'
slug: enum4linux-ng
description: >-
  Scopri come usare enum4linux-ng per estrarre utenti, gruppi, condivisioni e
  SID da sistemi Windows. Strumento essenziale per ogni fase di information
  gathering.
image: /enum4linux.webp
draft: false
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - enum4linux-ng
featured: true
---

# Enum4linux-ng: Enumerazione Avanzata su reti Windows

Risolverai il classico problema “SMB aperto ma non capisco cosa posso tirar fuori” con una pipeline rapida e verificabile, **solo in lab/CTF/HTB/PG/VM personali**.

## Intro

enum4linux-ng è una **riscrittura moderna** (Python) di enum4linux per estrarre informazioni da host **Windows/Samba** via SMB/NetBIOS/RPC e, quando ha senso, via LDAP.

In un workflow offensivo da lab ti serve per trasformare “porta 445 aperta” in asset concreti: nomi host, dominio/workgroup, utenti/gruppi, condivisioni, policy e SID/RID.

Cosa farai in questa guida:

* Eseguire un “do-the-right-thing” scan con `-A` / `-As`
* Passare a moduli mirati (`-U`, `-S`, `-P`, `-R`) quando serve
* Gestire autenticazione (null/credenziali/hash/ticket) senza perdere tempo
* Interpretare output e fixare errori comuni

Nota etica: tutto qui sotto è per ambienti **autorizzati** e controllati.

## Cos’è enum4linux-ng e dove si incastra nel workflow SMB

> **In breve:** enum4linux-ng è un wrapper “intelligente” attorno ai tool Samba (rpcclient/smbclient/net/nmblookup) per fare enumerazione SMB/AD rapida e modulare in lab.

Nel flusso operativo, di solito viene **dopo** un check porte (445/139) e **prima** di interazioni più invasive (accesso share, spraying, post-exploitation).

Quando NON usarlo:
Se hai già credenziali valide e vuoi azione immediata su tanti host, spesso è più veloce passare a un framework tipo CrackMapExec/NetExec e poi tornare qui solo per dettagli specifici.

Perché: capire “che mondo è” (workgroup vs dominio, naming, policy) evita di sprecare colpi.

Cosa aspettarti: output strutturato con sezioni (users/groups/shares/policy/os) e stop anticipato se non riesce a stabilire sessione.

Comando:

```bash
enum4linux-ng -A 10.10.10.10
```

Esempio di output (può variare):

```text
[*] Target ........... 10.10.10.10
[*] SMB reachable .... yes
[*] Session setup .... ok (anonymous/guest)
[+] Workgroup/Domain . LAB
[+] OS info .......... Windows Server (build ...)
[+] Shares ........... IPC$, NETLOGON, SYSVOL
[+] Users (RPC) ...... 12 found
[+] Password policy .. minlen=7 lockout=0
```

Interpretazione: se vedi `Session setup ok`, puoi fidarti che i moduli RPC “camminano” e l’enumerazione è significativa.

Errore comune + fix: se vedi stop per sessione fallita, passa a credenziali o prova `-As` (meno dipendenze NetBIOS) e aumenta timeout con `-t`.

## Installazione, verifica versione e quick sanity check

> **In breve:** su Kali conviene installare via APT; poi verifica help/versione e fai un run “short” per controllare sessione e reachability.

Perché: enum4linux-ng dipende da tool Samba e librerie Python; un’installazione “mezza” produce falsi negativi.

Cosa aspettarti: `-h` mostra moduli disponibili e opzioni di auth/export.

Comando:

```bash
sudo apt update && sudo apt install enum4linux-ng -y
```

Esempio di output (può variare):

```text
Setting up enum4linux-ng ...
Processing triggers for man-db ...
```

Interpretazione: se l’install termina pulita, hai anche le dipendenze principali (smbclient, samba-common-bin).

Errore comune + fix: se `enum4linux-ng: command not found`, controlla PATH o installazione; in alternativa usa `python3 -m pip install` dal repo (solo se sai cosa stai facendo in lab).

Perché: sanity check veloce prima di andare “all-in”.

Cosa aspettarti: help con opzioni come `-A`, `-As`, `-U`, `-S`, `-P`, `-R`, export JSON/YAML.

Comando:

```bash
enum4linux-ng -h
```

Interpretazione: se vedi opzioni di export (`-oJ`, `-oY`, `-oA`) puoi già pensare a pipeline e parsing.

Errore comune + fix: se mancano tool Samba, reinstalla `samba-common-bin` e `smbclient`.

## Sintassi base + 3 pattern che userai sempre

> **In breve:** pattern 1 = “default smart” (`-A`), pattern 2 = “short e veloce” (`-As`), pattern 3 = “moduli mirati + export” (es. `-U/-S/-P` + `-oJ`).

### Pattern 1 — “Fai tutto (safe)”: `-A`

Perché: `-A` lancia l’enumerazione “semplice” completa e spesso basta per scegliere il prossimo step.

Cosa aspettarti: moduli users/groups/shares/policy/os + lookup NetBIOS e info LDAP se applicabile.

Comando:

```bash
enum4linux-ng -A 10.10.10.10
```

Interpretazione: perfetto come primo comando quando vuoi una fotografia generale.

Errore comune + fix: troppo lento o NetBIOS problematico → passa a `-As` o aumenta `-t`.

### Pattern 2 — “Short, meno dipendenze NetBIOS”: `-As`

Perché: evita il lookup dei nomi NetBIOS, utile quando 137/138 sono filtrate o rumorose.

Cosa aspettarti: output simile a `-A` ma senza la parte NetBIOS.

Comando:

```bash
enum4linux-ng -As 10.10.10.10
```

Interpretazione: se `-A` ti dà errori su NetBIOS, `-As` spesso “salva” l’enumerazione RPC.

Errore comune + fix: se comunque non stabilisce sessione, devi passare ad auth.

### Pattern 3 — “Mirato + esportabile”: moduli + `-oJ`

Perché: quando vuoi solo una cosa (es. utenti) e vuoi salvare risultati per riuso.

Cosa aspettarti: JSON con findings riutilizzabili (anche per report o parsing).

Comando:

```bash
enum4linux-ng -U -S -P 10.10.10.10 -oJ e4lng_10.10.10.10
```

Esempio di output (può variare):

```text
[+] Users (RPC) ...... done
[+] Shares (RPC) ..... done
[+] Password policy .. done
[*] Writing JSON ..... e4lng_10.10.10.10.json
```

Interpretazione: ottimo per “freeze” dei risultati durante un lab e confronto tra run con credenziali diverse.

Errore comune + fix: file non creato → controlla permessi nella directory o usa path assoluto.

## Enumerazione “in profondità”: utenti, share, policy, servizi

> **In breve:** quando `-A` ti dà segnali interessanti, passi a moduli specifici per estrarre dettagli e ridurre rumore.

Qui, se vuoi affiancare verifiche manuali e query più chirurgiche, ti torna utilissima anche la guida a **Rpcclient** per interrogazioni SMB/MS-RPC più granulari: [rpcclient: attacco e enum SMB su Active Directory](https://hackita.it/articoli/rpcclient/)

### Utenti via RPC: `-U` (+ dettagli `-d`)

Perché: una userlist (anche parziale) sblocca password policy, naming convention, possibili account di servizio.

Cosa aspettarti: elenco utenti; con `-d` ottieni dettagli extra per utenti/gruppi.

Comando:

```bash
enum4linux-ng -U -d 10.10.10.10
```

Esempio di output (può variare):

```text
[+] Users (RPC)
  LAB\Administrator
  LAB\Guest
  LAB\svc_backup
  LAB\jdoe
```

Interpretazione: `svc_*` è spesso un segnale “lab-offensivo” (account di servizio) da trattare con attenzione e detection in mente.

Errore comune + fix: output vuoto → prova con credenziali, oppure passa a RID cycling se permesso.

### Share via RPC: `-S`

Perché: share esposte (NETLOGON/SYSVOL o share custom) sono una delle fonti più “concrete” di leakage.

Cosa aspettarti: lista share con permessi/descrizioni (a seconda dell’accesso).

Comando:

```bash
enum4linux-ng -S 10.10.10.10
```

Interpretazione: se vedi share non standard, il passo successivo naturale è verificare accesso e listing con smbclient. Vedi anche: [smbclient: accesso e attacco alle condivisioni Windows](https://hackita.it/articoli/smbclient/)

Errore comune + fix: `NT_STATUS_ACCESS_DENIED` → serve auth valida o la share è protetta; prova `-u/-p` o `--local-auth` se stai usando account locali.

### Password policy: `-P`

Perché: ti dice quanto è “weak” il lab (minlen, lockout) e guida scelte successive senza inventare.

Cosa aspettarti: valori di policy recuperati via RPC.

Comando:

```bash
enum4linux-ng -P 10.10.10.10
```

Interpretazione: lockout a 0 e minlen basso in lab spesso significa che test di credenziali possono essere parte dello scenario, ma resta nel perimetro autorizzato.

Errore comune + fix: se non recupera policy, spesso manca sessione RPC; risolvi prima auth.

### Servizi e stampanti: `-C` / `-I`

Perché: in alcuni lab, servizi esposti e stampanti sono “indizi” (naming, ruoli, surface area).

Cosa aspettarti: elenco servizi (se permesso) e info printer.

Comando:

```bash
enum4linux-ng -C -I 10.10.10.10
```

Interpretazione: non è sempre determinante, ma può confermare il ruolo (server vs workstation) e suggerire path di escalation in lab.

Errore comune + fix: se dà errori RPC, aumenta `-t` e verifica reachability 445.

## Autenticazione e session setup: null session, credenziali, hash, ticket

> **In breve:** enum4linux-ng si ferma se non riesce a creare sessione; la leva principale è scegliere l’auth giusta (dominio vs locale) e ridurre attrito (timeout/DNS).

### Credenziali base: `-u` / `-p` (+ dominio `-w`)

Perché: anche un account low-priv in lab spesso sblocca `-U/-G/-S/-P` e info più pulite.

Cosa aspettarti: più enumerazione, meno “Access denied”.

Comando:

```bash
enum4linux-ng -A 10.10.10.10 -u jdoe -p 'Password123!' -w LAB
```

Interpretazione: se cambiano drasticamente share/utenti visibili rispetto ad anonymous, hai conferma che era un limite di sessione.

Errore comune + fix: dominio sbagliato → specifica `-w` corretto o lascia auto-detect e prova senza.

### Account locali: `--local-auth`

Perché: in lab capita di avere credenziali locali valide ma non di dominio.

Cosa aspettarti: auth contro SAM locale, non contro AD.

Comando:

```bash
enum4linux-ng -S 10.10.10.10 -u localuser -p 'LocalPass!' --local-auth
```

Interpretazione: utile quando l’host non è DC o quando stai validando accesso a share locali.

Errore comune + fix: se continui a prendere logon failure, prova a specificare correttamente utente e verifica che l’account sia locale sull’host.

### Auth con hash: `-H` (lab-only, con detection/hardening)

Perché: in alcuni lab l’obiettivo è validare che “pass-the-hash” funzioni su SMB.

Cosa aspettarti: se l’hash è valido e l’host lo accetta, l’enumerazione procede come con password.

Comando:

```bash
enum4linux-ng -U 10.10.10.10 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef
```

Interpretazione: se ottieni userlist, hai confermato in lab che l’autenticazione NTLM via hash è accettata.

Errore comune + fix: hash in formato errato → assicurati `LM:NT` (anche LM “vuoto” va espresso).

Validazione in lab: usa un target di prova e confronta risultati `-U` con password vs hash (stesso account), senza cambiare altri parametri.

Segnali di detection: logon SMB ripetuti (Type 3), anomalie su account privilegiati e da host inattesi.

Hardening/mitigazione: restrizioni NTLM, auditing logon, protezione credenziali, segmentazione e controllo accessi SMB.

### Kerberos ticket: `-K` (AD + DNS ok)

Perché: in AD lab, un ticket Kerberos può essere il modo “pulito” per auth senza password in chiaro.

Cosa aspettarti: funziona solo se DNS/realm sono coerenti e il ticket è valido.

Comando:

```bash
enum4linux-ng -A 10.10.10.10 -K /tmp/krb5cc_1000
```

Interpretazione: se l’enumerazione parte senza chiedere password, stai usando correttamente il ticket.

Errore comune + fix: DNS non configurato → sistema risoluzione e realm prima di usare `-K`.

## Errori comuni e troubleshooting (quelli che fanno perdere tempo)

> **In breve:** i fallimenti più frequenti sono sessione non stabilita, timeout troppo basso, NetBIOS filtrato e mismatch dominio/locale.

### “Stops enumeration / no session can be set up”

Perché: enum4linux-ng interrompe quando SMB è raggiungibile ma non riesce ad aprire una sessione valida.

Cosa aspettarti: output che si ferma presto, con avvisi su session setup.

Comando:

```bash
enum4linux-ng -As 10.10.10.10 -t 10
```

Interpretazione: `-As` riduce dipendenze NetBIOS; `-t` aumenta la tolleranza su reti lente.

Errore comune + fix: se persiste, devi passare ad auth (`-u/-p`, `--local-auth`) o verificare che 445 non sia “fake-open” dietro firewall/IPS in lab.

### Capire cosa sta eseguendo davvero: `-v`

Perché: vedere i comandi Samba sottostanti ti fa capire subito dove si rompe (rpcclient, smbclient, net).

Cosa aspettarti: stampa dei comandi “raw” e più contesto sugli errori.

Comando:

```bash
enum4linux-ng -U 10.10.10.10 -v
```

Interpretazione: se vedi un comando specifico fallire, puoi riprodurlo manualmente e isolare il problema.

Errore comune + fix: output troppo lungo → usa `-v` solo su un modulo alla volta.

### RID cycling che esplode: `-R` + range controllati

Perché: RID cycling può diventare rumoroso o lento se i range sono larghi.

Cosa aspettarti: enumerazione di SID/RID e mapping a nomi.

Comando:

```bash
enum4linux-ng -R 10.10.10.10 -r 500-550,1000-1050
```

Interpretazione: se ottieni nomi utenti anche senza `-U`, hai un canale alternativo di discovery.

Errore comune + fix: troppo lento → restringi `-r` o imposta bulk size (`-R 20`) e aumenta `-t`.

## Alternative e tool correlati (quando preferirli)

> **In breve:** enum4linux-ng è perfetto per “capire e documentare”; altri tool sono migliori per “scalare e agire” su molti host.

Se la tua next-move è validare credenziali e muoverti lateralmente in rete Windows (sempre in lab), spesso conviene passare a un framework credential-centric: [CrackMapExec: attacchi rapidi su Active Directory](https://hackita.it/articoli/crackmapexec/)

Se invece vuoi visualizzare percorsi di attacco e relazioni AD come grafo (e poi tornare a enumerare in modo mirato), qui la combo classica è BloodHound + collector: [BloodHound: mappa l’Active Directory come un hacker](https://hackita.it/articoli/bloodhound/)

Quando NON usarlo:
Se devi solo listare una share e scaricare file, vai diretto con smbclient; se devi fare query RPC specifiche, rpcclient è più chirurgico.

## Hardening & detection: cosa “regala” enum4linux-ng e come chiuderlo

> **In breve:** l’enumerazione SMB vive di configurazioni permissive (anonymous/RPC/LDAP). Hardening = ridurre leakage + tracciare accessi.

Perché: in lab ti interessa capire cosa un attaccante vede “da fuori”; in difesa vuoi ridurre quella superficie.

Cosa aspettarti: l’enumerazione più ricca avviene quando:

* anonymous/null session sono permissive
* RPC consente listing users/groups/shares
* LDAP/LDAPS risponde con info di dominio

Segnali di detection:

* spike di connessioni su 445/139 e richieste RPC ravvicinate
* tentativi di RID cycling (pattern ripetuti)
* enumerazioni share/policy in sequenza rapida

Hardening/mitigazione (alto livello):

* limita enumerazione anonima e restringi accesso a pipe/RPC
* segmenta SMB e consenti 445 solo dove serve
* auditing e alert su accessi anomali a share sensibili (SYSVOL/NETLOGON in contesti AD)
* enforcement di policy credenziali e riduzione account privilegiati esposti

***

## Scenario pratico: enum4linux-ng su una macchina HTB/PG

> **In breve:** in 3 comandi passi da “445 open” a una lista di share/utenti e un file JSON riusabile, con note rapide su detection/hardening.

Ambiente: Kali attacker → target `10.10.10.10` (Windows/Samba lab)

Obiettivo: capire dominio/workgroup, share interessanti e possibili utenti per step successivi.

Perché: fotografia iniziale completa senza ragionare “a mano”.

Cosa aspettarti: output con domain, share, policy, users se sessione ok.

Comando:

```bash
enum4linux-ng -A 10.10.10.10
```

Interpretazione: se vedi `SYSVOL/NETLOGON` o share custom, hai già un vettore di raccolta file/creds in lab.

Perché: isolare subito la superficie più utile (share) con output più pulito.

Cosa aspettarti: lista share e commenti/permessi se disponibili.

Comando:

```bash
enum4linux-ng -S 10.10.10.10
```

Interpretazione: share non standard = priorità alta per listing e ricerca configurazioni.

Perché: salvare findings per non ripetere run e per confrontare “anonymous vs auth”.

Cosa aspettarti: un JSON con risultati aggregati.

Comando:

```bash
enum4linux-ng -U -P 10.10.10.10 -oJ e4lng_10.10.10.10
```

Risultato atteso: un file `e4lng_10.10.10.10.json` con users/policy da riusare.

Detection + hardening: questa sequenza genera richieste RPC in poco tempo e può essere visibile nei log SMB. In difesa, riduci enumerazione anonima/RPC, segmenta 445 e monitora burst su `lsarpc/srvsvc`.

## Playbook 10 minuti: enum4linux-ng in un lab

> **In breve:** sequenza “sempre uguale” per ottenere risultati affidabili, riducendo rumore e bloccandoti solo quando serve davvero l’auth.

### Step 1 – Pre-flight rapido su SMB

Perché: confermi che stai mirando il servizio giusto.

Cosa aspettarti: 445/139 open o filtered (dipende dal lab).

Comando:

```bash
nmap -p 139,445 --open -sV 10.10.10.10
```

### Step 2 – Enumerazione smart completa

Perché: primo dump di info per decidere la direzione.

Cosa aspettarti: domain/workgroup, OS info, share e (se possibile) utenti/policy.

Comando:

```bash
enum4linux-ng -A 10.10.10.10
```

### Step 3 – Fallback “short” se NetBIOS dà fastidio

Perché: togli una dipendenza e spesso recuperi stabilità.

Cosa aspettarti: output simile a `-A` ma senza lookup NetBIOS.

Comando:

```bash
enum4linux-ng -As 10.10.10.10
```

### Step 4 – Moduli mirati: share e policy

Perché: share + policy sono quick-win per leakage e scelte successive.

Cosa aspettarti: elenco share e parametri policy.

Comando:

```bash
enum4linux-ng -S -P 10.10.10.10
```

### Step 5 – Se serve: utenti via RPC (con dettagli)

Perché: userlist = naming, account di servizio, pivot logico nel lab.

Cosa aspettarti: utenti (e dettagli extra con `-d`).

Comando:

```bash
enum4linux-ng -U -d 10.10.10.10
```

### Step 6 – Se `-U` fallisce: RID cycling controllato

Perché: recuperi identità anche quando listing diretto è bloccato.

Cosa aspettarti: mapping RID→nome su range limitati.

Comando:

```bash
enum4linux-ng -R 10.10.10.10 -r 500-550,1000-1050
```

### Step 7 – Export e “freeze” dei risultati

Perché: salvi stato e lo riusi (report, parsing, confronto con run autenticati).

Cosa aspettarti: file JSON e YAML (se usi `-oA`).

Comando:

```bash
enum4linux-ng -A 10.10.10.10 -oA e4lng_10.10.10.10
```

## Checklist operativa

> **In breve:** controlli rapidi per evitare falsi negativi e mantenere l’enumerazione ripetibile.

* Verifica porte `139/445` raggiungibili prima di lanciare enum.
* Parti con `-A`, passa a `-As` se NetBIOS crea attrito.
* Se non stabilisce sessione, non “insistere”: passa subito ad auth (`-u/-p` o `--local-auth`).
* Usa `-t 10` su reti lente o VM “stanche”.
* Isola obiettivi: `-S` per share, `-P` per policy, `-U` per utenti.
* Applica `-d` solo quando ti servono dettagli (più tempo/rumore).
* Mantieni RID cycling su range piccoli con `-r`.
* Usa `-v` solo per debug mirato (un modulo alla volta).
* Esporta sempre risultati (`-oJ` o `-oA`) quando trovi qualcosa di utile.
* Non fidarti di un solo run: confronta “anonymous vs auth” in lab.
* Se trovi share interessanti, valida accesso con tool dedicato (es. `smbclient`).
* Documenta detection/hardening quando identifichi leakage significativo.

## Riassunto 80/20

> **In breve:** 6 azioni ti coprono la maggior parte dei lab SMB/Windows senza perdere tempo.

| Obiettivo                 | Azione pratica                 | Comando/Strumento                                   |
| ------------------------- | ------------------------------ | --------------------------------------------------- |
| Foto completa iniziale    | Enumerazione smart “do-all”    | `enum4linux-ng -A 10.10.10.10`                      |
| Evitare grane NetBIOS     | Run short senza lookup NetBIOS | `enum4linux-ng -As 10.10.10.10`                     |
| Trovare share utili       | Enumerazione condivisioni      | `enum4linux-ng -S 10.10.10.10`                      |
| Capire policy credenziali | Estrarre password policy       | `enum4linux-ng -P 10.10.10.10`                      |
| Recuperare identità       | Users via RPC                  | `enum4linux-ng -U 10.10.10.10`                      |
| Fallback discovery        | RID cycling su range piccoli   | `enum4linux-ng -R 10.10.10.10 -r 500-550,1000-1050` |

## Concetti controintuitivi

> **In breve:** gli errori “stupidi” su SMB fanno buttare via ore: questi sono i 4 più frequenti.

* **“445 open = posso enumerare tutto”**
  No: senza sessione valida, enum4linux-ng può fermarsi presto. Risolvi prima auth/session setup.
* **“RID cycling sempre utile”**
  Se lo fai su range larghi diventa lento e rumoroso. In lab restringi `-r` e valuta bulk size.
* **“NetBIOS è sempre necessario”**
  Spesso no: `-As` ti dà risultati più stabili quando 137/138 sono filtrate.
* **“Se non vedo share, non ce ne sono”**
  Potresti essere bloccato da permessi. Con credenziali anche low-priv la visibilità cambia drasticamente.

## FAQ

> **In breve:** risposte rapide ai blocchi più comuni su enum4linux-ng in lab.

D: Se non passo nessuna opzione, cosa succede?

R: Di default enum4linux-ng abilita l’equivalente di `-A` (enumerazione “semplice” completa). Se vuoi essere esplicito, usa sempre `-A`.

D: Quando uso `--local-auth`?

R: Quando hai credenziali **locali** dell’host e non di dominio. È utile su workstation/server non-DC.

D: Perché `-A` si ferma subito?

R: Tipicamente perché non riesce a creare sessione SMB/RPC. Prova `-As`, aumenta `-t`, oppure passa a `-u/-p`.

D: `-U` non restituisce utenti: è finita?

R: No. Prova `-R` con range controllati (`-r`) per RID cycling, oppure riprova con credenziali valide.

D: A cosa serve davvero l’export JSON/YAML?

R: A “congelare” findings e riusarli: confronto tra run, parsing, report e condivisione del contesto nel team.

## Link utili su HackIta.it

> **In breve:** percorso consigliato (pillar → spoke → child) per passare da enumerazione a validazione e movimento in lab.

* [CrackMapExec: attacchi rapidi su Active Directory](https://hackita.it/articoli/crackmapexec/)
* [BloodHound: mappa l’Active Directory come un hacker](https://hackita.it/articoli/bloodhound/)
* [rpcclient: attacco e enum SMB su Active Directory](https://hackita.it/articoli/rpcclient/)
* [smbclient: accesso e attacco alle condivisioni Windows](https://hackita.it/articoli/smbclient/)
* [ldapsearch: enumerazione utenti e directory in attacco](https://hackita.it/articoli/ldapsearch/)
* [nbtscan: scansione silenziosa NetBIOS su reti Windows](https://hackita.it/articoli/nbtscan/)

In coda (pagine istituzionali):

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

> **In breve:** fonti primarie per opzioni, release e comportamento del tool.

* [https://github.com/cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
* [https://www.kali.org/tools/enum4linux-ng/](https://www.kali.org/tools/enum4linux-ng/)

Se vuoi supportare HackIta, trovi tutto qui: /supporto/

Se ti serve una formazione 1:1 (Kali/HTB/PG/AD lab), la trovi qui: /servizi/

Per servizi per aziende (assessment, hardening, simulazioni autorizzate), vai su: /servizi/
