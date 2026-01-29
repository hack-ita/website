---
title: 'CrackMapExec (CME): Lo Strumento Definitivo per il Penetration Testing'
slug: crackmapexec
description: >-
  CrackMapExec è uno strumento potente e versatile utilizzato da ethical hacker
  e professionisti della cybersecurity per il penetration testing su reti
  Windows. In questo articolo scoprirai come funziona, come usarlo in scenari
  reali, e perché è fondamentale per attività di post-exploitation, enumerazione
  e movimento laterale in ambienti Active Directory.
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

# CrackMapExec (CME): guida operativa SMB e Active Directory in lab

Vuoi passare da “445 aperta” a “questa credenziale è valida e qui sono admin” senza perdere ore? Con CrackMapExec (CME) lo fai in modo misurabile e ripetibile (solo lab/CTF/HTB/PG/VM personali).

## Intro

CrackMapExec (CME) è un tool per pentest interno che automatizza enumerazione e azioni su ambienti Windows/Active Directory, soprattutto via SMB.

In un workflow da lab ti serve per trasformare target + credenziali in risposte operative: “login valido?”, “admin locale?”, “share scrivibili?”, “posso eseguire un comando?”.

Cosa farai/imparerai:

* sanity check e sintassi base
* 3 pattern che userai sempre (scan → cred-check → enum mirata)
* enumerazione utile (shares/users/policy) senza rumore inutile
* azioni “da lab” con validazione, detection e hardening

Nota etica: tutto ciò che segue è SOLO per ambienti autorizzati e controllati.

## Cos’è CrackMapExec e dove si incastra nel workflow

> **In breve:** CME accelera la fase “SMB/AD con credenziali”: provi accessi su molti host, leggi segnali di privilegi e fai enumerazione mirata prima di qualsiasi azione più invasiva.

CME entra tipicamente dopo il recon base (host/porte) e prima della post-exploitation pesante. È un “decision engine”: ti dice dove investire tempo.

Se dopo CME vuoi modellare “percorsi d’attacco” in AD (gruppi, ACL, sessioni), il passo naturale è BloodHound: [BloodHound: mappa l’Active Directory come un hacker](/articoli/bloodhound/).

Quando NON usarlo:

* se non hai autorizzazione esplicita (anche “solo test credenziali” è intrusivo)
* se stai facendo debug ultra-dettagliato di un singolo host: lì spesso vince un tool specifico (es. query RPC puntuali)

## Installazione / verifica versione / quick sanity check

> **In breve:** prima di copiare flag “da memoria”, controlla la tua build: `--help` e `smb --help` sono la fonte di verità per opzioni e moduli disponibili.

Perché: alcune opzioni cambiano tra versioni/distribuzioni, e un flag sbagliato = falsi negativi.

Cosa aspettarti: `crackmapexec --help` e `crackmapexec smb --help` ti mostrano sintassi e opzioni.

Comando:

```bash
crackmapexec --help 2>/dev/null | head -n 30
crackmapexec smb --help 2>/dev/null | head -n 60
```

Esempio di output (può variare):

```text
usage: crackmapexec [-h] {smb,winrm,ldap,mssql,rdp,ssh,ftp,vnc} ...
...
usage: crackmapexec smb [-h] [--shares] [--users] [--pass-pol] [-x CMD] [-X PS] ...
```

Interpretazione: se vedi il subcommand `smb` e opzioni tipo `--shares`, `--users`, `--pass-pol`, `-x`, sei pronto per il workflow.

Errore comune + fix: `command not found` → installazione non in PATH. Su Kali spesso basta reinstallare il pacchetto, oppure usare un venv/pipx (sempre in lab e sapendo cosa fai).

## Sintassi base + 3 pattern che userai sempre

> **In breve:** i 3 pattern “core” sono: (1) scan SMB su subnet, (2) validazione credenziali, (3) enumerazione mirata (shares/users/policy) sui soli host interessanti.

### Pattern 1 — scan SMB su subnet (fingerprint rapido)

Perché: trovare host che rispondono su SMB e avere segnali rapidi (nome host, dominio, signing, SMBv1).

Cosa aspettarti: una riga per host SMB raggiungibile con info utili.

Comando:

```bash
crackmapexec smb 10.10.10.0/24
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [*] Windows 10.0 Build 17763 (name:DC01) (domain:LAB.LOCAL) (signing:True) (SMBv1:False)
SMB  10.10.10.23  445  WS01  [*] Windows 10.0 Build 19045 (name:WS01) (domain:LAB.LOCAL) (signing:False) (SMBv1:False)
```

Interpretazione: ora hai una lista di candidati dove provare credenziali o fare enum mirata.

Errore comune + fix: risultati vuoti → subnet sbagliata/VPN down/firewall. Cross-check “vecchia scuola” sui nomi NetBIOS con [NBTScan su rete Windows via NetBIOS](/articoli/nbtscan/).

### Pattern 2 — validazione credenziali (user/pass) su molti host

Perché: capire dove una credenziale è valida e se hai privilegi elevati.

Cosa aspettarti: `+` quando le credenziali sono corrette; spesso un indicatore tipo `Pwn3d!` quando risulti admin locale.

Comando:

```bash
crackmapexec smb 10.10.10.0/24 -d LAB.LOCAL -u 'jdoe' -p 'Password123!'
```

Esempio di output (può variare):

```text
SMB  10.10.10.23  445  WS01  [+] LAB.LOCAL\jdoe:Password123!
SMB  10.10.10.45  445  FS01  [+] LAB.LOCAL\jdoe:Password123! (Pwn3d!)
```

Interpretazione: “cred valide” ≠ “admin”. Se vedi `Pwn3d!`, il tuo workflow cambia (puoi validare exec remota o moduli “admin-only” in lab).

Errore comune + fix: dominio/formato user errato → prova `-d LAB.LOCAL` oppure `-u 'LAB\\jdoe'` per essere esplicito.

### Pattern 3 — enum mirata: shares prima di tutto

Perché: le share (soprattutto scrivibili) sono leve concrete e spesso low-effort.

Cosa aspettarti: elenco share con permessi.

Comando:

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'jdoe' -p 'Password123!' --shares
```

Esempio di output (può variare):

```text
SMB  10.10.10.45  445  FS01  [*] Enumerated shares
SMB  10.10.10.45  445  FS01  Share    Permissions  Remark
SMB  10.10.10.45  445  FS01  IT       READ,WRITE   Department share
SMB  10.10.10.45  445  FS01  HR       READ         Department share
```

Interpretazione: parti da `READ,WRITE` perché ti permette validazioni pulite (creazione file, timestamp, evidenza).

Errore comune + fix: se trovi share interessanti, spesso conviene passare a browsing manuale con [smbclient: accesso e attacco alle condivisioni Windows](/articoli/smbclient/).

## Enumerazione SMB/AD utile: shares, users, policy, RPC

> **In breve:** in lab vuoi output “azionabile”: share accessibili, userlist (quando possibile) e password policy. Se CME non ti dà il dettaglio, integra con RPC tool dedicati.

### Password policy (prima di qualsiasi test ripetitivo)

Perché: evitare lockout e capire i limiti del lab.

Cosa aspettarti: parametri tipo min length e lockout threshold (se la tua build li supporta).

Comando:

```bash
crackmapexec smb 10.10.10.10 -d LAB.LOCAL -u 'jdoe' -p 'Password123!' --pass-pol
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [+] Minimum password length: 10
SMB  10.10.10.10  445  DC01  [+] Lockout threshold: 5
```

Interpretazione: lockout basso = spray lentissimo e con pochissime varianti, oppure lo eviti del tutto nel lab.

Errore comune + fix: output vuoto/errore → esegui contro il DC e verifica che stai autenticando come domain user.

### Enumerare utenti (quando permesso)

Perché: una userlist pulita sblocca naming convention e controllo mirato.

Cosa aspettarti: elenco utenti o sezioni con “found user”.

Comando:

```bash
crackmapexec smb 10.10.10.10 -d LAB.LOCAL -u 'jdoe' -p 'Password123!' --users
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [+] LAB\Administrator
SMB  10.10.10.10  445  DC01  [+] LAB\svc_backup
SMB  10.10.10.10  445  DC01  [+] LAB\helpdesk
```

Interpretazione: account `svc_*` in lab spesso indica “leva” (ma va trattato con detection/hardening in mente).

Errore comune + fix: `ACCESS_DENIED` su DC → non tutte le cred possono enumerare via SMB. In quel caso sposta l’enum su LDAP con [ldapsearch: enumerazione utenti e directory in attacco](/articoli/ldapsearch/).

### Spidering controllato di una share (solo mirato)

Perché: cercare 2–3 file “chiave” senza fare dump totale.

Cosa aspettarti: path di file matchati (dipende dalla tua build e opzioni).

Comando:

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'jdoe' -p 'Password123!' --spider IT --pattern pass
```

Esempio di output (può variare):

```text
SMB  10.10.10.45  445  FS01  [+] Found: \\FS01\IT\deploy\passwords.txt
SMB  10.10.10.45  445  FS01  [+] Found: \\FS01\IT\scripts\set-pass.ps1
```

Interpretazione: pochi risultati “buoni” sono meglio di cento output inutili: ora verifichi manualmente e documenti.

Errore comune + fix: share con `$` → in shell va escapato (es. `C\$`) oppure usa la share senza `$` se disponibile.

Se ti serve enum SMB/RPC ultra-granulare su un singolo host, affianca [rpcclient: attacco e enum SMB su Active Directory](/articoli/rpcclient/).

## Password spraying in lab (controllato) + validazione

> **In breve:** spray “buono” = pochi tentativi per utente, rispetto della policy, stop quando hai successo e scope minimo. In lab impari il pattern senza trasformarlo in bruteforce cieco.

Perché: testare una password su una lista utenti mantenendo controllo e ripetibilità.

Cosa aspettarti: molte righe `STATUS_LOGON_FAILURE` e qualche `+` se trovi una cred valida.

Comando:

```bash
crackmapexec smb 10.10.10.10 -d LAB.LOCAL -u users.txt -p 'Winter2026!' --no-bruteforce
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [-] LAB\bob:Winter2026! (STATUS_LOGON_FAILURE)
SMB  10.10.10.10  445  DC01  [+] LAB\alice:Winter2026!
```

Interpretazione: appena hai una cred valida, smetti di spruzzare a caso e passi a enum mirata (shares/policy/admin check).

Errore comune + fix: lockout in lab → prima leggi `--pass-pol`, riduci la lista e aumenta il tempo tra tentativi (o elimina lo spray dallo scenario se il lab simula policy rigide).

Segnali di detection: molte 4625/failed logon in poco tempo, spike su DC, pattern ripetitivo su più account.

Hardening/mitigazione: lockout policy coerente, alert su pattern spray, MFA dove possibile, password policy robusta, limitazione NTLM e auditing centralizzato.

## Esecuzione remota “da lab”: prova innocua e misurabile

> **In breve:** prima fai un proof innocuo su un solo host dove sei chiaramente admin; poi, se serve, aumenti complessità. Non “sparare” exec su tutta la subnet.

### Comando remoto con `-x` (CMD) come proof

Perché: dimostrare in modo ripetibile che puoi eseguire un comando remoto con quelle credenziali.

Cosa aspettarti: output del comando (o almeno conferma di esecuzione) e segnali coerenti nel log del lab.

Comando:

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'administrator' -p 'P@ssw0rd!' -x whoami
```

Esempio di output (può variare):

```text
SMB  10.10.10.45  445  FS01  [+] LAB.LOCAL\administrator:P@ssw0rd! (Pwn3d!)
SMB  10.10.10.45  445  FS01  [+] Executed command
SMB  10.10.10.45  445  FS01  lab\administrator
```

Interpretazione: `Pwn3d!` + output coerente = prova forte e report-ready.

Errore comune + fix: “Executed command” ma niente output → prova `hostname` o un comando più semplice; alcune tecniche non ritornano output come ti aspetti.

Validazione in lab: oltre all’output, crea evidenza innocua (es. scrivere un file in una share scrivibile) e verifica timestamp.

Segnali di detection: eventi di logon, activity anomala su SMB/RPC, possibili artefatti di exec (service/task) a seconda del metodo.

Hardening/mitigazione: least privilege, riduzione admin locali, segmentazione, SMB signing dove applicabile, auditing e alert su exec remota.

### PowerShell remoto con `-X` (quando serve)

Perché: alcune azioni sono più semplici in PowerShell (sempre in lab e con obiettivo chiaro).

Cosa aspettarti: output PowerShell o conferma di esecuzione.

Comando:

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'administrator' -p 'P@ssw0rd!' -X "Get-ChildItem C:\\Windows | Select-Object -First 3"
```

Esempio di output (può variare):

```text
SMB  10.10.10.45  445  FS01  [+] Executed PS command
SMB  10.10.10.45  445  FS01  Directory: C:\Windows
SMB  10.10.10.45  445  FS01  ...
```

Interpretazione: usalo come “strumento”, non come “scusa” per fare rumore: una query piccola, un output piccolo, una decisione chiara.

Errore comune + fix: escaping di backslash e virgolette → usa doppie virgolette esterne e raddoppia `\` dove necessario.

## Moduli CME: come usarli senza auto-sabotarti

> **In breve:** i moduli sono potenti ma vanno scelti solo dopo capability check. Se la tua build non supporta un’opzione, non inventare: leggi `--help` e adatta.

Perché: capire cosa la tua installazione espone (moduli e opzioni) prima di lanciare roba “a caso”.

Cosa aspettarti: una lista moduli o indicazioni su come invocarli (dipende dalla build).

Comando:

```bash
crackmapexec smb -h 2>/dev/null | grep -i -E "module|modules| -M | -L " || true
```

Esempio di output (può variare):

```text
  -M MODULE           Module to use
  -o MODULE_OPTION    Module options
  -L                  List available modules
```

Interpretazione: se trovi `-L`, puoi provare a listare moduli; se non c’è, la tua build gestisce moduli in modo diverso: non forzare.

Errore comune + fix: “module not found” → lista moduli (`-L`) e verifica nome esatto, poi prova su un SOLO host in lab.

Se vuoi un’alternativa “modulare” con sintassi simile ma tool più recente, vedi la guida dedicata: [NetExec (NXC): guida operativa SMB/AD in lab](/articoli/netexec/).

## CrackMapExec vs NetExec (NXC): differenze pratiche (senza cambiare tool)

> **In breve:** CME resta ottimo se lo conosci e ce l’hai già nel workflow; NXC/NetExec è la “continuazione moderna” con sintassi molto simile. Qui i comandi restano CME, ma è utile sapere cosa cambia.

Differenze operative tipiche:

* **Manutenzione e release:** NetExec tende ad aggiornarsi più spesso; CME può essere più “stabile” ma dipende dal canale di install.
* **Compatibilità opzioni:** molte opzioni sono simili, ma non dare per scontato che un flag esista identico: prima `--help`.
* **Output e moduli:** naming moduli/flag può variare; i moduli disponibili dipendono dalla build e dal pacchetto.
* **Scelta pratica:** se nel tuo lab hai CME funzionante e scriptato, non cambiare tool a metà esercizio; se stai partendo da zero, considera NXC ma solo dopo aver chiuso questo workflow con CME.

Approfondimento (solo confronto e migrazione): [NetExec (NXC): guida operativa SMB/AD in lab](/articoli/netexec/).

## Hardening & detection (cosa far emergere nel report)

> **In breve:** ogni “abuso tipico” va chiuso con osservabili (log/alert) e una mitigazione concreta. In lab misuri cosa succede, poi lo traduci in remediation.

Detection utile in lab:

* spike di autenticazioni fallite (spray) e pattern su DC
* autenticazioni riuscite su molti host in poco tempo (lateral movement pattern)
* esecuzione remota (service/task/WMI-like) e correlazione con account privilegiati
* accessi anomali a share admin e spidering troppo aggressivo

Hardening pratico:

* riduci admin locali e ruoli eccessivi
* segmenta rete (workstation ≠ server ≠ DC)
* abilita auditing centralizzato e alert su spray/exec/lateral movement
* SMB signing dove applicabile, riduzione NTLM dove possibile, igiene credenziali (LAPS, rotazione, ecc.)

***

## Scenario pratico: CrackMapExec su una macchina HTB/PG

> **In breve:** in 4 comandi passi da subnet → cred valida → share con write → proof di exec remota su un solo host (lab).

Ambiente: attacker Kali su VPN lab, subnet `10.10.10.0/24`, DC `10.10.10.10`, file server `10.10.10.45`.

Obiettivo: validare una credenziale, trovare un host dove sei admin e ottenere una prova ripetibile.

Perché: ridurre rumore e produrre evidenza concreta.

Cosa aspettarti: almeno un host con cred valide e, idealmente, un `Pwn3d!` su un server.

Comando:

```bash
crackmapexec smb 10.10.10.0/24
```

Comando:

```bash
crackmapexec smb 10.10.10.0/24 -d LAB.LOCAL -u 'jdoe' -p 'Password123!'
```

Comando:

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'jdoe' -p 'Password123!' --shares
```

Comando:

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'administrator' -p 'P@ssw0rd!' -x whoami
```

Risultato atteso concreto: output con `Pwn3d!` su `10.10.10.45` e ritorno `lab\administrator` da `whoami` (più evidenza su share scrivibile se presente).

Detection + hardening: in lab osserva eventi di logon e gli artefatti dell’exec remoto; poi ripeti scenario dopo aver ridotto admin locali e attivato alert su spray/exec per misurare l’impatto delle mitigazioni.

## Playbook 10 minuti: CrackMapExec in un lab

> **In breve:** sequenza corta e sempre uguale: scan → cred-check → shares/policy → proof (solo se admin).

### Step 1 – Verifica help della tua build

Leggi la help per evitare flag non supportati e falsi negativi.

```bash
crackmapexec smb --help 2>/dev/null | head -n 80
```

### Step 2 – Scan SMB della subnet

Fai una passata veloce per scoprire host SMB e segnali utili.

```bash
crackmapexec smb 10.10.10.0/24
```

### Step 3 – Valida una credenziale candidata

Misura dove funziona e dove no.

```bash
crackmapexec smb 10.10.10.0/24 -d LAB.LOCAL -u 'jdoe' -p 'Password123!'
```

### Step 4 – Enum shares sui soli host interessanti

Cerca subito permessi `READ,WRITE` e share non standard.

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'jdoe' -p 'Password123!' --shares
```

### Step 5 – Leggi password policy prima di test ripetuti

Evita lockout e non improvvisare lo spray.

```bash
crackmapexec smb 10.10.10.10 -d LAB.LOCAL -u 'jdoe' -p 'Password123!' --pass-pol
```

### Step 6 – Se (e solo se) sei admin: proof innocuo di exec

Una prova su un solo host, output piccolo, evidenza chiara.

```bash
crackmapexec smb 10.10.10.45 -d LAB.LOCAL -u 'administrator' -p 'P@ssw0rd!' -x whoami
```

### Step 7 – Se trovi share interessanti: valida manualmente con smbclient

Trasforma “permesso” in “evidenza” (listing, file test) in modo controllato.

```bash
smbclient //10.10.10.45/IT -U 'LAB.LOCAL\jdoe'
```

## Checklist operativa

* Scope lab definito (subnet/host) prima di lanciare CME.
* `crackmapexec smb --help` letto per evitare flag non supportati.
* Scan SMB su subnet completato e shortlist host creata.
* Credenziali validate e annotazione `Pwn3d!` dove presente.
* `--pass-pol` letto prima di qualunque test ripetitivo.
* Shares enumerate e priorità data a `READ,WRITE`.
* Proof di exec (`-x whoami`) solo su un host dove sei chiaramente admin.
* Spidering solo su una share selezionata e con pattern mirato.
* Ogni abuso tipico corredato da detection e hardening nel report.
* Nessuna azione “a tappeto” senza obiettivo misurabile.

## Riassunto 80/20

| Obiettivo           | Azione pratica          | Comando/Strumento                                              |
| ------------------- | ----------------------- | -------------------------------------------------------------- |
| Scoprire host SMB   | Scan subnet             | `crackmapexec smb 10.10.10.0/24`                               |
| Validare cred       | Cred-check su subnet    | `crackmapexec smb 10.10.10.0/24 -d LAB.LOCAL -u jdoe -p '...'` |
| Trovare leve rapide | Enumerare share         | `crackmapexec smb <ip> ... --shares`                           |
| Evitare lockout     | Leggere password policy | `crackmapexec smb <dc> ... --pass-pol`                         |
| Provare controllo   | Proof innocuo           | `crackmapexec smb <ip> ... -x whoami`                          |
| Cercare file mirati | Spidering controllato   | `crackmapexec smb <ip> ... --spider <share> --pattern <str>`   |

## Concetti controintuitivi

* **“Cred valide = admin”**
  No: spesso hai solo auth. `Pwn3d!` (o segnali equivalenti) è ciò che cambia davvero il piano.
* **“Più scan = più progress”**
  No: output enorme = rumore. Riduci scope e fai enum mirata solo dove serve.
* **“Lo spray è sempre una buona idea in lab”**
  Non se lockout è basso. Prima `--pass-pol`, poi pochi tentativi ragionati o zero spray.
* **“Se non vedo output, non ha eseguito”**
  Non sempre: cambia comando (più semplice), valida con evidenza alternativa (share/file) e controlla logging nel lab.

## FAQ

D: CrackMapExec funziona anche senza credenziali?

R: Puoi fare fingerprint SMB e, in alcuni lab, vedere qualcosa in anon/guest. Ma il valore vero arriva con cred valide per enum mirata e capability check.

D: Come capisco se sono admin locale?

R: Spesso CME lo segnala (es. `Pwn3d!`). In ogni caso valida con un proof innocuo su un solo host (`-x whoami`) e osserva l’evidenza.

D: Perché `--users` o `--pass-pol` non mi tornano?

R: Dipende da permessi, target (meglio DC) e build/flag supportati. Se SMB enum è limitata, sposta l’enum su LDAP con `ldapsearch`.

D: Quando usare `--local-auth`?

R: Quando stai autenticando con account locali (non di dominio) e vuoi forzare quel contesto. È utile in lab dove esistono cred locali riutilizzate.

D: CME o NetExec (NXC)?

R: Se hai CME già stabile e scriptato nel lab, resta su CME e chiudi il workflow. Se parti da zero o vuoi tool più “moderno”, valuta NXC ma senza mischiare comandi a metà esercizio.

## Link utili su HackIta.it

* [NetExec (NXC): guida operativa SMB/AD in lab](/articoli/netexec/)
* [Enum4linux-ng: enumerazione avanzata su reti Windows](/articoli/enum4linux-ng/)
* [smbclient: accesso e attacco alle condivisioni Windows](/articoli/smbclient/)
* [rpcclient: attacco e enum SMB su Active Directory](/articoli/rpcclient/)
* [ldapsearch: enumerazione utenti e directory in attacco](/articoli/ldapsearch/)
* [Responder: attacco LLMNR/NBT-NS/WPAD in LAN](/articoli/responder/)

Inoltre:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

* [https://www.kali.org/tools/crackmapexec/](https://www.kali.org/tools/crackmapexec/)
* [https://github.com/byt3bl33d3r/CrackMapExec/wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki)

Supporta HackIta: se questa guida ti fa risparmiare tempo in lab, puoi dare una mano qui: /supporto/

Formazione 1:1: vuoi accelerare davvero su AD/SMB (setup lab, workflow, report-ready)? Trovi la formazione qui: /servizi/

Servizi per aziende/assessment: per test autorizzati, assessment e hardening orientato a detection, trovi tutto qui: /servizi/
