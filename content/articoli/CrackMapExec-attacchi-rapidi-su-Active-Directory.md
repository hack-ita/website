---
title: >-
  NetExec (NXC): Guida Operativa SMB/AD per Enumerazione e Validazare
  Credenziali in Lab 
slug: netexec
description: >-
  Guida operativa a NXC (NetExec) per fare enumerazione e validazione
  credenziali in lab AD/SMB (HTB/PG/VM). Focus offensivo ma controllato: comandi
  realistici, output atteso, errori comuni e contromisure. Perfetta per passare
  da “vedo una 445 aperta” a “capisco cosa posso fare con queste credenziali”.
image: /Gemini_Generated_Image_jxrwbzjxrwbzjxrw.webp
draft: false
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - netexec
  - nxc
featured: false
---

# NetExec (NXC): Guida Operativa SMB/AD per Enumerazione e Validazare Credenziali in Lab

Blocchi su SMB/AD perché “non sai cosa aspettarti” dall’output di NXC? Qui lo usi in modo ripetibile per validare credenziali e tirare fuori info utili, **solo in lab/CTF/HTB/PG/VM personali**.

## Intro

NXC (NetExec) è un tool “offensive operator” per **enumerazione e validazione accessi** su protocolli tipici Windows/AD (soprattutto SMB), con workflow orientato a “testo dentro → segnali operativi fuori”.
In lab ti serve per trasformare host/porte/creds in risposte: *“utente valido?”, “admin locale?”, “guest abilitato?”, “posso eseguire codice?”, “cosa vedo senza fare rumore?”*.
Cosa farai in questa guida:

* capire dove NXC si incastra nel workflow
* usare 3 pattern che tornano sempre (host → cred → check)
* fare enumerazione SMB “pulita” e spray controllato
* leggere segnali di detection e applicare hardening in ottica difensiva

Nota etica: tutto quello che segue è pensato **solo per ambienti autorizzati** (lab/CTF/macchine tue).

## Cos’è NXC (NetExec) e dove si incastra nel workflow

> **In breve:** NXC accelera la fase “recon con credenziali” su Windows/AD: provi accessi, leggi capacità (es. admin), e tiri fuori enumerazione utile senza reinventare ogni comando a mano.

NXC entra dopo il “recon base” (porte/servizi) e prima della post-exploitation pesante.
Se hai già usato tooling simile, la mentalità è: *target(s) + credenziali + protocollo → output “decisionale”*.

Se ti interessa il confronto storico/mentale con tool affini, vedi la guida su **CrackMapExec per automazione SMB/AD**: [https://hackita.it/articoli/crackmapexec/](https://hackita.it/articoli/crackmapexec/)

Quando NON usarlo: se devi fare analisi forense o debug dettagliato di un singolo protocollo; in quel caso meglio strumenti specifici e verbosi.

## Installazione e sanity check (Kali/HTB/PG)

> **In breve:** installa NXC dal canale che preferisci e verifica subito help/versione e il “protocol help” per evitare flag sbagliati.

In pratica: in base alla tua distro puoi averlo da pacchetti oppure tramite Python environment (pipx/venv). La regola anti-hallucination è semplice: **prima leggi l’help della tua build**, perché alcune opzioni cambiano.

Perché: confermare che NXC gira e che i subcommand/protocolli sono presenti.
Cosa aspettarti: help con lista protocolli (SMB/LDAP/WINRM ecc.).
Comando:

```bash
nxc --help
```

Interpretazione: se vedi i protocolli, puoi già lavorare; se mancano, stai usando un’installazione incompleta.
Errore comune + fix: `command not found` → installazione non in PATH; prova `pipx ensurepath` (se usi pipx) o riapri la shell.

Perché: evitare di usare flag “da blog” non compatibili con la tua versione.
Cosa aspettarti: help specifico SMB con opzioni dedicate.
Comando:

```bash
nxc smb -h
```

Interpretazione: questa schermata è la tua “fonte di verità” per i flag.
Errore comune + fix: `invalid choice: 'smb'` → build senza modulo SMB; reinstalla o cambia metodo di install.

## Sintassi base + 3 pattern che userai sempre

> **In breve:** i 3 pattern sono: (1) scan host SMB, (2) test credenziali, (3) enum mirata (shares/guest) con output leggibile.

### Pattern 1 — “host alive su SMB”

Perché: scoprire rapidamente host raggiungibili con SMB nel range lab.
Cosa aspettarti: lista di host “vivi” che rispondono sulla logica SMB.
Comando:

```bash
nxc smb 10.10.10.0/24
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [*] Windows 10 / Server (name:DC01) (domain:LAB.LOCAL)
SMB  10.10.10.23  445  WS01  [*] Windows 10 (name:WS01) (domain:LAB.LOCAL)
```

Interpretazione: hai target candidati per cred-check ed enumerazione.
Errore comune + fix: risultati vuoti → subnet sbagliata/VPN down/firewall; verifica routing e connettività.

Se vuoi prima fare naming/NetBIOS “vecchia scuola” per cross-check in LAN lab, vedi **NBTScan per enumerazione NetBIOS**: [https://hackita.it/articoli/nbtscan/](https://hackita.it/articoli/nbtscan/)

### Pattern 2 — “validazione credenziali (user/pass)”

Perché: capire subito se una coppia credenziali è valida e se hai privilegi (es. admin locale).
Cosa aspettarti: riga di login status; spesso segnali tipo “Pwn3d!” quando la sessione indica capability elevate.
Comando:

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Password123!'
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [+] LAB\alice:Password123! (Pwn3d!)
```

Interpretazione: credenziale valida; se compare indicatore di “pwned/admin”, hai leve operative maggiori (in lab).
Errore comune + fix: `STATUS_LOGON_FAILURE` → username formato errato; prova `alice` vs `LAB\alice` e ricontrolla la password.

### Pattern 3 — “enum rapida delle share”

Perché: mappare subito superfici di lettura/scrittura (dove spesso stanno file utili).
Cosa aspettarti: elenco share e permessi.
Comando:

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Password123!' --shares
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [*] Enumerated shares
SMB  10.10.10.10  445  DC01  Share      Permissions  Remark
SMB  10.10.10.10  445  DC01  SYSVOL     READ         Logon server share
SMB  10.10.10.10  445  DC01  NETLOGON   READ         Logon server share
```

Interpretazione: READ su SYSVOL/NETLOGON in lab AD è un segnale utile per policy/script/credenziali “lasciate in giro”.
Errore comune + fix: output incompleto → permessi insufficienti; riprova con cred differenti o valida prima l’accesso.

## Enumerazione SMB “pulita” (leakage tipici in lab)

> **In breve:** parti da share e accessi “low noise”, poi approfondisci solo se trovi segnali (write, config, script, GPP, ecc.).

In ottica offensiva controllata, SMB è spesso la fonte più “economica” di informazioni.
La regola: **non eseguire subito**; prima estrai contesto.

Perché: verificare se esiste accesso guest/anon (capita in lab e in ambienti legacy).
Cosa aspettarti: share enumerate anche con cred “vuote” o utente fittizio.
Comando:

```bash
nxc smb 10.10.10.10 -u 'a' -p '' --shares
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [+] a: (Guest)
SMB  10.10.10.10  445  DC01  Share      Permissions  Remark
SMB  10.10.10.10  445  DC01  public     READ         Public share
```

Interpretazione: in lab questo è “leakage gratuito”; in real world è un misconfig serio.
Errore comune + fix: `ACCESS_DENIED` → guest disabilitato (normale); passa a cred-check standard.

Perché: capire se conviene scendere a livello “manuale” per browsing/file ops.
Cosa aspettarti: share che puoi aprire e navigare.
Comando:

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Password123!' --shares
```

Interpretazione: quando trovi share interessanti, spesso conviene usare strumenti dedicati per navigare e scaricare file.
Errore comune + fix: confondere “READ” con “WRITE” → verifica sempre permessi prima di tentare upload.

Per la parte manuale di listing/download/upload da SMB, usa **smbclient**: [https://hackita.it/articoli/smbclient/](https://hackita.it/articoli/smbclient/)

Quando NON usarlo: se il target è estremamente “sensibile” (anche in lab simulazioni blue-team) e vuoi ridurre l’impronta; in quel caso limita i check e passa a query mirate.

## Password spraying in lab (controllato) + validazione

> **In breve:** lo spray va fatto con logica e limiti (lockout, frequenza, scope). In lab impari il pattern senza trasformarlo in bruteforce cieco.

Spray “buono” = pochi tentativi per utente, password plausibili, stop quando hai successo, e consapevolezza lockout.

Perché: testare una password su una lista utenti senza bruteforce per-utente.
Cosa aspettarti: righe di success/fail; su success, ti fermi o continui in modo controllato.
Comando:

```bash
nxc smb 10.10.10.10 -u users.txt -p 'Winter2026!' --continue-on-success --no-bruteforce
```

Esempio di output (può variare):

```text
SMB  10.10.10.10  445  DC01  [-] LAB\bob:Winter2026! (STATUS_LOGON_FAILURE)
SMB  10.10.10.10  445  DC01  [+] LAB\alice:Winter2026! (Pwn3d!)
```

Interpretazione: hai almeno una cred valida; passa subito a enum mirata (shares/priv).
Errore comune + fix: lockout in lab → riduci scope, aumenta delay e verifica policy prima (anche simulata).

Detection (segnali): molte 4625/failed logon in poco tempo, spike su DC o host.
Hardening/mitigazione: lockout policy coerente, MFA dove possibile, password policy robusta, alert su spray pattern.

## Moduli e azioni “da lab” (senza sparare nel buio)

> **In breve:** prima elenchi le capability, poi scegli moduli/azioni solo se hai un motivo (creds valide, permessi, obiettivo chiaro).

NXC può fare molto oltre l’enum: in lab spesso viene usato per verificare se, con una cred, puoi anche “spingerti” verso esecuzione o raccolta.
La disciplina operativa è: **capability → azione → verifica → stop**.

Perché: vedere cosa la tua build espone come opzioni e (eventuali) moduli.
Cosa aspettarti: lista opzioni; se disponibile, anche lista moduli per protocollo.
Comando:

```bash
nxc smb -h
```

Interpretazione: scegli solo 1–2 azioni a valore (es. `--shares`) prima di pensare a esecuzione.
Errore comune + fix: usare moduli senza prerequisiti → leggi help/parametri e prova su una sola macchina lab.

Perché: capire se una credenziale è “operativa” (es. admin locale) senza inventarti catene.
Cosa aspettarti: indicatore nel risultato (spesso segnala privilegi elevati quando possibile).
Comando:

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Password123!'
```

Interpretazione: se sei admin locale, il tuo workflow cambia: puoi passare a azioni più “impattanti” (sempre in lab).
Errore comune + fix: confondere “login ok” con “admin” → non dare per scontato; valida con segnali e check dedicati.

Detection (segnali): autenticazioni ripetute, tentativi su più host, pattern coerente con tool automation.
Hardening/mitigazione: segmentazione SMB, SMB signing dove applicabile, limitazione admin locali, auditing, EDR.

## Alternative e tool correlati (quando preferirli)

> **In breve:** NXC è “multi-check veloce”. Per task specifici spesso vincono tool specializzati.

* Per enum “single-host” molto dettagliata: strumenti nativi o query specifiche.
* Per mapping AD e relazioni: BloodHound (ottimo per visualizzare percorsi di privilegio).
* Per query LDAP a mano: ldapsearch e filtri mirati.

Se stai costruendo una picture AD “seria” in lab, collega i dati a **BloodHound**: [https://hackita.it/articoli/bloodhound/](https://hackita.it/articoli/bloodhound/)

Per interrogazioni LDAP precise (filtri, attributi, OU), usa **ldapsearch**: [https://hackita.it/articoli/ldapsearch/](https://hackita.it/articoli/ldapsearch/)

## Hardening & detection (cosa vede la difesa)

> **In breve:** NXC lascia impronte riconoscibili: autenticazioni, enumerazioni SMB e (se presenti) tentativi di esecuzione. In lab devi imparare anche “come ti beccano”.

Segnali tipici (dipende dal lab e dai log abilitati):

* molte autenticazioni fallite/success in poco tempo (spray)
* accessi SMB su share note (SYSVOL/NETLOGON/public) da host “attacker”
* pattern ripetitivo su più target in subnet

Hardening/mitigazione (approccio pratico):

* riduci superficie SMB (host non necessari, segmentazione)
* password policy e lockout sensati + alert su spray
* auditing di logon e accessi a share sensibili
* limita admin locali e rimuovi cred “riutilizzate”
* EDR/alert su tool-like behavior e tentativi di remote exec

Quando NON usarlo: se stai simulando un engagement “stealth” (anche in lab), evita scan/spray larghi; lavora host-by-host e con scope minimal.

## Scenario pratico: NXC su una macchina HTB/PG

> **In breve:** obiettivo: validare cred, enumerare share e capire se la cred è “operativa” (admin) con 3 comandi netti.

Ambiente: attacker Kali (VPN), target `10.10.10.10` (Windows/AD lab).
Obiettivo: trovare superfici utili (share) e capire se una cred lab è “pwned/admin”.

Perché: confermare che SMB risponde e avere contesto (hostname/domain).
Cosa aspettarti: banner/identità target.
Comando:

```bash
nxc smb 10.10.10.10
```

Interpretazione: se vedi name/domain, sei pronto per cred-check.
Errore comune + fix: nessun output → connettività/VPN/routing.

Perché: validare cred e vedere subito se hai privilegi elevati.
Cosa aspettarti: login ok e possibile indicatore di admin.
Comando:

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Winter2026!'
```

Interpretazione: se la cred è valida, passi all’enum; se appare segnale “admin”, prendi nota.
Errore comune + fix: fail logon → prova formato utente diverso o cred alternative.

Perché: enumerare share e capire dove guardare prima.
Cosa aspettarti: lista share con permessi.
Comando:

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Winter2026!' --shares
```

Interpretazione: priorità a share con READ/WRITE e a share “di dominio” (in lab spesso contengono artefatti).
Errore comune + fix: output “vuoto” → cred ok ma permessi limitati; cambia utente o enum su altro host.

Detection + hardening: lo scenario genera logon e accessi SMB; in blue-team lab li becchi con alert su 4624/4625 e accessi a share sensibili. Mitiga con segmentazione SMB, auditing e lockout policy.

## Playbook 10 minuti: NXC in un lab

> **In breve:** sequenza corta e ripetibile per passare da target a enumerazione utile, senza spray cieco.

### Step 1 – Conferma target SMB vivo

Valida rapidamente che il target risponda e annota name/domain.

```bash
nxc smb 10.10.10.10
```

### Step 2 – Prova credenziali (singolo utente)

Prima di qualsiasi cosa “larga”, testa una cred che hai già.

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Password123!'
```

### Step 3 – Enum share (valore alto, rumore basso)

Le share spesso ti danno file/config senza “rompere” niente.

```bash
nxc smb 10.10.10.10 -u 'LAB\alice' -p 'Password123!' --shares
```

### Step 4 – Check guest/anon se il lab lo consente

Utile per capire misconfig e leakage “gratis”.

```bash
nxc smb 10.10.10.10 -u 'a' -p '' --shares
```

### Step 5 – Spray controllato (solo se serve e se non locki)

Riduci scope e usa opzioni anti-bruteforce.

```bash
nxc smb 10.10.10.10 -u users.txt -p 'Winter2026!' --continue-on-success --no-bruteforce
```

### Step 6 – Passa a tool specializzati per approfondire

Quando trovi share o segnali AD, passa a strumenti dedicati per query/visualizzazione (non restare bloccato su un solo tool).

## Checklist operativa

> **In breve:** spunta questi punti per usare NXC in modo efficace e “pulito” in lab.

* Contesto: solo lab/CTF/HTB/PG/VM personali, scope chiaro.
* `nxc --help` e `nxc smb -h` letti prima di usare flag.
* Target validato (`nxc smb <ip>`), name/domain annotati.
* Cred-check su singolo utente prima di qualunque spray.
* `--shares` sempre tra i primi check.
* Guest/anon check solo se ha senso nel lab.
* Spray: pochi tentativi, scope ridotto, attenzione lockout.
* Su success: stop e pivot su enum mirata (non continuare “per sport”).
* Output salvato/loggato (note operative) per non rifare scan inutili.
* Detection mindset: sai quali segnali stai generando e perché.
* Se serve profondità: passa a tool specializzati (SMB file ops, LDAP query, AD graph).

## Riassunto 80/20

> **In breve:** 5 mosse che coprono la maggior parte dei casi d’uso NXC in lab.

| Obiettivo               | Azione pratica                  | Comando/Strumento                                           |
| ----------------------- | ------------------------------- | ----------------------------------------------------------- |
| Trovare host SMB vivi   | Scan subnet lab                 | `nxc smb 10.10.10.0/24`                                     |
| Identificare target     | Banner/name/domain              | `nxc smb 10.10.10.10`                                       |
| Validare credenziali    | Login check + capability        | `nxc smb 10.10.10.10 -u 'LAB\alice' -p '...'`               |
| Trovare superfici utili | Enumerare share                 | `nxc smb 10.10.10.10 -u ... -p ... --shares`                |
| Spray controllato       | Test 1 password su lista utenti | `nxc smb 10.10.10.10 -u users.txt -p '...' --no-bruteforce` |

## Concetti controintuitivi

> **In breve:** errori tipici che fanno perdere tempo o generano rumore inutile.

* **“Se logga allora sono admin”**
  Non è vero: login valido ≠ privilegi elevati. In lab valida sempre capability e fai enum mirata prima di eseguire altro.
* **“Spray subito su tutta la subnet”**
  È rumore e rischi lockout. Fai prima share/enum e limita scope; lo spray è una scelta, non un riflesso.
* **“Un solo tool per tutto”**
  NXC è ottimo per triage e check rapidi. Per file ops, LDAP query o AD graph, vincono tool specializzati.
* **“Output = verità assoluta”**
  Dipende da policy, hardening e versione tool. Se qualcosa non torna, torna all’help e ripeti su un singolo host.

## FAQ

D: NXC e NetExec sono la stessa cosa?
R: In pratica sì: “NXC” è il comando/alias comune per NetExec. Verifica la tua install con `nxc --help`.

D: Posso usare NXC senza credenziali?
R: Sì, per discovery e per alcuni check (es. host mapping). Ma il valore vero arriva quando validi cred e fai enum con permessi reali.

D: “Pwn3d!” cosa significa?
R: È un indicatore operativo che suggerisce capability elevate (tipicamente admin locale) sul protocollo/host. Non sostituisce una validazione mirata.

D: Come riduco il rischio lockout durante lo spray?
R: Riduci scope, pochi tentativi, usa opzioni anti-bruteforce e conosci la policy del lab. Se non sai la policy, evita spray.

D: Meglio NXC o strumenti manuali?
R: NXC per triage e automazione rapida; strumenti manuali quando serve controllo fine, debugging o operazioni specifiche.

## Link utili su HackIta.it

* Automazione SMB/AD con CrackMapExec: [https://hackita.it/articoli/crackmapexec/](https://hackita.it/articoli/crackmapexec/)
* Enumerazione SMB e file ops con smbclient: [https://hackita.it/articoli/smbclient/](https://hackita.it/articoli/smbclient/)
* Enum AD grafica con BloodHound: [https://hackita.it/articoli/bloodhound/](https://hackita.it/articoli/bloodhound/)
* Query LDAP operative con ldapsearch: [https://hackita.it/articoli/ldapsearch/](https://hackita.it/articoli/ldapsearch/)
* LLMNR/NBNS e capture in lab con Inveigh: [https://hackita.it/articoli/inveigh/](https://hackita.it/articoli/inveigh/)
* Recon NetBIOS con NBTScan: [https://hackita.it/articoli/nbtscan/](https://hackita.it/articoli/nbtscan/)

Inoltre:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

* [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)
* [https://www.netexec.wiki/](https://www.netexec.wiki/)

Supporta HackIta: se questi playbook ti fanno risparmiare ore in lab, considera di sostenermi su /supporto/.

Formazione 1:1: se vuoi una roadmap pratica (HTB/PG/OSCP-style) e review dei tuoi workflow, trovi i dettagli su /servizi/.

Servizi per aziende/assessment: per test autorizzati, simulazioni e security review operative, contattami su /servizi/.
