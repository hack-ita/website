---
title: 'Nikto: Web Server Scanner per Vulnerabilità e Misconfiguration'
slug: nikto
description: >-
  Nikto è uno scanner web per individuare vulnerabilità note, file sensibili,
  configurazioni errate e software obsoleto su server HTTP/HTTPS.
image: /Gemini_Generated_Image_ghwknrghwknrghwk.webp
draft: false
date: 2026-02-19T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - web-scanning
---

## Introduzione

Nikto è un web server scanner open source che identifica configurazioni errate, software obsoleto, file pericolosi e vulnerabilità note su server HTTP/HTTPS. Non è uno strumento silenzioso — genera centinaia di richieste in pochi minuti — ma nella fase iniziale di un engagement, quando devi mappare rapidamente la superficie d'attacco di un'applicazione web, è tra i primi tool da lanciare.

Il database di Nikto contiene oltre 6.700 file e programmi potenzialmente pericolosi, verifica più di 1.250 versioni di server obsolete e oltre 270 problemi specifici per versione. Nella kill chain si posiziona nella fase di **Reconnaissance / Vulnerability Assessment** (MITRE ATT\&CK T1595). Questo articolo copre setup, configurazione operativa, tuning delle scansioni e integrazione nella pipeline offensiva.

***

## 1️⃣ Setup e Installazione

Nikto è preinstallato su Kali Linux.

```bash
nikto -Version
```

Output:

```
Nikto v2.5.0
```

**Installazione manuale:**

```bash
sudo apt install nikto
```

**Da sorgente:**

```bash
git clone https://github.com/sullo/nikto.git
cd nikto/program
perl nikto.pl -Version
```

**Requisiti:**

* Perl 5.x
* Moduli: `Net::SSLeay`, `IO::Socket::SSL` (per HTTPS)
* Database aggiornato (auto-update con `-update`)

**Aggiornamento database:**

```bash
nikto -update
```

***

## 2️⃣ Uso Base

Scansione standard di un target:

```bash
nikto -h http://10.10.10.50
```

Output:

```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.10.50
+ Target Hostname:    10.10.10.50
+ Target Port:        80
+ Start Time:         2025-01-20 14:30:00 (GMT)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ /icons/README: Apache default file found.
+ /admin/: Directory indexing found.
+ /admin/login.php: Admin login page found.
+ /backup/: Directory indexing found.
+ /config.php.bak: PHP config backup found.
+ /server-status: Apache server-status accessible.
+ 7521 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2025-01-20 14:32:15 (GMT) (135 seconds)
```

**Parametri chiave:**

* `-h` → host target (IP, hostname o URL)
* `-p` → porta (default 80, usa `-p 443` per HTTPS)
* `-ssl` → forza connessione SSL
* `-output file` → salva risultati
* `-Format` → formato output (csv, htm, xml, json)

Scansione HTTPS:

```bash
nikto -h https://10.10.10.50 -ssl
```

***

## 3️⃣ Tecniche Operative

### Scansione multi-porta

Il target ha servizi web su più porte:

```bash
nikto -h 10.10.10.50 -p 80,443,8080,8443
```

Nikto scansiona ogni porta in sequenza.

### Tuning della scansione

Nikto permette di selezionare categorie di test specifiche con `-Tuning`:

```bash
nikto -h http://10.10.10.50 -Tuning 1234
```

Categorie:

* `1` → File interessanti / log
* `2` → Misconfiguration / default file
* `3` → Information disclosure
* `4` → Injection (XSS/Script)
* `5` → Remote file retrieval (dentro web root)
* `6` → Denial of service (da evitare in pentest)
* `7` → Remote file retrieval (server wide)
* `8` → Command execution / remote shell
* `9` → SQL injection
* `0` → File upload

Per un pentest web focalizzato su injection e command execution:

```bash
nikto -h http://10.10.10.50 -Tuning 489
```

### Scansione con autenticazione

Per scansionare aree autenticate:

```bash
nikto -h http://10.10.10.50 -id admin:password123
```

Con cookie di sessione:

```bash
nikto -h http://10.10.10.50 -C "PHPSESSID=abc123def456"
```

### Output in formati multipli

Per report del pentest:

```bash
nikto -h http://10.10.10.50 -output scan.html -Format htm
```

Genera un report HTML navigabile con tutti i finding categorizzati.

***

## 4️⃣ Tecniche Avanzate

### Evasion IDS con encoding

Nikto supporta tecniche di evasion per bypassare IDS/WAF:

```bash
nikto -h http://10.10.10.50 -evasion 1
```

Opzioni di evasion:

* `1` → Random URI encoding (non-UTF8)
* `2` → Directory self-reference (`/./`)
* `3` → Premature URL ending
* `4` → Prepend long random string
* `5` → Fake parameter
* `6` → TAB as request spacer
* `7` → Change URL case
* `8` → Use Windows directory separator (`\`)

Combina multiple tecniche:

```bash
nikto -h http://10.10.10.50 -evasion 1357
```

### Proxy support per pivoting

Scansiona attraverso un tunnel SOCKS o HTTP proxy:

```bash
nikto -h http://172.16.0.10 -useproxy http://127.0.0.1:8080
```

Integra con [Burp Suite](https://hackita.it/articoli/burp-suite/) come proxy per catturare tutte le richieste generate da Nikto e analizzarle manualmente.

### Scansione con virtual host specifico

```bash
nikto -h 10.10.10.50 -vhost app.target.com
```

Invia l'header `Host: app.target.com` — utile per target con virtual hosting.

### Aggiornamento database offline

Se il target non ha connettività:

```bash
nikto -h http://target -dbcheck
```

Verifica l'integrità del database locale prima della scansione.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Web server Apache — Quick assessment iniziale

```bash
nikto -h http://10.10.10.50 -Tuning 123 -output nikto_initial.txt -Format txt
```

**Output atteso:**

```
+ Server: Apache/2.4.52 (Ubuntu)
+ /admin/: Directory indexing found.
+ /phpmyadmin/: phpMyAdmin directory found.
+ /config.php.bak: PHP config backup found.
+ /server-status: Apache server-status accessible.
```

**Cosa fare se fallisce:**

* `Connection refused` → Porta errata. Verifica con: `nmap -p 80,443,8080 10.10.10.50`.
* Nessun finding → Server ben hardened o WAF attivo. Prova con evasion: `-evasion 1357`.

**Timeline:** 2-3 minuti per scansione standard su server singolo.

### Scenario 2: Target HTTPS con certificato self-signed

```bash
nikto -h https://10.10.10.50:8443 -ssl -nointeractive
```

**Output atteso:**

```
+ SSL Info: Subject: /CN=internal.corp.local
+ /: Directory listing enabled.
+ /api/debug: Debug endpoint found.
```

**Cosa fare se fallisce:**

* Errore SSL → Moduli Perl SSL mancanti. Installa: `sudo apt install libnet-ssleay-perl libio-socket-ssl-perl`.
* Timeout → Server lento. Aumenta timeout: `-timeout 30`.

**Timeline:** 3-5 minuti con HTTPS.

### Scenario 3: Scansione multi-target da file

```bash
nikto -h targets.txt -output bulk_scan.html -Format htm
```

Il file `targets.txt` contiene un URL per riga.

**Cosa fare se fallisce:**

* File format errato → Ogni riga deve essere un URL completo: `http://host:port`.
* Troppo lento su molti target → Lancia istanze parallele: `cat targets.txt | xargs -P 5 -I {} nikto -h {} -output {}.txt`.

**Timeline:** \~3 minuti per target, in parallelo il tempo scala linearmente.

***

## 6️⃣ Toolchain Integration

Nikto si posiziona dopo il port scanning e prima dell'analisi manuale.

**Flusso operativo:**

[Masscan](https://hackita.it/articoli/masscan/) (port scan) → Nmap (service detection) → **Nikto (vulnerability scan)** → Burp Suite (manual testing)

**Passaggio dati:**

```bash
# Nmap trova le porte web
nmap -sV -p 80,443,8080 10.10.10.0/24 -oG web_hosts.gnmap

# Estrai target web
grep "80/open\|443/open\|8080/open" web_hosts.gnmap | awk '{print $2}' > web_targets.txt

# Nikto su ciascuno
while read host; do
  nikto -h "http://$host" -output "nikto_$host.html" -Format htm
done < web_targets.txt
```

| Criterio            | Nikto    | [Nuclei](https://hackita.it/articoli/nuclei/) | ZAP   | Nessus   |
| ------------------- | -------- | -------------------------------------------- | ----- | -------- |
| Velocità            | ★★★☆☆    | ★★★★★                                        | ★★★☆☆ | ★★★★☆    |
| Detection accuracy  | ★★★☆☆    | ★★★★☆                                        | ★★★★☆ | ★★★★★    |
| Stealth             | ★☆☆☆☆    | ★★★☆☆                                        | ★★☆☆☆ | ★☆☆☆☆    |
| Configurabilità     | ★★★☆☆    | ★★★★★                                        | ★★★★★ | ★★★★☆    |
| Community templates | No       | Sì (migliaia)                                | Sì    | No       |
| Uso in CI/CD        | Limitato | Ottimo                                       | Buono | Limitato |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Compromissione web server tramite misconfiguration trovata da Nikto.

**Fase 1 — Port Discovery (3 min)**

```bash
sudo masscan 10.10.10.0/24 -p 80,443,8080 --rate 1000
```

**Fase 2 — Vulnerability Scanning con Nikto (5 min)**

```bash
nikto -h http://10.10.10.50 -Tuning 12389 -output findings.html -Format htm
```

Trovi: `/config.php.bak` con credenziali DB, `/admin/` accessibile, `server-status` esposto.

**Fase 3 — Exploitation (10 min)**

Le credenziali nel backup config danno accesso al database [MySQL](https://hackita.it/articoli/porta-3306-mysql/). Trovi hash delle password admin.

**Fase 4 — Admin Access (5 min)**

Crack degli hash. Login al pannello admin. Upload di una [web shell](https://hackita.it/articoli/weevely3/) tramite funzionalità di upload del CMS.

**Fase 5 — Post-exploitation (20 min)**

Shell come `www-data`. Enumerazione locale, privilege escalation, persistenza.

**Timeline totale:** \~43 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Volume massiccio di richieste HTTP in pochi minuti (Nikto genera 6.000-8.000 richieste)
* User-Agent `Nikto` (default, facilmente identificabile)
* Pattern di richieste verso path noti come `/admin/`, `/phpmyadmin/`, `/server-status`

### Log rilevanti

* Apache/Nginx access log → migliaia di entry 404 ravvicinate
* WAF → ModSecurity CRS rule 913100 (scanner detection)
* IDS → Snort/Suricata signature per Nikto user-agent

### Tecniche di evasion

1. **User-Agent custom:**

```bash
nikto -h http://target -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
```

1. **Encoding evasion combinato:**

```bash
nikto -h http://target -evasion 12478
```

1. **Throttling delle richieste:** Nikto non ha rate limiting nativo. Usa un proxy (Burp) con throttling configurato come intermediario.

### Cleanup

Nikto non lascia artefatti sul target. Le tracce sono esclusivamente nei log del web server.

***

## 9️⃣ Performance & Scaling

**Single target:** scansione completa in 2-5 minuti. Con HTTPS e evasion attiva, 5-10 minuti.

**Multi-target:** Nikto non ha parallelismo nativo. Usa `xargs` per parallelizzare:

```bash
cat targets.txt | xargs -P 10 -I {} nikto -h {} -output {}.txt
```

10 scansioni parallele.

**Consumo risorse:** Nikto usa \~30-50MB di RAM. Il bottleneck è la rete — ogni richiesta è sequenziale all'interno di una singola istanza.

***

## 🔟 Tabelle Tecniche

### Command Reference

| Flag             | Descrizione                    |
| ---------------- | ------------------------------ |
| `-h host`        | Target (IP/URL/file)           |
| `-p port`        | Porta (default 80)             |
| `-ssl`           | Forza SSL                      |
| `-Tuning N`      | Categorie di test              |
| `-evasion N`     | Tecniche evasion IDS           |
| `-output file`   | Salva output                   |
| `-Format fmt`    | Formato (csv/htm/xml/json/txt) |
| `-id user:pass`  | Autenticazione HTTP Basic      |
| `-useproxy URL`  | Proxy HTTP                     |
| `-vhost name`    | Virtual host header            |
| `-useragent str` | User-Agent custom              |
| `-timeout N`     | Timeout connessione (sec)      |
| `-update`        | Aggiorna database              |
| `-C cookie`      | Cookie di sessione             |

### Tuning Categories

| ID | Categoria                 | Uso nel pentest     |
| -- | ------------------------- | ------------------- |
| 1  | Interesting file / log    | Sempre              |
| 2  | Misconfiguration          | Sempre              |
| 3  | Information disclosure    | Sempre              |
| 4  | Injection (XSS/Script)    | Web app test        |
| 5  | File retrieval (web root) | Web app test        |
| 6  | Denial of Service         | Mai (pentest)       |
| 7  | File retrieval (server)   | Infrastructure test |
| 8  | Command execution         | Sempre              |
| 9  | SQL injection             | Web app test        |
| 0  | File upload               | Web app test        |

***

## 11️⃣ Troubleshooting

| Problema                         | Causa                            | Fix                                       |
| -------------------------------- | -------------------------------- | ----------------------------------------- |
| `ERROR: Cannot resolve hostname` | DNS non risolvibile              | Usa IP diretto: `-h http://IP`            |
| Nessun finding                   | WAF blocca le richieste          | Aggiungi `-evasion 1357`                  |
| Errore SSL/TLS                   | Moduli Perl mancanti             | `sudo apt install libnet-ssleay-perl`     |
| Scansione troppo lenta           | Server con latenza alta          | Aumenta `-timeout` e usa `-Tuning` mirato |
| Output vuoto                     | Porta errata o servizio non HTTP | Verifica con `curl -I http://target`      |
| Database obsoleto                | Non aggiornato                   | `nikto -update`                           |

***

## 12️⃣ FAQ

**Nikto è stealth?**
No. È uno dei tool più rumorosi. Genera migliaia di richieste e il suo User-Agent è noto. Usalo quando la stealth non è una priorità.

**Nikto trova vulnerabilità zero-day?**
No. Controlla vulnerabilità e misconfiguration note. Per testing dinamico avanzato, usa ZAP o Burp Suite.

**Posso usare Nikto attraverso un proxy SOCKS?**
Non direttamente. Usa `proxychains4 nikto -h target` oppure un proxy HTTP intermedio.

**Nikto sostituisce Nuclei?**
No. [Nuclei](https://hackita.it/articoli/nuclei/) ha template community-driven e aggiornati costantemente, è più veloce e configurabile. Nikto è complementare per check di configurazione classici.

**Quanto dura una scansione completa?**
Su un singolo host con tutte le categorie attive: 2-5 minuti. Con HTTPS e evasion: 5-10 minuti.

**Nikto supporta autenticazione a due fattori?**
No. Per scansioni autenticate con 2FA, usa Burp Suite con sessione manuale e poi esporta il cookie a Nikto con `-C`.

***

## 13️⃣ Cheat Sheet

| Azione           | Comando                                           |
| ---------------- | ------------------------------------------------- |
| Scan base        | `nikto -h http://target`                          |
| Scan HTTPS       | `nikto -h https://target -ssl`                    |
| Multi-porta      | `nikto -h target -p 80,443,8080`                  |
| Tuning specifico | `nikto -h target -Tuning 12389`                   |
| Evasion IDS      | `nikto -h target -evasion 1357`                   |
| Con auth         | `nikto -h target -id user:pass`                   |
| Con cookie       | `nikto -h target -C "session=abc"`                |
| Via proxy        | `nikto -h target -useproxy http://127.0.0.1:8080` |
| Virtual host     | `nikto -h target -vhost app.corp.local`           |
| Output HTML      | `nikto -h target -output scan.html -Format htm`   |
| Aggiorna DB      | `nikto -update`                                   |

***

**Disclaimer:** Nikto è un vulnerability scanner che genera traffico significativo. Usa esclusivamente su target con autorizzazione scritta. Scansioni non autorizzate possono violare leggi nazionali. Repository: [github.com/sullo/nikto](https://github.com/sullo/nikto).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
