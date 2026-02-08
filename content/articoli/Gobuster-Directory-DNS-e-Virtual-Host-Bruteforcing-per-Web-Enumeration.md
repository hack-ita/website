---
title: 'Gobuster: Directory, DNS e Virtual Host Bruteforcing per Web Enumeration'
slug: gobuster
description: >-
  Gobuster è uno strumento veloce per brute-force di directory, DNS e virtual
  host. Guida pratica all’uso in fase di web enumeration durante un penetration
  test.
image: /Gemini_Generated_Image_6kltpu6kltpu6klt.webp
draft: false
date: 2026-02-09T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - directory-enumeration
---

Trovare directory nascoste, file di configurazione esposti e virtual host non documentati è il primo passo per compromettere un'applicazione web. Gobuster fa esattamente questo: lancia richieste HTTP massicce contro un target usando wordlist, identificando path e risorse che non compaiono nei link visibili del sito.

Scritto in Go, Gobuster è veloce e gestisce centinaia di richieste parallele senza problemi di performance. Supporta tre modalità principali: `dir` per directory/file bruteforce, `dns` per enumerazione subdomain e `vhost` per virtual host discovery. A differenza di tool più vecchi come DirBuster, Gobuster è a riga di comando, scriptabile e facilmente integrabile in pipeline automatizzate.

Nella kill chain si colloca nella fase di **Reconnaissance** (MITRE ATT\&CK T1595.003). L'articolo copre tutte le modalità, la scelta delle wordlist, gli status code da interpretare e l'integrazione operativa con scanner e exploit.

***

## Setup e Installazione

**Kali Linux (preinstallato):**

```bash
gobuster version
```

Output:

```
gobuster v3.6
```

**Installazione manuale:**

```bash
sudo apt install gobuster
```

**Da sorgente (ultima versione):**

```bash
go install github.com/OJ/gobuster/v3@latest
```

Il binario si trova in `~/go/bin/gobuster`.

**Wordlist necessarie:**

Gobuster non include wordlist. Le migliori per web enumeration provengono da SecLists:

```bash
sudo apt install seclists
```

Path tipici:

* `/usr/share/seclists/Discovery/Web-Content/common.txt` → 4.727 entry, scansione veloce
* `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` → 220.560 entry, scansione approfondita
* `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` → per subdomain enum

***

## Uso Base

### Modalità dir — Directory bruteforce

```bash
gobuster dir -u http://10.10.10.50 -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Output:

```
===============================================================
Gobuster v3.6
===============================================================
[+] Url:           http://10.10.10.50
[+] Threads:       10
[+] Wordlist:      common.txt
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/admin                (Status: 301) [Size: 313]
/api                  (Status: 200) [Size: 0]
/backup               (Status: 301) [Size: 315]
/config               (Status: 403) [Size: 277]
/login                (Status: 200) [Size: 1523]
/uploads              (Status: 301) [Size: 316]
/server-status        (Status: 403) [Size: 277]
===============================================================
```

**Lettura output:**

* `200` → Pagina accessibile, da esplorare
* `301` → Redirect (directory esistente)
* `403` → Forbidden (esiste ma non accessibile — potenziale misconfiguration)
* `404` → Non trovato (Gobuster li filtra di default)

### Modalità dns — Subdomain enumeration

```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Output:

```
Found: mail.target.com
Found: vpn.target.com
Found: dev.target.com
Found: staging.target.com
Found: api.target.com
```

### Modalità vhost — Virtual host discovery

```bash
gobuster vhost -u http://10.10.10.50 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

Utile quando più applicazioni sono ospitate sullo stesso IP con virtual hosting.

***

## Tecniche Operative

### Ricerca file con estensioni specifiche

Non cercare solo directory. Cerca file di configurazione, backup e script:

```bash
gobuster dir -u http://10.10.10.50 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak,old,conf,sql,zip
```

Output:

```
/config.php.bak       (Status: 200) [Size: 482]
/database.sql         (Status: 200) [Size: 15728]
/backup.zip           (Status: 200) [Size: 3472890]
/.env                 (Status: 200) [Size: 312]
```

Un `.env` esposto o un backup SQL scaricabile sono game over per molte applicazioni.

### Filtrare per dimensione risposta

Molte applicazioni restituiscono 200 su tutto con una pagina di errore custom. Filtra per size:

```bash
gobuster dir -u http://10.10.10.50 -w wordlist.txt --exclude-length 1523
```

Se la pagina 404 custom ha size 1523, tutte le risposte con quella dimensione vengono filtrate.

### Autenticazione HTTP Basic

```bash
gobuster dir -u http://10.10.10.50/admin -w wordlist.txt -U admin -P password123
```

### Cookie di sessione per aree autenticate

```bash
gobuster dir -u http://10.10.10.50/dashboard -w wordlist.txt -c "PHPSESSID=abc123def456"
```

Scansiona dietro il login — trova funzionalità accessibili solo a utenti autenticati.

### User-Agent custom

WAF e applicazioni possono bloccare user-agent di scanner:

```bash
gobuster dir -u http://target.com -w wordlist.txt -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### HTTPS con certificati non validi

```bash
gobuster dir -u https://10.10.10.50 -w wordlist.txt -k
```

Il flag `-k` ignora errori di certificato SSL.

***

## Tecniche Avanzate

### Bruteforce ricorsivo

Gobuster non supporta ricorsione nativa. Simula con un wrapper:

```bash
gobuster dir -u http://10.10.10.50 -w common.txt -o first_pass.txt
grep "Status: 301" first_pass.txt | awk '{print $1}' | while read dir; do
  gobuster dir -u "http://10.10.10.50${dir}" -w common.txt -o "recursive_${dir//\//_}.txt"
done
```

Per ricorsione nativa, usa [Dirsearch](https://hackita.it/articoli/dirsearch) che la supporta out of the box.

### Pattern-based bruteforce

Cerca endpoint con pattern numerici o temporali:

```bash
for i in $(seq 1 100); do echo "report_$i"; done > custom_wordlist.txt
gobuster dir -u http://10.10.10.50/documents/ -w custom_wordlist.txt -x pdf
```

Trova file come `report_42.pdf` che non comparirebbero in wordlist generiche.

### Parallelizzazione su target multipli

```bash
cat web_targets.txt | xargs -P 5 -I {} gobuster dir -u http://{} -w common.txt -o gobuster_{}.txt -q
```

5 istanze parallele di Gobuster, una per target. Il flag `-q` sopprime l'header per output pulito.

### Fuzzing parametri con modalità fuzz

Gobuster v3.6 include una modalità fuzz per cercare parametri:

```bash
gobuster fuzz -u http://10.10.10.50/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

`FUZZ` viene sostituito con ogni entry della wordlist.

***

## Scenari Pratici di Pentest

### Scenario 1: Web application CTF/HTB — Trovare il pannello admin

```bash
gobuster dir -u http://10.10.10.50 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html -t 50
```

**Output atteso:**

```
/index.php            (Status: 200) [Size: 8421]
/login.php            (Status: 200) [Size: 2103]
/admin                (Status: 301) [Size: 313]
/backup               (Status: 301) [Size: 315]
/secret               (Status: 301) [Size: 315]
```

**Cosa fare se fallisce:**

* Tutti i path restituiscono 200 → L'applicazione ha una custom 404 page. Identifica la size della 404: `curl -s http://target/nonexistent | wc -c`. Poi: `--exclude-length SIZE`.
* Rate limiting attivo → Riduci thread: `-t 5`. Aggiungi delay: `--delay 200ms`.

**Timeline:** Wordlist common (4.7K): 30 secondi. Medium (220K): 5-10 minuti a 50 thread.

### Scenario 2: Webapp enterprise — Enumerazione post-autenticazione

```bash
gobuster dir -u https://portal.corp.local/app -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -c "session=eyJhbGciOiJIUzI1NiJ9..." -k -x json,xml -t 30
```

**Output atteso:**

```
/app/api/users        (Status: 200) [Size: 4521]
/app/api/config       (Status: 200) [Size: 891]
/app/admin/settings   (Status: 200) [Size: 3210]
/app/debug            (Status: 200) [Size: 156]
```

**Cosa fare se fallisce:**

* `401 Unauthorized` su tutto → Il cookie di sessione è scaduto. Rinnova la sessione e aggiorna il cookie.
* WAF blocca le richieste → Cambia User-Agent e riduci il rate. Prova con header `X-Forwarded-For: 127.0.0.1`.

**Timeline:** 3-8 minuti con wordlist raft-medium.

### Scenario 3: Subdomain enumeration su target esterno

```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50
```

**Output atteso:**

```
Found: dev.target.com
Found: staging.target.com
Found: jenkins.target.com
Found: grafana.target.com
```

**Cosa fare se fallisce:**

* DNS wildcard attivo (tutto risolve) → Usa `--wildcard` per rilevamento automatico. Se confermato wildcard, passa a tool come `ffuf` con response size filtering.
* Pochi risultati → Cambia resolver DNS: `-r 8.8.8.8`. Il resolver di default potrebbe filtrare o cacheare.

**Timeline:** 20K subdomain a 50 thread: 1-2 minuti.

***

## Toolchain Integration

Gobuster è il collegamento tra la scoperta di porte web (Masscan/Nmap) e l'exploitation.

**Flusso operativo:**

[Masscan](https://hackita.it/articoli/masscan) (port scan) → [Nmap](https://hackita.it/articoli/nmap) (service ID) → **Gobuster (content discovery)** → [Burp Suite ](https://hackita.it/articoli/burp-suite)/ [sqlmap](https://hackita.it/articoli/sqlmap) / exploit manuale

**Passaggio dati:**

```bash
# Da Nmap: estrai host con porta 80/443
grep "80/open\|443/open" nmap_scan.gnmap | awk '{print $2}' > web_hosts.txt

# Gobuster su ciascuno
while read host; do
  gobuster dir -u "http://$host" -w common.txt -o "gobuster_$host.txt" -q
done < web_hosts.txt
```

| Feature            | Gobuster | Dirsearch | ffuf     | DirBuster   |
| ------------------ | -------- | --------- | -------- | ----------- |
| Linguaggio         | Go       | Python    | Go       | Java        |
| Velocità           | ★★★★★    | ★★★☆☆     | ★★★★★    | ★★☆☆☆       |
| Ricorsione nativa  | No       | Sì        | No       | Sì          |
| Modalità DNS       | Sì       | No        | No       | No          |
| Modalità vhost     | Sì       | No        | Sì       | No          |
| Filtering avanzato | Base     | Base      | Avanzato | Base        |
| Manutenzione       | Attiva   | Attiva    | Attiva   | Abbandonato |

***

## Attack Chain Completa

**Obiettivo:** Accesso a un server web tramite file di backup esposto.

**Fase 1 — Port Discovery (3 min)**

```bash
sudo masscan 10.10.10.0/24 -p 80,443,8080,8443 --rate 1000
```

Trovi 10.10.10.50 con porta 80 e 8080 aperte.

**Fase 2 — Content Discovery con Gobuster (8 min)**

```bash
gobuster dir -u http://10.10.10.50 -w directory-list-2.3-medium.txt -x php,bak,zip,sql -t 50
```

Trovi `/backup/site.zip` (Status: 200).

**Fase 3 — Analisi backup (10 min)**

Scarichi il file. Dentro trovi `config.php` con credenziali database e un file `.git/` con la storia del codice.

**Fase 4 — Exploitation (15 min)**

Le credenziali nel backup danno accesso al database. Trovi una SQL injection nel codice sorgente, la sfrutti per esecuzione di comandi.

**Fase 5 — Post-exploitation (20 min)**

Installi una web shell [Weevely3](https://hackita.it/articoli/weevely3) per persistenza e inizi l'enumerazione interna.

**Timeline totale:** \~56 minuti.

***

## Detection & Evasion

### Cosa monitora il Blue Team

* Volume di richieste HTTP anomalo da un singolo IP (centinaia di 404 in pochi secondi)
* WAF rules che matchano User-Agent di scanner noti (Gobuster default: `gobuster/3.6`)
* Pattern sequenziale di richieste verso path inesistenti

### Log rilevanti

* Apache/Nginx access log → centinaia di entry 404 dallo stesso IP
* WAF log (ModSecurity, Cloudflare, AWS WAF) → pattern di directory traversal e file probing
* SIEM → correlazione tra volume richieste e IP sorgente

### Tecniche di evasion

1. **User-Agent legittimo:** `-a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"`. Rimuove il fingerprint Gobuster.
2. **Rate limiting volontario:** `-t 5 --delay 500ms`. Mantieni il volume sotto la soglia di detection.
3. **Rotazione IP sorgente:** se possibile, instrada il traffico attraverso più proxy per distribuire le richieste su IP diversi.

### Cleanup

Gobuster non lascia artefatti sul target. L'unica traccia sono le entry nei log del web server.

***

## Performance & Scaling

**Thread ottimali:** il default è 10. Per target robusti, 50-100 thread funzionano bene. Oltre 100, rischi di saturare il target o ricevere rate limiting.

**Wordlist e tempi:**

| Wordlist                      | Entry   | Tempo (\~50 thread) |
| ----------------------------- | ------- | ------------------- |
| common.txt                    | 4.727   | \~15 sec            |
| directory-list-2.3-small.txt  | 87.664  | \~3 min             |
| directory-list-2.3-medium.txt | 220.560 | \~8 min             |
| raft-large-directories.txt    | 62.284  | \~2 min             |

**Estensioni:** ogni estensione aggiunta moltiplica il numero di richieste. Con `-x php,txt,bak` su common.txt: 4.727 × 4 = 18.908 richieste.

**Consumo risorse:** Gobuster usa circa 20-40MB di RAM e CPU minimale. Il bottleneck è sempre la rete o il rate limiting del target.

***

## Tabelle Tecniche

### Command Reference

| Flag                 | Descrizione                   |
| -------------------- | ----------------------------- |
| `dir`                | Modalità directory bruteforce |
| `dns`                | Modalità DNS subdomain        |
| `vhost`              | Modalità virtual host         |
| `fuzz`               | Modalità fuzzing              |
| `-u URL`             | Target URL                    |
| `-w wordlist`        | Path alla wordlist            |
| `-t N`               | Numero thread                 |
| `-x ext1,ext2`       | Estensioni da cercare         |
| `-s codes`           | Status code da mostrare       |
| `-b codes`           | Status code da escludere      |
| `--exclude-length N` | Escludi risposte per size     |
| `-c cookie`          | Cookie di sessione            |
| `-k`                 | Ignora errori SSL             |
| `-a agent`           | User-Agent custom             |
| `-o file`            | Output su file                |
| `-q`                 | Quiet mode (no header)        |
| `--delay duration`   | Delay tra richieste           |

### Wordlist raccomandate per scenario

| Scenario          | Wordlist                        | Entry   | Note                       |
| ----------------- | ------------------------------- | ------- | -------------------------- |
| Quick scan        | common.txt                      | 4.727   | Primo passaggio veloce     |
| Scan approfondito | directory-list-2.3-medium.txt   | 220.560 | Standard per CTF e pentest |
| API discovery     | api-endpoints.txt               | \~2.000 | Specifico per REST API     |
| Backup files      | raft-large-files.txt            | 37.042  | Cerca file residui         |
| Subdomain         | subdomains-top1million-5000.txt | 5.000   | Quick subdomain enum       |

***

## Troubleshooting

| Problema                       | Causa                                   | Fix                                                          |
| ------------------------------ | --------------------------------------- | ------------------------------------------------------------ |
| Tutti i path restituiscono 200 | Custom 404 page                         | Usa `--exclude-length` con size della pagina 404             |
| Troppi falsi positivi          | Wildcard DNS o redirect generico        | Identifica il pattern e filtra con `-b` o `--exclude-length` |
| `connection refused`           | Target non raggiungibile o porta errata | Verifica connettività: `curl -I URL`                         |
| Scansione lenta                | Thread bassi o rete lenta               | Aumenta thread: `-t 50`                                      |
| `Too many open files`          | Ulimit troppo basso                     | `ulimit -n 10000` prima di lanciare                          |
| WAF blocca richieste           | User-Agent riconosciuto                 | Cambia con `-a "Mozilla/..."`                                |

***

## FAQ

**Gobuster è meglio di ffuf?**
Dipende. Gobuster è più semplice e include modalità DNS/vhost native. ffuf è più flessibile per fuzzing avanzato con filtering granulare. Per directory bruteforce base, sono equivalenti.

**Quale wordlist uso per il primo scan?**
`common.txt` di SecLists. Se non trovi nulla, scala a `directory-list-2.3-medium.txt`.

**Gobuster supporta la ricorsione?**
No nativamente. Usa [Dirsearch](https://hackita.it/articoli/dirsearch) se hai bisogno di ricorsione automatica, oppure scripta la ricorsione con un wrapper bash.

**Posso usare Gobuster attraverso un proxy?**
Sì: `gobuster dir -u URL -w wordlist --proxy socks5://127.0.0.1:1080`. Funziona con proxy HTTP e SOCKS5.

**Come gestisco il rate limiting?**
Riduci thread (`-t 5`), aggiungi delay (`--delay 500ms`) e cambia User-Agent. Se il WAF è aggressivo, usa IP rotation tramite proxy chain.

**Gobuster può trovare parametri GET?**
Non nativamente. Usa la modalità `fuzz` con `FUZZ` nell'URL: `gobuster fuzz -u http://target/page?FUZZ=test -w params.txt`.

***

## Cheat Sheet

| Azione              | Comando                                                           |
| ------------------- | ----------------------------------------------------------------- |
| Dir scan rapido     | `gobuster dir -u URL -w common.txt`                               |
| Dir con estensioni  | `gobuster dir -u URL -w wordlist -x php,txt,bak`                  |
| Thread elevati      | `gobuster dir -u URL -w wordlist -t 50`                           |
| Con cookie          | `gobuster dir -u URL -w wordlist -c "session=..."`                |
| HTTPS no cert check | `gobuster dir -u https://URL -w wordlist -k`                      |
| Subdomain enum      | `gobuster dns -d domain.com -w subdomains.txt`                    |
| Vhost discovery     | `gobuster vhost -u URL -w subdomains.txt --append-domain`         |
| Fuzzing             | `gobuster fuzz -u URL/FUZZ -w wordlist`                           |
| Via proxy           | `gobuster dir -u URL -w wordlist --proxy socks5://127.0.0.1:1080` |
| Output su file      | `gobuster dir -u URL -w wordlist -o results.txt`                  |

***

**Disclaimer:** Gobuster è un tool open source per security assessment. L'uso su target senza autorizzazione è illegale. Ottieni sempre permesso scritto prima di avviare scansioni. Repository: [github.com/OJ/gobuster](https://github.com/OJ/gobuster).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
