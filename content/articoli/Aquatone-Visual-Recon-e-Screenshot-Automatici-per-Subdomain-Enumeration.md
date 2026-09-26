---
title: 'Aquatone: Visual Recon e Screenshot Automatici per Subdomain Enumeration'
slug: aquatone
description: >-
  Aquatone è un tool di visual reconnaissance che cattura screenshot automatici
  di host e subdomain scoperti durante la fase di recon. Ideale per mappare
  rapidamente superfici web in penetration test.
image: /Gemini_Generated_Image_2smu2n2smu2n2smu.webp
draft: false
date: 2026-02-10T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - subdomain-enumeration
---

Quando hai centinaia di subdomain e porte web aperte, Aquatone ti dà una panoramica visuale istantanea. Il tool cattura screenshot di ogni target e genera un report HTML interattivo dove puoi scorrere rapidamente tutte le pagine web trovate, identificando pannelli admin, pagine di login, applicazioni interne e servizi esposti con un colpo d'occhio.

La visual recon accelera drasticamente il triage: invece di visitare manualmente ogni URL, scorri le thumbnail nel report e ti concentri sui target interessanti. Un Jenkins esposto, un phpMyAdmin senza password, una pagina di errore che rivela stack trace — li individui in secondi.

Kill chain: **Reconnaissance** (MITRE ATT\&CK T1595). Aquatone si posiziona dopo la subdomain enumeration e l'HTTP probing, come fase di triage visuale prima del vulnerability scanning.

***

## 1️⃣ Setup e Installazione

```bash
go install github.com/michenriksen/aquatone@latest
```

Alternativa (binary release):

```bash
wget https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip -d /usr/local/bin/
```

**Verifica:**

```bash
aquatone --version
```

**Requisiti:**

* Chromium o Chrome installato (per screenshot)
* Go 1.17+ (per installazione da sorgente)

```bash
sudo apt install chromium-browser
```

***

## 2️⃣ Uso Base

Pipe una lista di URL in Aquatone:

```bash
cat subdomains.txt | aquatone
```

Output:

```
aquatone v1.7.0
[*] Targets    : 147
[*] Threads    : 6
[*] Ports      : 80, 443, 8080, 8443
[*] Output dir : ./aquatone
[*] Requesting 147 URLs...
[*] Screenshotting 134 pages...
[*] Generating HTML report...
[*] Done! Report: ./aquatone/aquatone_report.html
```

Apri `aquatone_report.html` nel browser. Vedi thumbnail di ogni pagina con URL, status code, server header e dimensione della risposta.

**Parametri chiave:**

* `-ports` → porte da testare (default: 80,443,8080,8443)
* `-threads N` → thread paralleli
* `-timeout N` → timeout in ms (default: 15000)
* `-out dir` → directory output
* `-screenshot-timeout N` → timeout screenshot
* `-scan-timeout N` → timeout scansione porta

***

## 3️⃣ Tecniche Operative

### Porte custom per servizi web non standard

```bash
cat hosts.txt | aquatone -ports 80,443,3000,5000,8000,8080,8443,9090,9200
```

Trova Grafana (3000), Flask (5000), Elasticsearch (9200) e altri servizi su porte non standard.

### Pipeline con subfinder e httpx

```bash
subfinder -d target.com -silent | httpx -silent | aquatone -out target_recon/
```

Subdomain discovery → probe alive → screenshot. Report completo in una pipeline.

### Solo screenshot senza port scan

Se hai già una lista di URL verificati:

```bash
cat verified_urls.txt | aquatone -ports skip
```

Salta la fase di port scanning e fa solo screenshot degli URL forniti.

### Porte specifiche su rete interna

```bash
seq 1 254 | sed 's/^/http:\/\/172.16.0./' | aquatone -ports 80,443,8080 -out internal_recon/
```

Screenshot di tutta una subnet /24 su porte web. Perfetto dopo un [pivoting](https://hackita.it/articoli/sshuttle/) con SSHuttle.

***

## 4️⃣ Tecniche Avanzate

### Integrazione con Nmap per target mirati

```bash
nmap -p 80,443,8080 10.10.10.0/24 -oG - | grep "open" | awk '{print $2}' | aquatone
```

### Report per comparazione temporale

Esegui Aquatone periodicamente e confronta i report per identificare cambiamenti (nuovi servizi, pagine modificate):

```bash
aquatone -out recon_week1/
# Una settimana dopo
aquatone -out recon_week2/
```

### Chromium headless con opzioni custom

Se Aquatone ha problemi con Chromium:

```bash
cat urls.txt | aquatone -chrome-path /usr/bin/chromium-browser
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Triage rapido di 200+ subdomain

```bash
subfinder -d corp.com -silent | httpx -silent | aquatone -threads 10 -out corp_recon/
```

**Output atteso:** Report HTML con 100-200 screenshot navigabili.

**Cosa fare se fallisce:**

* Screenshot vuoti → Chromium non installato o path errato. Specifica: `-chrome-path /usr/bin/chromium`.
* Timeout → `-screenshot-timeout 30000` (30 secondi).

**Timeline:** 200 target: 5-10 minuti.

### Scenario 2: Identificare pannelli admin in rete interna

```bash
cat internal_ips.txt | aquatone -ports 80,443,8080,8443,3000,9090 -out internal/
```

**Scorrendo il report trovi:** Jenkins su :8080, Grafana su :3000, Kibana su :5601, phpMyAdmin su :80.

**Timeline:** 50 host × 6 porte: 3-5 minuti.

### Scenario 3: Monitorare cambiamenti su perimetro esterno

```bash
cat external_assets.txt | aquatone -out scan_$(date +%Y%m%d)/
```

**Confronta con la scansione precedente per trovare nuovi servizi o pagine modificate.**

**Timeline:** Setup automatico con cron: 0 sforzo ricorrente.

***

## 6️⃣ Toolchain Integration

**Flusso:**

[Subfinder](https://hackita.it/articoli/subfinder/) → [Httpx](https://hackita.it/articoli/httpx/) → **Aquatone (visual triage)** → [Nuclei](https://hackita.it/articoli/nuclei/) (vuln scan su target selezionati)

| Tool              | Screenshot | Report HTML      | Port scan | Speed |
| ----------------- | ---------- | ---------------- | --------- | ----- |
| Aquatone          | Sì         | Sì (interattivo) | Sì        | ★★★★☆ |
| Eyewitness        | Sì         | Sì               | No        | ★★★☆☆ |
| gowitness         | Sì         | Sì               | No        | ★★★★☆ |
| httpx -screenshot | Sì         | No               | No        | ★★★★★ |

***

## 7️⃣ Attack Chain Completa

**Fase 1 — Subdomain enum (10 min):** Subfinder trova 500 subdomain.

**Fase 2 — Probe (1 min):** Httpx filtra 180 live.

**Fase 3 — Visual recon Aquatone (5 min):** Screenshot di tutti. Nel report trovi un Tomcat Manager esposto su `staging.corp.com:8080`.

**Fase 4 — Exploitation (5 min):** Default credentials `tomcat:tomcat`. Deploy WAR shell.

**Fase 5 — Post-exploitation (25 min):** Shell sul server. Escalation e pivoting.

**Timeline:** \~46 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Richieste HTTP da headless Chrome (User-Agent contiene "HeadlessChrome")
* Burst di richieste verso molti subdomain in poco tempo

### Tecniche di evasion

1. Rate limitato con `-threads 2` per ridurre il volume.
2. Aquatone genera traffico simile a un browser reale — meno sospetto di scanner CLI.

***

## 9️⃣ Performance & Scaling

**100 target:** 2-5 minuti. **500 target:** 10-20 minuti. **Consumo:** \~200-500MB RAM (Chromium).

***

## 🔟 Tabelle Tecniche

| Flag                    | Descrizione             |
| ----------------------- | ----------------------- |
| `-ports`                | Porte da testare        |
| `-threads N`            | Thread paralleli        |
| `-timeout N`            | Timeout richiesta (ms)  |
| `-screenshot-timeout N` | Timeout screenshot (ms) |
| `-out dir`              | Directory output        |
| `-chrome-path`          | Path a Chromium         |
| `-ports skip`           | Salta port scan         |

***

## 11️⃣ Troubleshooting

| Problema              | Causa             | Fix                                 |
| --------------------- | ----------------- | ----------------------------------- |
| Screenshot vuoti      | Chromium mancante | `sudo apt install chromium-browser` |
| Crash su molti target | RAM insufficiente | Riduci thread: `-threads 3`         |
| Report non generato   | Errore path       | Specifica `-out ./output/`          |

***

## 12️⃣ FAQ

**Aquatone vs Eyewitness?**
Aquatone è più veloce e ha un report più navigabile. Eyewitness ha più opzioni di categorizzazione.

**Funziona su target HTTPS con cert non valido?**
Sì, Chromium headless ignora gli errori di certificato.

**Posso usarlo su rete interna post-pivot?**
Sì, genera gli IP e pipali in Aquatone.

***

## 13️⃣ Cheat Sheet

| Azione            | Comando                                                  |
| ----------------- | -------------------------------------------------------- |
| Scan base         | `cat subs.txt \| aquatone`                               |
| Porte custom      | `cat list.txt \| aquatone -ports 80,443,3000,8080`       |
| Pipeline completa | `subfinder -d domain \| httpx -silent \| aquatone`       |
| Rete interna      | `seq 1 254 \| sed 's/^/http:\/\/172.16.0./' \| aquatone` |
| Skip port scan    | `cat urls.txt \| aquatone -ports skip`                   |
| Thread limitati   | `cat list.txt \| aquatone -threads 3`                    |

***

**Disclaimer:** Aquatone è un tool per security assessment autorizzato. Repository: [github.com/michenriksen/aquatone](https://github.com/michenriksen/aquatone).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
