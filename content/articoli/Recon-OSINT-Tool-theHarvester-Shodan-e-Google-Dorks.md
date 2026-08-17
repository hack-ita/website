---
title: 'Recon OSINT: Tool, theHarvester, Shodan e Google Dorks.'
slug: reconnaissance
description: >-
  Reconnaissance OSINT passiva per pentest: raccogli email, sottodomini,
  dispositivi esposti e metadati con theHarvester, Google Dorks, Shodan e
  Metagoofil.
image: /osint-reconnaissance-pentest-dossier-ezgif.com-png-to-webp-converter.webp
draft: false
date: 2026-08-18T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - recon
tags:
  - OSINT
  - Passive Reconnaissance
  - theHarvester
  - Google Dorks
  - Shodan
  - Metagoofil
---

# Reconnaissance nel Pentesting: Passive Recon e OSINT

La reconnaissance nel pentesting è la fase di raccolta di informazioni su un target prima dell'enumerazione e dello scanning. La passive reconnaissance usa fonti pubbliche — motori di ricerca, WHOIS, Shodan, GitHub, social media — senza inviare richieste dirette all'infrastruttura del target. Costruisci il profilo completo del target — email dei dipendenti, stack tecnologico, documenti esposti, dispositivi accessibili da internet, credenziali in leak — prima di aprire nmap.

Un target letto bene in reconnaissance vale più di ore di scanning aggressivo: puoi identificare indirizzi aziendali, ruoli e naming convention utili per valutare la superficie di attacco e simulare scenari di social engineering autorizzati, individuare un VPN gateway esposto su Shodan, un `.sql` di backup indicizzato da Google, o credenziali in un repo GitHub pubblico.

**Prerequisiti:** nessuno — è il primo step di ogni engagement. I risultati alimentano [DNS](https://hackita.it/articoli/dns/), la subdomain enumeration, [nmap](https://hackita.it/articoli/nmap/) e tutte le fasi successive.

***

## Cos'è la Reconnaissance nel Pentesting?

La reconnaissance è la raccolta sistematica di informazioni su un target prima di interagire direttamente con la sua infrastruttura. Si divide in due categorie con implicazioni molto diverse sul piano OPSEC.

## Passive vs Active Reconnaissance

| Tipo    | Interazione con il target | Esempi                                                              |
| ------- | ------------------------- | ------------------------------------------------------------------- |
| Passive | Nessuna diretta           | Google, Shodan, WHOIS, crt.sh, GitHub, VirusTotal                   |
| Active  | Diretta                   | DNS query verso i nameserver del target, port scan, banner grabbing |

La maggior parte di questo articolo copre reconnaissance passiva: interroghi database e fonti già popolate (Google, Shodan, WHOIS, Certificate Transparency), senza toccare i server del target. Fanno eccezione i comandi `dig`/`host` per la risoluzione inversa e, più avanti nella pipeline, lo scanning con nmap — quelli sì generano traffico osservabile verso l'infrastruttura target, e sono reconnaissance/enumeration attiva, non passiva.

## Reconnaissance vs Enumeration

* **Reconnaissance** → cosa posso sapere sul target da fonti pubbliche, prima di toccarlo?
* **Enumeration** → quali servizi, host e account esistono realmente, verificati direttamente?
* **Scanning** → quali porte e servizi sono raggiungibili adesso?

Sono fasi sequenziali: la reconnaissance alimenta l'enumeration, che alimenta lo scanning mirato.

***

## Ordine delle Operazioni

```text
RECON (questo articolo)          → DNS/SUBDOMAIN ENUM → PORT SCAN → EXPLOITATION
theHarvester, Shodan, Dorks         dig, puredns           nmap
Email, documenti, tech stack        AXFR                   service detection
```

La recon alimenta tutto: sapere che il target usa Cisco ASA (trovato su Shodan) ti dice di cercare CVE Cisco. Sapere che un dipendente si chiama Mario Rossi ti dice di provare `m.rossi@`, `mario.rossi@`, `mrossi@` come pattern username — utile poi per password spraying o brute force contro [Active Directory](https://hackita.it/articoli/active-directory/). Sapere che il target usa AWS (da un job posting LinkedIn) ti dice di cercare bucket S3 esposti.

***

## theHarvester – Email, Subdomain, IP da Fonti Pubbliche

theHarvester interroga motori di ricerca, database DNS, LinkedIn e altre fonti per raccogliere email, subdomain e IP associati al dominio target, senza toccare direttamente i suoi server.

```bash
# Se non è già installato
sudo apt install theharvester -y
theHarvester --help

# Scan base con Google
theHarvester -d target.com -b google

# Scan con Bing (a volte indicizza più cose di Google)
theHarvester -d target.com -b bing

# LinkedIn – trova nomi di dipendenti
theHarvester -d target.com -b linkedin

# Combina più fonti
theHarvester -d target.com -b google,bing,linkedin,dnsdumpster

# Tutto quello che ha
theHarvester -d target.com -b all -l 500

# Salva output in file XML e HTML
theHarvester -d target.com -b all -f recon_output

# Con proxy Burp Suite (per vedere le query che fa)
theHarvester -d target.com -b google --proxy 127.0.0.1:8080
```

```text
[*] Emails found:
   mario.rossi@target.com
   info@target.com
   helpdesk@target.com
   admin@target.com

[*] Hosts found:
   mail.target.com:203.0.113.20
   vpn.target.com:203.0.113.40
   dev.target.com:10.0.0.50

[*] IPs found:
   203.0.113.10
   203.0.113.20
   203.0.113.40
```

**Cosa fare con i risultati:**

* **Email**: formula il pattern di naming (`nome.cognome@`, `ncognome@`) → usa per username enumeration su servizi di autenticazione, o per simulazioni di phishing autorizzate
* **Subdomain**: aggiungi alla lista per DNS enumeration e subdomain enumeration attiva
* **IP**: passa a Shodan per vedere cosa gira su quegli IP, poi a [nmap](https://hackita.it/articoli/nmap/) per il port scan completo

> Errore tipico: fidarsi ciecamente dei risultati di theHarvester. Alcune email sono falsi positivi estratti da contesti errati. Verifica sempre il pattern di naming su 2-3 email trovate prima di usarle.

***

## Google Dorks – Trova Quello Che Non Dovrebbe Essere Indicizzato

I Google Dork sono query avanzate che usano operatori speciali per trovare informazioni specifiche indicizzate da Google — file sensibili, pannelli admin, directory esposte, backup, credenziali.

### Operatori Fondamentali

| Operatore   | Cosa fa           | Esempio                              |
| ----------- | ----------------- | ------------------------------------ |
| `site:`     | Limita al dominio | `site:target.com`                    |
| `filetype:` | Tipo di file      | `filetype:pdf site:target.com`       |
| `intitle:`  | Parola nel titolo | `intitle:"index of" site:target.com` |
| `inurl:`    | Parola nell'URL   | `inurl:admin site:target.com`        |
| `intext:`   | Parola nel testo  | `intext:"password" site:target.com`  |
| `ext:`      | Estensione file   | `ext:env site:target.com`            |
| `-`         | Escludi           | `site:target.com -www`               |
| `"..."`     | Stringa esatta    | `"mario.rossi" target.com`           |

### Dork per File Sensibili

```text
# File di configurazione e backup
site:target.com ext:env
site:target.com ext:conf
site:target.com ext:cfg
site:target.com ext:ini
site:target.com ext:bak
site:target.com ext:sql
site:target.com ext:log

# Documenti con info potenzialmente sensibili
site:target.com filetype:pdf
site:target.com filetype:xlsx
site:target.com filetype:xls "password"
site:target.com filetype:doc "confidential"
site:target.com filetype:pptx "internal only"

# File .env e credenziali (sviluppatori) — poi testa i parametri trovati con SQL injection
site:github.com "target.com" ext:env
site:github.com "target.com" "api_key"
site:github.com "target.com" "password"
site:github.com "target.com" "secret"
```

### Dork per Pannelli Admin e Login

```text
# Pannelli di amministrazione — trovato un /admin? Testalo con Burp Suite e directory fuzzing
inurl:admin site:target.com
inurl:login site:target.com
inurl:wp-admin site:target.com
inurl:phpmyadmin site:target.com
inurl:cpanel site:target.com
inurl:webmail site:target.com
intitle:"admin panel" site:target.com
intitle:"login" inurl:admin site:target.com
```

### Dork per Directory Esposte

```text
# Directory listing aperte
intitle:"index of" site:target.com
intitle:"index of" "backup" site:target.com
intitle:"index of" ".git" site:target.com
intitle:"index of" "/uploads" site:target.com
```

### Dork per Technology Stack

```text
# Identifica tech usata (utile prima di cercare CVE specifici)
site:target.com "Powered by WordPress"
site:target.com "Apache/2"
site:target.com "nginx/"
site:target.com "IIS"
site:target.com intext:"Django" OR intext:"Laravel" OR intext:"Spring Boot"
```

### Dork su GitHub

```text
# Cerca nel codice sorgente su GitHub
site:github.com "target.com" "password"
site:github.com "target.com" "api_key" OR "apikey" OR "api-key"
site:github.com "target.com" "secret" OR "token"
site:github.com org:targetorg "internal"
site:github.com "@target.com" password
```

> Google può mostrare CAPTCHA o limitare temporaneamente le query se ne mandi troppe in sequenza — non è una regola fissa e assoluta, ma succede spesso. Usa un browser normale, fai pause tra le ricerche, o alterna con Bing, che spesso indicizza cose diverse.

***

## Shodan – Dispositivi Esposti su Internet

Shodan indicizza dispositivi connessi a internet (server, router, IoT, ICS, telecamere) con i banner di ogni porta aperta. La ricerca nel database di Shodan è passiva rispetto al target — non lo tocchi tu, l'ha già scansionato Shodan in precedenza con la propria infrastruttura.

```bash
# Installa CLI Shodan
pip install shodan
shodan init TUA_API_KEY

# Cerca per dominio
shodan domain target.com

# Cerca per IP specifico
shodan host 203.0.113.10

# Cerca per hostname
shodan search "hostname:target.com"

# Cerca per certificato SSL (trova tutti i host con cert per target.com)
shodan search "ssl.cert.subject.cn:target.com"

# Cerca per organizzazione (trova tutto l'ASN)
shodan search "org:\"Target Corporation\""

# Cerca tecnologie specifiche esposte
shodan search "hostname:target.com product:Apache"
shodan search "hostname:target.com port:3389"   # RDP esposto
shodan search "hostname:target.com port:22"     # SSH esposto

# Cerca vulnerabilità note su host del target
shodan search "net:203.0.113.0/24 vuln:CVE-2021-44228"  # Log4Shell

# Trova dispositivi AD (utile prima di attaccare Active Directory)
shodan search "hostname:target.com port:88"   # Kerberos
shodan search "hostname:target.com port:389"  # LDAP
```

```text
# Output shodan host 203.0.113.10
IP: 203.0.113.10
Organization: Target Corporation
OS: Windows Server 2019
Open ports:
  80/tcp   Apache httpd 2.4.51
  443/tcp  Apache httpd 2.4.51
  3389/tcp Microsoft Terminal Services  ← RDP esposto!
  8443/tcp Apache Tomcat/9.0.54
```

### Shodan Dork Utili

```text
hostname:target.com http.title:"admin"
hostname:target.com http.title:"dashboard" 200
hostname:target.com port:3306   # MySQL
hostname:target.com port:5432   # PostgreSQL
hostname:target.com port:27017  # MongoDB
hostname:target.com port:6379   # Redis (spesso senza auth)
hostname:target.com port:9200 product:Elastic
```

***

## Censys – Search Engine per Internet Assets

Censys copre lo stesso spazio di Shodan (dispositivi e servizi esposti su internet), ma con un focus più orientato a host e certificati piuttosto che ai soli banner di servizio.

| Shodan                                     | Censys                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| Banner/service oriented                    | Host/certificate oriented                                                 |
| Ottimo per identificare servizi e versioni | Ottimo per certificati e correlazione asset                               |
| Query rapide su porte/prodotti             | Utile per mappare tutta l'infrastruttura certificata di un'organizzazione |

```bash
# Ricerca via web UI: search.censys.io
# Query per organizzazione
services.tls.certificates.leaf_data.subject.organization: "Target Corporation"

# Query per hostname
services.tls.certificates.leaf_data.subject_dn: "target.com"
```

Usa Shodan e Censys insieme: spesso un dispositivo che manca in uno compare nell'altro, specialmente per host con certificati TLS particolari.

***

## Certificate Transparency e crt.sh

I certificati TLS emessi pubblicamente finiscono nei log di Certificate Transparency — consultabili gratuitamente, e spesso rivelano sottodomini, ambienti di staging/dev e infrastruttura dimenticata che non compare da nessun'altra parte.

```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  sort -u
```

I risultati alimentano direttamente la fase di subdomain enumeration — è spesso il primo posto dove emergono host come `staging-old.target.com` o `dev-2019.target.com` che nessuno ricorda più di aver esposto.

***

## WHOIS e ASN – Network Footprint

WHOIS può rivelare chi possiede il dominio e i contatti amministrativi — ma non sempre: privacy protection e normative come il GDPR spesso oscurano questi dati, specialmente per domini registrati in Europa. L'ASN rivela gli IP range di proprietà dell'organizzazione, importante per capire lo scope completo.

```bash
# WHOIS base
whois target.com
# Se non oscurato: registrar, admin email, name server, data di scadenza

# WHOIS su IP
whois 203.0.113.10
# Rivela: Organization, Country, Net Range, CIDR

# Trova ASN dell'organizzazione
whois -h whois.radb.net -- '-i origin AS12345'

# Tutti gli IP range di un ASN
# bgpview.io/asn/12345#prefixes

# Risoluzione inversa (IP → hostname)
dig -x 203.0.113.10 +short
host 203.0.113.10
```

***

## VirusTotal – Passive DNS e Infrastructure Intelligence

VirusTotal non è solo scansione malware: la sua sezione "Relations" correla domini, sottodomini, IP, record DNS storici e certificati — utile per trovare infrastruttura collegata al target che altre fonti non mostrano.

```bash
# Via API (richiede API key gratuita)
curl -s "https://www.virustotal.com/api/v3/domains/target.com/subdomains" \
  -H "x-apikey: TUA_API_KEY" | jq -r '.data[].id'

# Passive DNS: IP storici associati al dominio
curl -s "https://www.virustotal.com/api/v3/domains/target.com" \
  -H "x-apikey: TUA_API_KEY" | jq '.data.attributes.last_dns_records'
```

Utile in combinazione con crt.sh: dove crt.sh mostra i certificati emessi, VirusTotal mostra le relazioni DNS storiche tra gli asset.

***

## Wayback Machine – Reconnaissance Storica

L'Internet Archive conserva snapshot storici di pagine web — spesso rivela vecchi sottodomini, endpoint rimossi, file dimenticati e tecnologie sostituite ma ancora referenziate da qualche parte.

```bash
# Tutti gli URL archiviati per un dominio
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" \
  | sort -u > wayback_urls.txt

# Filtra per estensioni interessanti
grep -E "\.(env|sql|bak|config|json)$" wayback_urls.txt

# Con gau (Wayback + Common Crawl + OTX insieme)
gau target.com | sort -u > gau_urls.txt
```

Particolarmente utile per trovare endpoint API vecchi ancora attivi ma non più linkati, o parametri che rivelano logiche applicative dismesse.

***

## Email Enumeration – Trova il Pattern e Verifica

Una volta trovate alcune email con theHarvester, estrapola il pattern di naming e trova altri dipendenti. Questa fase alimenta username enumeration e, più avanti nell'engagement, test di autenticazione — non va confusa con il credential dumping, che avviene solo dopo aver già ottenuto un accesso.

```bash
# Hunter.io (API con piano gratuito limitato)
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=TUA_KEY" | \
  jq '.data.pattern'
# Output: "{first}.{last}" → mario.rossi@target.com

# Verifica se un indirizzo esiste (SMTP verify)
curl "https://api.hunter.io/v2/email-verifier?email=mario.rossi@target.com&api_key=TUA_KEY" | \
  jq '.data.result'
# Output: "deliverable" oppure "undeliverable"

# Estrai nomi dipendenti da LinkedIn (manuale nel browser → azienda → persone)

# Genera wordlist di email da lista di nomi con username-anarchy
git clone https://github.com/urbanadventurer/username-anarchy
cat nomi.txt | ./username-anarchy --input-format firstname_lastname \
  | sed 's/$/@target.com/' > email_list.txt
```

***

## Document Metadata – Metagoofil

I documenti PDF, Word, Excel pubblicati sul sito del target contengono metadata: nome autore, username Windows, software usato, path interni del filesystem.

```bash
# Installa
sudo apt install metagoofil -y

# Scarica e analizza tutti i PDF del sito
metagoofil -d target.com -t pdf -l 50 -o output_pdf/

# Analizza anche doc, xls, pptx
metagoofil -d target.com -t pdf,doc,xls,ppt,docx,xlsx -l 100 -o output_docs/
```

```bash
# Analisi manuale di un PDF con exiftool
sudo apt install exiftool
exiftool documento.pdf
```

**Cosa cerchi nei metadata:**

* **Username** → prova come username SSH, VPN, RDP, o come base per attacchi contro [Active Directory](https://hackita.it/articoli/active-directory/)
* **Software versions** → cerca CVE per quella versione
* **Internal path** → rivela struttura directory interna
* **Email address** → conferma il pattern di naming

***

## Social Media e GitHub Intelligence

### LinkedIn – Tech Stack e Persone

```text
# Ricerche manuali su LinkedIn:

# 1. Trova dipendenti IT/Security
# LinkedIn search → People → Company: Target → Department: IT

# 2. Analizza job posting per tech stack
# Job posting per "DevOps Engineer": "AWS, Kubernetes, Terraform, Jenkins"
# → Il target usa AWS + k8s + Terraform + Jenkins, cerca misconfigurazioni note

# 3. Estrai email dal pattern trovato
# Se Mario Rossi → mario.rossi@target.com (da hunter.io)
# Allora Giulia Bianchi → giulia.bianchi@target.com
```

### GitHub – Credenziali e Config Leak

```bash
# Con trufflehog: cerca secret in repos pubblici dell'organizzazione
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

trufflehog github --org=targetorg --only-verified
trufflehog git https://github.com/targetorg/repo --only-verified
```

```text
# Dork manuali su GitHub (nel browser):
target.com "api_key"
target.com "password" "BEGIN RSA"
target.com "mongodb+srv://"
target.com "s3.amazonaws.com" "access_key"
```

***

## Fonti OSINT Aggiuntive

| Fonte             | Informazioni                                      |
| ----------------- | ------------------------------------------------- |
| crt.sh            | Certificati TLS, sottodomini                      |
| VirusTotal        | Passive DNS, relazioni tra infrastrutture         |
| Censys            | Host, certificati, asset internet                 |
| Wayback Machine   | Vecchie versioni, endpoint dismessi               |
| GitHub            | Codice sorgente, secret esposti                   |
| Have I Been Pwned | Verifica se email/domini compaiono in breach noti |

Non serve usarle tutte su ogni engagement — sono strumenti da tirare fuori quando le fonti principali (theHarvester, Google, Shodan) non bastano o quando il target ha una superficie ampia.

***

## recon-ng – Framework di Automazione OSINT

recon-ng è un framework con workspace, moduli e database integrato per organizzare reconnaissance più estese.

```bash
recon-ng

[recon-ng] > workspaces create target_com
[recon-ng][target_com] > db insert domains
> domain: target.com

[recon-ng][target_com] > marketplace install recon/domains-hosts/hackertarget
[recon-ng][target_com] > marketplace install recon/domains-contacts/whois_pocs
[recon-ng][target_com] > marketplace install recon/hosts-hosts/shodan_ip

[recon-ng][target_com] > modules load recon/domains-hosts/hackertarget
[recon-ng][target_com][hackertarget] > run

[recon-ng][target_com] > modules load recon/domains-contacts/whois_pocs
[recon-ng][target_com][whois_pocs] > run

[recon-ng][target_com] > marketplace install reporting/html
[recon-ng][target_com] > modules load reporting/html
[recon-ng][target_com][html] > set FILENAME /tmp/recon_report.html
[recon-ng][target_com][html] > run
```

***

## SpiderFoot – OSINT Automatico

SpiderFoot automatizza decine di moduli OSINT in una sola run con interfaccia web.

```bash
pip install spiderfoot
spiderfoot -l 127.0.0.1:5001
# Apri browser su http://127.0.0.1:5001
# Nuovo Scan → Inserisci target.com → Seleziona moduli → Start
```

**Moduli utili in SpiderFoot:** Shodan, Censys, VirusTotal per IP/host intelligence; Have I Been Pwned per email in breach; Hunter.io per email pattern; crt.sh per certificate transparency; DNS/WHOIS per network info; LinkedIn/GitHub per social e code recon.

***

## Percorso Operativo Consigliato

```text
1. WHOIS + ASN
   └─ whois target.com → nameserver, contatti (se non oscurati), org
   └─ bgpview.io → IP range dell'organizzazione

2. THEHARVESTER
   └─ theHarvester -d target.com -b all -l 500
   └─ Raccogli: email, subdomain, IP

3. GOOGLE DORKS
   └─ File sensibili: ext:env, ext:sql, ext:bak
   └─ Admin panels: inurl:admin, intitle:"index of"
   └─ GitHub: site:github.com "target.com" "password"

4. SHODAN + CENSYS
   └─ shodan domain target.com
   └─ Porte, tecnologie, versioni software esposte

5. CERTIFICATE TRANSPARENCY + VIRUSTOTAL + WAYBACK
   └─ crt.sh per sottodomini da certificati
   └─ VirusTotal per passive DNS
   └─ Wayback per endpoint storici

6. LINKEDIN + JOB POSTING
   └─ Dipendenti IT/Security, tech stack, pattern email

7. METAGOOFIL
   └─ Username Windows, path interni, versioni software

8. GITHUB SCAN
   └─ trufflehog + dork manuali per credenziali

9. CONSOLIDA
   └─ Subdomain → DNS enumeration → subdomain enumeration attiva
   └─ IP → nmap port scan
   └─ Email/username → test di autenticazione, phishing simulation
   └─ Tech stack → tool specifici (WPScan per WordPress, ecc.)
```

***

## Reconnaissance Checklist

```text
[ ] Target scope definito e autorizzato
[ ] Domini principali identificati
[ ] Sottodomini raccolti (theHarvester, crt.sh, VirusTotal)
[ ] ASN e CIDR identificati
[ ] IP correlati
[ ] Certificati analizzati (crt.sh, Censys)
[ ] Tecnologie identificate
[ ] Email pubbliche raccolte
[ ] Naming convention identificata
[ ] Documenti pubblici analizzati
[ ] Metadata estratti
[ ] GitHub analizzato
[ ] Leak pubblici verificati (Have I Been Pwned)
[ ] Asset Shodan/Censys correlati
[ ] Vecchi asset analizzati (Wayback Machine)
[ ] Risultati consolidati
[ ] Passaggio a enumeration attiva
```

## Errori da Evitare in Reconnaissance Passiva

* Scansionare il target senza autorizzazione esplicita
* Verificare manualmente porte o servizi durante una fase dichiarata passiva
* Inviare email di test verso indirizzi trovati
* Tentare login su pannelli scoperti
* Interagire attivamente con servizi individuati passivamente
* Scaricare più dati del necessario per l'engagement
* Usare credenziali trovate in leak pubblici senza autorizzazione esplicita
* Confondere dati indicizzati (potenzialmente vecchi) con lo stato attuale reale del target

***

## Troubleshooting

| Problema                       | Causa                              | Soluzione                                                     |
| ------------------------------ | ---------------------------------- | ------------------------------------------------------------- |
| theHarvester trova 0 email     | Dominio piccolo o poco indicizzato | Prova `-b bing` e `-b linkedin` separatamente                 |
| Google mostra CAPTCHA          | Troppe query veloci                | Pausa manuale, usa Bing come alternativa                      |
| Shodan richiede API key        | Serve un account                   | Registra su shodan.io, verifica i limiti del piano attuale    |
| Metagoofil non trova documenti | Sito con pochi documenti pubblici  | Prova manualmente Google: `site:target.com filetype:pdf`      |
| trufflehog lentissimo          | Molti repo da scansionare          | Usa `--only-verified` e limita l'org                          |
| recon-ng moduli non installano | Proxy o firewall                   | `marketplace install` richiede connessione diretta a internet |
| WHOIS non mostra contatti      | Privacy protection attiva          | Normale con GDPR — prova ASN/IP WHOIS o fonti alternative     |

***

## FAQ

**Cos'è la passive reconnaissance?**
La raccolta di informazioni su un target usando solo fonti pubbliche già popolate (motori di ricerca, WHOIS, Shodan, certificate transparency), senza inviare richieste dirette all'infrastruttura del target.

**Qual è la differenza tra reconnaissance ed enumeration?**
La reconnaissance raccoglie cosa è pubblicamente noto sul target. L'enumeration verifica direttamente, interagendo con l'infrastruttura, quali servizi e account esistono davvero.

**Quali tool si usano per la reconnaissance?**
theHarvester, Google Dorks, Shodan, Censys, WHOIS, crt.sh, VirusTotal, Wayback Machine, Metagoofil, recon-ng e SpiderFoot coprono la maggior parte dei casi.

**Shodan è passive reconnaissance?**
La tua ricerca nel database di Shodan sì — non generi traffico verso il target. Shodan stesso, però, raccoglie quei dati tramite proprie attività di scanning attivo su tutto internet.

**Quali informazioni si possono raccogliere durante la reconnaissance?**
Email, sottodomini, IP, tecnologie usate, documenti pubblici con metadata, dipendenti e ruoli, credenziali in leak, certificati TLS e infrastruttura storica.

**Qual è il primo passo della reconnaissance?**
Di solito WHOIS e ASN per capire lo scope del network, seguiti da theHarvester per email e sottodomini.

**La reconnaissance passiva è legale?**
Stai leggendo dati pubblici già indicizzati, senza inviare request al target. Verifica comunque sempre le regole d'ingaggio dell'engagement prima di iniziare, e non confondere la passive recon con azioni attive (login, test, download massivi).

**Come uso le email trovate?**
Identifica il pattern di naming, genera una lista da nomi dipendenti trovati su LinkedIn, verifica con Hunter.io o SMTP, e usale per test di autenticazione o simulazioni di phishing autorizzate — non per credential dumping, che è una fase successiva e diversa.

***

## Cheat Sheet Finale

```text
=== THEHARVESTER ===
Singola fonte:     theHarvester -d target.com -b google
Multi-fonte:       theHarvester -d target.com -b google,bing,linkedin,dnsdumpster
Tutto:             theHarvester -d target.com -b all -l 500 -f output

=== GOOGLE DORKS ===
File sensibili:    site:target.com ext:env OR ext:sql OR ext:bak
Admin panels:      inurl:admin site:target.com
Dir listing:       intitle:"index of" site:target.com
GitHub leak:       site:github.com "target.com" "password" OR "api_key"
Documenti:         site:target.com filetype:pdf OR filetype:xlsx

=== SHODAN / CENSYS ===
Setup:             pip install shodan && shodan init API_KEY
Per dominio:       shodan domain target.com
Per IP:            shodan host IP
SSL cert:          shodan search "ssl.cert.subject.cn:target.com"
Censys:            search.censys.io → services.tls.certificates.leaf_data.subject.organization

=== CERTIFICATE TRANSPARENCY ===
crt.sh:            curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

=== WHOIS / ASN ===
WHOIS:             whois target.com
Reverse WHOIS:     whois 203.0.113.10
ASN IP ranges:     bgpview.io/asn/AS12345

=== VIRUSTOTAL / WAYBACK ===
VT subdomains:     curl -s ".../domains/target.com/subdomains" -H "x-apikey: KEY"
Wayback URLs:      curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text"

=== EMAIL ENUMERATION ===
theHarvester:      theHarvester -d target.com -b all
Pattern:           curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"
Username gen:      cat nomi.txt | ./username-anarchy | sed 's/$/@target.com/'

=== METAGOOFIL ===
PDF:               metagoofil -d target.com -t pdf -l 50 -o out/
Tutti i tipi:      metagoofil -d target.com -t pdf,doc,xls,ppt,docx,xlsx -l 100 -o out/
Exiftool:          exiftool documento.pdf

=== GITHUB / TRUFFLEHOG ===
Org scan:          trufflehog github --org=targetorg --only-verified
Repo singolo:      trufflehog git https://github.com/org/repo --only-verified

=== RECON-NG ===
Start:             recon-ng
Workspace:         workspaces create target_com
Modulo:            marketplace install recon/domains-hosts/hackertarget → run
Report:            modules load reporting/html → run
```

***

**Guide correlate su hackita.it:**

* [DNS: Fondamenti e Attacchi](https://hackita.it/articoli/dns/)
* [Nmap: Port Scanning e Service Detection](https://hackita.it/articoli/nmap/)
* [SQL Injection: Guida Completa](https://hackita.it/articoli/sql-injection/)
* [Burp Suite: Intercettare e Analizzare Traffico HTTP](https://hackita.it/articoli/burp-suite/)
* [Credential Dumping: Come Estrarre Hash](https://hackita.it/articoli/credential-dumping/)
* [John the Ripper: Password Cracking Completo](https://hackita.it/articoli/john-the-ripper/)
* [Hashcat: GPU Password Cracking](https://hackita.it/articoli/hashcat/)
* [Responder: Hash Capture NTLM](https://hackita.it/articoli/responder/)
* [Active Directory: Attack Paths Completi](https://hackita.it/articoli/active-directory/)
* [Kerberoasting: Attacchi a Service Account](https://hackita.it/articoli/kerberoasting/)
* [Impacket: Tool Suite per AD](https://hackita.it/articoli/impacket/)
* [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc/)

## Riferimenti

* [OSINT Framework – osintframework.com](https://osintframework.com/)
* [Google Hacking Database (GHDB) – exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)

\#tools #reconnaissance
