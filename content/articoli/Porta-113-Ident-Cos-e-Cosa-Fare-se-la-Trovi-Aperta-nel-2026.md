---
title: 'Porta 113 Ident: Cos''è e Cosa Fare se la Trovi Aperta nel 2026'
slug: porta-113-ident
description: >-
  Porta 113 aperta? Ident è quasi defunto ma rivela username e indica sistemi
  legacy vulnerabili. Scopri come enumerare e cosa cercare dopo.
image: /porta-113-ident.webp
draft: false
date: 2026-04-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - recon
---

La porta 113 espone **Ident** (Identification Protocol, RFC 1413) — un servizio legacy Unix/Linux progettato negli anni '80 per identificare quale user locale ha aperto una specifica connessione TCP outbound. Ident opera su TCP porta 113 rispondendo a query tipo "Chi ha aperto connessione da tua porta 12345 verso mia porta 80?" con risposta "alice" o "UID 1000". In penetration testing moderno, la porta 113 è **quasi completamente obsoleta** — deprecata da 20+ anni, disabilitata di default su tutti OS moderni, e sostituita da logging interno. Tuttavia, alcuni legacy systems (IRC servers 1990s-style, old FTP daemons, mail servers antichi) ancora richiedono Ident, e trovarla attiva nel 2026 indica **infrastructure severely outdated** con potenziali vulnerabilities multiple. L'unico uso pentest è username enumeration passivo su sistemi legacy.

Ident sopravvive marginalmente nel 2026 solo su: IRC networks legacy (Freenode-era servers), mail servers antichi senza modern auth, e appliance embedded mai aggiornati (router/firewall anni 2000). Modern networks usano logging centralizzato, NAT mascheramento, e autenticazione application-level. In CTF/lab, porta 113 aperta è rare finding che indica o challenge retro-style o honeypot detection.

***

## Anatomia tecnica di Ident

Ident usa **TCP porta 113** con protocollo testuale minimal.

**Flow Ident query:**

1. **Connection established** — User `alice` su client 10.10.10.50 connette server 10.10.10.100:80 da source port 45678
2. **Server Ident query** — Server 10.10.10.100 connette client 10.10.10.50:113
3. **Ident request** — Server chiede: `45678, 80` (chi ha aperto porta 45678 verso mia 80?)
4. **Ident response** — Client risponde: `45678, 80 : USERID : UNIX : alice`
5. **Server logs** — Server logga: connessione da alice\@10.10.10.50

**Formato request/response:**

```
REQUEST: <local-port>, <remote-port>
RESPONSE: <local-port>, <remote-port> : USERID : <os-type> : <username>

Esempio:
Query: 45678, 80
Response: 45678, 80 : USERID : UNIX : alice
```

**Ident limitations critiche:**

| Limitation          | Implicazione security                                 |
| ------------------- | ----------------------------------------------------- |
| No authentication   | Chiunque può query, response trustable zero           |
| Username disclosure | **Privacy leak**                                      |
| NAT incompatible    | Non funziona dietro NAT (2026 = 99% networks)         |
| Trivial spoof       | Attacker può run fake identd con response arbitrarie  |
| Deprecated          | RFC 1413 obsoleto, nessun modern OS enable di default |

Le **misconfigurazioni** (rare) sono: Ident abilitato su server production modern, identd che espone UID numerici invece di username (meno info leak ma still disclosure), e logging Ident responses senza validation (log poisoning vulnerability).

***

## Enumerazione

```bash
nmap -sV -p 113 10.10.10.113
```

**Output tipico (se abilitato, rare):**

```
PORT    STATE SERVICE VERSION
113/tcp open  ident   OpenBSD identd
```

**Se closed (expected 2026):**

```
PORT    STATE  SERVICE
113/tcp closed ident
```

**Test manuale:**

```bash
# Assume attacker ha connessione aperta verso target
# Es: attacker porta 12345 → target porta 22

nc -vn 10.10.10.113 113
12345, 22
```

**Response se Ident attivo:**

```
12345, 22 : USERID : UNIX : root
```

**Username disclosed:** `root` ha aperto connessione SSH.

***

## Tecniche offensive (limitate)

### 1. Username enumeration passivo

**Scenario:** Attacker apre connessione verso target (es: SSH, HTTP), poi query Ident per scoprire username.

```bash
# Fase 1: Open connection SSH
ssh user@10.10.10.113
# Connection aperta, attacker source port: 54321
```

```bash
# Fase 2: Query Ident (da altro terminal)
nc -vn 10.10.10.113 113
54321, 22
```

**Response:**

```
54321, 22 : USERID : UNIX : alice
```

**Intel:** User `alice` ha SSH attivo.

**Pentest use case:** Minimal — username enumeration è più facile via [SMTP VRFY](https://hackita.it/articoli/smtp), LDAP, o RPC.

### 2. Information disclosure per lateral movement

**Scenario:** Post-compromise di un host, query Ident su altri host per username mapping.

```bash
# Attacker compromised 10.10.10.50
# Query altri servers per chi ha connessioni attive

for ip in $(seq 1 254); do
  nc -w 1 10.10.10.$ip 113 <<< "80, 80" 2>/dev/null | grep USERID
done
```

**Output (se qualche Ident attivo):**

```
10.10.10.100: 80, 80 : USERID : UNIX : webadmin
10.10.10.150: 80, 80 : USERID : UNIX : dbuser
```

**Intel:** Username `webadmin` e `dbuser` per targeting [password spraying](https://hackita.it/articoli/password-spraying).

### 3. Ident spoofing (attacker-controlled identd)

**Scenario:** Attacker run fake identd su propria macchina per spoof responses.

```bash
# Install oidentd (customizable identd)
apt install oidentd

# Config /etc/oidentd.conf
default {
  default {
    reply "admin"
  }
}

# Start identd
oidentd -d
```

**Ogni Ident query riceve response "admin"** — utile se target server trust Ident per access control (rare, antiquato).

***

## Scenari pratici

### Scenario 1 — Ident username enum → SSH brute force

**Contesto:** Legacy IRC server richiede Ident.

```bash
# Fase 1: Connect IRC server
telnet 10.10.10.113 6667
```

```
:server NOTICE * :*** Looking up your hostname...
:server NOTICE * :*** Checking Ident
:server NOTICE * :*** Found your hostname
```

Server query Ident automaticamente.

```bash
# Fase 2: Capture Ident response (Wireshark su attacker machine)
# Ident response: alice
```

```bash
# Fase 3: SSH brute force con username
hydra -l alice -P rockyou.txt ssh://10.10.10.113
```

**Risultato:** Username conocido riduce brute force space.

**COSA FARE SE FALLISCE:**

* **Ident closed:** Expected modern networks, skip enumeration
* **Ident timeout:** Firewall block, port not exposed
* **Numeric UID response:** `1000` invece di username, meno utile ma correlabile

### Scenario 2 — Identificare quale user esegue servizio

**Contesto:** Port scan rivela servizio unknown su porta custom.

```bash
# Unknown service on port 8080
nc -vn 10.10.10.113 8080
# Banner: "Custom App v1.0"
```

```bash
# Query Ident per username
nc -vn 10.10.10.113 113
8080, <attacker_port>
```

**Response:**

```
8080, 44567 : USERID : UNIX : developer
```

**Intel:** Service run da user `developer` (non root) → potential privilege escalation path se compromised.

***

## Detection & evasion

### Lato Blue Team

**Ident NON dovrebbe essere abilitato nel 2026.**

```bash
# Check if identd running
systemctl status oidentd
# Should be: inactive (dead)

# Firewall block
iptables -A INPUT -p tcp --dport 113 -j DROP
```

**Se legacy requirement esiste:**

```bash
# Restrict Ident responses (oidentd config)
# /etc/oidentd.conf
default {
  default {
    reply "UNKNOWN-USER"
  }
}
```

### Lato Red Team

**Ident enumeration è extremely low-noise** — single TCP connection, no authentication required.

```bash
# Quick check Ident availability
nc -w 1 -vn 10.10.10.113 113 <<< "1, 1"
# Se response → Ident attivo
```

***

## Troubleshooting

| Errore                  | Causa                         | Fix                             |
| ----------------------- | ----------------------------- | ------------------------------- |
| Connection refused      | Ident disabilitato (expected) | Skip enumeration                |
| Timeout                 | Firewall block                | Verify port 113 open            |
| `ERROR : NO-USER`       | Porta non valida nel query    | Use active connection ports     |
| `ERROR : UNKNOWN-ERROR` | Identd misconfiguration       | Try different port combinations |

***

## FAQ

**Ident è usato nel 2026?**

No. \<1% servers globally. Solo legacy IRC, mail servers antichi.

**Perché Ident è obsoleto?**

NAT incompatibility, privacy concerns (username disclosure), trivial spoofing, modern auth methods superiori.

**Posso usare Ident per privilege escalation?**

No. Solo information disclosure (username). Exploitation richiede altri vettori.

**Come blocco Ident?**

Disable identd daemon (`systemctl disable oidentd`), firewall block porta 113.

***

## Cheat sheet

| Azione              | Comando                                         |
| ------------------- | ----------------------------------------------- |
| Scan Ident          | `nmap -sV -p 113 <target>`                      |
| Manual query        | `nc <target> 113` → `<localport>, <remoteport>` |
| Check identd status | `systemctl status oidentd`                      |
| Block Ident         | `iptables -A INPUT -p tcp --dport 113 -j DROP`  |

***

## Perché documentare Ident (quasi defunto)

Ident è **99% obsoleto** nel 2026 ma documentato per:

1. **Legacy systems** — Rare IRC networks, mail servers anni '90
2. **CTF challenges** — Retro-style boxes
3. **Completeness** — Port 113 assignment IANA exists
4. **Historical context** — Understand evolution network security

**Pentest strategy:** Se porta 113 aperta → assume **severely outdated system** → focus su CVE legacy, default credentials, ancient software versions.

## Hardening (se Ident necessario, unlikely)

```bash
# Minimize disclosure
# /etc/oidentd.conf
default {
  default {
    reply "user"  # Generic reply
  }
}

# Firewall limit to specific IPs
iptables -A INPUT -p tcp --dport 113 -s <trusted_subnet> -j ACCEPT
iptables -A INPUT -p tcp --dport 113 -j DROP
```

***

> **Disclaimer:** Ident è legacy protocol. Porta 113 nel 2026 rarissima. L'autore e HackIta declinano responsabilità. RFC 1413: [https://www.rfc-editor.org/rfc/rfc1413.html](https://www.rfc-editor.org/rfc/rfc1413.html)

Vuoi supportare HackIta? Visita hackita.it/supporto.
