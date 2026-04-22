---
title: 'Porta 90 PointCast: Cos''è e Cosa Fare se la Trovi Aperta nel 2026'
slug: porta-90-pointcast
description: >-
  Porta 90 aperta durante una scansione? PointCast è morto dal 2001. Scopri come
  identificare il servizio reale, che sia un web server nascosto, proxy o app
  custom.
image: /porta-90-pointcast.webp
draft: false
date: 2026-04-23T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - pointcast
---

La porta 90 era utilizzata da **PointCast** — un software commerciale di web push notification popolare nel 1996-2001, predecessore di RSS feeds e modern push notifications. PointCast Network usava TCP porta 90 per distribuire news, weather e stock updates direttamente ai desktop utenti in modalità "push" invece che "pull" (browser). In penetration testing moderno, la porta 90 è **completamente irrilevante** — PointCast è defunto dal 2001, nessun software attivo usa porta 90 standard, e trovarla aperta nel 2026 indica o un servizio custom non-standard o scansione di rete obsoleta. Questa guida copre PointCast per completezza storica e per riconoscere falsi positivi in scansioni nmap.

PointCast fallì nel 2001 a causa di bandwidth consumption eccessivo (corporate networks saturati da push content), rise di RSS (lightweight alternative), e business model insostenibile. Nel 2026, porta 90 aperta è 99.9% probability **non-PointCast** — server custom, misconfiguration, o honeypot.

***

## Anatomia tecnica di PointCast (storico)

PointCast usava **TCP porta 90** con protocollo proprietario binario.

**Flow PointCast (1996-2001):**

1. **Client Connection** — Desktop client connette porta 90 del PointCast server
2. **Channel Subscription** — Client richiede channels (CNN, ESPN, weather)
3. **Push Delivery** — Server push content updates ogni 15 minuti
4. **Rendering** — Client visualizza content come screensaver interattivo

**Caratteristiche:**

* Bandwidth-intensive (10-20MB/hour per client in era 56k modem)
* No autenticazione richiesta (server pubblici)
* Content format: HTML-like proprietario
* Protocollo cifrato: ❌ Plaintext

**Perché PointCast è morto:**

| Anno | Evento                                                 |
| ---- | ------------------------------------------------------ |
| 1996 | PointCast lanciato, 1M utenti in 6 mesi                |
| 1997 | Corporate networks bannano PointCast (bandwidth abuse) |
| 1999 | RSS syndication emerge come alternative                |
| 2000 | PointCast acquisito da Launchpad Technologies          |
| 2001 | Servizio discontinuato, porta 90 abbandonata           |

***

## Enumerazione (nel 2026)

```bash
nmap -sV -p 90 10.10.10.90
```

**Output tipico (se porta aperta):**

```
PORT   STATE SERVICE VERSION
90/tcp open  dnsix?
```

**Nota:** nmap identifica porta 90 come `dnsix` (DoD Network Security for Information Exchange) — altro servizio obsoleto anni '80. Se vedi porta 90 aperta, probabilmente **non è PointCast né dnsix** ma un servizio custom.

**Test manuale:**

```bash
nc -vn 10.10.10.90 90
```

Se risponde con binary data incomprensibile → servizio custom, non PointCast (che è defunto).

***

## Contesto penetration testing

**Porta 90 aperta nel 2026 = quasi sempre false positive o custom service.**

### Scenario 1: Custom application su porta 90

Alcune applicazioni custom scelgono porta 90 perché "non standard" (security by obscurity fallace).

```bash
# Identify real service
nmap -sV -p 90 --version-intensity 9 10.10.10.90
```

Se identifica Apache/Nginx → web server on non-standard port. Applica il playbook HTTP completo.

### Web server nascosto su porta 90

Questa è la situazione più comune e più interessante per un pentester. Qualcuno ha messo un web server su una porta "strana" pensando di nasconderlo.

```bash
# Prova HTTP direttamente
curl -v http://10.10.10.90:90/
wget -q -O- http://10.10.10.90:90/

# Directory bruteforce
gobuster dir -u http://10.10.10.90:90/ -w /usr/share/wordlists/dirb/common.txt

# Con ffuf
ffuf -u http://10.10.10.90:90/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Se risponde HTTP → trattalo esattamente come una porta 80/8080. Panel di admin, login page, endpoint esposti — tutto il playbook web si applica identico. Spesso su porte non standard ci sono pannelli di gestione, interfacce di debug o API interne che l'admin credeva "non visibili".

### Reverse proxy o tunnel su porta 90

Alcune configurazioni proxy (Squid, Nginx reverse proxy) finiscono su porte non standard per "nascondersi". Se il banner contiene `squid` o `nginx`:

```bash
nmap -p 90 --script http-headers,http-title 10.10.10.90
```

Un proxy aperto su porta 90 può essere sfruttato per pivot verso reti interne — se il proxy non richiede autenticazione, puoi instradare traffico verso IP non raggiungibili direttamente.

### Scenario 2: Honeypot detection

Porta 90 può essere honeypot (detect scanning activity).

```bash
# Connect e observe behavior
nc 10.10.10.90 90
# Se instant disconnect → likely honeypot
```

### Scenario 3: Firewall misconfiguration

Porta 90 aperta ma nessun servizio → firewall rule obsoleto.

```bash
nmap -sV -p 90 10.10.10.90
# open|filtered (no response) → abandoned firewall rule
```

***

## Raccomandazioni per pentester

**Se trovi porta 90 aperta:**

1. **Identify real service** con `-sV --version-intensity 9`
2. **Testa subito HTTP** — è il caso più frequente
3. **Banner grab manuale** per determine protocol
4. **Apply vulnerability assessment** basato su real service

**Non assumere PointCast** — è defunto da 23 anni.

***

## Hardening (network admin perspective)

**Porta 90 NON dovrebbe essere aperta.**

```bash
# Linux firewall (iptables)
iptables -A INPUT -p tcp --dport 90 -j DROP

# Windows firewall
netsh advfirewall firewall add rule name="Block Port 90" dir=in action=block protocol=TCP localport=90
```

Se hai servizio legittimo su porta 90 → **move to standard port** o **document thoroughly**.

***

## Cheat sheet

| Azione           | Comando                                                |
| ---------------- | ------------------------------------------------------ |
| Scan port 90     | `nmap -sV -p 90 <target>`                              |
| Banner grab      | `nc -vn <target> 90`                                   |
| Test HTTP        | `curl -v http://<target>:90/`                          |
| Directory brute  | `gobuster dir -u http://<target>:90/ -w common.txt`    |
| Identify service | `nmap --version-intensity 9 -p 90 <target>`            |
| HTTP headers     | `nmap -p 90 --script http-headers,http-title <target>` |

***

## FAQ

**PointCast è ancora usato nel 2026?**

No. Defunto dal 2001. Porta 90 aperta = custom service, non PointCast.

**Cosa faccio se trovo porta 90 aperta?**

Prima cosa: `curl -v http://TARGET:90/`. Se risponde HTTP è il caso più comune — applica il playbook web standard. Altrimenti, banner grab manuale e vulnerability assessment basato sul servizio reale.

**Porta 90 è vulnerabilità?**

Non intrinsecamente, ma porta non-standard aperta è suspicious. Spesso indica servizi dimenticati, panel di admin non protetti o proxy aperti.

***

> **Disclaimer:** Tutti i comandi sono destinati esclusivamente all'uso in ambienti autorizzati. L'autore e HackIta declinano ogni responsabilità per usi impropri.

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
