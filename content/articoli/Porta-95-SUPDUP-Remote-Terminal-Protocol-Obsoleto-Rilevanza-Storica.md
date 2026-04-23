---
title: 'Porta 95 SUPDUP: Remote Terminal Protocol Obsoleto (Rilevanza Storica'
slug: porta-95-supdup
description: >-
  Porta 95 aperta durante una scansione? SUPDUP è defunto dagli anni '90. Scopri
  come identificare il servizio reale: web server nascosto, app custom o
  honeypot.
image: /porta-95-supdup.webp
draft: false
date: 2026-04-24T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - supdup
---

La porta 95 era utilizzata da **SUPDUP** (SUPer-DUPlicate) — un protocollo di remote terminal sviluppato al MIT negli anni '70 come predecessore di Telnet, specificamente progettato per terminali DEC (Digital Equipment Corporation) e ITS (Incompatible Timesharing System). SUPDUP operava su TCP porta 95 fornendo accesso remote shell a mainframe PDP-10 e LISP machines. In penetration testing moderno, la porta 95 è **completamente obsoleta** — nessun sistema operativo moderno implementa SUPDUP, l'ultimo server attivo risale agli anni '90, e trovarla aperta nel 2026 è impossibile outside simulazioni storiche o honeypot. Questa guida documenta SUPDUP per context storico e per distinguere porta 95 da servizi modern se erroneamente identificata.

SUPDUP è defunto perché Telnet (porta 23) lo ha completamente sostituito entro 1985, e Telnet stesso è stato sostituito da SSH (porta 22) entro 2000. Nel 2026, porta 95 aperta indica **non-SUPDUP** — custom service, misconfiguration, o scanning artifact.

***

## Anatomia tecnica di SUPDUP (1974-1990)

SUPDUP usava **TCP porta 95** con protocollo testuale command-based simile a Telnet ma ottimizzato per DEC terminals.

**Flow SUPDUP (storico):**

1. **TCP Connect** — Client connette porta 95 del ITS server
2. **Terminal Negotiation** — Client invia terminal type (TECO, EMACS)
3. **Authentication** — Username/password plaintext (no encryption)
4. **Shell Access** — Access a LISP REPL o Unix-like shell su PDP-10
5. **Session** — Remote terminal interaction

**SUPDUP vs Telnet:**

| Feature               | SUPDUP (1974)           | Telnet (1969)                 |
| --------------------- | ----------------------- | ----------------------------- |
| Porta                 | 95                      | 23                            |
| Target systems        | PDP-10, ITS             | Universal                     |
| Terminal optimization | ✅ DEC-specific          | ❌ Generic                     |
| Encryption            | ❌ None                  | ❌ None                        |
| Adoption              | Limited (MIT, Stanford) | Universal                     |
| Status 2026           | Defunto                 | Deprecato (sostituito da SSH) |

**Perché SUPDUP è morto:**

1. **Limited adoption** — Solo MIT AI Lab, Stanford AI Lab
2. **Telnet dominance** — RFC 854 (1983) standardizzò Telnet universalmente
3. **Hardware obsolescence** — PDP-10 discontinuato 1983
4. **SSH emergence** — SSH (1995) rese sia SUPDUP che Telnet obsoleti 

Leggi anche il nostro articolo su [telnet](https://hackita.it/articoli/telnet/). 

***

## Enumerazione (nel 2026)

```bash
nmap -sV -p 95 10.10.10.95
```

**Output se porta aperta (unlikely):**

```
PORT   STATE SERVICE VERSION
95/tcp open  supdup?
```

**Test manuale:**

```bash
telnet 10.10.10.95 95
```

Se nessuna connessione → porta closed (expected).\
Se connessione aperta ma no response → likely custom service on port 95, not SUPDUP.

***

## Contesto penetration testing

**Porta 95 aperta nel 2026 = 100% custom service o misconfiguration.**

### Scenario 1: Historical simulation (museum/academia)

Alcuni computer science museums o academic projects mantengono PDP-10 emulators con SUPDUP per scopo educational.

```bash
# Connect to historical emulator
telnet pdp10-emulator.university.edu 95
```

**Security note:** Se esiste, treat come [Telnet](https://hackita.it/articoli/telnet) (credentials plaintext, no encryption).

### Scenario 2: Custom application su porta 95

Applicazioni custom potrebbero usare porta 95 (port squatting).

```bash
# Banner grab
nc -vn 10.10.10.95 95
# Analyze response per identify real service
```

Se risponde HTTP-like → apply [HTTP exploitation](https://hackita.it/articoli/http).\
Se binary protocol → reverse engineer o skip (custom protocol).

### Scenario 3: Honeypot

Porta 95 insolita attiva può essere honeypot (log attacker activity).

```bash
# Test connectivity
nc 10.10.10.95 95
# Monitor per IP ban (honeypot detection)
```

***

## Exploit teorico (se SUPDUP esistesse)

**SUPDUP aveva vulnerabilities identiche a Telnet:**

1. **No encryption** — Credentials in plaintext
2. **Packet sniffing** — Wireshark capture username/password
3. **Brute force** — No rate limiting (1970s security)
4. **Default credentials** — `guest:guest`, `demo:demo`

**Exploitation (teorico):**

```bash
# Packet capture
tcpdump -i eth0 port 95 -w supdup.pcap

# Brute force (se server esistesse)
hydra -l admin -P passwords.txt supdup://10.10.10.95
```

Ma nel 2026, **nessun server SUPDUP esiste** → exploitation è puramente accademico.

***

## Raccomandazioni per pentester

**Se trovi porta 95 aperta (raro):**

1. **Assume custom service** — Non SUPDUP
2. **Banner grab** → identify real application
3. **Version detection** → `nmap --version-intensity 9`
4. **Document anomaly** → Insolito = security concern

**Non spendere tempo su porta 95** — priority basse, likely false positive.

***

## Hardening

**Porta 95 NON dovrebbe essere aperta.**

```bash
# Block port 95 (firewall)
iptables -A INPUT -p tcp --dport 95 -j DROP
```

Se hai legacy system requirement → **isolate on VLAN** e **VPN-only access**.

***

## Cheat sheet

| Azione            | Comando                   |
| ----------------- | ------------------------- |
| Scan port 95      | `nmap -sV -p 95 <target>` |
| Test connectivity | `telnet <target> 95`      |
| Banner grab       | `nc -vn <target> 95`      |

***

## FAQ

**SUPDUP è usato nel 2026?**

No. Defunto dagli anni '90. Porta 95 aperta = custom service, non SUPDUP.

**SUPDUP è più sicuro di Telnet?**

No. Identical security (plaintext, no encryption). SSH è l'unico modern alternative sicuro.

**Devo testare porta 95 in pentest?**

Low priority. Se aperta, investigate brevemente ma non aspettarti SUPDUP.

***

> **Disclaimer:** SUPDUP è puramente storico. Porta 95 nel 2026 non è SUPDUP. L'autore e HackIta declinano responsabilità.

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto).
