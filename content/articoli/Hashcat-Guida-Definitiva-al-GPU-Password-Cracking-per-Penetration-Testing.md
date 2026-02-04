---
title: 'Hashcat: Guida Definitiva al GPU Password Cracking per Penetration Testing'
slug: hashcat
description: 'Hashcat: guida pratica GPU password cracking per hash NTLM, MD5, SHA, bcrypt. Attack modes, mask patterns, wordlist rules e tecniche reali da CTF e penetration testing.'
image: /Gemini_Generated_Image_mzi4bgmzi4bgmzi4.webp
draft: false
date: 2026-02-04T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - bcrypt
  - ntlm
  - hash
---

# Hashcat: Guida Definitiva al GPU Password Cracking per Penetration Testing

Hashcat è il motore di password cracking più veloce al mondo. Quando catturi un hash durante un pentest (magari con [Responder](https://hackita.it/articoli/responder)), Hashcat è il tool che lo trasforma in password in chiaro sfruttando la potenza della tua GPU.

Dimentica John the Ripper che impiega ore. Con Hashcat e una GPU decente cracchi milioni di password al secondo. In questa guida impari a usare Hashcat come un vero penetration tester: da zero a cracking di hash enterprise complessi con tecniche che funzionano su target reali.

## Setup Lab: Da Hardware a Cracking Operativo

### Requisiti Hardware

**GPU compatibili:**

* NVIDIA (CUDA): GTX 1060 o superiore (consigliato RTX 3060+)
* AMD (OpenCL): RX 580 o superiore (consigliato RX 6700+)
* Apple Silicon: M1/M2/M3 (via Metal, performance limitate)

**RAM minima:** 8GB (16GB consigliato per wordlist grandi)

**Storage:** 50GB+ liberi per wordlist e rainbow tables

### Installazione su Kali Linux

```bash
# Update sistema
sudo apt update && sudo apt upgrade -y

# Installa Hashcat
sudo apt install hashcat

# Verifica versione
hashcat --version
```

**Output:**

```
v6.2.6
```

### Installazione Driver GPU

**NVIDIA (critiche per performance):**

```bash
# Verifica GPU riconosciuta
lspci | grep -i nvidia

# Installa driver NVIDIA
sudo apt install nvidia-driver nvidia-cuda-toolkit

# Reboot
sudo reboot

# Verifica CUDA funzionante
nvidia-smi
```

**Output nvidia-smi:**

```
+-----------------------------------------------------------------------------+
| NVIDIA-SMI 525.147.05   Driver Version: 525.147.05   CUDA Version: 12.0     |
|-------------------------------+----------------------+----------------------+
| GPU  Name        Persistence-M| Bus-Id        Disp.A | Volatile Uncorr. ECC |
| Fan  Temp  Perf  Pwr:Usage/Cap|         Memory-Usage | GPU-Util  Compute M. |
|===============================+======================+======================|
|   0  NVIDIA GeForce ...  Off  | 00000000:01:00.0  On |                  N/A |
| 30%   45C    P8    15W / 170W |   1024MiB /  8192MiB |      0%      Default |
+-------------------------------+----------------------+----------------------+
```

**AMD:**

```bash
# Installa driver OpenCL
sudo apt install mesa-opencl-icd

# Verifica OpenCL
clinfo | grep "Device Name"
```

### Test Benchmark

Prima di craccare, testa performance GPU:

```bash
hashcat -b
```

**Output (esempio RTX 3060):**

```
Hashmode: 0 - MD5
Speed.#1.........:  8523.4 MH/s

Hashmode: 1000 - NTLM
Speed.#1.........:  15234.7 MH/s

Hashmode: 2500 - WPA-EAPOL-PBKDF2
Speed.#1.........:    12345 H/s

Hashmode: 3200 - bcrypt
Speed.#1.........:     5432 H/s
```

**Legenda velocità:**

* **MH/s** = Milioni hash/secondo (MD5, NTLM - veloci)
* **kH/s** = Migliaia hash/secondo (SHA256, SHA512 - medi)
* **H/s** = Hash/secondo (bcrypt, scrypt, Argon2 - lenti intenzionalmente)

Con RTX 3060 testi circa 15 miliardi di NTLM al secondo.

## Identificare Tipo di Hash

Prima di craccare devi sapere che tipo di hash hai. Hashcat supporta oltre 300 algoritmi.

### Hash Comuni Penetration Testing

| Hash Type | Hashcat Mode | Esempio                                                            | Uso Comune                                                      |
| --------- | ------------ | ------------------------------------------------------------------ | --------------------------------------------------------------- |
| MD5       | 0            | `5f4dcc3b5aa765d61d8327deb882cf99`                                 | Web apps legacy                                                 |
| NTLM      | 1000         | `8846f7eaee8fb117ad06bdd830b7586c`                                 | Windows (da [Responder](https://hackita.it/articoli/responder)) |
| NTLMv2    | 5600         | `admin::N46iSNekpT:08ca45b7d7ea58ee:...`                           | Windows challenge-response                                      |
| SHA1      | 100          | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8`                         | Git, legacy systems                                             |
| SHA256    | 1400         | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | Linux shadow modern                                             |
| bcrypt    | 3200         | `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy`     | Web apps secure                                                 |
| WPA2      | 22000        | `WPA*02*hash*BSSID*STATION*ESSID...`                               | WiFi handshake                                                  |

### Identificazione Automatica

**Usa `hashid` o `hash-identifier`:**

```bash
# Installa hashid
pip3 install hashid

# Identifica hash
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashid
```

**Output:**

```
Analyzing '5f4dcc3b5aa765d61d8327deb882cf99'
[+] MD5 
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Oppure usa tool online (ma attento a non uploadare hash di clienti reali):

* [https://hashes.com/en/tools/hash\_identifier](https://hashes.com/en/tools/hash_identifier)

## Attack Mode 0: Dictionary Attack

L'attacco più semplice: prova tutte le password in una wordlist.

### Wordlist Essenziali

**RockYou (must-have):**

```bash
# Già inclusa in Kali, compressa
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Dimensione: 133MB, 14.3 milioni password
wc -l /usr/share/wordlists/rockyou.txt
# Output: 14344392 /usr/share/wordlists/rockyou.txt
```

**SecLists:**

```bash
cd /opt
sudo git clone https://github.com/danielmiessler/SecLists.git
```

**CrackStation:**

```bash
wget https://crackstation.net/crackstation-human-only.txt.gz
gunzip crackstation-human-only.txt.gz
# 1.5GB, password più comuni
```

### Cracking Hash MD5 (Base)

**Scenario:** Hai dumpato database MySQL, password sono MD5.

```bash
# Hash MD5 di "password123"
echo -n "password123" | md5sum
# Output: 482c811da5d5b4bc6d497ffa98491e38

# Salva hash
echo "482c811da5d5b4bc6d497ffa98491e38" > hash.txt

# Cracka con RockYou
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Parametri:**

* `-m 0` = MD5 mode
* `-a 0` = Straight attack (dictionary)
* `hash.txt` = file con hash
* `rockyou.txt` = wordlist

**Output durante cracking:**

```
hashcat (v6.2.6) starting...

OpenCL API (OpenCL 3.0) - Platform #1 [NVIDIA]
======================================================
* Device #1: NVIDIA GeForce RTX 3060, 8192 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385

482c811da5d5b4bc6d497ffa98491e38:password123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Time.Started.....: Wed Feb  5 14:23:45 2025
Time.Estimated...: Wed Feb  5 14:23:46 2025 (1 sec)
Speed.#1.........:  8523.4 MH/s
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8523456/14344385 (59.42%)
```

**Craccato in 1 secondo!** Password trovata: `password123`

### Visualizzare Password Craccate

```bash
hashcat -m 0 hash.txt --show
```

**Output:**

```
482c811da5d5b4bc6d497ffa98491e38:password123
```

Se lavori in ambienti senza GPU o vuoi analizzare formati specifici in modalità CPU, puoi usare l’alternativa storica **John the Ripper**, approfondita in modo operativo qui:
👉 [https://hackita.it/articoli/john-the-ripper](https://hackita.it/articoli/john-the-ripper)

Hashcat resta superiore in termini di velocità grazie all’accelerazione GPU, ma conoscere entrambi i tool è fondamentale in un contesto di penetration testing reale.

### Cracking Hash NTLM (Windows)

**Scenario:** Catturato hash NTLM con [Responder](https://hackita.it/articoli/responder).

```bash
# Hash NTLM di "Summer2024!"
echo "8846f7eaee8fb117ad06bdd830b7586c" > ntlm.txt

# Cracka con wordlist italiana
hashcat -m 1000 -a 0 ntlm.txt /opt/SecLists/Passwords/italian.txt
```

**Performance NTLM:**
Con RTX 3060 → circa 15 GH/s → testa 15 miliardi password/secondo.

RockYou (14.3M password) viene esaurita in meno di 1 secondo.

### Cracking NTLMv2 (Challenge-Response)

Hash NTLMv2 catturati da Responder hanno formato diverso:

```bash
# Esempio hash NTLMv2
echo "admin::CORP:1122334455667788:8C5D91E2F42AB3C5:010100..." > ntlmv2.txt

# Cracka (più lento di NTLM semplice)
hashcat -m 5600 -a 0 ntlmv2.txt rockyou.txt
```

**Performance NTLMv2:**
RTX 3060 → circa 500 kH/s (500.000 hash/secondo)

Molto più lento perché include challenge-response. RockYou richiede circa 30 secondi.

## Attack Mode 3: Brute Force con Mask

Quando wordlist falliscono, usi mask attack: generi tutte le combinazioni possibili basate su pattern.

### Charset Predefiniti

| Charset           | Simbolo | Caratteri           | Esempio                           |
| ----------------- | ------- | ------------------- | --------------------------------- |
| Lowercase         | `?l`    | a-z                 | `?l?l?l?l` = aaaa, aaab, ... zzzz |
| Uppercase         | `?u`    | A-Z                 | `?u?u?u?u` = AAAA, AAAB, ... ZZZZ |
| Digits            | `?d`    | 0-9                 | `?d?d?d?d` = 0000, 0001, ... 9999 |
| Special           | `?s`    | !@#$%...            | `?s?s` = !!, !@, ...              |
| All lowercase+num | `?l?d`  | a-z0-9              | Combined                          |
| All printable     | `?a`    | a-zA-Z0-9 + special | Tutto                             |

### Pattern Password Comuni

**Password aziendali tipiche:**

```bash
# Estate2024!  (Stagione + Anno + !)
hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?l?l?d?d?d?d!

# Admin123
hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?l?d?d?d

# Welcome@2024
hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?l?l?l?s?d?d?d?d

# Password1! (comune)
hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?l?l?l?l?d!
```

### Incremento Automatico

Testa tutte le lunghezze da minimo a massimo:

```bash
# Password 6-8 caratteri lowercase+digits
hashcat -m 0 -a 3 hash.txt --increment --increment-min=6 --increment-max=8 ?l?l?l?l?l?l?l?l
```

**Esempio concreto - PIN 4 cifre:**

```bash
# Tutti i PIN da 0000 a 9999
hashcat -m 0 -a 3 hash.txt ?d?d?d?d
```

**Keyspace:** 10.000 combinazioni
**Tempo con RTX 3060:** \< 1 millisecondo (8.5 GH/s per MD5)

### Custom Charset

Definisci charset personalizzati:

```bash
# Solo vocali lowercase
hashcat -m 0 -a 3 hash.txt -1 aeiou ?1?1?1?1?1

# Hex characters (0-9a-f)
hashcat -m 0 -a 3 hash.txt -1 0123456789abcdef ?1?1?1?1?1?1?1?1
```

**Esempio pratico - Seriali software:**

```bash
# Formato: XXXX-XXXX (X = 0-9A-F)
hashcat -m 0 -a 3 hash.txt -1 ?u?d ?1?1?1?1-?1?1?1?1
```

### Mask File per Campagne Estese

Crea file con multipli mask:

```bash
nano masks.hcmask
```

**Contenuto:**

```
?d?d?d?d
?d?d?d?d?d
?d?d?d?d?d?d
?l?l?l?l?d?d
?l?l?l?l?d?d?d
?u?l?l?l?l?d?d
?u?l?l?l?l?d?d?d
?u?l?l?l?l?d?d?d!
?u?l?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?s?d?d?d?d
```

**Esecuzione:**

```bash
hashcat -m 1000 -a 3 hash.txt masks.hcmask
```

Hashcat prova tutti i mask in sequenza.

## Attack Mode 6: Hybrid Wordlist + Mask

Combina wordlist con mask: appende/prepende caratteri alle password esistenti.

### Hybrid Attack: Wordlist + Suffix

**Scenario:** Password aziendali = parola comune + anno.

```bash
# Appende anno 2020-2025
hashcat -m 1000 -a 6 hash.txt rockyou.txt ?d?d?d?d
```

**Cosa fa:**

* Legge `password` da rockyou.txt
* Genera: `password2020`, `password2021`, ..., `password9999`
* Legge `admin` da rockyou.txt
* Genera: `admin2020`, `admin2021`, ...

### Hybrid Attack: Prefix + Wordlist

```bash
# Prepende carattere speciale + digit
hashcat -m 1000 -a 7 hash.txt ?s?d rockyou.txt
```

**Genera:**

* `!1password`, `!2password`, ..., `!9password`
* `@1admin`, `@2admin`, ...

**Esempio reale - Policy "carattere speciale obbligatorio":**

Molte aziende forzano: "Almeno un carattere speciale". Utenti fanno semplicemente: `Password123!`

```bash
# Testa parole comuni + ! alla fine
hashcat -m 1000 -a 6 hash.txt common_passwords.txt !
```

## Rules: Mutazione Avanzata Wordlist

Le rules sono il segreto dei pro. Trasformano ogni password della wordlist in decine di varianti.

### Rule Base Predefinite

Hashcat include ruleset ottimizzati:

```bash
ls -lh /usr/share/hashcat/rules/
```

**Output:**

```
best64.rule           # 64 regole migliori (veloce)
d3ad0ne.rule          # 33k regole (medio)
dive.rule             # 100k regole (lento, completo)
InsidePro-PasswordsPro.rule  # 727M regole (massiccio)
```

### Applicare Rules

```bash
# RockYou + best64 rules
hashcat -m 1000 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Cosa fanno best64 rules:**

* `password` → `Password` (capitalize)
* `password` → `PASSWORD` (uppercase)
* `password` → `p@ssword` (leetspeak)
* `password` → `password123` (append digits)
* `password` → `drowssap` (reverse)
* `password` → `Password!` (capitalize + !)
* ... 58 varianti aggiuntive

**Effetto moltiplicatore:**
RockYou ha 14.3M password → con best64 diventa circa 915M combinazioni da testare.

### Combinare Multiple Rules

```bash
# Applica best64 + leetspeak + specifiche
hashcat -m 1000 -a 0 hash.txt rockyou.txt -r best64.rule -r leetspeak.rule
```

### Custom Rules

Crea `custom.rule`:

```bash
nano custom.rule
```

**Contenuto:**

```
# Append anno corrente
$2$0$2$4

# Capitalize first + append !
c$!

# Leetspeak common
sa4 se3 si1 so0

# Duplicate
d

# Reverse + append 123
r$1$2$3
```

**Sintassi rules:**

* `c` = Capitalize first
* `$X` = Append character X
* `^X` = Prepend character X
* `sXY` = Substitute X with Y
* `d` = Duplicate
* `r` = Reverse
* `T0` = Toggle case
* `[` / `]` = Rotate left/right

**Applica custom rule:**

```bash
hashcat -m 1000 -a 0 hash.txt wordlist.txt -r custom.rule
```

## Cracking Hash Complessi: bcrypt, SHA512crypt

### bcrypt (Lentissimo per Design)

bcrypt è progettato per essere lento (anti-bruteforce). Usa cost factor (work factor).

**Esempio hash bcrypt:**

```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```

**Struttura:**

* `$2a$` = Algoritmo bcrypt
* `10` = Cost factor (2^10 = 1024 iterazioni)
* `N9qo8uLOickgx2ZMRZoMye` = Salt
* `IjZAgcfl7p92ldGxad68LJZdL17lhWy` = Hash

**Cracking:**

```bash
hashcat -m 3200 -a 0 bcrypt.txt rockyou.txt
```

**Performance bcrypt (cost 10):**
RTX 3060 → circa 5.4 kH/s (5.400 hash/secondo)

**Tempo per RockYou:** 14.3M password / 5.4k/s = circa 44 minuti

Per cost factor 12 (4x più lento): circa 3 ore

**Workaround per bcrypt:**

* Usa wordlist piccole e mirate
* Applica solo rule essenziali
* Considera solo password probabili (no brute force completo)

### SHA512crypt (Linux Shadow)

```bash
# Hash da /etc/shadow Linux
echo '$6$rounds=5000$salt$hash...' > shadow.txt

hashcat -m 1800 -a 0 shadow.txt rockyou.txt
```

**Performance SHA512crypt:**
RTX 3060 → circa 120 kH/s

Più veloce di bcrypt ma più lento di NTLM.

## Ottimizzazione Performance

### Workload Tuning

```bash
# Performance massima (può bloccare GUI)
hashcat -m 1000 -a 0 hash.txt rockyou.txt -w 4

# Performance bilanciata (default)
hashcat -m 1000 -a 0 hash.txt rockyou.txt -w 3

# Performance bassa (sistema usabile)
hashcat -m 1000 -a 0 hash.txt rockyou.txt -w 2
```

**Workload levels:**

* `-w 1` = Low (PC usabile, GPU al 20%)
* `-w 2` = Default (PC usabile, GPU al 50%)
* `-w 3` = High (GUI lag, GPU al 90%)
* `-w 4` = Nightmare (sistema freezato, GPU al 100%)

### Ottimizzatore Kernel

```bash
# Auto-tune kernel (consigliato)
hashcat -m 1000 -a 0 hash.txt rockyou.txt -O
```

Flag `-O` abilita kernel ottimizzati specifici per password corte (≤32 char). Aumenta velocità del 20-40% tipicamente.

### Multiple GPU

```bash
# Usa solo GPU 1 e 2
hashcat -m 1000 -a 0 hash.txt rockyou.txt -d 1,2

# Info su GPU disponibili
hashcat -I
```

**Output `-I`:**

```
OpenCL Info:
============

Platform ID #1
  Vendor  : NVIDIA Corporation
  Name    : NVIDIA CUDA
  Device ID #1
    Name             : NVIDIA GeForce RTX 3060
    Compute capability: 8.6
    
Platform ID #2
  Vendor  : AMD
  Name    : AMD Accelerated Parallel Processing
  Device ID #2
    Name             : AMD Radeon RX 6700
```

Usa entrambe:

```bash
hashcat -m 1000 hash.txt rockyou.txt -d 1,2
```

Performance si somma: RTX 3060 (15 GH/s) + RX 6700 (12 GH/s) = 27 GH/s totali.

## Sessioni e Restore

### Save/Restore Session

Hashcat può essere interrotto e ripreso:

```bash
# Avvia con session name
hashcat -m 1000 -a 3 hash.txt ?a?a?a?a?a?a?a --session=mycrack

# Durante esecuzione, premi 'q' per quit (salva stato)

# Riprendi session
hashcat --session=mycrack --restore
```

### Checkpoint Automatico

Hashcat salva automaticamente stato ogni 10 secondi in:

```
~/.hashcat/sessions/mycrack.restore
```

Se crash sistema/GPU, puoi riprendere esattamente da dove era arrivato.

### Monitor Progress

Durante esecuzione, premi:

* `s` = Status (mostra progress)
* `p` = Pause
* `r` = Resume
* `b` = Bypass current word (debug)
* `q` = Quit (salva e esci)

**Output status (premi 's'):**

```
Session..........: hashcat
Status...........: Running
Hash.Mode........: 1000 (NTLM)
Time.Started.....: Wed Feb  5 15:30:22 2025
Time.Estimated...: Wed Feb  5 15:45:12 2025 (14 mins, 50 secs)
Guess.Base.......: File (rockyou.txt)
Speed.#1.........:  15234.7 MH/s
Recovered........: 3/10 (30.00%)
Progress.........: 5234567890/14344385000 (36.47%)
Rejected.........: 12345/5234567890 (0.00%)
Restore.Point....: 5234560000/14344385000
```

## Hash più comuni nel Penetration Testing — Tabella Top 30

Questa tabella presenta i 30 hash più rilevanti che incontrerai durante attività di penetration testing reali. Basata sulla documentazione ufficiale disponibile su [https://hashcat.net/wiki/doku.php?id=example\_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) e sull'esperienza pratica in engagement enterprise.

| Mode  | Algoritmo/Tipo                        | Esempio Hash                               | Dove si trova                             | Sicurezza |
| ----- | ------------------------------------- | ------------------------------------------ | ----------------------------------------- | --------- |
| 0     | MD5                                   | `5f4dcc3b5aa765d61d8327deb882cf99`         | Database web app legacy, phpBB, vBulletin | Debole    |
| 100   | SHA1                                  | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | Git commits, legacy systems               | Debole    |
| 1000  | NTLM                                  | `b4b9b02e6f09a9bd760f388b67351e2b`         | Windows SAM, Active Directory             | Debole    |
| 1100  | Domain Cached Credentials (DCC)       | `4dd8965d1d476fa0d84ffea16e96b7...`        | Windows cached credentials                | Medio     |
| 1400  | SHA256                                | `5e884898da28047151d0e56f8dc6292...`       | Linux /etc/shadow moderno                 | Medio     |
| 1700  | SHA512                                | `b109f3bbbc244eb82441917ed06d618...`       | Linux /etc/shadow enterprise              | Medio     |
| 1800  | sha512crypt $6$, SHA512(Unix)         | `$6$rounds=5000$salt$hash...`              | Linux/Unix shadow file                    | Forte     |
| 2500  | WPA-EAPOL-PBKDF2                      | `hash$bssid$station$essid...`              | WiFi WPA/WPA2 handshake (legacy)          | Medio     |
| 3200  | bcrypt $2\*$, Blowfish(Unix)          | `$2a$10$N9qo8uLOickgx2ZMRZoMy...`          | Web apps moderne (Laravel, Django)        | Forte     |
| 5500  | NetNTLMv1 / NetNTLMv1+ESS             | `u4-netntlm::kNS:338d08f8e26...`           | Windows NTLM auth legacy                  | Debole    |
| 5600  | NetNTLMv2                             | `admin::N46iSNekpT:08ca45b7d7...`          | Windows NTLM auth, Responder captures     | Medio     |
| 13100 | Kerberos 5 TGS-REP etype 23           | `$krb5tgs$23$*user$realm$...`              | Kerberoasting attacks AD                  | Medio     |
| 18200 | Kerberos 5 AS-REP etype 23            | `$krb5asrep$23$user@domain...`             | AS-REP roasting attacks AD                | Medio     |
| 16800 | WPA-PMKID-PBKDF2                      | `hash*bssid*station*essid`                 | WiFi WPA/WPA2 clientless attack           | Medio     |
| 22000 | WPA-PBKDF2-PMKID+EAPOL                | `WPA*02*hash*mac*mac*essid...`             | WiFi WPA/WPA2/WPA3 (formato nuovo)        | Medio     |
| 7500  | Kerberos 5 AS-REQ Pre-Auth            | `$krb5pa$23$user$realm$...`                | Kerberos pre-auth                         | Medio     |
| 13400 | KeePass 1/2 AES                       | `$keepass$*2*60000*...`                    | KeePass database files                    | Forte     |
| 11300 | Bitcoin/Litecoin wallet.dat           | `$bitcoin$96$hash...`                      | Crypto wallets                            | Forte     |
| 15700 | Ethereum Wallet, PBKDF2-HMAC-SHA256   | `$ethereum$p*262144*...`                   | Ethereum keystore                         | Forte     |
| 1500  | descrypt, DES(Unix), Traditional DES  | `48c/R8JAv757A`                            | Legacy Unix systems                       | Debole    |
| 3000  | LM                                    | `299BD128C1101FD6`                         | Windows legacy (pre-Vista)                | Debole    |
| 400   | phpass, WordPress (MD5), phpBB3 (MD5) | `$P$9IQRaTwmfeRo7u...`                     | WordPress, Joomla, phpBB                  | Medio     |
| 2611  | vBulletin \< v3.8.5                   | `bf366348c53ddcfbd16e63edfdd1eee6:48`      | vBulletin forum                           | Debole    |
| 121   | SMF (Simple Machines Forum) > v1.1    | `sha1:a94c0...`                            | SMF forums                                | Debole    |
| 124   | Django (SHA-1)                        | `sha1$salt$hash`                           | Django web framework                      | Medio     |
| 10000 | Django (PBKDF2-SHA256)                | `pbkdf2_sha256$120000$salt...`             | Django moderno                            | Forte     |
| 16100 | TACACS+                               | `$tacacs-plus$0$hash...`                   | Cisco TACACS+ auth                        | Medio     |
| 8900  | scrypt                                | `SCRYPT:1024:1:1:salt:hash`                | Litecoin, Tarsnap                         | Forte     |
| 11600 | 7-Zip                                 | `$7z$0$19$0$salt...`                       | 7-Zip archives encrypted                  | Medio     |
| 9700  | MS Office ≤ 2003 $0/$1, MD5 + RC4     | `$oldoffice$0$hash...`                     | Office doc legacy                         | Debole    |

**Note:**

* **Debole**: Veloce da craccare con GPU moderne (MD5, SHA1, NTLM, LM)
* **Medio**: Richiede wordlist buone o pattern specifici (NetNTLMv2, WPA2, phpass)
* **Forte**: Lento per design, richiede password deboli o wordlist mirate (bcrypt, scrypt, Argon2)

## Tecniche Avanzate CTF

### Hash Salted

Hash con salt richiedono formato specifico:

```bash
# MD5 salted: hash:salt
echo "5f4dcc3b5aa765d61d8327deb882cf99:randomsalt" > salted.txt

# Mode 10 = md5($pass.$salt)
hashcat -m 10 -a 0 salted.txt rockyou.txt

# Mode 20 = md5($salt.$pass)
hashcat -m 20 -a 0 salted.txt rockyou.txt
```

**Verifica mode corretto con:**

```bash
hashcat --example-hashes | grep -i "md5.*salt" -A 5
```

### Combinator Attack

Combina due wordlist:

```bash
# Crea firstname.txt
echo -e "john\nmary\ndavid" > first.txt

# Crea lastname.txt
echo -e "smith\njones\nbrown" > last.txt

# Combina
hashcat -m 0 -a 1 hash.txt first.txt last.txt
```

**Genera:**

* johnsmith, johnjones, johnbrown
* marysmith, maryjones, marybrown
* davidsmith, davidjones, davidbrown

**Uso reale:** Password = nome + cognome (comune in aziende).

## Scenari Pratici Penetration Testing

### Scenario 1: Hash da Database Dumpato

**Situazione:** SQL injection su web app, dumpato users table.

```sql
SELECT username, password FROM users;
```

**Output:**

```
admin, 5f4dcc3b5aa765d61d8327deb882cf99
john, 482c811da5d5b4bc6d497ffa98491e38
mary, e10adc3949ba59abbe56e057f20f883e
```

**Identifica hash:**

```bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashid
# MD5
```

**Cracka tutti:**

```bash
# Crea file hash
cat > hashes.txt << EOF
5f4dcc3b5aa765d61d8327deb882cf99
482c811da5d5b4bc6d497ffa98491e38
e10adc3949ba59abbe56e057f20f883e
EOF

# Cracking con RockYou
hashcat -m 0 -a 0 hashes.txt rockyou.txt -o cracked.txt
```

**Risultato:**

```bash
cat cracked.txt
5f4dcc3b5aa765d61d8327deb882cf99:password
482c811da5d5b4bc6d497ffa98491e38:password123
e10adc3949ba59abbe56e057f20f883e:123456
```

**Credential spray su web app:**

```
admin:password
john:password123
mary:123456
```

### Scenario 2: NTLM da Responder

**Catturato con [Responder](https://hackita.it/articoli/responder):**

```bash
cat /opt/Responder/logs/SMB-NTLMv2-SSP-192.168.1.50.txt
```

**Hash NTLMv2:**

```
john.doe::CORP:1122334455667788:A4F2E8C9D1B6A3F7:01010000000000008B2...
```

**Cracking:**

```bash
hashcat -m 5600 -a 0 ntlmv2.txt rockyou.txt -w 4 -O
```

**Se fallisce wordlist, prova mask aziendale:**

```bash
# Password policy: Stagione + Anno + carattere speciale
hashcat -m 5600 -a 3 ntlmv2.txt ?u?l?l?l?l?l?d?d?d?d?s
```

**Genera:** Spring2024!, Summer2024!, Winter2024!, etc.

### Scenario 3: WiFi WPA2 Handshake

**Catturato handshake con aircrack-ng:**

```bash
# Converti .cap in formato hashcat
hcxpcapngtool -o hash.hc22000 capture.cap

# Cracka WPA2 (mode 22000)
hashcat -m 22000 -a 0 hash.hc22000 rockyou.txt
```

**WPA2 è lento (PBKDF2):**
RTX 3060 → circa 120 kH/s

RockYou richiede circa 30 minuti.

**Ottimizzazione con wordlist WiFi-specifica:**

```bash
wget https://github.com/kennyn510/wpa2-wordlists/raw/master/Wordlists/wifi.txt
hashcat -m 22000 -a 0 hash.hc22000 wifi.txt
```

Password WiFi comuni: nome router + anno, indirizzo via, numero telefono.

## Integrazione con Altri Tool

### John the Ripper → Hashcat

John usa formato proprio. Converti:

```bash
# Hash craccato da John
john shadow.txt --format=sha512crypt

# Mostra in formato Hashcat
john shadow.txt --show
```

Copia hash e usa con Hashcat per GPU acceleration.

### Hashcat → Password Spray

**Dopo cracking, usa password per spray:**

```bash
# Craccati 50 NTLM hash, ottieni 30 password
hashcat -m 1000 hashes.txt rockyou.txt --show > cracked.txt

# Estrai solo password
cut -d: -f2 cracked.txt > passwords.txt

# Spray con [SMBClient](https://hackita.it/articoli/smbclient)
for pwd in $(cat passwords.txt); do
    smbclient -L //target -U admin%$pwd
done
```

### Export Potfile

Hashcat mantiene database di hash craccati:

```bash
cat ~/.hashcat/hashcat.potfile
```

**Output:**

```
5f4dcc3b5aa765d61d8327deb882cf99:password
8846f7eaee8fb117ad06bdd830b7586c:Summer2024!
482c811da5d5b4bc6d497ffa98491e38:password123
```

Utile per campagne multi-target: se hash già craccato in passato, Hashcat lo riconosce istantaneamente.

## Troubleshooting Comune

### "No hashes loaded" - Formato Hash Sbagliato

**Errore:**

```
No hashes loaded
```

**Causa:** Hash format non matcha mode.

**Fix:**

```bash
# Identifica hash corretto
hashcat --example-hashes | grep -i ntlm

# Verifica formato richiesto
hashcat -m 1000 --example-hashes
```

**Hash NTLM deve essere:** 32 caratteri hex, no spazi, no prefissi.

**Corretto:**

```
8846f7eaee8fb117ad06bdd830b7586c
```

**Errato:**

```
NTLM:8846f7eaee8fb117ad06bdd830b7586c    # ha prefisso
8846f7ee e8fb117 ad06bdd830b7586c        # ha spazi
```

### GPU Non Riconosciuta

**Errore:**

```
No devices found/left
```

**Fix NVIDIA:**

```bash
# Reinstalla driver
sudo apt purge nvidia-*
sudo apt autoremove
sudo apt install nvidia-driver-525 nvidia-cuda-toolkit
sudo reboot

# Verifica
nvidia-smi
```

**Fix AMD:**

```bash
# Installa ROCm
sudo apt install rocm-opencl-runtime
sudo usermod -a -G video $USER
sudo reboot
```

### Kernel Timeout / Watchdog

**Errore:**

```
Watchdog: Temperature abort trigger set to 90c
```

**Cause:**

* GPU overheating
* Overclock instabile
* PSU insufficiente

**Fix:**

```bash
# Limita workload
hashcat -m 1000 hash.txt wordlist.txt -w 2

# Limita kernel runtime
hashcat -m 1000 hash.txt wordlist.txt --kernel-accel=1 --kernel-loops=64
```

### Out of Memory

**Errore:**

```
CUDA error: out of memory
```

**Fix:**

```bash
# Riduci dimensione wordlist
head -n 1000000 rockyou.txt > small_rockyou.txt

# Oppure split e cracka a chunks
split -l 1000000 rockyou.txt chunk_
for file in chunk_*; do
    hashcat -m 0 hash.txt $file
done
```

## Tabella Comparative Performance

### Hash Speed per GPU (Hashcat Benchmark)

| Hash Type        | RTX 3060 | RTX 4090 | RX 6700 XT | M1 Max   | Metodo Difesa   |
| ---------------- | -------- | -------- | ---------- | -------- | --------------- |
| MD5              | 8.5 GH/s | 25 GH/s  | 7.2 GH/s   | 2.1 GH/s | Non usare       |
| SHA1             | 3.2 GH/s | 9.5 GH/s | 2.8 GH/s   | 1.2 GH/s | Non usare       |
| SHA256           | 1.2 GH/s | 3.8 GH/s | 1.1 GH/s   | 450 MH/s | Non usare       |
| NTLM             | 15 GH/s  | 45 GH/s  | 12 GH/s    | 4.5 GH/s | Non usare       |
| NTLMv2           | 500 kH/s | 1.5 MH/s | 420 kH/s   | 180 kH/s | SMB Signing     |
| bcrypt (cost 10) | 5.4 kH/s | 15 kH/s  | 4.8 kH/s   | 2.1 kH/s | ✓ Sicuro        |
| WPA2             | 120 kH/s | 350 kH/s | 110 kH/s   | 45 kH/s  | Password lunga  |
| scrypt           | 150 H/s  | 450 H/s  | 130 H/s    | 60 H/s   | ✓ Sicuro        |
| Argon2           | 80 H/s   | 220 H/s  | 70 H/s     | 35 H/s   | ✓✓ Molto sicuro |

**Legenda:**

* GH/s = Giga hash/secondo (miliardi)
* MH/s = Mega hash/secondo (milioni)
* kH/s = Kilo hash/secondo (migliaia)
* H/s = Hash/secondo

### Tempo Cracking RockYou (14.3M password)

| Hash Type   | RTX 3060 | RTX 4090 | Raccomandazione Dev    |
| ----------- | -------- | -------- | ---------------------- |
| MD5         | \< 1 sec | \< 1 sec | ❌ Mai usare            |
| NTLM        | \< 1 sec | \< 1 sec | ❌ Mai usare            |
| SHA256      | \~10 sec | \~3 sec  | ❌ Mai usare            |
| bcrypt (10) | \~44 min | \~16 min | ✓ OK (cost 12+ meglio) |
| bcrypt (12) | \~3 ore  | \~1 ora  | ✓✓ Buono               |
| Argon2id    | \~50 ore | \~18 ore | ✓✓✓ Eccellente         |

## Checklist Operational

**Pre-Cracking:**

* Hash identificato correttamente (hashid)
* Mode Hashcat verificato (`--example-hashes`)
* GPU funzionante (nvidia-smi / clinfo)
* Wordlist scaricate (RockYou, SecLists)
* Spazio disco sufficiente (>50GB per wordlist grandi)

**During Cracking:**

* Session salvata (`--session=name`)
* Workload ottimizzato (`-w 3` o `-w 4`)
* Kernel optimized abilitato (`-O`)
* Temperatura GPU monitorata (\< 85°C)
* Progress verificato periodicamente (premi `s`)

**Post-Cracking:**

* Password visualizzate (`--show`)
* Output salvato (`-o cracked.txt`)
* Potfile backuppato (`~/.hashcat/hashcat.potfile`)
* Password testate su target reale
* Documentato per report cliente

**Best Practices:**

* Sempre inizia con wordlist prima di brute force
* Usa rule solo dopo wordlist base fallisce
* Mask attack solo se conosci pattern password
* Backup session ogni giorno per campagne lunghe
* Non condividere hash clienti con servizi online

## FAQ Tecniche Hashcat

**Quanto tempo serve per craccare password 8 caratteri random?**

Dipende dal charset:

* Solo lowercase (26^8): RTX 3060 → \~5 minuti (MD5)
* Lowercase + digits (36^8): RTX 3060 → \~45 minuti (MD5)
* Alphanumerico misto (62^8): RTX 3060 → \~15 ore (MD5)
* Full ASCII (95^8): RTX 3060 → impraticabile (anni)

Per NTLM (più veloce): dividi tempi per 2.
Per bcrypt: impossibile brute force completo.

**Hashcat funziona senza GPU?**

Sì, ma estremamente lento. CPU mode:

```bash
hashcat -m 1000 hash.txt rockyou.txt --force
```

CPU Intel i7: \~200 MH/s MD5 vs GPU RTX 3060: 8.500 MH/s → 42x più lento.

**Posso craccare hash senza salt se applicazione usa salt?**

No. Se applicazione fa `hash(password + salt)`, devi fornire salt:

```bash
# Formato hash:salt
echo "5f4dcc3b5aa765d61d8327deb882cf99:randomsalt123" > hash.txt
hashcat -m 10 hash.txt wordlist.txt
```

Senza salt corretto, hash non matcherà mai.

**Conviene comprare RTX 4090 per cracking?**

Dipende da uso:

* Occasional (CTF, pentest sporadici): No, RTX 3060 sufficiente
* Professional (pentest mensili): Sì, ROI in tempo risparmiato
* Full-time red team: Assolutamente, considera multi-GPU rig

**Come craccare 1000 hash contemporaneamente?**

Hashcat gestisce automaticamente:

```bash
# File con 1000 hash (uno per riga)
hashcat -m 1000 1000_hashes.txt rockyou.txt
```

Performance identica a singolo hash. Hashcat ottimizza in automatico.

**Password "Tr0ub4dor&3" è sicura?**

Contro dizionario: Sì (parola inventata, leetspeak)
Contro brute force: Relativamente (14 char, mixed case+special+digits)
Contro targeted attack: Dipende

Meglio passphrase: `correct horse battery staple` (più lunga, più sicura).

**Hashcat può craccare hash senza conoscere algoritmo?**

No. Devi specificare mode corretto. Usa `hashid` per identificazione automatica, poi verifica mode manualmente:

```bash
hashid hash.txt
hashcat --help | grep -i "algoritmo_identificato"
```

***

**Link Utili:**

* [Hashcat GitHub](https://github.com/hashcat/hashcat)
* [Hashcat Wiki](https://hashcat.net/wiki/)
* [Responder per Hash Capture](https://hackita.it/articoli/responder)
* [SMBClient per SMB Auth](https://hackita.it/articoli/smbclient)

**Disclaimer Legale:** Hashcat è tool legale per recupero password proprie, penetration testing autorizzato e ricerca sicurezza. L'utilizzo per craccare password di terzi senza esplicito consenso scritto costituisce reato penale. Usa solo su hash di tua proprietà o in contesto di security assessment formalmente autorizzato.
