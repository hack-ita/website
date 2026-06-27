---
title: 'John the Ripper: Guida Completa al Password Cracking'
slug: john-the-ripper
description: >-
  Guida completa a John the Ripper (Jumbo): estrai hash da ZIP, SSH, KeePass,
  PDF, Office con *2john; crack con wordlist e regole. Confronto con hashcat e
  cheat sheet finale.
image: /john-the-ripper-password-cracking.webp
draft: false
date: 2026-06-01T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - password-cracking
  - zip2john
  - ssh2john
  - keepass2john
  - jumbo
  - bcrypt
---

# Come Crackare Password con John the Ripper: Guida Completa Hash e Wordlist

Hai trovato un file `.kdbx`, una chiave SSH protetta da passphrase, un archivio ZIP cifrato, o un disco BitLocker? **John the Ripper** (JtR) è il password cracker offline più flessibile in circolazione: auto-rileva il formato dell'hash, supporta 470+ tipi nella versione Jumbo, e include una famiglia di script `*2john` che estraggono hash craccabili da qualsiasi file cifrato — ZIP, SSH, KeePass, BitLocker, Office, WPA — per poi craccarli offline con una wordlist. Dove [hashcat](https://hackita.it/articoli/hashcat/) vince in velocità GPU su hash comuni, John vince in copertura di formati: quando trovi un file strano in un backup, John è spesso l'unica strada praticabile.

**Cosa imparerai:**

* Come identificare il formato di un hash e specificarlo esplicitamente
* Tutti i modi di cracking: wordlist, single crack, incremental, mask
* Come usare `--rules` per moltiplicare la potenza della wordlist
* Come usare i tool `*2john` per crackare ZIP, SSH, KeePass, PDF, Office
* La differenza operativa tra John e hashcat e quando usare quale

**Prerequisiti:** hash catturati durante post-exploitation (con [credential dumping](https://hackita.it/articoli/credential-dumping/)) e una wordlist come rockyou o [SecLists](https://hackita.it/articoli/wordlist/).

***

## John vs Hashcat – Quando usare quale

|                        | **John the Ripper**                      | **[Hashcat](https://hackita.it/articoli/hashcat/)** |
| ---------------------- | ---------------------------------------- | --------------------------------------------------- |
| **Velocità**           | CPU (lento su hash veloci)               | GPU (10-1000× più veloce)                           |
| **Formati supportati** | 470+ (Jumbo)                             | \~400 (ma i più comuni)                             |
| **Auto-detection**     | ✅ automatica                             | ❌ devi specificare `-m N`                           |
| **File extraction**    | ✅ \*2john scripts (ZIP, SSH, KeePass...) | ❌ devi estrarre manualmente                         |
| **Regole mangling**    | ✅ Jumbo, KoreLogic, custom               | ✅ rule files                                        |
| **GPU support**        | ✅ limitato (OpenCL)                      | ✅ nativo, ottimizzato                               |
| **Formati strani**     | ✅ (Lotus Notes, Mac keychain, vecchi DB) | ❌ spesso non supporta                               |

**In pratica:** quando hai NTLM o NTLMv2 e una GPU, usa hashcat. Quando trovi un `.zip`, `.kdbx`, chiave SSH con passphrase o un hash che hashcat non riconosce, usa John. Nella realtà un pentester installa entrambi.

***

## Installazione – Usa sempre Jumbo

La versione stock supporta \~12 formati. La versione **Jumbo** ne supporta 470+. Su Kali e Parrot, `apt install john` installa già la versione Jumbo.

```bash
# Kali / Parrot (già Jumbo)
sudo apt install john -y

# Verifica che sia Jumbo
john --list=build-info | head -3
```

```text
John the Ripper 1.9.0-jumbo-1 (linux-gnu 64-bit, OpenMP)
Build: linux-gnu 64-bit, OpenMP
```

Se non vedi "jumbo", compila da source:

```bash
git clone https://github.com/openwall/john.git
cd john/src && ./configure && make -sj4
# Binario in: ../run/john
```

***

## 1. Identificazione Hash e Formato Esplicito

John auto-rileva il formato, ma a volte sbaglia (es: Raw-MD5 confuso con LM). Specifica sempre `--format` per sicurezza.

**Formati più comuni in pentesting:**

| Hash tipo              | Esempio                                    | Flag John              |
| ---------------------- | ------------------------------------------ | ---------------------- |
| NTLM (Windows)         | `8846F7EAEE8FB117AD06BDD830B7586C`         | `--format=nt`          |
| NTLMv2 (Responder)     | `user::DOMAIN:challenge:hash`              | `--format=netntlmv2`   |
| MD5 raw                | `5f4dcc3b5aa765d61d8327deb882cf99`         | `--format=raw-md5`     |
| SHA-1 raw              | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | `--format=raw-sha1`    |
| SHA-256 raw            | `5e884898da28047...`                       | `--format=raw-sha256`  |
| Linux shadow SHA-512   | `$6$salt$hash...`                          | `--format=sha512crypt` |
| Linux shadow MD5       | `$1$salt$hash...`                          | `--format=md5crypt`    |
| bcrypt                 | `$2a$12$...`                               | `--format=bcrypt`      |
| SSH key passphrase     | estratto con ssh2john                      | `--format=ssh`         |
| ZIP classic            | estratto con zip2john                      | `--format=pkzip`       |
| ZIP AES (WinZip)       | estratto con zip2john                      | `--format=zip`         |
| KeePass                | estratto con keepass2john                  | `--format=keepass`     |
| PDF                    | estratto con pdf2john                      | `--format=pdf`         |
| Kerberos TGS (TGT-REP) | `$krb5tgs$23$...`                          | `--format=krb5tgs`     |

```bash
# Lista tutti i formati disponibili
john --list=formats | grep -i ntlm
john --list=formats | grep -i sha
```

***

## 2. Workflow Base – Da Hash a Password

```bash
# Crea file con hash (uno per riga)
echo "8846F7EAEE8FB117AD06BDD830B7586C" > hashes.txt

# Lancia con wordlist + formato esplicito
john --wordlist=/usr/share/wordlists/rockyou.txt \
     --format=nt \
     hashes.txt
```

```text
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
password         (?)
1g 0:00:00:00 DONE (2026-06-24 22:01) 100% 250g/s Session completed
```

```bash
# Visualizza password craccate
john --show hashes.txt

# ⚠️ IMPORTANTE: --show richiede STESSO file hash E stesso --format
john --show --format=nt hashes.txt
```

```text
?:password

1 password hash cracked, 0 left
```

> Errore tipico: lanciare `john --show hashes.txt` senza `--format` dopo aver craccato con formato specifico. John dice "0 cracked" anche se ha trovato la password. Specifica sempre `--format` anche con `--show`.

***

## 3. Modalità di Cracking

John ha 4 modi principali. Senza specificare nulla, li usa in sequenza automaticamente.

### Single Crack Mode

Usa username, GECOS field e home directory dal file come candidati, con mangling. È il più veloce — spesso cracca password banali come `admin:admin` o `john:john123` in pochi secondi.

```bash
# Formato file per single crack: username:hash
echo "administrator:8846F7EAEE8FB117AD06BDD830B7586C" > hashes.txt

john --single --format=nt hashes.txt
```

### Wordlist Mode

Il modo principale: testa ogni entry della wordlist contro l'hash. Con `--rules` applica trasformazioni prima di testare ogni parola.

```bash
# Wordlist pura
john --wordlist=/usr/share/wordlists/rockyou.txt --format=nt hashes.txt

# Wordlist + regole di mangling (raccomandato — vedi sezione 5)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules --format=nt hashes.txt
```

### Incremental Mode (Brute Force)

Testa tutte le combinazioni possibili di caratteri. Lento, usa solo se wordlist + rules falliscono.

```bash
# Brute force con charset alfanumerico (a-z, A-Z, 0-9)
john --incremental=Alnum --format=nt hashes.txt

# Brute force solo lowercase (più veloce)
john --incremental=Lower --format=nt hashes.txt

# Charset custom
john --incremental=Alpha --format=nt hashes.txt
```

### Mask Mode

Brute force con pattern specifico — quando conosci parte della struttura della password.

```bash
# Password di 8 char: prima maiuscola, 6 lowercase, 1 cifra (tipo "Password1")
john --mask='?u?l?l?l?l?l?l?d' --format=nt hashes.txt

# ?u = uppercase, ?l = lowercase, ?d = digit, ?s = special, ?a = all
# Password da 6 char solo lowercase
john --mask='?l?l?l?l?l?l' --format=nt hashes.txt

# Anno 2026 in coda (pattern "parola2026")
john --mask='?w2026' --wordlist=rockyou.txt --format=nt hashes.txt
```

***

## 4. Hash da Linux – Shadow File

Dopo privilege escalation su Linux ([linux-privesc](https://hackita.it/articoli/linux-privesc/)), dumpa il file shadow e cracca offline.

```bash
# Sul target (come root)
cat /etc/shadow > shadow.txt
# oppure
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Cracca su macchina attaccante
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# SHA-512 (formato moderno Linux)
john --wordlist=/usr/share/wordlists/rockyou.txt \
     --format=sha512crypt unshadowed.txt
```

```text
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2])
toor             (root)
password123      (www-data)
```

***

## 5. Hash Windows – NTLM e NTLMv2

### NTLM da SAM/NTDS

Hash estratti dal dump AD (secretsdump, mimikatz) — vedi [credential dumping](https://hackita.it/articoli/credential-dumping/).

```bash
# File formato: username:RID:LMhash:NThash:::
# Es: administrator:500:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::

john --wordlist=/usr/share/wordlists/rockyou.txt \
     --format=nt \
     ntds_hashes.txt

# Solo NT hash (senza username)
echo "8846F7EAEE8FB117AD06BDD830B7586C" > nt.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=nt nt.txt
```

### NTLMv2 da Responder

Hash catturati con [Responder](https://hackita.it/articoli/responder/) durante un attacco NTLM relay su [SMB](https://hackita.it/articoli/smb/).

```bash
# File formato Responder (Logs/SMB-NTLMv2-*.txt)
# administrator::CORP:1122334455667788:hash:challenge

john --wordlist=/usr/share/wordlists/rockyou.txt \
     --format=netntlmv2 \
     /usr/share/responder/logs/SMB-NTLMv2-SSP-192.168.1.10.txt
```

### Kerberos TGS (Kerberoasting)

Hash TGS catturati durante [Kerberoasting](https://hackita.it/articoli/kerberos/) su [Active Directory](https://hackita.it/articoli/active-directory/).

```bash
# Hash formato: $krb5tgs$23$*username*$domain$*SPN*$hash
john --wordlist=/usr/share/wordlists/rockyou.txt \
     --format=krb5tgs \
     kerberoast_hashes.txt
```

***

## 6. Rules – Moltiplica la Wordlist

Le regole sono trasformazioni applicate a ogni parola prima di testarla: capitalizza, aggiungi numeri, sostituisci lettere. Senza `--rules`, John manca \~80% delle password craccabili con wordlist.

```bash
# Regole di default (Wordlist rules)
john --wordlist=rockyou.txt --rules --format=nt hashes.txt

# Ruleset Jumbo (3000+ regole, più potente ma più lento)
john --wordlist=rockyou.txt --rules=Jumbo --format=nt hashes.txt

# KoreLogic (enterprise-oriented, ottimo per AD)
john --wordlist=rockyou.txt --rules=KoreLogic --format=nt hashes.txt

# Tutti i ruleset concatenati (lento, massima copertura)
john --wordlist=rockyou.txt --rules=All --format=nt hashes.txt
```

**Cosa fanno le regole (esempi):**

| Input      | Trasformazione  | Output         |
| ---------- | --------------- | -------------- |
| `password` | Capitalizza     | `Password`     |
| `password` | Appende anno    | `password2026` |
| `password` | Leet speak      | `p@ssw0rd`     |
| `password` | Reverse         | `drowssap`     |
| `password` | Appende simbolo | `password!`    |
| `password` | Tutte uppercase | `PASSWORD`     |

```bash
# Regola custom in john.conf
# [List.Rules:MioRuleset]
# c Az"2026"        → Capitalizza + appende 2026
# sa@ se3 si1 so0   → Leet speak
# $!                → Appende !

john --wordlist=rockyou.txt --rules=MioRuleset --format=nt hashes.txt

# Genera candidati senza crackare (verifica le trasformazioni)
john --wordlist=rockyou.txt --rules=Jumbo --stdout | head -20
```

***

## 7. Script \*2john – Tutti i Tool di Estrazione Hash

La killer feature di John: una famiglia di script che estraggono hash craccabili da qualsiasi file cifrato. Hashcat non fa questo autonomamente — usi \*2john per estrarre, poi passi l'hash a hashcat se vuoi GPU.

```bash
locate *2john*
ls /usr/share/john/*2john* 2>/dev/null
```

**Workflow universale:** `TOOL2JOHN file > hash.txt` → `john --wordlist=rockyou.txt hash.txt` → `john --show hash.txt`

***

### Archivi cifrati

Per craccare un archivio ZIP, RAR o 7-Zip protetto da password trovato su una SMB share, webserver (`/backup/`, `/files/`) o durante post-exploitation, estrai prima l'hash con lo script corrispondente e poi attaccalo offline. Gli archivi cifrati contengono spesso credenziali, config file, o dump di database.

```bash
# ZIP – classico PKZIP o WinZip/AES
zip2john protected.zip > hash.txt
john --wordlist=rockyou.txt hash.txt
```

```text
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x AES])
secret123        (protected.zip)
```

```bash
# RAR v3/v4 – comune in ambienti Windows
rar2john protected.rar > hash.txt
john --wordlist=rockyou.txt hash.txt

# 7-Zip – AES-256, usato per backup e archivi aziendali
7z2john.pl archive.7z > hash.txt
john --wordlist=rockyou.txt hash.txt
```

> Errore tipico: `zip2john` su un file non cifrato non produce hash. Verifica con `file archive.zip` — se non dice "encrypted" il file è in chiaro.

***

### Documenti Office e PDF

Per craccare la password di un documento Word, Excel, PowerPoint o PDF trovato in una share aziendale, come attachment email, o durante post-exploitation. Un foglio Excel con credenziali o un PDF con documentazione riservata bloccati da password sono tra gli obiettivi più frequenti in pentest enterprise.

```bash
# Microsoft Office – Word, Excel, PowerPoint (tutte le versioni 2003→2019)
office2john.py document.docx > hash.txt
office2john.py spreadsheet.xlsx > hash.txt
john --wordlist=rockyou.txt hash.txt

# PDF protetto da apertura o da modifica
pdf2john.pl protected.pdf > hash.txt
john --wordlist=rockyou.txt hash.txt

# LibreOffice / OpenOffice (.ods, .odt, .odp)
libreoffice2john.py file.ods > hash.txt

# StarOffice (versioni legacy)
staroffice2john.py starfile > hash.txt

# Apple iWork (Pages, Numbers, Keynote) – target su macOS
iwork2john.py document.pages > hash.txt

# Apple Notes database – note cifrate su Mac
applenotes2john.py ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite > hash.txt

# Lotus Notes ID file – ancora vivo in banche e assicurazioni IBM
# Il file .id è la chiave di accesso all'account Lotus Notes dell'utente
lotus2john.py user.id > hash.txt
john --wordlist=rockyou.txt hash.txt --format=lotus5

# MS Money – software finanziario Microsoft 2002-2007
# Trovato su PC di utenti che gestiscono finanze con Money
money2john.py finances.mny > hash.txt
john --wordlist=rockyou.txt hash.txt
```

***

### Chiavi e Certificati

Per craccare la passphrase di una chiave SSH, un certificato PFX, una chiave GPG o un PEM trovati durante post-exploitation. Se rompi la passphrase di una chiave SSH (`id_rsa`) puoi usarla direttamente per autenticarti come quell'utente su tutti i server dove quella chiave è autorizzata — spesso decine di macchine.

```bash
# Chiave SSH con passphrase (RSA/DSA/EC/ECDSA/Ed25519)
ssh2john.py id_rsa > hash.txt
john --wordlist=rockyou.txt hash.txt
```

```text
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 256/256 AVX2])
mysshpass        (id_rsa)
```

```bash
# PuTTY private key (.ppk) – usato da sviluppatori Windows per SSH
putty2john key.ppk > hash.txt

# GPG/PGP private key – email cifrate, repo firmati, backup cifrati
gpg2john private.asc > hash.txt
gpg2john private.gpg > hash.txt

# PEM certificate/key (PKCS#8) – chiave TLS, certificati server
pem2john.py certificate.pem > hash.txt

# PFX / P12 (PKCS#12) – cert + chiave privata per VPN client auth, code signing
# Trovato in %APPDATA%, share aziendali, o estratto da browser
pfx2john.py certificate.pfx > hash.txt
john --wordlist=rockyou.txt hash.txt --format=pfx

# OpenSSL encrypted private key
openssl2john.py encrypted.key > hash.txt

# PGP Disk (.pgd) – volume virtuale cifrato con PGP Desktop/Symantec
pgpdisk2john.py disk.pgd > hash.txt

# PGP Self-Decrypting Archive – archivio .exe cifrato con PGP
pgpsda2john.py archive.exe > hash.txt

# PGP Whole Disk Encryption – disco intero con PGP WDE/Symantec
pgpwde2john.py /dev/sda > hash.txt
```

***

### Password Manager

Craccare un database KeePass è il jackpot del pentest: un singolo file `.kdbx` contiene tutte le credenziali dell'utente — email, VPN, RDP, banche, tutto. Cerca in `%USERPROFILE%\Desktop`, `Documents`, e share personali. Lo stesso vale per 1Password, Bitwarden, LastPass, Dashlane: se trovi il vault e lo cracki, l'intera identità digitale dell'utente è compromessa.

```bash
# KeePass (.kdbx) – il più diffuso in enterprise
keepass2john database.kdbx > hash.txt
keepass2john -k keyfile.key database.kdbx > hash.txt  # con keyfile separato
john --wordlist=rockyou.txt hash.txt --format=keepass

# 1Password (.agilekeychain, .opvault) – diffuso su macOS/iOS
1password2john.py vault.agilekeychain > hash.txt

# Bitwarden – export JSON locale dal browser extension
bitwarden2john.py bitwarden_export.json > hash.txt

# LastPass 3.x Firefox – file in ~/.lastpass/
lastpass2john.py email@example.com lastpass_lpall.slps lastpass_key.itr > hash.txt

# Dashlane (.aes, .dash) – da %AppData%\Dashlane\profiles\
dashlane2john.py dashlane.aes > hash.txt

# Enpass v6 (.enpassdb) – diffuso su mobile e desktop
enpass2john.py vault.enpassdb > hash.txt

# Enpass v5 (formato legacy)
enpass5tojohn.py vault.db > hash.txt

# Password Safe (.psafe3) – usato da sistemisti e security team
pwsafe2john.py database.psafe3 > hash.txt

# Kwallet – password manager di default su KDE/Plasma Linux
kwallet2john.py wallet.kwl > hash.txt

# Strip – password manager mobile iOS/Android
strip2john database.db > hash.txt
```

***

### Crypto Wallet

Per craccare la password di un wallet Bitcoin, Ethereum, Electrum o Monero trovato durante post-exploitation. Un `wallet.dat` in `~/.bitcoin/` o un keystore Ethereum in `~/.ethereum/` può contenere fondi significativi. Controlla anche nelle cartelle cloud sincronizzate (Dropbox, OneDrive) e nei backup.

```bash
# Bitcoin wallet.dat – Bitcoin Core
bitcoin2john.py wallet.dat > hash.txt

# Ethereum keystore UTC--*.json (Geth/Mist/MyEtherWallet)
ethereum2john.py UTC--2021-01-01.json > hash.txt

# Electrum wallet (v1/v2/v3) – Desktop Linux/Windows/macOS
electrum2john.py default_wallet > hash.txt

# Blockchain.info wallet (export .aes.json)
blockchain2john.py wallet.aes.json > hash.txt

# Cardano wallet (.db)
cardano2john.py wallet.db > hash.txt

# Coinomi – app Android (/data/data/com.coinomi.wallet/)
coinomi2john.py com.coinomi.wallet.db > hash.txt

# Bitshares (.ldb su Chrome o .sqlite su desktop)
bitshares2john.py wallet.json > hash.txt

# MultiBit Classic e HD wallet (.key, .wallet)
multibit2john.py multibit.wallet > hash.txt

# Monero (.keys – solo versioni JSON > gennaio 2016)
monero2john.py wallet.keys > hash.txt

# Tezos (.json)
tezos2john.py wallet.json > hash.txt
```

***

### Disk Encryption e Filesystem Cifrati

Per craccare la password di un disco cifrato — BitLocker su Windows, LUKS su Linux, VeraCrypt, DMG su macOS — quando hai accesso fisico al disco, un'immagine estratta da VMware/VirtualBox, o un disco smontato da un server. Crackata la passphrase, accedi all'intero filesystem.

```bash
# BitLocker – disco Windows cifrato (laptop aziendali, USB cifrate)
# Scenario tipico: laptop sequestrato, disco estratto, immagine .img
bitlocker2john -i /dev/sda > hash.txt
bitlocker2john -i bitlocker.img > hash.txt
john --wordlist=rockyou.txt hash.txt --format=bitlocker

# LUKS – partizioni Linux cifrate (Ubuntu/Fedora encrypted install, server cifrati)
# Scenario: accesso a server con disco smontato, o immagine VM Linux
luks2john.py /dev/sda1 > hash.txt
luks2john.py disk_image.img > hash.txt
john --wordlist=rockyou.txt hash.txt --format=luks

# macOS DMG – disk image cifrata, usata anche per distribuire software o backup
dmg2john image.dmg > hash.txt

# TrueCrypt / VeraCrypt – container cifrati o full-disk
# Scenario: file .tc o volume VeraCrypt trovato su server o workstation
truecrypt2john.py volume.tc > hash.txt
john --wordlist=rockyou.txt hash.txt --format=TrueCrypt

# DiskCryptor – alternativa Windows a BitLocker (open source)
diskcryptor2john.py /dev/sdb1 > hash.txt

# EncFS – cartelle cifrate su Linux spesso usate con Dropbox o backup
# Scenario: trovi .encfs6.xml + file cifrati in un backup
encfs2john.py .encfs6.xml > hash.txt

# eCryptfs – home directory cifrate su Ubuntu (default su versioni vecchie)
ecryptfs2john.py wrapped-passphrase > hash.txt

# FreeBSD GELI – full disk encryption su FreeBSD, pfSense, FreeNAS
geli2john.py /dev/ada0.eli > hash.txt

# OpenBSD SoftRAID – RAID cifrato su OpenBSD
openbsd_softraid2john.py disk_image > hash.txt

# VirtualBox VDI cifrato – disco virtuale con encryption abilitata
# Scenario: server di sviluppo con VMs cifrate, trovi il .vdi
vdi2john.pl disk.vdi > hash.txt

# VMware VMX cifrato – trovi "encryption.keySafe" nel file .vmx
vmx2john.py vm.vmx > hash.txt

# BestCrypt Container (.jbc) – Jetico BestCrypt, usato in enterprise
bestcrypt2john.py container.jbc > hash.txt

# BestCrypt Volume Encryption v4 – full disk, alternativa enterprise a BitLocker
bestcryptve2john.py volume.bde > hash.txt
john --wordlist=rockyou.txt hash.txt --format=BestCryptVE

# PGP Disk, SDA, WDE – soluzioni Symantec/PGP disk encryption enterprise
pgpdisk2john.py disk.pgd > hash.txt
pgpsda2john.py archive.exe > hash.txt
pgpwde2john.py /dev/sda > hash.txt

# Padlock SecureDrive – USB cifrata con hardware PIN
padlock2john.py padlock_file > hash.txt

# EFS – file cifrati con Windows Encrypting File System (attributo "E" in dir)
efs2john.py --masterkey=samples/92573301.efs \
            --sid="S-1-5-21-1482476501-1659004503-725345543-1003"
```

***

### Wireless / Network

Per craccare una password WPA/WPA2 da un handshake catturato, recuperare credenziali da traffico VNC intercettato, o estrarre password da config di router e firewall. Il caso più comune: hai catturato un handshake WPA con airodump-ng e vuoi ricavare il PSK della rete.

```bash
# WPA/WPA2 handshake – catturato con airodump-ng durante wireless audit
# Cracking del PSK della rete aziendale
hccap2john capture.hccap > hash.txt
hccapx2john.py capture.hccapx > hash.txt
john --wordlist=rockyou.txt hash.txt --format=wpapsk

# WPA da pcap generico (tcpdump/Wireshark con handshake incluso)
wpapcap2john capture.cap > hash.txt

# VNC password – sniffata da sessione VNC non cifrata su LAN interna
# Una volta crackato hai accesso remoto grafico al sistema
vncpcap2john vnc_capture.pcap > hash.txt

# SIP Digest Auth – credenziali VoIP intercettate da traffico SIP plaintext
sipdump2john.py voip_capture.pcap > hash.txt

# HTTP Digest Auth – file .htdigest su web server
htdigest2john.py /etc/apache2/.htdigest > hash.txt

# IKE PSK – PSK di un VPN IPsec (da output di ike-scan)
# Crackato il PSK puoi negoziare il tunnel VPN
ikescan2john.py ikescan_psk.txt > hash.txt

# EAP-MD5 – wireless enterprise 802.1x, credenziali da pcap
eapmd5tojohn capture.pcap > hash.txt

# RADIUS shared secret – catturato da pcap
radius2john.pl capture.pcap > hash.txt
radius2john.py capture.pcap > hash.txt

# APOP – POP3 authentication challenge/response da pcap
apop2john.py pop3_capture.pcap > hash.txt

# Pcap generico – tenta di estrarre hash da qualunque protocollo
pcap2john.py capture.pcap > hash.txt

# Lua multi-protocol – RADIUS CHAP, SNMPv3, ISCSI CHAP, DHCPv6 auth
tshark -q -Xlua_script:network2john.lua -r capture.pcap > hash.txt

# Cisco IOS enable secret / type 7 password – da running-config estratto
# Scenario: accedi a un router, esporti la config, cracki l'enable secret
cisco2john.pl running-config.txt > hash.txt 2> seed.txt
john --format=md5 --wordlist=seed.txt --rules hash.txt

# NetScreen (Juniper) – hash password amministrativi da config firewall
netscreen.py netscreen_config.txt > hash.txt

# Aruba wireless controller – hash da config controller
aruba2john.py aruba_config.txt > hash.txt
```

***

### Kerberos e Active Directory

Per craccare hash Kerberos in ambienti Active Directory. Il caso tipico è il Kerberoasting: dopo Mimikatz o Rubeus esporti ticket `.kirbi` di service account, li converti con kirbi2john e li cracki offline — senza generare alert di autenticazione fallita sul DC. Il ccache è invece la credential cache Kerberos su macchine Linux joiniate ad AD.

```bash
# Ticket Kerberos .kirbi – da Mimikatz (sekurlsa::tickets /export) o Rubeus
# Kerberoasting: crack offline TGS → password service account
kirbi2john.py ticket.kirbi > hash.txt
john --wordlist=rockyou.txt hash.txt --format=krb5tgs

# Kerberos credential cache – da /tmp/krb5cc_1000 su Linux joinato AD
# Crack → ticket riusabile per lateral movement
ccache2john.py /tmp/krb5cc_1000 > hash.txt

# KDC dump – dump del Key Distribution Center
kdcdump2john.py dump.bin > hash.txt

# Kerberos AS-REQ / TGS-REP da pcap (converti con tshark → .pdml prima)
tshark -r ad_capture.pcap -T pdml > data.pdml
krb2john.py data.pdml > hash.txt

# DPAPI Master Key – protegge password browser, WiFi, credenziali Windows
# Trovato in %APPDATA%\Roaming\Microsoft\Protect\<SID>\
DPAPImk2john.py -S S-1-5-21-xxx -mk masterkey_file -c domain > hash.txt

# known_hosts hashed – SSH fingerprinting con HashKnownHosts yes
known_hosts2john.py ~/.ssh/known_hosts > hash.txt
```

***

### Windows, macOS e Mobile

Per craccare password su device sequestrati durante forensics o incident response. Un backup iTunes cifrato di un iPhone contiene messaggi, foto e credenziali. La keychain macOS contiene password WiFi, account email e credenziali Safari. I backup Android cifrati coprono l'intero contenuto del telefono.

```bash
# IBM RACF mainframe – sistema legacy ancora usato in banche e grandi enterprise
racf2john racf_database > hash.txt

# UAF (OpenVMS) – sistema DEC/HP ancora in ambienti industriali
uaf2john uaf.dat > hash.txt

# iTunes backup cifrato – da %APPDATA%\Apple\MobileSync\ su Windows
# Forensics iPhone/iPad: crack → accesso a messaggi, foto, credenziali
itunes_backup2john.pl Manifest.plist > hash.txt

# Android backup cifrato (.ab) – da adb backup
androidbackup2john.py backup.ab > hash.txt

# Android FDE (Full Disk Encryption, solo Android ≤4.3)
androidfde2john.py data_partition footer_partition > hash.txt

# iOS 7+ restriction PIN (.plist da iPhone) – rimuovi parental controls
ios7tojohn.pl com.apple.restrictionspassword.plist > hash.txt
john hash --incremental:Digits --min-len=4 --max-len=4

# EFS – file cifrati NTFS con attributo "E" (post-exploitation Windows)
efs2john.py --masterkey=samples/92573301.efs \
            --sid="S-1-5-21-1482476501-1659004503-725345543-1003"

# Mac OS X keychain – WiFi passwords, account email, credenziali Safari
keychain2john.py ~/Library/Keychains/login.keychain > hash.txt

# macOS account hash (Mountain Lion 10.8+) – da .plist utente
mac2john.py /var/db/dslocal/nodes/Default/users/admin.plist > hash.txt
mac2john-alt.py admin.plist > hash.txt

# Mac OS X Lion 10.7 – SHA-512 salted hashes (formato pre-Mountain Lion)
lion2john.pl /var/db/dslocal/nodes/Default/users/*.plist > hash.txt
lion2john-alt.pl user.plist > hash.txt
```

***

### App, Browser e Enterprise

Per recuperare credenziali da applicazioni post-exploitation: la master password di Firefox dà accesso a tutte le password salvate nel browser, un vault Ansible cifrato nel repo git nasconde API key e password di database, un keystore Java su un server Tomcat protegge i certificati TLS. Ogni tool qui copre un'applicazione specifica che altrimenti richiederebbe analisi manuale.

```bash
# Mozilla Firefox – master password del password manager (key3.db)
# Crack → vedi tutte le password salvate nel browser dell'utente
mozilla2john.py ~/.mozilla/firefox/*.default/key3.db > hash.txt

# FileZilla – credenziali FTP/SFTP salvate in "FileZilla Server.xml"
filezilla2john.py "FileZilla Server.xml" > hash.txt

# Ansible Vault (.yml cifrati) – playbook con credenziali nel repo git
# Crack → leggi API key, password database, segreti infrastruttura
ansible2john.py vault.yml > hash.txt

# Signal (v4.13.5) – passphrase database messaggi
signal2john.py SecureSMS-Preferences.xml > hash.txt

# Telegram desktop – passphrase locale del client (map.db)
telegram2john.py map.db > hash.txt

# Ejabberd XMPP – hash utenti da dump del server di chat
ejabberd2john.py ejabberd.dump > hash.txt

# Prosody XMPP – .dat in /var/lib/prosody/<domain>/accounts/
prosody2john.py /var/lib/prosody/corp.local/accounts/admin.dat > hash.txt

# AIX /etc/security/passwd – sistema Unix IBM
aix2john.py /etc/security/passwd > hash.txt

# SAP ERP – hash password da export del sistema
sap2john.pl sap_export.txt > hash.txt

# McAfee ePO – CSV da dbo.OrionUsers (database ePO)
mcafee_epo2john.py orion_users.csv > hash.txt

# Oracle APEX – hash da export applicazione web Oracle
apex2john.py apex-hashes.txt > hash.txt

# NetIQ SSPR (Self-Service Password Reset) – via LDAP server
sspr2john.py -H ldap.corp.local -b "dc=corp,dc=local" > hash.txt

# Java KeyStore (.jks) – certificati per Tomcat/JBoss/WildFly
# Crack → accede ai certificati, impersona il server
keystore2john.py keystore.jks > hash.txt

# BKS (BouncyCastle Android KeyStore) – certificate pinning nelle app Android
bks2john.py keystore.bks > hash.txt

# GNOME Keyring – password manager default su Ubuntu/GNOME
keyring2john.py login.keyring > hash.txt

# LDIF – export LDAP con hash utenti
ldif2john.pl export.ldif > hash.txt

# MongoDB – hash autenticazione database
mongodb2john.js mongod.conf > hash.txt

# IBM 4690 OS (POS retail IBM) – sistemi cassa
adxcsouf2john.py ADXCSOUF.DAT > hash.txt

# IBM CRACF – gestione password su mainframe IBM
cracf2john.py CRACF.TXT > hash.txt

# IBM i scanner (AS/400 iSeries)
ibmiscanner2john.py userid_hash_file.txt > hash.txt

# AEM (Adobe Experience Manager) – CMS enterprise Adobe
aem2john.py aem_hashes.txt > hash.txt

# Atmail – hash da database mail server
atmail2john.pl atmail.db > hash.txt

# andOTP (.json.aes) – backup 2FA cifrato dell'app Android andOTP
# Crack → hai tutti i token TOTP dell'utente
andotp2john.py freeotp-backup.json.aes > hash.txt

# DeepSound – file audio con dati nascosti via steganografia (comune nei CTF)
deepsound2john.py carrier.wav > hash.txt

# AxCrypt (.axx) – file cifrati con AxCrypt su Windows
axcrypt2john.py file.axx > hash.txt

# ZED – Zed Attack Proxy session file cifrata
zed2john.py session.zed > hash.txt

# NeoWallet (Neo blockchain)
neo2john.py wallet.db3 > hash.txt
```

> Errore tipico: lanciare `john hash.txt` senza `--format` dopo aver usato uno script \*2john. Specifica sempre `--format` o controlla con `john --show hash.txt`.

***

### Tabella Riepilogativa \*2john – Quick Reference

| Categoria           | Script                                                                                                                    | Quando lo usi                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **Archivi**         | zip2john, rar2john, 7z2john.pl                                                                                            | Archivi cifrati su share, backup, webserver       |
| **Office/Doc**      | office2john.py, pdf2john.pl, libreoffice2john.py                                                                          | Documenti protetti in share aziendali             |
| **IBM/Legacy**      | lotus2john.py, money2john.py                                                                                              | Ambienti IBM legacy, PC con software finanziario  |
| **Apple doc**       | iwork2john.py, applenotes2john.py                                                                                         | Target macOS con documenti cifrati                |
| **SSH/Keys**        | ssh2john.py, putty2john, gpg2john, pem2john.py                                                                            | Chiave SSH con passphrase trovata post-compromise |
| **PFX/PGP**         | pfx2john.py, pgpdisk2john.py, pgpsda2john.py, pgpwde2john.py                                                              | Certificati VPN/code signing, dischi PGP          |
| **Password Mgr**    | keepass2john, 1password2john.py, bitwarden2john.py, lastpass2john.py, dashlane2john.py, pwsafe2john.py, kwallet2john.py   | .kdbx sul desktop → jackpot di credenziali        |
| **Crypto**          | bitcoin2john.py, ethereum2john.py, electrum2john.py, monero2john.py, blockchain2john.py, cardano2john.py, coinomi2john.py | Wallet cripto su PC/server target                 |
| **Disk/LUKS**       | bitlocker2john, luks2john.py, truecrypt2john.py, encfs2john.py, ecryptfs2john.py, geli2john.py, dmg2john                  | Disco cifrato fisico o immagine VM                |
| **VM**              | vdi2john.pl, vmx2john.py                                                                                                  | VM cifrata su server di sviluppo/backup           |
| **BestCrypt**       | bestcrypt2john.py, bestcryptve2john.py                                                                                    | Container/volume BestCrypt enterprise             |
| **WPA/WiFi**        | hccap2john, hccapx2john.py, wpapcap2john                                                                                  | Wireless audit, handshake WPA catturato           |
| **Network**         | vncpcap2john, sipdump2john.py, htdigest2john.py, pcap2john.py, ikescan2john.py, eapmd5tojohn                              | Traffico intercettato su LAN interna              |
| **Router/FW**       | cisco2john.pl, netscreen.py, aruba2john.py                                                                                | Config estratta da router/firewall                |
| **Kerberos/AD**     | kirbi2john.py, ccache2john.py, DPAPImk2john.py, krb2john.py                                                               | Post-exploitation AD: Mimikatz, Rubeus, ccache    |
| **Windows/Mobile**  | racf2john, itunes\_backup2john.pl, androidbackup2john.py, ios7tojohn.pl, efs2john.py                                      | Forensics su device sequestrati                   |
| **macOS**           | keychain2john.py, mac2john.py, lion2john.pl                                                                               | Pentest/forensics su sistemi Apple                |
| **Browser/DevOps**  | mozilla2john.py, filezilla2john.py, ansible2john.py                                                                       | Post-exploitation su workstation, repo git        |
| **Chat/Messaging**  | signal2john.py, telegram2john.py, ejabberd2john.py, prosody2john.py                                                       | Server XMPP, app messaggistica                    |
| **Java/Enterprise** | keystore2john.py, bks2john.py, mcafee\_epo2john.py                                                                        | Server Java Tomcat/JBoss, ambienti enterprise     |
| **IBM/Mainframe**   | aix2john.py, cracf2john.py, ibmiscanner2john.py, adxcsouf2john.py                                                         | Sistemi AIX, AS/400, mainframe IBM                |
| **Misc/CTF**        | deepsound2john.py, axcrypt2john.py, andotp2john.py, zed2john.py                                                           | CTF, file cifrati rari, steganografia, 2FA backup |

## 7b. Tool Alternativi per File Cracking

Oltre ai \*2john scripts, esistono tool specializzati che cracckano direttamente il file — senza passare dall'estrazione dell'hash. Alcuni sono più veloci su certi formati, altri coprono casi che John non gestisce.

***

### fcrackzip – ZIP diretto (senza hash)

Cracca ZIP direttamente senza estrarre l'hash prima. Più rapido di zip2john+john su password brevi.

```bash
sudo apt install fcrackzip

# Wordlist attack (il metodo da usare sempre per primo)
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip
# -u: verifica con unzip (elimina falsi positivi)
# -D: dictionary mode
# -p: wordlist path
```

```text
PASSWORD FOUND!!!!: pw == secret123
```

```bash
# Brute force: solo lowercase da 4 a 6 caratteri
fcrackzip -b -c 'a' -l 4-6 -u file.zip
# -b: brute force
# -c 'a': charset lowercase (a=lowercase, A=upper+lower, 1=digits, !=specials)
# -l 4-6: lunghezza minima-massima

# Brute force: alfanumerico da 3 a 5 caratteri
fcrackzip -b -c 'aA1' -l 3-5 -u file.zip

# Verbose (mostra i tentativi in corso)
fcrackzip -v -u -D -p rockyou.txt file.zip
```

> Errore tipico: `fcrackzip` senza `-u` mostra falsi positivi perché non verifica che il file si decomprima correttamente. Usa sempre `-u`.

***

### pdfcrack – PDF diretto

Cracca PDF protetti da password direttamente. Supporta revision 2, 3 e 4 dello standard PDF.

```bash
sudo apt install pdfcrack

# Wordlist attack
pdfcrack -f protected.pdf -w /usr/share/wordlists/rockyou.txt

# Brute force (senza wordlist — testa tutte le combinazioni)
pdfcrack -f protected.pdf

# Solo uppercase da 4 a 6 caratteri
pdfcrack -f protected.pdf -n 4 -m 6 -c 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
# -n: lunghezza minima, -m: lunghezza massima, -c: charset

# Cracca owner password (quella che blocca stampa/copia)
pdfcrack -f protected.pdf -o -w rockyou.txt

# Salva stato e riprendi dopo interruzione
pdfcrack -f protected.pdf -w rockyou.txt -l stato.txt
pdfcrack -f protected.pdf -w rockyou.txt -L stato.txt  # -L = riprendi
```

```text
found user-password: 'password123'
```

***

### rarcrack – RAR / 7z (brute force puro)

Brute force diretto su RAR, 7z e ZIP. Non supporta wordlist — solo brute force alfabetico.

```bash
sudo apt install rarcrack

# Brute force RAR (auto-rileva il tipo)
rarcrack archive.rar --threads 4

# Specifica tipo esplicitamente
rarcrack archive.7z --type 7z --threads 8
rarcrack archive.zip --type zip --threads 4
```

> **Limiti di rarcrack:** non supporta wordlist (solo brute force), e in pratica funziona bene solo su password molto brevi (\<5 caratteri). Per qualcosa di più serio usa rar2john → john o hashcat.

***

### truecrack – TrueCrypt / VeraCrypt

Cracking di volumi TrueCrypt (e VeraCrypt in modalità compatibilità) con GPU NVIDIA CUDA.

```bash
sudo apt install truecrack

# Wordlist attack con RIPEMD-160 (default TrueCrypt)
truecrack -t volume.tc -k ripemd160 -w /usr/share/wordlists/rockyou.txt

# Specifica encryption algorithm (default: AES)
truecrack -t volume.tc -k sha512 -e serpent -w rockyou.txt

# Brute force alfabetico da 6 a 8 caratteri
truecrack -t volume.tc -c abcdefghijklmnopqrstuvwxyz -s 6 -m 8

# Volume hidden (VeraCrypt hidden volume)
truecrack -t volume.tc -k ripemd160 -w rockyou.txt -H

# Backup header (testa sull'header di backup)
truecrack -t volume.tc -k ripemd160 -w rockyou.txt -b
```

```text
TrueCrack v3.0
Found password: "s3cr3t"
Password length: "7"
Total computations: "78"
```

***

### crackpkcs12 – Certificati PFX / P12

Cracking di certificati PKCS#12 (file `.pfx` e `.p12`) — usati per autenticazione client TLS, code signing, VPN.

```bash
# Install
git clone https://github.com/crackpkcs12/crackpkcs12
cd crackpkcs12 && ./configure && make && sudo make install

# Wordlist attack
crackpkcs12 -d /usr/share/wordlists/rockyou.txt certificate.pfx

# Brute force: solo lowercase
crackpkcs12 -b -c a certificate.pfx

# Brute force: alfanumerico da 4 a 6 caratteri
crackpkcs12 -b -c aA1 -m 4 -M 6 certificate.pfx

# Combina: prima wordlist poi brute force su lowercase
crackpkcs12 -d rockyou.txt -b -c a certificate.pfx

# Multi-threaded
crackpkcs12 -d rockyou.txt -t 8 certificate.pfx
```

```text
Dictionary attack - Starting 4 threads
Password found: certpass2026
```

> Scenario reale: trovi un `.pfx` in un share SMB o in una directory web — spesso contiene chiavi private per autenticazione client o code signing. Craccato il `.pfx`, puoi importarlo e usarlo per impersonare il device/utente.

***

### hcxtools – WiFi WPA Capture → Hashcat

Ecosistema completo per catturare e convertire handshake WPA/WPA2/WPA3 in hash per hashcat. Più moderno di aircrack-ng per il PMKID attack (non serve client connesso).

```bash
sudo apt install hcxtools hcxdumptool

# Step 1: Cattura handshake/PMKID (monitor mode richiesto)
sudo systemctl stop NetworkManager wpa_supplicant
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

hcxdumptool -i wlan0 -o capture.pcapng --enable_status=1

# Step 2: Converti in formato hashcat (22000 = WPA-PBKDF2-PMKID+EAPOL)
hcxpcapngtool -o hash.hc22000 -E essidlist.txt capture.pcapng

# Step 3: Cracca con hashcat
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Alternativa: converti per John
wlanhcx2john capture.pcapng > wpa_hash.txt
john --wordlist=rockyou.txt wpa_hash.txt --format=wpapsk
```

```text
hashcat (v6.2.6) starting...
* Device #1: NVIDIA GeForce RTX 4090
...
aa:bb:cc:dd:ee:ff:HomeNetwork:password123
Session..........: hashcat
Status...........: Cracked
```

***

### Hashcat – Modi File Diretti (senza \*2john)

Per hash veloci (Office, ZIP, PDF), hashcat con GPU è molto più veloce di John. Usa `*2john` per estrarre, poi hashcat per craccare.

| Formato                   | hashcat `-m` | Esempio                                |
| ------------------------- | ------------ | -------------------------------------- |
| Office 2007               | `-m 9400`    | `hashcat -m 9400 hash.txt rockyou.txt` |
| Office 2010               | `-m 9500`    |                                        |
| Office 2013               | `-m 9600`    |                                        |
| Office 2016/2019          | `-m 25400`   |                                        |
| PDF 1.1–1.3 (40-bit RC4)  | `-m 10400`   |                                        |
| PDF 1.4–1.6 (128-bit RC4) | `-m 10500`   |                                        |
| PDF 1.7 Level 3 (AES-256) | `-m 10600`   |                                        |
| PDF 1.7 Level 8 (AES-256) | `-m 10700`   |                                        |
| ZIP (PKZIP)               | `-m 17200`   |                                        |
| ZIP (WinZip AES)          | `-m 13600`   |                                        |
| 7-Zip                     | `-m 11600`   |                                        |
| RAR3                      | `-m 12500`   |                                        |
| RAR5                      | `-m 13000`   |                                        |
| KeePass 1                 | `-m 13400`   |                                        |
| KeePass 2                 | `-m 13400`   |                                        |
| Bitcoin wallet            | `-m 11300`   |                                        |
| Ethereum wallet           | `-m 15600`   |                                        |
| TrueCrypt AES-RIPEMD      | `-m 6211`    |                                        |
| TrueCrypt AES-SHA512      | `-m 6221`    |                                        |
| VeraCrypt SHA-256         | `-m 13751`   |                                        |
| SSH key                   | `-m 22921`   |                                        |
| PEM key                   | `-m 22921`   |                                        |
| iTunes backup             | `-m 14700`   |                                        |
| WPA/WPA2 PMKID+EAPOL      | `-m 22000`   |                                        |

```bash
# Workflow completo: estrai con *2john, cracca con hashcat
office2john documento.docx > office.hash
hashcat -m 9600 office.hash /usr/share/wordlists/rockyou.txt

# Con rules per massimizzare probabilità
hashcat -m 9600 office.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force mask (password tipo "Azienda2026!")
hashcat -m 9600 office.hash -a 3 '?u?l?l?l?l?l?l?d?d?d?d?s'
```

***

### Tabella Comparativa – Quale tool usare

| Formato   | Tool diretto       | John (\*2john)       | hashcat (GPU)             |
| --------- | ------------------ | -------------------- | ------------------------- |
| ZIP       | fcrackzip          | zip2john → john      | `-m 17200` o `-m 13600`   |
| RAR       | rarcrack (solo BF) | rar2john → john      | `-m 12500` / `-m 13000`   |
| 7z        | —                  | 7z2john → john       | `-m 11600`                |
| PDF       | pdfcrack           | pdf2john → john      | `-m 10400/10500/10600`    |
| Office    | —                  | office2john → john   | `-m 9400/9500/9600/25400` |
| KeePass   | —                  | keepass2john → john  | `-m 13400`                |
| SSH key   | —                  | ssh2john → john      | `-m 22921`                |
| PFX/P12   | crackpkcs12        | pfx2john → john      | —                         |
| TrueCrypt | truecrack (GPU)    | tc\_\* format john   | `-m 621x`                 |
| WPA/WPA2  | —                  | wpapcap2john → john  | `-m 22000` (hcxtools)     |
| Bitcoin   | —                  | bitcoin2john → john  | `-m 11300`                |
| Ethereum  | —                  | ethereum2john → john | `-m 15600`                |

```bash
# Multi-core con --fork (N processi paralleli)
john --wordlist=rockyou.txt --rules=Jumbo --fork=4 --format=nt hashes.txt

# Salva sessione con nome (per recovery)
john --wordlist=rockyou.txt --rules --session=sessione_ad hashes.txt

# Ripristina sessione interrotta
john --restore=sessione_ad

# Esegui in background
john --wordlist=rockyou.txt --rules --format=nt hashes.txt &
# Premi qualsiasi tasto per status
# Ctrl+C per sospendere (salva automaticamente)

# Status mentre gira
john --status=sessione_ad
```

***

## Percorso Operativo Consigliato

```text
1. IDENTIFICA IL FORMATO
   └─ john --list=formats | grep -i <tipo>
   └─ Guarda il prefisso: $6$ = sha512crypt, $2a$ = bcrypt, ecc.

2. LANCIA SINGLE CRACK PRIMA
   └─ john --single --format=FORMAT hashes.txt
   └─ Velocissimo, cracca password banali in secondi

3. WORDLIST + RULES
   └─ john --wordlist=rockyou.txt --rules --format=FORMAT hashes.txt
   └─ Se non basta: --rules=Jumbo poi --rules=KoreLogic

4. SE HAI FILE CIFRATI → *2john
   └─ zip2john / ssh2john / keepass2john / pdf2john / office2john
   └─ john --wordlist=rockyou.txt hash_estratto.txt

5. FALLBACK: MASK
   └─ Se conosci la struttura (lunghezza, pattern)
   └─ john --mask='?u?l?l?l?l?l?l?d' --format=FORMAT hashes.txt

6. LEGGI RISULTATI
   └─ john --show --format=FORMAT hashes.txt
   └─ cat ~/.john/john.pot (tutti i risultati globali)
```

***

## Troubleshooting

| Problema                           | Causa                                            | Soluzione                                                        |
| ---------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------- |
| `0 password hashes loaded`         | Formato hash non riconosciuto                    | Specifica `--format=` esplicitamente                             |
| `--show` dice 0 craccati           | `--show` senza `--format` dopo crack con formato | Usa `--show --format=FORMAT`                                     |
| Hash auto-rilevato sbagliato       | Collisione di formato (MD5 vs LM)                | Forza con `--format=raw-md5`                                     |
| Lentissimo su bcrypt/sha512        | Hash lenti per design — è normale                | Usa GPU con hashcat se possibile                                 |
| `zip2john: invalid file`           | ZIP non cifrato oppure corrotto                  | Verifica con `file file.zip`                                     |
| Session non si ripristina          | Nome sessione diverso                            | Usa `john --restore` senza nome (default session)                |
| Rules non fanno differenza         | `--rules` usa default (deboli)                   | Prova `--rules=Jumbo` o `--rules=KoreLogic`                      |
| Risultati in john.pot già craccati | John salta hash già nel .pot                     | Cancella con `john --pot=/dev/null` oppure `rm ~/.john/john.pot` |

***

## FAQ

**John o hashcat per NTLM?**
Con GPU potente, hashcat. NTLM è MD4 puro — hashcat su RTX 4090 fa 100+ GH/s, John su CPU fa pochi milioni. Ma se non hai GPU, John con `--fork=N` è comunque valido.

**Come cracco un hash che non riconosco?**
Usa `hash-identifier` o `hashid` per identificarlo, poi cerca il formato corretto con `john --list=formats | grep -i <nome>`.

**Come si aggiorna il .pot file?**
John.pot accumula tutti gli hash craccati globalmente. Se vuoi razzare di nuovo un hash già craccato: `john --pot=/dev/null --wordlist=rockyou.txt hash.txt`.

\**Posso usare hashcat per crackare gli hash estratti con 2john?*
Sì — la maggior parte degli hash \*2john ha un corrispondente modo in hashcat (es: `hashcat -m 22000` per WPA, `-m 13400` per KeePass). Ma devi convertire il formato manualmente. John è più comodo per il workflow completo.

**Le regole KoreLogic sono migliori di Jumbo?**
Diverse, non migliori. KoreLogic è orientata ad ambienti enterprise (password aziendali tipo `Company2026!`). Jumbo è più generale. In un AD engagement, prova entrambe.

***

## Cheat Sheet Finale

```text
=== FORMATO E IDENTIFICAZIONE ===
Lista formati:    john --list=formats | grep -i TIPO
Verifica build:   john --list=build-info | head -3
Auto-detect:      john hashes.txt  (senza --format)
Formato esplicito: john --format=nt hashes.txt

=== MODALITÀ ===
Single (veloce):  john --single --format=FORMAT hashes.txt
Wordlist:         john --wordlist=rockyou.txt --format=FORMAT hashes.txt
Rules:            john --wordlist=rockyou.txt --rules=Jumbo --format=FORMAT hashes.txt
Incremental:      john --incremental=Alnum --format=FORMAT hashes.txt
Mask:             john --mask='?u?l?l?l?l?d?d' --format=FORMAT hashes.txt

=== HASH WINDOWS ===
NTLM:             john --wordlist=rockyou.txt --format=nt hashes.txt
NTLMv2:           john --wordlist=rockyou.txt --format=netntlmv2 responder.txt
Kerberoast TGS:   john --wordlist=rockyou.txt --format=krb5tgs tgs.txt

=== HASH LINUX ===
Shadow:           john --wordlist=rockyou.txt unshadowed.txt
SHA-512:          john --wordlist=rockyou.txt --format=sha512crypt shadow.txt

=== *2JOHN SCRIPTS ===
ZIP:              zip2john file.zip > hash.txt
RAR:              rar2john file.rar > hash.txt
SSH key:          ssh2john id_rsa > hash.txt
KeePass:          keepass2john db.kdbx > hash.txt
PDF:              pdf2john.pl file.pdf > hash.txt
Office:           office2john file.docx > hash.txt
7z:               7z2john file.7z > hash.txt

=== MULTI-CORE / SESSIONI ===
Fork:             john --fork=4 --wordlist=rockyou.txt hash.txt
Sessione:         john --session=nome --wordlist=rockyou.txt hash.txt
Ripristino:       john --restore=nome
Status:           john --status=nome

=== RISULTATI ===
Mostra craccat:   john --show --format=FORMAT hashes.txt
John.pot globale: cat ~/.john/john.pot
Reset .pot:       john --pot=/dev/null hash.txt

=== RULES ===
Default:          --rules
Jumbo (3000+):    --rules=Jumbo
Enterprise:       --rules=KoreLogic
Tutto:            --rules=All
Preview rules:    john --wordlist=rockyou.txt --rules=Jumbo --stdout | head -50

=== CONFRONTO CON HASHCAT ===
NTLM:             hashcat -m 1000 -a 0 hashes.txt rockyou.txt
NTLMv2:           hashcat -m 5600 -a 0 hashes.txt rockyou.txt
sha512crypt:      hashcat -m 1800 -a 0 hashes.txt rockyou.txt
KeePass:          hashcat -m 13400 -a 0 hashes.txt rockyou.txt
```

***

**Guide correlate su hackita.it:**

* [Hashcat: GPU Password Cracking](https://hackita.it/articoli/hashcat/)
* [Credential Dumping: Come Estrarre Hash da Windows e Linux](https://hackita.it/articoli/credential-dumping/)
* [Responder: Hash Capture NTLM e NTLMv2](https://hackita.it/articoli/responder/)
* [Kerberoasting: Attacchi a Service Account AD](https://hackita.it/articoli/kerberos/)
* [SMB: NTLM Relay e Pass-the-Hash](https://hackita.it/articoli/smb/)
* [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc/)
* [Wordlist e SecLists: Guida Operativa](https://hackita.it/articoli/wordlist/)

## Riferimenti

* [John the Ripper GitHub – openwall/john](https://github.com/openwall/john)
* [Pentestmonkey – JtR Hash Formats](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

\#tools #password-cracking
