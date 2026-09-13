---
title: 'OpenSSL: Tool per TLS, Certificati e Crittografia'
slug: openssl
description: 'OpenSSL per TLS, certificati X.509, RSA ed ECDSA, PKI, s_client e crittografia. Comandi pratici per Linux, Windows, troubleshooting e pentest.'
image: /openssl-tls-certificati-crittografia.webp
draft: true
date: 2026-09-28T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - OpenSSL
  - TLS
  - certificati
  - PKI
  - Pentest
---

# OpenSSL: Guida Definitiva — Certificati, TLS, Crittografia e Security

OpenSSL è la libreria crittografica più diffusa al mondo. Alimenta le connessioni TLS dei web server, genera certificati per la PKI enterprise, diagnostica i problemi di handshake alle 3 di mattina e converte tra tutti i formati di certificato mai inventati. Se lavori con certificati, chiavi o connessioni cifrate, usi OpenSSL — spesso senza saperlo.

Questa guida copre tutto: dalla comprensione interna del protocollo TLS fino ai comandi pratici per ogni scenario — certificati, ispezione remota, crittografia file, PKI privata, e uso offensivo in contesti autorizzati.

***

## Versioni e stato attuale

OpenSSL 3.5 LTS è la versione raccomandata per la produzione, supportata fino ad aprile 2030. OpenSSL 4.0, rilasciato il 14 aprile 2026, è una release feature con breaking changes.

| Versione      | Stato                | Note                                                           |
| ------------- | -------------------- | -------------------------------------------------------------- |
| **4.0.x**     | Attuale (2026)       | Breaking changes — algoritmi deprecati disabilitati di default |
| **3.5.x LTS** | Stabile raccomandato | Supportato fino aprile 2030                                    |
| **3.0.x**     | Security-only        | EOL settembre 2026                                             |
| **1.1.1**     | ☠️ EOL               | Fine vita settembre 2023 — **migra subito**                    |

```bash
# Verifica versione installata
openssl version -a
# OpenSSL 3.5.0 8 Apr 2025 (Library: OpenSSL 3.5.0 8 Apr 2025)

# Lista tutti i subcomandi disponibili
openssl help

# Installa su Debian/Ubuntu (3.x)
sudo apt install openssl libssl-dev

# macOS — LibreSSL di default (compatibile ma diverso), installa OpenSSL reale
brew install openssl
export PATH="/opt/homebrew/opt/openssl/bin:$PATH"
```

> **OpenSSL 4.0 breaking change principale:** Note: -ssl3, -tls1, -tls1\_1 sono stati rimossi in OpenSSL 4.0 e algoritmi come MD5, RC4, DES sono disabilitati di default. Se lavori con file legacy (PKCS#12 vecchi, certificati con MD5), aggiungi `-legacy -provider default`.

***

## Come funziona TLS internamente

Prima di usare i comandi, capire il flusso TLS rende tutto più chiaro.

### Il TLS handshake passo per passo

```
[CLIENT]                              [SERVER]
    │                                     │
    │──── ClientHello ───────────────────►│
    │     (versioni TLS, cipher suites,   │
    │      estensioni, random client)     │
    │                                     │
    │◄─── ServerHello ────────────────────│
    │     (versione scelta, cipher scelto,│
    │      random server, session ID)     │
    │                                     │
    │◄─── Certificate ────────────────────│
    │     (certificato X.509 del server)  │
    │                                     │
    │◄─── ServerHelloDone ────────────────│
    │                                     │
    │──── ClientKeyExchange ─────────────►│
    │     (chiave pre-master cifrata con  │
    │      public key del server)         │
    │                                     │
    │══════ Derivazione chiave sessione ══│
    │      (entrambi calcolano la stessa  │
    │       session key dai random)       │
    │                                     │
    │──── ChangeCipherSpec ──────────────►│
    │──── Finished (cifrato) ────────────►│
    │◄─── ChangeCipherSpec ───────────────│
    │◄─── Finished (cifrato) ─────────────│
    │                                     │
    │══════ Trasferimento dati cifrato ═══│
```

**In TLS 1.3** (il default attuale) il flow è più corto — solo 1 round-trip invece di 2, e il key exchange usa sempre perfect forward secrecy.

### La chain of trust — perché il browser si fida

```
Root CA (auto-firmata, nel trust store del OS/browser)
    └── Intermediate CA (firmata dalla Root)
            └── Certificato server (firmato dall'Intermediate)
                    └── Il tuo dominio
```

Il browser si fida del certificato del server perché può risalire la catena fino a una Root CA che è già nel suo trust store (installata con il sistema operativo). Se la catena è incompleta o una CA non è trusted, il browser mostra l'errore.

***

## Formati dei certificati e chiavi

Capire i formati evita la metà degli errori. I file di certificato e chiave esistono in più formati — stessa informazione, rappresentazione diversa.

| Formato     | Estensione                     | Codifica          | Contenuto tipico                           |
| ----------- | ------------------------------ | ----------------- | ------------------------------------------ |
| **PEM**     | `.pem`, `.crt`, `.cer`, `.key` | Base64 con header | Cert, chiave, CSR — il più comune su Linux |
| **DER**     | `.der`, `.cer`                 | Binario           | Stesso di PEM ma binario — Java, Windows   |
| **PKCS#12** | `.pfx`, `.p12`                 | Binario cifrato   | Cert + chiave privata + chain in un file   |
| **PKCS#8**  | `.key`, `.pem`                 | PEM o DER         | Chiave privata con metadata del tipo       |
| **PKCS#7**  | `.p7b`, `.p7c`                 | PEM o DER         | Solo certificati (no chiave), chain        |

```bash
# Riconosci il tipo di file PEM dall'header
head -1 file.pem
# -----BEGIN CERTIFICATE-----         → certificato X.509
# -----BEGIN PRIVATE KEY-----         → chiave privata PKCS#8
# -----BEGIN RSA PRIVATE KEY-----     → chiave RSA legacy (PKCS#1)
# -----BEGIN EC PRIVATE KEY-----      → chiave EC legacy
# -----BEGIN CERTIFICATE REQUEST----- → CSR

# Ispeziona qualsiasi PEM senza saperne il tipo
openssl asn1parse -in file.pem
```

***

## Generazione chiavi private

La chiave privata è il segreto assoluto. Non si manda mai via email, non si carica su server terzi, non si mette nel repository.

### RSA

RSA è lo standard storico. RSA 2048-bit è il minimo accettato da tutte le CA. RSA 4096-bit offre un margine di sicurezza maggiore al costo di handshake TLS leggermente più lenti.

```bash
# RSA 4096 — buon bilanciamento sicurezza/compatibilità
openssl genrsa -out private.key 4096

# Con passphrase AES-256 (protegge la chiave se il file viene rubato)
openssl genrsa -aes256 -out private_enc.key 4096
# Verrà chiesta la passphrase — sceglila lunga e salvala

# Rimuovi passphrase da una chiave (necessario per web server che si avviano automaticamente)
openssl rsa -in private_enc.key -out private_nopass.key
# Inserisci la passphrase quando richiesta

# Ispeziona la chiave — modulus, exponent, ecc.
openssl rsa -in private.key -noout -text

# Estrai solo la chiave pubblica dalla privata
openssl rsa -in private.key -pubout -out public.key

# Verifica integrità chiave
openssl rsa -in private.key -check -noout
# RSA key ok
```

### ECDSA e ED25519 — il presente e il futuro

ECDSA P-256 dà sicurezza equivalente a RSA 3072 con handshake 3x più veloci. Usa RSA 4096 solo se hai bisogno di compatibilità con client molto vecchi.

```bash
# ECDSA con curva P-256 (NIST) — standard enterprise
openssl ecparam -name prime256v1 -genkey -noout -out ec_private.key

# ECDSA con curva P-384 (più sicura, leggermente più lenta)
openssl ecparam -name secp384r1 -genkey -noout -out ec_p384.key

# ED25519 — moderna, veloce, resistente ad alcune vulnerabilità side-channel
openssl genpkey -algorithm ED25519 -out ed25519_private.key

# Lista tutte le curve ellittiche supportate
openssl ecparam -list_curves

# Ispeziona chiave EC
openssl ec -in ec_private.key -noout -text
```

***

## Certificati X.509 e CSR

### CSR — Certificate Signing Request

La CSR è la richiesta di firma del certificato che invii a una CA. Contiene la tua chiave pubblica e le informazioni sul tuo dominio/organizzazione. La CA la verifica e ti restituisce il certificato firmato.

```bash
# Genera CSR dalla chiave privata esistente
openssl req -new -key private.key -out server.csr

# Genera chiave E CSR in un solo comando
openssl req -new -newkey rsa:4096 -nodes -keyout private.key -out server.csr

# CSR senza prompt interattivo — fornisci tutto via -subj
openssl req -new -key private.key -out server.csr \
  -subj "/C=IT/ST=Campania/L=Napoli/O=HackITA/OU=Security/CN=hackita.it"

# CSR con SAN (Subject Alternative Names) — obbligatorio per Chrome/Firefox moderni
# Crea file di configurazione
cat > san.cnf << EOF
[req]
default_bits = 4096
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
C=IT
ST=Campania
L=Napoli
O=HackITA
CN=hackita.it

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = hackita.it
DNS.2 = www.hackita.it
DNS.3 = api.hackita.it
EOF

openssl req -new -key private.key -out server_san.csr -config san.cnf

# Ispeziona la CSR — verifica il contenuto prima di mandarla
openssl req -in server.csr -noout -text
openssl req -in server.csr -noout -subject
```

### Certificato self-signed (per test/laboratorio)

Un certificato self-signed è firmato dalla stessa chiave che certifica. Il browser lo rifiuta in produzione (perché non c'è una CA trusted nella chain) ma è utile per test interni.

```bash
# Self-signed valido 365 giorni
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost"

# Self-signed con SAN — necessario per Chrome/Firefox anche in lab
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 3650 -nodes \
  -subj "/CN=myserver.local" \
  -addext "subjectAltName=DNS:myserver.local,DNS:localhost,IP:127.0.0.1"

# Verifica il certificato generato
openssl x509 -in cert.pem -noout -text
```

***

## Ispezione certificati

### File locali

```bash
# Mostra tutto il contenuto del certificato
openssl x509 -in cert.pem -noout -text

# Campi specifici — più veloci per script
openssl x509 -in cert.pem -noout -subject        # chi è
openssl x509 -in cert.pem -noout -issuer         # chi l'ha firmato
openssl x509 -in cert.pem -noout -dates          # validità
openssl x509 -in cert.pem -noout -serial         # numero seriale
openssl x509 -in cert.pem -noout -fingerprint -sha256  # fingerprint SHA256

# SAN — Subject Alternative Names (domini coperti)
openssl x509 -in cert.pem -noout -ext subjectAltName

# KeyUsage — cosa può fare il certificato
openssl x509 -in cert.pem -noout -ext keyUsage
openssl x509 -in cert.pem -noout -ext extendedKeyUsage

# Scade tra X giorni? (exit 0 = ancora valido)
openssl x509 -in cert.pem -noout -checkend 2592000   # 30 giorni
openssl x509 -in cert.pem -noout -checkend 0          # è già scaduto?

# Verifica che chiave e certificato siano la stessa coppia
openssl x509 -noout -modulus -in cert.pem | md5sum
openssl rsa  -noout -modulus -in private.key | md5sum
# Se i due MD5 coincidono → cert e chiave sono la stessa coppia
```

### Server remoto — `s_client`

`s_client` è uno degli strumenti più potenti di OpenSSL. Ti connette a qualsiasi servizio TLS e ti mostra tutto: certificato, chain, cipher negoziato, versione del protocollo.

```bash
# Connessione base — mostra tutta la handshake
openssl s_client -connect example.com:443

# Con SNI (Server Name Indication) — necessario per host con più certificati
openssl s_client -connect example.com:443 -servername example.com

# Solo il certificato del server — sopprime l'output della handshake
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -text

# Date di scadenza del certificato remote
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -dates

# SAN del certificato remoto
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName

# Versione TLS e cipher negoziato
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  grep -E "^(Protocol|Cipher)"

# Testa se il server supporta TLS 1.3
openssl s_client -connect example.com:443 -tls1_3 2>&1 | grep -E "Protocol|error"

# Testa TLS 1.2
openssl s_client -connect example.com:443 -tls1_2 2>&1 | grep Protocol

# Testa cipher suite specifica
openssl s_client -connect example.com:443 -cipher "ECDHE-RSA-AES256-GCM-SHA384"

# Mostra tutta la chain di certificati (root + intermediate + server)
openssl s_client -connect example.com:443 -servername example.com -showcerts 2>/dev/null

# STARTTLS — per SMTP, IMAP, POP3, FTP che upgrade da plain a TLS
openssl s_client -connect mail.example.com:25  -starttls smtp
openssl s_client -connect mail.example.com:143 -starttls imap
openssl s_client -connect mail.example.com:110 -starttls pop3
openssl s_client -connect ftp.example.com:21   -starttls ftp

# Fingerprint SHA256 del certificato remoto
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256
```

> **Nota sempre `-servername`:** senza di esso su host condivisi (CDN, shared hosting) potresti ricevere il certificato sbagliato.

***

## Costruisci la tua CA privata

Una PKI privata è fondamentale per ambienti enterprise, lab di pentesting, e certificati interni. Ti permette di firmare i tuoi certificati senza pagare una CA pubblica.

```bash
# === STEP 1: Crea la Root CA ===
mkdir -p ca/{certs,private,newcerts}
chmod 700 ca/private
echo 01 > ca/serial
touch ca/index.txt

# Genera chiave Root CA (4096 bit, cifrata — proteggi questa chiave sopra ogni altra cosa)
openssl genrsa -aes256 -out ca/private/ca.key 4096
chmod 400 ca/private/ca.key

# Genera certificato Root CA — valido 10 anni
openssl req -new -x509 -days 3650 \
  -key ca/private/ca.key \
  -out ca/certs/ca.crt \
  -subj "/C=IT/ST=Campania/O=HackITA Lab CA/CN=HackITA Root CA"

# Verifica la Root CA
openssl x509 -in ca/certs/ca.crt -noout -text

# === STEP 2: Emetti certificato per un server ===

# Genera chiave per il server
openssl genrsa -out server.key 4096

# Genera CSR per il server
openssl req -new -key server.key -out server.csr \
  -subj "/C=IT/O=HackITA/CN=lab.hackita.it"

# Firma la CSR con la nostra Root CA
# Dobbiamo aggiungere i SAN durante la firma
cat > server_ext.cnf << EOF
[v3_req]
subjectAltName = DNS:lab.hackita.it, DNS:*.hackita.it, IP:10.10.10.1
EOF

openssl x509 -req -days 365 \
  -in server.csr \
  -CA ca/certs/ca.crt \
  -CAkey ca/private/ca.key \
  -CAcreateserial \
  -out server.crt \
  -extfile server_ext.cnf \
  -extensions v3_req

# Verifica che il certificato sia firmato correttamente dalla CA
openssl verify -CAfile ca/certs/ca.crt server.crt
# server.crt: OK

# === STEP 3: Installa la Root CA nel sistema ===
# Su Debian/Ubuntu
sudo cp ca/certs/ca.crt /usr/local/share/ca-certificates/hackita-lab-ca.crt
sudo update-ca-certificates

# Su Kali/RedHat/CentOS
sudo cp ca/certs/ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract
```

***

## Conversione tra formati

Il cambio di formato è l'operazione più comune con OpenSSL — ogni applicazione vuole il suo.

### PEM ↔ DER

```bash
# PEM → DER (da testo Base64 a binario)
openssl x509 -in cert.pem -outform DER -out cert.der
openssl rsa   -in key.pem  -outform DER -out key.der

# DER → PEM (da binario a Base64)
openssl x509 -in cert.der -inform DER -outform PEM -out cert.pem
openssl rsa   -in key.der  -inform DER -outform PEM -out key.pem
```

### PEM ↔ PKCS#12 (.pfx/.p12)

Il PKCS#12 bundla certificato + chiave privata + chain in un file singolo cifrato. Usato da Windows, Java, e molte applicazioni che vogliono tutto in un file.

```bash
# PEM → PKCS#12 (cert + chiave + eventuale chain)
openssl pkcs12 -export \
  -in cert.pem \
  -inkey private.key \
  -certfile ca.crt \
  -out bundle.pfx \
  -name "mio-certificato"

# PKCS#12 → PEM (estrai tutti i componenti)
openssl pkcs12 -in bundle.pfx -out bundle.pem -nodes
# -nodes = no passphrase sulla chiave estratta

# Estrai solo il certificato dal PKCS#12
openssl pkcs12 -in bundle.pfx -nokeys -out cert_only.pem

# Estrai solo la chiave privata
openssl pkcs12 -in bundle.pfx -nocerts -nodes -out key_only.pem

# File .pfx legacy (OpenSSL 3.x+) — aggiungere -legacy per vecchi export Windows
openssl pkcs12 -in old_export.pfx -out bundle.pem -nodes -legacy
```

### PKCS#1 ↔ PKCS#8

```bash
# RSA PKCS#1 → PKCS#8 (formato moderno)
openssl pkcs8 -topk8 -inform PEM -in rsa_pkcs1.key -out rsa_pkcs8.key -nocrypt

# PKCS#8 → PKCS#1
openssl rsa -in rsa_pkcs8.key -out rsa_pkcs1.key
```

***

## Crittografia file — cifratura/decifratura

OpenSSL può cifrare e decifrare file arbitrari. Utile per trasferire file sensibili o proteggere backup.

```bash
# Cifra file con AES-256-CBC (password-based)
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 \
  -in file_originale.txt -out file_cifrato.enc
# Verrà chiesta la password

# Decifra
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -d \
  -in file_cifrato.enc -out file_recuperato.txt

# Con chiave esplicita in Base64 (per scripting)
KEY=$(openssl rand -hex 32)    # 256-bit key
IV=$(openssl rand -hex 16)     # 128-bit IV
openssl enc -aes-256-cbc -K $KEY -iv $IV -in file.txt -out file.enc

# Cifra con chiave pubblica RSA (per destinatario specifico)
openssl rsautl -encrypt -inkey public.key -pubin -in secret.txt -out secret.enc

# Decifra con chiave privata RSA
openssl rsautl -decrypt -inkey private.key -in secret.enc -out secret_dec.txt
```

***

## Hashing e verifica integrità

```bash
# Hash MD5, SHA1, SHA256, SHA512 di un file
openssl dgst -md5    file.bin
openssl dgst -sha1   file.bin
openssl dgst -sha256 file.bin
openssl dgst -sha512 file.bin

# Solo l'hash (senza il prefisso "MD5(file.bin)=")
openssl dgst -sha256 -r file.bin | awk '{print $1}'

# HMAC — hash con chiave segreta (per verifica autenticata)
openssl dgst -sha256 -hmac "chiavesegreta" file.bin

# Firma digitale — firma un file con la tua chiave privata
openssl dgst -sha256 -sign private.key -out firma.sig file.bin

# Verifica firma — verifica con la chiave pubblica del mittente
openssl dgst -sha256 -verify public.key -signature firma.sig file.bin
# Verified OK

# Genera password hash (per /etc/shadow o htpasswd)
openssl passwd -6 "mypassword"   # SHA-512 (crypt)
openssl passwd -apr1 "mypassword"  # MD5-APR (Apache)

# Genera bytes casuali crittograficamente sicuri
openssl rand -hex 32      # 32 byte in hex → chiave 256-bit
openssl rand -base64 48   # 48 byte in base64 → password random
```

***

## OpenSSL in security — uso offensivo autorizzato

OpenSSL è uno strumento essenziale anche in contesti offensivi autorizzati — ispezione TLS, estrazione informazioni da certificati, analisi PKI di un'organizzazione target.

### Enumerazione certificati di un target

Prima di un pentest web, l'analisi del certificato rivela spesso informazioni preziose: reparti interni, subdomini, software stack.

```bash
TARGET="target.com"

# Recupera e analizza il certificato
echo | openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | \
  openssl x509 -noout -text | head -80

# Estrai SAN — spesso contiene subdomain interni
echo | openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName

# Certificate Transparency — tutti i certificati emessi per un dominio
# Usa crt.sh (API pubblica, non richiede OpenSSL ma complementare)
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -m json.tool | \
  grep '"name_value"' | sort -u

# Testa quali versioni TLS supporta il server
for VER in -tls1_2 -tls1_3; do
  result=$(echo | openssl s_client -connect $TARGET:443 -servername $TARGET $VER 2>&1 | grep "Protocol")
  echo "$VER: $result"
done

# Lista cipher suites accettate (brute-force delle cipher)
for CIPHER in $(openssl ciphers 'ALL:eNULL' | tr ':' ' '); do
  result=$(echo | openssl s_client -connect $TARGET:443 -cipher $CIPHER 2>&1)
  if echo "$result" | grep -q "Cipher is"; then
    echo "[+] $CIPHER"
  fi
done
```

### Certificati ADCS — uso in ambienti Active Directory

In ambienti Windows con ADCS ([Active Directory Certificate Services](https://hackita.it/articoli/adcs-esc1-esc16/)), OpenSSL è usato per gestire i certificati generati durante attacchi ESC8/ESC11.

```bash
# Converti certificato .pem ricevuto da ntlmrelayx in .pfx
openssl pkcs12 -export -in dc01.crt -inkey dc01.key -out dc01.pfx -passout pass:

# Estrai hash NT dal certificato .pfx (via certipy o Rubeus)
# Vedi /articoli/ntlmrelayx e /articoli/golden-ticket

# Ispeziona un certificato ADCS — controlla OID di Extended Key Usage
openssl x509 -in adcs_cert.pem -noout -ext extendedKeyUsage
# 1.3.6.1.5.5.7.3.2 = Client Authentication
# 1.3.6.1.4.1.311.20.2.2 = Smart Card Logon
# 1.3.6.1.5.5.7.3.1 = Server Authentication
```

### Analisi cipher suite e weaknesses

```bash
# Controlla se il server supporta ancora cipher deboli
WEAK_CIPHERS="RC4-SHA:RC4-MD5:DES-CBC-SHA:DES-CBC3-SHA:NULL-SHA"
echo | openssl s_client -connect target.com:443 -cipher $WEAK_CIPHERS 2>&1 | \
  grep -E "Cipher|error"

# Lista cipher disponibili per categoria
openssl ciphers -v 'HIGH:!aNULL:!MD5'     # solo cipher forti
openssl ciphers -v 'LOW:!aNULL:!eNULL'    # cipher deboli
openssl ciphers -v 'NULL'                  # cipher senza cifratura

# Verifica se il server è vulnerabile a renegotiation attacks
echo | openssl s_client -connect target.com:443 2>&1 | grep "Secure Renegotiation"
# "Secure Renegotiation IS supported" → ok
# "Secure Renegotiation IS NOT supported" → vulnerabile
```

***

## PKI completa per lab pentest

Un setup completo per simulare un'infrastruttura PKI realistica in un lab:

```bash
#!/bin/bash
# setup_lab_pki.sh — crea CA + cert server + cert client per lab

DOMAIN="lab.local"
mkdir -p pki/{ca,server,client}/{certs,private}

# Root CA
openssl genrsa -out pki/ca/private/ca.key 4096
openssl req -x509 -new -nodes -key pki/ca/private/ca.key \
  -days 3650 -out pki/ca/certs/ca.crt \
  -subj "/CN=$DOMAIN Root CA/O=Lab CA"

# Server cert (es. per web server o C2)
openssl genrsa -out pki/server/private/server.key 4096
openssl req -new -key pki/server/private/server.key \
  -out pki/server/server.csr \
  -subj "/CN=server.$DOMAIN"
openssl x509 -req -days 365 \
  -in pki/server/server.csr \
  -CA pki/ca/certs/ca.crt \
  -CAkey pki/ca/private/ca.key \
  -CAcreateserial \
  -out pki/server/certs/server.crt \
  -extfile <(printf "subjectAltName=DNS:server.$DOMAIN,DNS:*.server.$DOMAIN")

# Client cert (mutual TLS — mTLS per C2 come Sliver)
openssl genrsa -out pki/client/private/client.key 4096
openssl req -new -key pki/client/private/client.key \
  -out pki/client/client.csr \
  -subj "/CN=operator.$DOMAIN"
openssl x509 -req -days 365 \
  -in pki/client/client.csr \
  -CA pki/ca/certs/ca.crt \
  -CAkey pki/ca/private/ca.key \
  -CAcreateserial \
  -out pki/client/certs/client.crt

echo "[+] PKI creata in ./pki/"
echo "    CA cert:      pki/ca/certs/ca.crt"
echo "    Server cert:  pki/server/certs/server.crt"
echo "    Client cert:  pki/client/certs/client.crt"
```

***

## Troubleshooting — errori comuni e soluzioni

| Errore                                   | Causa                                               | Soluzione                                        |
| ---------------------------------------- | --------------------------------------------------- | ------------------------------------------------ |
| `unable to load Private Key`             | Chiave cifrata, passphrase mancante                 | Aggiungi `-passin pass:PASSWORD`                 |
| `PEM_read_bio_X509: no start line`       | File non è PEM valido o è DER                       | Prova `-inform DER` o ri-scarica il file         |
| `SSL handshake has read 0 bytes`         | Server non risponde su quella porta o non parla TLS | Verifica porta, usa `-starttls` se necessario    |
| `depth=0 ... error 18: self signed`      | Certificato auto-firmato non trusted                | Normale per self-signed; in test usa `-noverify` |
| `SSL alert number 40`                    | Server ha rifiutato versione TLS o cipher           | Prova `-tls1_2` o `-tls1_3` esplicitamente       |
| `Unsupported Algorithm` (.pfx legacy)    | OpenSSL 3.x disabilita algoritmi legacy             | Aggiungi `-legacy -provider default`             |
| `unable to get local issuer certificate` | Chain incompleta                                    | Specifica `-CAfile ca_bundle.crt`                |
| `certificate has expired`                | Certificato scaduto                                 | Rinnova il certificato                           |
| `wrong number of arguments`              | Sintassi cambiata tra versioni                      | Controlla `openssl COMMAND --help`               |

```bash
# Debug generale — aumenta verbosità
openssl s_client -connect host:443 -debug 2>&1 | head -100

# Verifica che chiave e certificato matchino (modulus identici)
diff <(openssl x509 -noout -modulus -in cert.pem | md5sum) \
     <(openssl rsa  -noout -modulus -in key.pem  | md5sum) && echo "OK" || echo "MISMATCH"

# Verifica chain completa
openssl verify -CAfile ca_bundle.crt -untrusted intermediate.crt server.crt
```

***

## OpenSSL in automazione — Bash e Python

### Script Bash per monitoraggio scadenze

```bash
#!/bin/bash
# check_cert_expiry.sh — controlla scadenza certificati remoti

HOSTS=("hackita.it:443" "github.com:443" "google.com:443")
WARN_DAYS=30

for host in "${HOSTS[@]}"; do
  expiry=$(echo | openssl s_client -connect $host -servername ${host%:*} 2>/dev/null | \
    openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  
  if [ -z "$expiry" ]; then
    echo "[-] $host: impossibile connettersi"
    continue
  fi
  
  expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s)
  now_epoch=$(date +%s)
  days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
  
  if [ $days_left -lt $WARN_DAYS ]; then
    echo "[!] $host: SCADE TRA $days_left GIORNI ($expiry)"
  else
    echo "[+] $host: ok ($days_left giorni rimanenti)"
  fi
done
```

### Python — ispezione certificati

```python
import ssl
import socket
from datetime import datetime

def get_cert_info(hostname: str, port: int = 443) -> dict:
    """Recupera informazioni sul certificato TLS di un host."""
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return {
                "subject": dict(x[0] for x in cert["subject"]),
                "issuer": dict(x[0] for x in cert["issuer"]),
                "not_before": cert["notBefore"],
                "not_after": cert["notAfter"],
                "san": cert.get("subjectAltName", []),
                "version": cert["version"],
            }

info = get_cert_info("hackita.it")
print(f"CN: {info['subject'].get('commonName')}")
print(f"Issuer: {info['issuer'].get('organizationName')}")
print(f"Scade: {info['not_after']}")
print(f"SAN: {[v for _, v in info['san']]}")
```

***

## Confronto con alternative

| Tool                     | Focus                             | Quando preferirlo                               |
| ------------------------ | --------------------------------- | ----------------------------------------------- |
| **OpenSSL**              | Tutto — chiavi, cert, TLS, crypto | Standard de-facto, massima flessibilità         |
| **cfssl** (Cloudflare)   | PKI automation                    | JSON-based, API REST, CI/CD                     |
| **step-cli** (Smallstep) | PKI moderna                       | ACME, CLI ergonomica, provisioner               |
| **certbot**              | Let's Encrypt                     | Rinnovo automatico certificati pubblici         |
| **mkcert**               | Dev/lab                           | Self-signed fidati localmente senza config      |
| **age**                  | Cifratura file                    | Più semplice di `openssl enc` per utenti finali |

***

## Quick Reference

```bash
# === CHIAVI ===
openssl genrsa -out key.pem 4096              # RSA 4096
openssl genrsa -aes256 -out key_enc.pem 4096  # RSA cifrata
openssl ecparam -name prime256v1 -genkey -noout -out ec.key  # ECDSA P-256
openssl genpkey -algorithm ED25519 -out ed25519.key           # ED25519
openssl rsa -in key.pem -pubout -out pub.key  # Estrai pubkey

# === CERTIFICATI ===
openssl req -new -key key.pem -out req.csr    # CSR
openssl req -in req.csr -noout -text          # Ispeziona CSR
openssl req -x509 -newkey rsa:4096 -keyout k.pem -out c.pem -days 365 -nodes  # Self-signed
openssl x509 -in cert.pem -noout -text        # Ispeziona cert
openssl x509 -in cert.pem -noout -dates       # Date validità
openssl x509 -in cert.pem -noout -ext subjectAltName  # SAN
openssl x509 -in cert.pem -noout -checkend 2592000    # Scade entro 30g?
openssl verify -CAfile ca.crt cert.pem        # Verifica chain

# === REMOTO ===
openssl s_client -connect host:443 -servername host   # Handshake completa
echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect host:443 -tls1_3            # Testa TLS 1.3
openssl s_client -connect host:25 -starttls smtp      # SMTP STARTTLS

# === CONVERSIONI ===
openssl x509 -in c.pem -outform DER -out c.der        # PEM→DER
openssl x509 -in c.der -inform DER -out c.pem         # DER→PEM
openssl pkcs12 -export -in c.pem -inkey k.pem -out b.pfx  # PEM→PKCS12
openssl pkcs12 -in b.pfx -out b.pem -nodes            # PKCS12→PEM

# === HASHING E CIFRATURA ===
openssl dgst -sha256 file                     # SHA256
openssl enc -aes-256-cbc -pbkdf2 -in f -out f.enc  # Cifra
openssl enc -aes-256-cbc -pbkdf2 -d -in f.enc -out f  # Decifra
openssl rand -hex 32                          # 32 byte random hex
openssl passwd -6 "password"                  # Hash password SHA-512
```

***

## FAQ

**Perché il browser non accetta il mio certificato self-signed anche se è valido?**
I browser moderni richiedono SAN (Subject Alternative Names) — il campo CN da solo non basta. Aggiungi `-addext "subjectAltName=DNS:tuo-dominio"` alla generazione. Inoltre devi installare la Root CA nel trust store del browser/OS.

**Qual è la differenza tra RSA e ECDSA?**
RSA è lo standard storico basato sulla difficoltà di fattorizzare grandi numeri. ECDSA usa la matematica delle curve ellittiche — chiavi molto più corte per la stessa sicurezza, handshake più veloci. P-256 ECDSA è equivalente a RSA 3072. Usa ECDSA in ambienti moderni; RSA se hai vincoli di compatibilità con sistemi molto vecchi.

**Cosa fa `-nodes` nella generazione dei certificati?**
`-nodes` = "no DES" (abbreviazione storica). In pratica significa: non cifrare la chiave privata con una passphrase. Utile per certificati di server che si avviano automaticamente (non puoi inserire la passphrase manualmente all'avvio).

**Come rinnovo un certificato senza cambiare la chiave?**
Genera una nuova CSR dalla stessa chiave privata, mandala alla CA, installa il nuovo certificato. La chiave resta identica — nessun cambio di configurazione per le applicazioni che la usano.

**OpenSSL 3.x vs 4.0 — cosa cambia praticamente?**
Per la maggior parte dei comandi CLI nulla. I breaking changes di 4.0 riguardano principalmente l'API C (per sviluppatori che usano OpenSSL come libreria) e la rimozione di protocolli legacy (SSLv3, TLS 1.0/1.1). I tuoi script dovrebbero funzionare invariati.

***

## Articoli correlati

* [ADCS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/) — certificati AD in pentest
* [ntlmrelayx.py](https://hackita.it/articoli/ntlmrelayx/) — ESC8/ESC11 e relay verso ADCS
* [Python](https://hackita.it/articoli/python/) — automazione con ssl module
* [Bash](https://hackita.it/articoli/bash/) — script per monitoraggio certificati
* [Active Directory — exploitation](https://hackita.it/articoli/active-directory/)

***

## Fonti e riferimenti esterni

* [OpenSSL Official Documentation](https://docs.openssl.org/)
* [OpenSSL GitHub Repository](https://github.com/openssl/openssl)
* [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)

> Uso esclusivo in ambienti autorizzati.
