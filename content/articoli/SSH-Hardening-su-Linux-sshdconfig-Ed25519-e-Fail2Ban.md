---
title: 'SSH Hardening su Linux: sshd_config, Ed25519 e Fail2Ban'
slug: ssh-security-hardening
description: >-
  SSH hardening su Linux: configura sshd_config, chiavi Ed25519, Fail2Ban, UFW e
  2FA; verifica algoritmi e accessi con ssh-audit e crea un jump host.
image: /ssh-hardening-linux-ed25519-fail2ban.webp
draft: false
date: 2026-08-19T00:00:00.000Z
categories:
  - linux
subcategories:
  - comandi
tags:
  - SSH Hardening
  - OpenSSH
  - sshd_config
  - Ed25519
  - Fail2Ban
  - SSH 2FA
  - ssh-audit
---

# SSH Hardening Linux: Guida Completa a OpenSSH, Chiavi, 2FA e Fail2Ban

Un server SSH esposto direttamente a Internet è normalmente soggetto a scansioni automatiche e tentativi di autenticazione — non è una questione di "se" ma di "quando". Un SSH configurato correttamente trasforma questi tentativi in rumore di fondo innocuo.

Questa guida copre l'hardening SSH completo dalla prospettiva di chi fa sicurezza: ogni impostazione spiegata con il "perché", più la **prospettiva del pentester** — quello che un auditor testa durante un SSH security assessment.

**Prerequisiti:** accesso root al server. Articolo complementare a [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc/) — una volta dentro un sistema, la configurazione SSH è tra i primi vettori di persistence che un attaccante cerca.

***

## Cosa Controlla un Pentester Durante un SSH Security Assessment

Prima di fare hardening, capisci cosa cerca chi testa la sicurezza. Questi sono i check standard in un SSH security assessment:

```bash
# 1. Versione OpenSSH (cerca CVE specifiche)
ssh -V
nmap -sV -p 22 target.com

# 2. Algoritmi supportati (cerca algoritmi deboli)
nmap -p22 --script ssh2-enum-algos target.com
# Cerca: 3des-cbc, arcfour, diffie-hellman-group1 → tutti deboli

# 3. Host key del server
nmap -p22 --script ssh-hostkey target.com

# 4. Verifica se il server supporta ancora SSHv1 (obsoleto e vulnerabile)
nmap -p22 --script sshv1 target.com

# 5. Metodi di autenticazione supportati
nmap -p22 --script ssh-auth-methods target.com

# 6. Brute force test (solo se autorizzato esplicitamente)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target.com
hydra -L users.txt -P passwords.txt ssh://target.com -t 4

# 7. Tool di audit dedicato
pip install ssh-audit
ssh-audit target.com
```

> Nota: `ssh-auth-methods` è classificato come script *intrusive* da Nmap perché avvia un vero tentativo di autenticazione. Se lo script mostra `password` tra i metodi supportati, significa che l'autenticazione via password **è supportata dal server** — non che sia automaticamente sfruttabile. Verifica se è realmente necessaria e se esistono controlli contro il password guessing (rate limiting, Fail2Ban, MFA) prima di segnarla come finding critico.

**I finding più comuni in un SSH audit:**

* Password authentication abilitata
* Root login permesso
* Algoritmi crittografici deboli (3DES, arcfour, diffie-hellman-group1)
* MaxAuthTries alto
* Assenza di banner di warning
* Chiavi SSH vecchie (RSA 1024-bit)
* SSH esposto su tutte le interfacce invece che solo su quella necessaria

***

## Generare e Configurare Chiavi SSH Ed25519

Prima di toccare `sshd_config`, genera le chiavi corrette sul client. Sono chiavi dell'**utente**, per l'autenticazione — diverse dalle host key che il server possiede già sotto `/etc/ssh/ssh_host_*` per identificarsi verso i client.

**Ed25519 vs RSA:**

|                                | Ed25519             | RSA 4096        |
| ------------------------------ | ------------------- | --------------- |
| **Sicurezza**                  | Equivalente         | Equivalente     |
| **Dimensione chiave pubblica** | Molto più corta     | Molto più lunga |
| **Velocità**                   | ★★★★★               | ★★★             |
| **Compatibilità**              | OpenSSH 6.5+ (2014) | Universale      |
| **Raccomandato 2026**          | ✅ Sì                | Se serve legacy |

```bash
# Sul CLIENT (non sul server)

# Genera chiave Ed25519 (preferita)
ssh-keygen -t ed25519 -C "commento-descrittivo-2026"

# Con numero di rounds KDF (maggiore = più lento per attacchi offline sulla chiave cifrata)
ssh-keygen -t ed25519 -a 100 -C "server-prod-2026"

# RSA 4096 (se devi supportare sistemi legacy)
ssh-keygen -t rsa -b 4096 -C "legacy-compat-2026"

# Le chiavi vengono salvate in:
# ~/.ssh/id_ed25519      (privata — non condividere MAI)
# ~/.ssh/id_ed25519.pub  (pubblica — va sul server)
```

```bash
# Copia la chiave pubblica sul server
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Oppure manualmente
cat ~/.ssh/id_ed25519.pub | ssh user@server "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

# Verifica che funzioni PRIMA di disabilitare le password
ssh -i ~/.ssh/id_ed25519 user@server
```

> **Regola d'oro:** testa sempre il login con chiave in una sessione separata prima di disabilitare le password. Se rompi l'autenticazione e chiudi la sessione corrente, ti blocchi fuori dal server.

***

## sshd\_config: Configurazione SSH Sicura

Il file centrale è `/etc/ssh/sshd_config`. Prima di qualsiasi modifica:

```bash
# SEMPRE backup prima di modificare
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Testa sintassi dopo ogni modifica (prima di riavviare!)
sudo sshd -t

# Verifica configurazione effettiva (include i default)
sudo sshd -T | grep -E 'passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|allowusers|allowgroups'

# Applica le modifiche: reload se possibile, restart se necessario
sudo sshd -t && sudo systemctl reload ssh    # Ubuntu/Debian, meno disruptivo
sudo sshd -t && sudo systemctl restart ssh   # se reload non basta
sudo sshd -t && sudo systemctl restart sshd  # RHEL/CentOS/Arch
```

### Disabilitare Password Authentication

Questa è la modifica più importante. Un dettaglio tecnico spesso sbagliato: `ChallengeResponseAuthentication` è un alias ormai deprecato nelle versioni moderne di OpenSSH. Il parametro corretto oggi è `KbdInteractiveAuthentication`.

```text
# Autenticazione: solo chiavi pubbliche
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes

# Dove sono le chiavi autorizzate
AuthorizedKeysFile .ssh/authorized_keys
```

`KbdInteractiveAuthentication` non è semplicemente "password con un altro nome" — è un metodo di autenticazione distinto (`keyboard-interactive`) che PAM può usare per chiedere una password, ma anche per un codice OTP o altro. Per questo qui va disabilitato solo se **non** usi PAM/2FA — se più avanti configuri il TOTP, tornerà a `yes` perché il codice viene richiesto proprio tramite `keyboard-interactive`.

### Disabilitare Root Login e Limitare gli Utenti

```text
# NO login diretto come root — usa utente normale + sudo
PermitRootLogin no

# Permetti SSH solo a utenti specifici
AllowUsers mario deploy backup
# Oppure per gruppo
# AllowGroups sshusers
```

### Limitare Forwarding e Tunneling

Il port forwarding può diventare un vettore utile a un attaccante che ha già accesso, per pivoting o esfiltrazione. Se l'account deve solo fare login e non ha bisogno di forwarding:

```text
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no

# In alternativa/insieme a policy più granulari, sulle versioni che lo supportano:
# DisableForwarding yes
```

### Tentativi, Timeout e Porta

```text
# Cambia da 22 a porta non standard. Riduce significativamente il rumore
# degli scanner automatici che puntano solo alla 22 — non è però una
# misura di sicurezza primaria: uno scanner può trovare SSH su qualsiasi porta.
Port 2222

AddressFamily inet

# Max tentativi prima della disconnessione
MaxAuthTries 3
MaxSessions 10

# Timeout per completare il login
LoginGraceTime 30

# Disconnetti client inattivi
ClientAliveInterval 300
ClientAliveCountMax 3
```

### Algoritmi Crittografici

Non trattare questa lista come statica e definitiva: parti dagli algoritmi supportati dalla versione di OpenSSH effettivamente installata e rimuovi esplicitamente quelli legacy/deboli, verificando con `ssh-audit` (sezione più avanti) invece di copiare una lista senza controllarne la compatibilità con la tua versione.

```text
# Esempio di partenza — verifica compatibilità con la tua versione OpenSSH
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# HostKeyAlgorithms controlla quali algoritmi il client può usare per
# autenticare la host key del server — non genera né sceglie la chiave
# sul filesystem, quella è governata dalle direttive HostKey
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
```

### Banner, Logging e Altre Opzioni

```text
Banner /etc/ssh/banner.txt

LogLevel VERBOSE
SyslogFacility AUTH

# Opzione legacy/compatibilità, non tra le misure di hardening principali
# sulle versioni moderne — evita solo un lookup DNS per connessione
UseDNS no

# Di default OpenSSH ha Compression yes. Disabilitarla riduce una
# superficie non necessaria quando non serve, ma il beneficio reale
# riguarda soprattutto scenari di port forwarding con traffico misto
# trusted/untrusted — non è un hardening obbligatorio generico
Compression no

TCPKeepAlive yes
PrintMotd no
```

```bash
# Crea il banner di avviso
sudo tee /etc/ssh/banner.txt << 'EOF'
 ╔══════════════════════════════════════════╗
 ║  ACCESSO AUTORIZZATO SOLO               ║
 ║  Tutte le attività vengono registrate   ║
 ╚══════════════════════════════════════════╝
EOF

sudo sshd -t && echo "OK" || echo "ERRORE — non riavviare!"
sudo systemctl reload ssh
```

***

## Fail2Ban per Proteggere SSH dal Brute Force

Fail2Ban monitora il log di autenticazione e banna automaticamente gli IP dopo N tentativi falliti.

```bash
sudo apt install fail2ban -y

# Non modificare jail.conf — crea jail.local
sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Whitelist del tuo IP (non bannarti da solo!)
ignoreip = 127.0.0.1/8 192.168.1.0/24 TUO_IP_FISSO

bantime  = 3600    # Ban per 1 ora
findtime = 600     # Finestra di 10 minuti
maxretry = 3       # 3 tentativi falliti → ban

[sshd]
enabled  = true
port     = 2222    # ← aggiorna con la tua porta
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

sudo fail2ban-client status sshd
```

> Il `logpath` non è uguale su tutte le distribuzioni — non tutti i sistemi usano `/var/log/auth.log` (alcuni loggano via `journalctl`/systemd invece che su file). Verifica con `sudo fail2ban-client get sshd logpath` e adegua se necessario.

```text
Status for the jail: sshd
|- Filter
|  |- Currently failed: 2
|  |- Total failed: 47
|  `- File list: /var/log/auth.log
`- Actions
   |- Currently banned: 1
   |- Total banned: 8
   `- Banned IP list: 203.0.113.50
```

```bash
sudo fail2ban-client status sshd            # Stato jail + IP bannati
sudo fail2ban-client set sshd unbanip IP    # Sblocca un IP (se ti sei bannato)
sudo tail -f /var/log/fail2ban.log          # Log in tempo reale
```

***

## Firewall: Limitare l'Accesso alla Porta SSH

> ⚠️ **Prima di abilitare UFW su un VPS remoto, assicurati di aver consentito la porta SSH corretta.** Tieni aperta una console out-of-band del provider (pannello DigitalOcean/Hetzner/AWS) finché non hai verificato che la regola funzioni — è molto facile tagliarsi fuori dal proprio server con una regola firewall sbagliata su una sessione remota.

```bash
sudo apt install ufw -y

# Regola base: permetti SSH solo dalla tua rete/IP
# (cambia la porta se hai cambiato Port in sshd_config)
sudo ufw allow from 192.168.1.0/24 to any port 2222

# Se devi permettere accesso da ovunque (meno sicuro)
sudo ufw allow 2222/tcp

sudo ufw enable
sudo ufw status verbose
```

```text
Status: active
To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW       192.168.1.0/24
```

***

## Aggiungere 2FA TOTP a SSH

Con 2FA, anche se un attaccante ruba la chiave SSH ha bisogno anche del codice TOTP (che cambia ogni 30 secondi).

```bash
sudo apt install libpam-google-authenticator -y

# Configura per l'utente (esegui come utente normale, non root)
google-authenticator
# Time-based tokens? → y
# Update .google_authenticator file? → y
# Disallow multiple uses? → y
# Rate limiting? → y
# Scansiona il QR code con Google Authenticator / Authy / Aegis
```

```bash
sudo nano /etc/pam.d/sshd
# Aggiungi in cima:
auth required pam_google_authenticator.so
```

In `sshd_config`, ricorda che qui `KbdInteractiveAuthentication` va **riattivato** — è il meccanismo con cui PAM chiede il codice TOTP:

```text
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

`AuthenticationMethods` richiede il completamento dei metodi elencati, nell'ordine indicato: prima la chiave pubblica, poi il codice keyboard-interactive.

```bash
sudo sshd -t && sudo systemctl reload ssh

# Test: il login chiederà prima la chiave, poi il codice TOTP
ssh -i ~/.ssh/id_ed25519 -p 2222 user@server
# Verification code: 123456
```

***

## SSH Bastion Host e ProxyJump

Per accedere a server interni senza esporli a Internet, usa un bastion host (unico server con SSH pubblico).

```bash
# Struttura:
# Tu → [Bastion pubblico :2222] → [Server interno 10.0.0.50:22]

# Metodo 1: ProxyJump (OpenSSH 7.3+)
ssh -J user@bastion.com:2222 user@10.0.0.50

# Metodo 2: config in ~/.ssh/config (più comodo)
nano ~/.ssh/config
```

```text
Host bastion
    HostName bastion.company.com
    User mario
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host server-interno
    HostName 10.0.0.50
    User mario
    ProxyJump bastion
    IdentityFile ~/.ssh/id_ed25519
```

```bash
ssh server-interno   # Passa automaticamente per il bastion
scp -J bastion file.txt mario@server-interno:/tmp/
```

***

## Come Fare un SSH Security Audit

```bash
# ssh-audit — audit completo della configurazione e degli algoritmi
pip install ssh-audit
ssh-audit localhost     # Il tuo server
ssh-audit target.com    # Un server remoto
```

```text
[info] SSH server version: OpenSSH 9.6
[warn] kex algorithm: diffie-hellman-group14-sha256 -- [info] 2048-bit moduli found
[fail] cipher: 3des-cbc -- [fail] vulnerable to SWEET32
[pass] cipher: chacha20-poly1305@openssh.com -- [info] available since OpenSSH 6.5
```

```bash
# Lynis — audit completo del sistema (include SSH)
sudo apt install lynis -y
sudo lynis audit system

# Monitoring login in tempo reale
sudo tail -f /var/log/auth.log | grep "sshd"

# Tentativi falliti nelle ultime 24h
sudo grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %d)" | wc -l

# IP che attaccano di più
sudo grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Login riusciti
sudo grep "Accepted" /var/log/auth.log | tail -20
```

***

## Percorso Operativo – Hardening SSH in Ordine

```text
1. GENERA CHIAVE ED25519 (sul client)
   └─ ssh-keygen -t ed25519 -a 100 -C "server-desc-2026"
   └─ ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

2. VERIFICA LOGIN CON CHIAVE (sessione separata!)
   └─ ssh -i ~/.ssh/id_ed25519 user@server
   └─ NON chiudere la sessione corrente finché non funziona

3. BACKUP E MODIFICA sshd_config
   └─ sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
   └─ PasswordAuthentication no, KbdInteractiveAuthentication no, PermitRootLogin no...
   └─ sudo sshd -t  → verifica sintassi
   └─ sudo systemctl reload ssh

4. CONFIGURA FAIL2BAN
   └─ /etc/fail2ban/jail.local con porta e logpath corretti
   └─ ignoreip = tuo IP fisso

5. FIREWALL (con console out-of-band aperta)
   └─ Permetti solo dalla tua rete/IP
   └─ sudo ufw allow from IP to any port PORTA

6. OPZIONALE: 2FA TOTP
   └─ google-authenticator per l'utente
   └─ KbdInteractiveAuthentication yes + AuthenticationMethods publickey,keyboard-interactive

7. AUDIT FINALE
   └─ ssh-audit localhost → verifica findings
   └─ nmap --script ssh-auth-methods -p PORTA localhost
```

***

## SSH Hardening Checklist

```text
[ ] OpenSSH aggiornato
[ ] PasswordAuthentication no
[ ] KbdInteractiveAuthentication no (yes solo se usi 2FA)
[ ] PermitRootLogin no
[ ] PubkeyAuthentication yes
[ ] Chiavi Ed25519 utilizzate
[ ] Chiavi private protette da passphrase
[ ] AllowUsers / AllowGroups configurato
[ ] MaxAuthTries ridotto
[ ] X11Forwarding disabilitato
[ ] AllowAgentForwarding disabilitato se non necessario
[ ] AllowTcpForwarding disabilitato se non necessario
[ ] PermitUserEnvironment no
[ ] Algoritmi legacy rimossi (verificati con ssh-audit)
[ ] Distinzione chiara tra user key e host key del server
[ ] Fail2Ban configurato, logpath verificato
[ ] Firewall configurato con console out-of-band a disposizione
[ ] 2FA configurato dove richiesto dall'engagement/policy
[ ] sshd -t eseguito prima di reload/restart
[ ] Login verificato da una seconda sessione prima di chiudere quella attiva
```

***

## Troubleshooting

| Problema                        | Causa                                                   | Soluzione                                                                                         |
| ------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Bloccato fuori dal server       | Password auth disabilitata senza chiave funzionante     | Usa console VPS (pannello del provider), ripristina `sshd_config.bak`                             |
| `sshd -t` dà errore             | Sintassi sbagliata in sshd\_config                      | Leggi il messaggio di errore, correggi la riga indicata                                           |
| Fail2Ban non banna              | Porta o logpath sbagliati in jail.local                 | Verifica `port` e usa `fail2ban-client get sshd logpath`                                          |
| 2FA non chiede il codice        | PAM non configurato o `KbdInteractiveAuthentication no` | Verifica `/etc/pam.d/sshd` e che sia impostato `yes` quando usi 2FA                               |
| `Permission denied (publickey)` | Chiave non copiata o permessi sbagliati                 | `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys` sul server                                 |
| Algoritmi deboli in ssh-audit   | Config non aggiornata                                   | Rivedi Ciphers/MACs/KexAlgorithms verificando la compatibilità con la versione OpenSSH installata |

***

## FAQ

**Cambiare la porta da 22 serve davvero?**
Non è una misura di sicurezza primaria — un port scan trova SSH su qualsiasi porta. Riduce però in modo significativo il rumore dei bot che scansionano solo la porta 22 di default, rendendo i log molto più leggibili.

**Ed25519 o RSA?**
Ed25519 per i sistemi moderni: più veloce, chiave più corta, sicurezza equivalente. RSA 4096 solo per compatibilità con sistemi legacy che non supportano Ed25519.

**`ChallengeResponseAuthentication` o `KbdInteractiveAuthentication`?**
`KbdInteractiveAuthentication` è il parametro corretto e attuale — `ChallengeResponseAuthentication` è un alias deprecato mantenuto solo per compatibilità.

**Il 2FA con chiave SSH è necessario?**
Se la chiave privata è protetta da una passphrase forte e non è mai esposta, non è strettamente indispensabile. Se usi una chiave senza passphrase (comune per automazione), il 2FA aggiunge un livello di protezione importante.

**Come gestisco più chiavi per diversi server?**
Con `~/.ssh/config`: un blocco `Host` per ogni server, con `IdentityFile` specifico per ciascuno.

**Come rimuovo chiavi SSH non autorizzate?**
Controlla `~/.ssh/authorized_keys` sul server e rimuovi le righe sconosciute — un attaccante che ottiene accesso spesso aggiunge la propria chiave lì per mantenere la persistenza.

***

## Cheat Sheet Finale

```text
=== GENERAZIONE CHIAVI ===
Ed25519:      ssh-keygen -t ed25519 -a 100 -C "desc-2026"
RSA legacy:   ssh-keygen -t rsa -b 4096 -C "desc-2026"
Copia su srv: ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
Test:         ssh -i ~/.ssh/id_ed25519 user@server

=== SSHD_CONFIG CHIAVE ===
Port 2222
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no      # yes se usi 2FA
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
AllowUsers mario deploy
X11Forwarding no
AllowTcpForwarding no
PermitUserEnvironment no

=== SYNTAX CHECK ===
Test config:    sudo sshd -t
Show effettivo: sudo sshd -T | grep -E 'passwordauthentication|kbdinteractiveauthentication|permitrootlogin'
Applica:        sudo sshd -t && sudo systemctl reload ssh

=== FAIL2BAN ===
Install:      sudo apt install fail2ban
Config:       /etc/fail2ban/jail.local
Logpath:      sudo fail2ban-client get sshd logpath
Status:       sudo fail2ban-client status sshd
Unban IP:     sudo fail2ban-client set sshd unbanip IP

=== FIREWALL UFW (con console out-of-band aperta) ===
Permetti IP:  sudo ufw allow from TUO_IP to any port 2222
Status:       sudo ufw status verbose

=== 2FA ===
Setup:        google-authenticator
PAM:          auth required pam_google_authenticator.so in /etc/pam.d/sshd
sshd_config:  KbdInteractiveAuthentication yes + AuthenticationMethods publickey,keyboard-interactive

=== AUDIT ===
ssh-audit:      pip install ssh-audit && ssh-audit localhost
Lynis:          sudo lynis audit system
Algoritmi:      nmap -p22 --script ssh2-enum-algos target
Host key:       nmap -p22 --script ssh-hostkey target
SSHv1 check:    nmap -p22 --script sshv1 target
Auth methods:   nmap -p22 --script ssh-auth-methods target

=== JUMP HOST ===
Config:       Host server → ProxyJump bastion in ~/.ssh/config
Uso:          ssh server-interno
```

***

**Guide correlate su hackita.it:**

* [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc/)
* [Credential Dumping: Come Estrarre Hash](https://hackita.it/articoli/credential-dumping/)

## Riferimenti

* [OpenSSH sshd\_config man page](https://man.openbsd.org/sshd_config)
* [ssh-audit – configurazione e cipher hardening](https://github.com/jtesta/ssh-audit)
