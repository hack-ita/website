---
title: 'Porta 3690 SVN: Repository Esposti e Secret Leakage'
slug: porta-3690-svn
description: 'Porta 3690 SVN nel pentest: repository esposti, checkout anonimo, history dei commit, source code disclosure e credenziali recuperabili.'
image: /porta-3690-svn.webp
draft: true
date: 2026-04-14T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Subversion
  - Source Code Disclosure
  - Secret Leakage
---

Apache Subversion (SVN) è un sistema di controllo versione centralizzato ancora molto diffuso in ambienti enterprise, specialmente dove Git non è stato adottato. Il protocollo nativo `svn://` ascolta sulla porta 3690 TCP e permette l'accesso ai repository senza passare per un web server. Nel penetration testing, un SVN esposto senza autenticazione — o con credenziali deboli — è una miniera: contiene codice sorgente completo dell'applicazione (con commenti, TODO e workaround), file di configurazione con credenziali hardcoded, chiavi API, certificati e l'intera history delle modifiche — incluse le credenziali che qualcuno ha "rimosso" in un commit successivo ma che restano nella history per sempre.

L'errore più comune è pensare "ho rimosso la password dal file di configurazione, quindi è sicuro". In SVN (come in Git), la history conserva ogni versione di ogni file. Se una password è stata committata anche una sola volta, è recuperabile.

## Come Funziona SVN

```
Developer                          SVN Server (:3690)
┌──────────────┐                   ┌──────────────────────┐
│ svn checkout │                   │ Repository:          │
│ svn commit   │ ── svn:// ──────►│  /svn/webapp         │
│ svn update   │                   │  /svn/infrastructure │
│              │ ◄── file data ──  │  /svn/internal-tools │
└──────────────┘                   │                      │
                                   │ Ogni repo contiene:  │
                                   │  trunk/ (main)       │
                                   │  branches/           │
                                   │  tags/               │
                                   └──────────────────────┘
```

A differenza di Git (distribuito), SVN è centralizzato: il server ha tutta la history, il client scarica solo ciò che serve. La porta 3690 usa il protocollo nativo `svn://` (non criptato). SVN può anche essere esposto via HTTP/HTTPS (Apache mod\_dav\_svn) sulle porte 80/443 — in quel caso le tecniche di enumerazione web standard si applicano.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 3690 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
3690/tcp open  svnserve Subversion
```

### Lista repository

```bash
svn list svn://10.10.10.40/
```

```
webapp/
infrastructure/
internal-tools/
legacy-app/
```

Se la lista funziona senza credenziali → accesso anonimo attivo. Quattro repository esposti.

```bash
# Lista contenuto di un repository
svn list svn://10.10.10.40/webapp/trunk/
```

```
src/
config/
docker/
scripts/
README.md
pom.xml
.env.example
```

### Info del repository

```bash
svn info svn://10.10.10.40/webapp
```

```
Path: webapp
URL: svn://10.10.10.40/webapp
Repository Root: svn://10.10.10.40/webapp
Repository UUID: 12345678-abcd-efgh-ijkl-123456789012
Revision: 1523
Last Changed Author: j.smith
Last Changed Date: 2026-01-14 17:30:00 +0100
Last Changed Rev: 1523
```

**Intelligence:** 1523 revisioni (molta history da analizzare), ultimo commit di `j.smith` → username valido per [brute force SSH](https://hackita.it/articoli/ssh) o [RDP](https://hackita.it/articoli/porta-3389-rdp).

## 2. Checkout — Scaricare il Repository

### Checkout completo

```bash
svn checkout svn://10.10.10.40/webapp /tmp/svn_webapp
```

```
A    /tmp/svn_webapp/trunk/src/main/java/...
A    /tmp/svn_webapp/trunk/config/application.yml
A    /tmp/svn_webapp/trunk/.env.example
...
Checked out revision 1523.
```

Hai una copia completa del codice sorgente. Se il checkout richiede credenziali:

```bash
svn checkout svn://10.10.10.40/webapp --username admin --password admin
```

Prova credenziali comuni: `admin:admin`, `svn:svn`, `guest:guest`, `anonymous:anonymous`.

### Export (senza metadata SVN)

```bash
svn export svn://10.10.10.40/webapp/trunk /tmp/svn_export
```

Export scarica i file senza le directory `.svn/` — più pulito per l'analisi.

## 3. Cercare Credenziali nel Codice

### File di configurazione

```bash
# File .env
find /tmp/svn_webapp -name ".env" -o -name ".env.*" -exec cat {} \; 2>/dev/null
```

```
DB_HOST=db-prod.corp.internal
DB_USER=webapp
DB_PASSWORD=W3bApp_Pr0d!
REDIS_URL=redis://10.10.10.50:6379
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SECRET=super_secret_jwt_key_2025
```

Credenziali per [MySQL](https://hackita.it/articoli/porta-3306-mysql), [Redis](https://hackita.it/articoli/porta-6379-redis), [AWS](https://hackita.it/articoli/aws-privilege-escalation) e JWT secret.

```bash
# Configurazioni applicative
find /tmp/svn_webapp -name "*.yml" -o -name "*.yaml" -o -name "*.properties" -o -name "*.xml" -o -name "*.conf" | \
  xargs grep -liE "password|secret|token|api_key|jdbc" 2>/dev/null
```

```bash
# Grep massivo
grep -riE "password|passwd|secret|token|api_key|private_key|aws_|jdbc:|mongodb://|redis://|smtp" /tmp/svn_webapp/ 2>/dev/null | grep -v ".svn" | head -50
```

### Chiavi SSH e certificati

```bash
find /tmp/svn_webapp -name "id_rsa" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" 2>/dev/null
```

### Dockerfile e docker-compose

```bash
cat /tmp/svn_webapp/trunk/docker/docker-compose.yml
```

```yaml
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: RootDBP@ss2025!
      MYSQL_DATABASE: webapp
  redis:
    image: redis:7
    command: redis-server --requirepass RedisP@ss!
```

Credenziali dei servizi in chiaro nel docker-compose.

### Script di deploy

```bash
find /tmp/svn_webapp -name "deploy*" -o -name "*.sh" | xargs grep -iE "ssh|scp|password|key" 2>/dev/null
```

```bash
#!/bin/bash
# deploy.sh
scp -i /opt/keys/prod_key target.war admin@10.10.10.50:/opt/tomcat/webapps/
ssh admin@10.10.10.50 "systemctl restart tomcat"
```

Path della chiave SSH, hostname del server di produzione, utente — tutto esposto.

## 4. History Analysis — Il Tesoro Nascosto

La feature più potente per il pentester: SVN conserva ogni versione di ogni file. Le credenziali "rimosse" sono nella history.

### Log delle modifiche

```bash
svn log svn://10.10.10.40/webapp -l 50
```

```
r1523 | j.smith | 2026-01-14 17:30:00 | Remove hardcoded credentials
r1520 | j.smith | 2026-01-14 15:00:00 | Add database connection
r1485 | admin   | 2025-12-20 10:00:00 | Initial deployment config
r1200 | devops  | 2025-09-01 09:00:00 | Add AWS credentials for CI/CD
...
```

Il commit r1523 "Remove hardcoded credentials" → le credenziali erano nel commit PRECEDENTE (r1522 o r1520).

### Recuperare una versione precedente

```bash
# Vedi cosa è cambiato nel commit che ha "rimosso" le credenziali
svn diff -c 1523 svn://10.10.10.40/webapp
```

```diff
--- config/database.yml (revision 1522)
+++ config/database.yml (revision 1523)
@@ -1,5 +1,5 @@
 production:
   adapter: mysql2
-  username: root
-  password: Pr0duction_DB_2025!
+  username: <%= ENV['DB_USER'] %>
+  password: <%= ENV['DB_PASS'] %>
```

La password `Pr0duction_DB_2025!` è stata "rimossa" ma il diff la mostra chiaramente.

```bash
# Checkout di una revisione specifica (quella CON le credenziali)
svn checkout -r 1522 svn://10.10.10.40/webapp /tmp/svn_old
cat /tmp/svn_old/trunk/config/database.yml
```

### Cercare nella history in modo sistematico

```bash
# Cerca commit con messaggi sospetti
svn log svn://10.10.10.40/webapp | grep -iEB2 "password|credential|secret|remove.*key|fix.*leak|oops"
```

```bash
# Diff completo tra la prima e l'ultima revisione
svn diff -r 1:HEAD svn://10.10.10.40/webapp | grep -iE "^\+.*password|^\+.*secret|^\+.*token|^\+.*api_key"
```

Le righe con `+` sono aggiunte — mostra tutte le credenziali che sono state aggiunte in qualsiasi momento della history.

### Username dalla history

```bash
svn log svn://10.10.10.40/webapp | grep "^r[0-9]" | awk '{print $3}' | sort -u
```

```
admin
devops
j.smith
m.rossi
svc_build
```

Cinque username → target per [brute force](https://hackita.it/articoli/vulnerability-exploitation) su SSH, RDP, VPN, web login.

## 5. SVN via HTTP (Apache mod\_dav\_svn)

Se SVN è esposto via HTTP/HTTPS anziché sulla porta 3690:

```bash
# Enumera da web
svn list http://10.10.10.40/svn/webapp/

# Cerca directory .svn esposte su web server
curl -s http://10.10.10.40/.svn/entries
curl -s http://10.10.10.40/.svn/wc.db
```

Se `.svn/entries` o `.svn/wc.db` sono accessibili, il repository SVN working copy è esposto. Usa tool come `svn-extractor` per ricostruire il sorgente:

```bash
# svn-extractor
python3 svn-extractor.py --url http://10.10.10.40/.svn/ --output /tmp/extracted/
```

## 6. Detection & Hardening

* **Autenticazione obbligatoria** — configura `svnserve.conf` con `auth-access = write` e `anon-access = none`
* **Mai `anon-access = read`** su repository con codice sensibile
* **Usa SVN via HTTPS** (Apache mod\_dav\_svn con TLS) invece del protocollo nativo sulla 3690
* **Firewall** — porta 3690 raggiungibile solo dalla rete di sviluppo
* **Non committare credenziali** — usa variabili d'ambiente o secret manager
* **svn:ignore** per file `.env` e chiavi
* **Pre-commit hook** che blocca commit con pattern di credenziali
* **Migra a Git** con repository privati — SVN è end-of-trend nel 2026

## 7. Cheat Sheet Finale

| Azione              | Comando                                                          |
| ------------------- | ---------------------------------------------------------------- |
| Nmap                | `nmap -sV -p 3690 target`                                        |
| Lista repo          | `svn list svn://target/`                                         |
| Info repo           | `svn info svn://target/repo`                                     |
| Checkout            | `svn checkout svn://target/repo /tmp/out`                        |
| Con creds           | `svn checkout svn://target/repo --username user --password pass` |
| Checkout revisione  | `svn checkout -r REVNUM svn://target/repo /tmp/old`              |
| Log                 | `svn log svn://target/repo -l 50`                                |
| Diff commit         | `svn diff -c REVNUM svn://target/repo`                           |
| Cerca password      | `grep -riE "password\|secret\|token" /tmp/out/`                  |
| Username dalla log  | `svn log ... \| grep "^r" \| awk '{print \$3}' \| sort -u`       |
| History credenziali | `svn diff -r 1:HEAD svn://target/repo \| grep "+.*password"`     |
| .svn web exposure   | `curl -s http://target/.svn/entries`                             |

***

Riferimento: Apache Subversion documentation, OWASP source code disclosure, HackTricks SVN. Uso esclusivo in ambienti autorizzati. [https://www.verylazytech.com/subversion-svn-server-port-3690](https://www.verylazytech.com/subversion-svn-server-port-3690)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
