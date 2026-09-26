---
title: 'Osquery: SQL-Based Endpoint Monitoring per Linux, macOS e Windows'
slug: osquery
description: >-
  Osquery permette di interrogare sistemi operativi con query SQL per analizzare
  processi, utenti, file e configurazioni in ottica security monitoring.
image: /Gemini_Generated_Image_7mmmr37mmmr37mmm.webp
draft: false
date: 2026-02-21T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - endpoint-monitoring
---

## Introduzione

Osquery trasforma il sistema operativo in un database relazionale interrogabile con SQL. Processi, connessioni di rete, utenti, servizi, cron job, chiavi SSH, moduli kernel, certificati — tutto diventa una tabella SQL che puoi interrogare con `SELECT`. Nel penetration testing lo usi sia in fase di post-exploitation per enumeration, sia come tool difensivo per threat hunting.

`osqueryi` è la shell interattiva, `osqueryd` è il daemon per monitoring continuo. Per il pentest, la shell interattiva è quello che serve.

Kill chain: **Discovery** (MITRE ATT\&CK T1082, T1057, T1049).

***

## 1️⃣ Setup e Installazione

```bash
sudo apt install osquery
```

Avvio shell: `osqueryi`. Funziona su Linux, macOS, Windows.

***

## 2️⃣ Uso Base

```bash
osqueryi
```

```sql
-- Lista processi
SELECT pid, name, path, cmdline FROM processes;

-- Connessioni di rete attive
SELECT pid, local_address, local_port, remote_address, remote_port FROM process_open_sockets WHERE state = 'ESTABLISHED';

-- Utenti del sistema
SELECT uid, username, shell, directory FROM users;

-- Cron jobs
SELECT * FROM crontab;
```

***

## 3️⃣ Tecniche Operative

### Trovare processi sospetti

```sql
SELECT pid, name, path, cmdline, uid FROM processes WHERE on_disk = 0;
```

Processi senza binario su disco — possibili memory-only implant.

### Connessioni verso IP esterni

```sql
SELECT p.name, p.pid, pos.remote_address, pos.remote_port
FROM processes p JOIN process_open_sockets pos ON p.pid = pos.pid
WHERE pos.remote_address NOT LIKE '10.%' AND pos.remote_address NOT LIKE '172.16.%'
AND pos.remote_address NOT LIKE '192.168.%' AND pos.remote_address != '127.0.0.1';
```

### Chiavi [SSH](https://hackita.it/articoli/ssh/) autorizzate

```sql
SELECT * FROM authorized_keys;
```

### Binari [SUID](https://hackita.it/articoli/suid/)

```sql
SELECT path, permissions FROM suid_bin;
```

Target per privilege escalation.

### Startup items e persistence

```sql
SELECT name, path, status FROM startup_items;
SELECT * FROM crontab;
SELECT * FROM systemd_units WHERE active_state = 'active';
```

***

## 4️⃣ Tecniche Avanzate

### Query one-liner da bash

```bash
osqueryi --json "SELECT pid, name, remote_address, remote_port FROM process_open_sockets WHERE state='ESTABLISHED'" | jq .
```

### Enumerazione per [privilege escalation](https://hackita.it/articoli/linux-privesc/)

```sql
SELECT path, permissions FROM suid_bin WHERE path NOT LIKE '/usr/bin%' AND path NOT LIKE '/usr/sbin%';
SELECT * FROM sudoers;
SELECT name, path FROM kernel_modules WHERE status = 'Live';
```

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Post-exploitation enum

```sql
SELECT name, path, cmdline FROM processes WHERE uid = 0;
SELECT * FROM suid_bin;
SELECT * FROM authorized_keys;
```

**Timeline:** 10 secondi per tutte le query.

### Scenario 2: Trovare C2 callback

```sql
SELECT p.name, pos.remote_address, pos.remote_port FROM processes p JOIN process_open_sockets pos ON p.pid = pos.pid WHERE pos.remote_port IN (4444, 8443, 443, 8080);
```

### Scenario 3: IOC hunting

```sql
SELECT * FROM file WHERE path LIKE '/tmp/%' AND size > 1000000;
SELECT * FROM hash WHERE path LIKE '/tmp/%';
```

***

## 6️⃣ Toolchain Integration

**Flusso:** Shell → **Osqueryi (system enum)** → [Lynis](https://hackita.it/articoli/lynis/) (hardening) → Exploit privesc

***

## 7️⃣ Attack Chain Completa

**Fase 1:** Shell → osqueryi → trova SUID custom (10 sec). **Fase 2:** Exploit SUID → root (5 min). **Fase 3:** Osqueryi → trova credenziali in processi (30 sec). **Timeline:** \~6 min.

***

## 8️⃣ Detection & Evasion

Osqueryi è un tool legittimo di security. AV non lo blocca. Genera log nel syslog se osqueryd è attivo.

***

## 9️⃣ Performance & Scaling

Query istantanee. Consumo minimo.

***

## 🔟 Tabelle Tecniche

| Tabella                | Contenuto        |
| ---------------------- | ---------------- |
| `processes`            | Processi attivi  |
| `process_open_sockets` | Connessioni rete |
| `users`                | Account utente   |
| `crontab`              | Cron jobs        |
| `suid_bin`             | Binari SUID      |
| `authorized_keys`      | Chiavi SSH       |
| `kernel_modules`       | Moduli kernel    |
| `startup_items`        | Elementi startup |
| `file`                 | File info        |
| `hash`                 | Hash file        |

***

## 11️⃣ Troubleshooting

| Problema            | Fix                          |
| ------------------- | ---------------------------- |
| Tabella non trovata | `.tables` per lista completa |
| Permission denied   | Esegui come root             |

***

## 12️⃣ FAQ

**Osquery funziona su Windows?** Sì, con tabelle specifiche (services, registry, wmi\_cli\_event\_consumers).

**È installato di default?** No, va installato. Ma è un tool legittimo che non viene bloccato.

***

## 13️⃣ Cheat Sheet

| Azione      | Query                                                           |
| ----------- | --------------------------------------------------------------- |
| Processi    | `SELECT pid, name, path FROM processes;`                        |
| Connessioni | `SELECT * FROM process_open_sockets WHERE state='ESTABLISHED';` |
| SUID        | `SELECT * FROM suid_bin;`                                       |
| Crontab     | `SELECT * FROM crontab;`                                        |
| SSH keys    | `SELECT * FROM authorized_keys;`                                |
| One-liner   | `osqueryi --json "QUERY" \| jq .`                               |

***

**Disclaimer:** Osquery per security assessment. Repository: [github.com/osquery/osquery](https://github.com/osquery/osquery).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
