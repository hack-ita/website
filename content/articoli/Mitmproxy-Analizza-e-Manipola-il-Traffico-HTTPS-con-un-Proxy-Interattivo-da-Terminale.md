---
title: 'Mitmproxy: Guida Pentest, Comandi e Tool per HTTPS'
slug: mitmproxy
description: 'Come usare mitmproxy per intercettare traffico HTTPS e Android: certificato CA, mitmdump, mitmweb, WireGuard, transparent proxy e addon Python nel pentest.'
image: /mitmproxy-http-https-interception-pentesting.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - mitmproxy
  - mitm
  - mitmdump
  - intercettare traffico https
  - Traffic Analysis
---

# Mitmproxy: Come Intercettare e Modificare il Traffico HTTP e HTTPS (Guida Pratica al Pentest)

Mitmproxy è un **proxy man in the middle** open source che si mette tra un client e un server, decifra il traffico HTTP e HTTPS e te lo fa leggere, modificare e rigiocare. In un pentest serve a vedere cosa si dicono davvero un'app e il suo backend: header, cookie, token, JSON, WebSocket.

In questa guida lo installi, intercetti il tuo primo traffico HTTPS, installi il **certificato mitmproxy**, passi ad **Android**, scrivi un addon Python e capisci come difenderti da chi lo usa contro di te. Ogni comando è fatto per funzionare così com'è, in un laboratorio tuo.

> Usa mitmproxy solo su traffico tuo o su sistemi per cui hai un'autorizzazione scritta. Intercettare il traffico di altre persone senza permesso è un reato.

## Cos'è mitmproxy e a cosa serve nel pentest

Un **mitm proxy** è un proxy che non si limita a inoltrare i pacchetti: li apre. Tecnicamente è un **tool di intercettazione** scritto in Python che supporta HTTP/1, HTTP/2, HTTP/3, WebSocket e anche TCP e UDP grezzi.

Nel lavoro di un red teamer lo usi per:

* **Analizzare API e app web** quando vuoi vedere ogni richiesta senza aprire il browser (utile per [IDOR](https://hackita.it/articoli/idor/), [JWT](https://hackita.it/articoli/jwt/) e problemi di sessione).
* **Intercettare il traffico di app mobile**, soprattutto Android, per trovare endpoint nascosti e secret nel traffico.
* **Automatizzare modifiche** a richieste e risposte con script Python.
* **Salvare e rigiocare il traffico** da riga di comando, senza interfaccia.

Se conosci [Burp Suite](https://hackita.it/articoli/burp-suite/), mitmproxy ti sembrerà simile nello scopo ma molto diverso nell'uso: meno click, più terminale e script.

## Come funziona l'intercettazione HTTPS

L'HTTPS è cifrato tra client e server, quindi un proxy in mezzo normalmente non vede nulla. Mitmproxy risolve il problema così: apre **due sessioni TLS separate**. Una con il client, usando un certificato falso generato al volo. Una con il server vero, usando il certificato vero.

Al primo avvio mitmproxy crea una **CA (certificate authority)** sua. Quando il client chiede un sito, mitmproxy contatta prima il server vero, copia i dati del suo certificato (nome, organizzazione, SAN) e ne genera uno identico firmato dalla sua CA. Il client lo accetta **solo se si fida di quella CA**. Per questo devi installare il certificato sul dispositivo che vuoi intercettare.

![How mitmproxy intercepts HTTPS](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDQwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmZmZmZiIvPgogICAgPC9tYXJrZXI+CiAgICA8bWFya2VyIGlkPSJhcnJvd1JlZCIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmMDEwMyIvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgogIDxyZWN0IHg9IjAiIHk9IjAiIHdpZHRoPSI5MDAiIGhlaWdodD0iNDAwIiBmaWxsPSIjNmIwMDAxIi8+CiAgPHRleHQgeD0iNDUwIiB5PSIzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIyMiIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiI+SG93IG1pdG1wcm94eSBpbnRlcmNlcHRzIEhUVFBTPC90ZXh0PgogIDxyZWN0IHg9IjMwIiB5PSI5MCIgd2lkdGg9IjE5MCIgaGVpZ2h0PSIxMzAiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjEyNSIgeT0iMTQwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjIwIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5DbGllbnQ8L3RleHQ+CiAgPHRleHQgeD0iMTI1IiB5PSIxNjgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPmJyb3dzZXIgb3IgYXBwPC90ZXh0PgogIDx0ZXh0IHg9IjEyNSIgeT0iMTkyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj50cnVzdHMgbWl0bXByb3h5IENBPC90ZXh0PgogIDxyZWN0IHg9IjM1NSIgeT0iOTAiIHdpZHRoPSIxOTAiIGhlaWdodD0iMTMwIiByeD0iOCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjMiLz4KICA8dGV4dCB4PSI0NTAiIHk9IjE0MCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIyMCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyI+bWl0bXByb3h5PC90ZXh0PgogIDx0ZXh0IHg9IjQ1MCIgeT0iMTY4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5kZWNyeXB0cywgc2hvd3MsPC90ZXh0PgogIDx0ZXh0IHg9IjQ1MCIgeT0iMTkyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5lZGl0cywgcmUtZW5jcnlwdHM8L3RleHQ+CiAgPHJlY3QgeD0iNjgwIiB5PSI5MCIgd2lkdGg9IjE5MCIgaGVpZ2h0PSIxMzAiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9Ijc3NSIgeT0iMTQwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjIwIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5TZXJ2ZXI8L3RleHQ+CiAgPHRleHQgeD0iNzc1IiB5PSIxNjgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPnJlYWwgd2Vic2l0ZSBvciBBUEk8L3RleHQ+CiAgPHRleHQgeD0iNzc1IiB5PSIxOTIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPnJlYWwgY2VydGlmaWNhdGU8L3RleHQ+CiAgPGxpbmUgeDE9IjIyMiIgeTE9IjE1NSIgeDI9IjM1MyIgeTI9IjE1NSIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIuNSIgbWFya2VyLXN0YXJ0PSJ1cmwoI2Fycm93KSIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8bGluZSB4MT0iNTQ3IiB5MT0iMTU1IiB4Mj0iNjc4IiB5Mj0iMTU1IiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMi41IiBtYXJrZXItc3RhcnQ9InVybCgjYXJyb3cpIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIvPgogIDx0ZXh0IHg9IjI4NyIgeT0iMTMyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5UTFMgc2Vzc2lvbiAxPC90ZXh0PgogIDx0ZXh0IHg9IjI4NyIgeT0iMTgyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5mb3JnZWQgY2VydGlmaWNhdGU8L3RleHQ+CiAgPHRleHQgeD0iNjEyIiB5PSIxMzIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI2MDAiIGZpbGw9IiNmZmZmZmYiPlRMUyBzZXNzaW9uIDI8L3RleHQ+CiAgPHRleHQgeD0iNjEyIiB5PSIxODIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPnJlYWwgY2VydGlmaWNhdGU8L3RleHQ+CiAgPGxpbmUgeDE9IjQ1MCIgeTE9IjIyMiIgeDI9IjQ1MCIgeTI9IjI2OCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIuNSIgc3Ryb2tlLWRhc2hhcnJheT0iNiw0IiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93UmVkKSIvPgogIDxyZWN0IHg9IjIxNSIgeT0iMjcwIiB3aWR0aD0iNDcwIiBoZWlnaHQ9IjkwIiByeD0iOCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSI0NTAiIHk9IjMwMiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxNiIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyI+UGxhaW50ZXh0IGZsb3cgdmlzaWJsZSBpbiBtaXRtcHJveHk8L3RleHQ+CiAgPHRleHQgeD0iNDUwIiB5PSIzMjgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPmhlYWRlcnMsIGNvb2tpZXMsIHRva2VucywgSlNPTiBib2RpZXM8L3RleHQ+CiAgPHRleHQgeD0iNDUwIiB5PSIzNDgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPmVkaXQsIHJlcGxheSBvciBzYXZlIHRvIGEgZmxvdyBmaWxlPC90ZXh0Pgo8L3N2Zz4K)

Se vuoi il quadro generale dell'attacco, leggi anche la guida al [Man in the Middle](https://hackita.it/articoli/man-in-the-middle/) e come funziona [HTTP e HTTPS](https://hackita.it/articoli/http-https/).

## Installare mitmproxy su Kali Linux, Linux e Windows

Su **Kali Linux** (e Debian/Ubuntu) è nei repository:

```bash
# Install from the distro repository
sudo apt update && sudo apt install -y mitmproxy

# Check that it works
mitmproxy --version
```

Su qualsiasi Linux o macOS puoi usare `pipx`, che lo isola dal resto del sistema:

```bash
# Install in an isolated environment
pipx install mitmproxy
```

Su **Windows** (cerchi "mitm windows"?) scarichi l'installer dal sito ufficiale mitmproxy. Su Windows la versione a console `mitmproxy` non è supportata: usa `mitmweb` o `mitmdump`.

## I tre strumenti: mitmproxy, mitmweb e mitmdump

Con un'installazione ottieni tre comandi. Fanno la stessa cosa, cambia l'interfaccia.

| Comando     | Interfaccia                       | Quando usarlo                                          |
| ----------- | --------------------------------- | ------------------------------------------------------ |
| `mitmproxy` | Console interattiva nel terminale | Analisi e modifica a mano, tutto da tastiera           |
| `mitmweb`   | Interfaccia web (porta 8081)      | Chi preferisce il browser, ottima per iniziare         |
| `mitmdump`  | Solo righe di log, senza UI       | Script, automazione, salvataggio e replay del traffico |

**Mitmdump** è l'equivalente di `tcpdump` per HTTP: non mostra niente di interattivo, ma lo puoi mettere in una pipeline o in uno script. Se sei abituato a [tcpdump](https://hackita.it/articoli/tcpdump/) o [Wireshark](https://hackita.it/articoli/wireshark/), la differenza è che qui vedi il traffico già decifrato a livello applicativo.

## Mitmproxy tutorial: il tuo primo traffico HTTPS intercettato

Facciamo un test completo in locale, senza telefoni. Terminale 1, avvia il proxy:

```bash
# Start the console proxy, it listens on port 8080 by default
mitmproxy
```

Terminale 2, manda una richiesta HTTPS passando dal proxy:

```bash
# Send an HTTPS request through the proxy, trusting the mitmproxy CA
curl --proxy http://127.0.0.1:8080 \
     --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem \
     https://httpbin.org/get
```

Nel Terminale 1 vedi comparire la richiesta. Premi `Invio` per aprirla: trovi header, cookie e risposta in chiaro. Questo è il traffico HTTPS **intercettato**: curl si fida del certificato falso perché gli hai passato la CA di mitmproxy con `--cacert`.

I tasti che usi di più nella console:

| Tasto | Cosa fa                                                                      |
| ----- | ---------------------------------------------------------------------------- |
| `i`   | Imposta un filtro di intercettazione (blocca le richieste che corrispondono) |
| `a`   | Lascia passare la richiesta bloccata                                         |
| `e`   | Modifica la richiesta o la risposta selezionata                              |
| `r`   | Rigioca la richiesta (replay)                                                |
| `f`   | Filtra la lista dei flussi                                                   |
| `?`   | Aiuto contestuale                                                            |
| `q`   | Esci                                                                         |

Esempio pratico: premi `i`, scrivi `~u httpbin & ~q` e conferma. Ora ogni richiesta verso httpbin si ferma **prima** di partire: la modifichi con `e`, poi la fai passare con `a`.

Per la versione web:

```bash
# Start the web interface, open the URL printed in the terminal (it includes an access token)
mitmweb
```

## Certificato mitmproxy: dove si trova e come si installa

Al primo avvio mitmproxy crea la sua CA in `~/.mitmproxy`. Questi sono i file:

| File                    | Contenuto                         | Uso                                       |
| ----------------------- | --------------------------------- | ----------------------------------------- |
| `mitmproxy-ca.pem`      | Certificato **e chiave privata**  | Non distribuirlo mai                      |
| `mitmproxy-ca-cert.pem` | Solo certificato, formato PEM     | Linux, macOS, la maggior parte dei client |
| `mitmproxy-ca-cert.p12` | Formato PKCS12                    | Windows                                   |
| `mitmproxy-ca-cert.cer` | Uguale al PEM, estensione diversa | Alcuni Android                            |

La CA è generata **unica per ogni installazione**: nessun altro può usare la tua per intercettarti. Chi ha la tua `mitmproxy-ca.pem` invece sì, quindi proteggila come una chiave privata.

Il metodo più veloce per installarla è il dominio magico **mitm.it**: imposta il proxy sul dispositivo, apri `http://mitm.it` dal browser e scarica il certificato per il tuo sistema. Se non puoi usarlo, installi a mano.

Linux (Debian, Ubuntu, Kali), per far fidare tutto il sistema:

```bash
# Copy the CA into the system trust store and refresh it
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

Windows, da un prompt con privilegi di amministratore:

```
:: Add the mitmproxy CA to the trusted root store
certutil -addstore root mitmproxy-ca-cert.cer
```

Se vedi un errore di certificato (**mitmproxy certificate error**), di solito il client non si fida della CA, oppure l'app usa il pinning (ne parliamo più sotto). Firefox ha un suo archivio di certificati e non usa quello di sistema: lo importi a parte.

## Le modalità di mitmproxy: quale scegliere

Il **proxy regolare** è quello che hai usato sopra: il client sa di parlare con un proxy. Funziona solo se l'applicazione rispetta le impostazioni proxy. Quando non le rispetta (molte app Android), servono altre modalità.

| Modalità      | Comando                                          | Quando usarla                                                |
| ------------- | ------------------------------------------------ | ------------------------------------------------------------ |
| Regular       | `mitmproxy`                                      | Il client supporta un proxy HTTP. Parti sempre da qui        |
| Local capture | `mitmproxy --mode local`                         | Intercettare app sulla stessa macchina                       |
| WireGuard     | `mitmweb --mode wireguard`                       | Dispositivi esterni e app che ignorano il proxy              |
| Reverse       | `mitmdump --mode reverse:https://httpbin.org`    | Metti mitmproxy davanti a un server                          |
| Transparent   | `mitmdump --mode transparent`                    | Cambiare il gateway di una rete, senza configurare il client |
| Upstream      | `mitmdump --mode upstream:http://127.0.0.1:3128` | Mettere mitmproxy davanti a un altro proxy                   |
| SOCKS5        | `mitmdump --mode socks5`                         | Client che parlano SOCKS                                     |
| TUN           | `sudo mitmdump --mode tun`                       | Interfaccia virtuale su Linux, routing a mano                |
| DNS           | `mitmdump --mode dns`                            | Server DNS scriptabile                                       |

Tre dettagli che fanno risparmiare ore:

* **Local capture** lo puoi limitare a un processo: `mitmproxy --mode local:curl` cattura solo curl, `--mode local:42` solo il PID 42. Su Linux serve `sudo`, cattura solo traffico in uscita e il supporto ufficiale è per kernel **6.8 o superiore** (usa eBPF). I container devono usare la rete dell'host.
* **WireGuard** gira in userspace: non servono privilegi di amministratore. Non puoi però usarlo per intercettare il traffico della macchina su cui gira mitmproxy.
* **Transparent** su Linux richiede routing e regole di redirect. Per un laboratorio:

```bash
# Enable IP forwarding and stop sending ICMP redirects
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

# Redirect incoming web traffic to mitmproxy (check your interface name with: ip -br a)
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Start mitmproxy in transparent mode
mitmdump --mode transparent --showhost
```

Il client deve usare la macchina con mitmproxy come **gateway predefinito**. Se vuoi mandare il traffico di un tool attraverso un proxy dall'altra parte, guarda anche [proxychains](https://hackita.it/articoli/proxychains/) e il caso di un proxy intermedio come [Squid sulla porta 3128](https://hackita.it/articoli/porta-3128-squid-proxy/).

## Mitmproxy Android: intercettare il traffico di un'app

Per **intercettare il traffico Android** hai due strade: il proxy Wi-Fi e WireGuard.

**Strada 1: proxy Wi-Fi.** Sul telefono, nelle impostazioni della rete Wi-Fi, metti il proxy in manuale: indirizzo IP del PC con mitmproxy e porta 8080. Poi installa il certificato. Dalle versioni recenti di Android il certificato CA non si installa più aprendolo dal browser: lo copi sul telefono e lo installi da *Impostazioni, Sicurezza, Crittografia e credenziali, Installa un certificato, Certificato CA*.

```bash
# Push the CA certificate to the connected device (Android accepts the .cer extension)
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/Download/
```

Se usi l'**emulatore Android** il PC è raggiungibile all'indirizzo fisso `10.0.2.2`, quindi puoi impostare il proxy da `adb`:

```bash
# Set the global proxy on the emulator (the host machine is 10.0.2.2)
adb shell settings put global http_proxy 10.0.2.2:8080

# Remove the proxy when you are done
adb shell settings put global http_proxy :0
```

**Il problema.** Da Android 7 in poi le app, per default, **non si fidano dei certificati CA installati dall'utente**: si fidano solo di quelli di sistema. Chrome e il browser vanno bene. Un'app qualsiasi invece rifiuta il certificato di mitmproxy. Hai tre opzioni: installare la CA come certificato **di sistema** (possibile su emulatore o dispositivo con root, la procedura è nella documentazione ufficiale di mitmproxy), usare una build di debug della tua app con una network security config che accetta le CA utente, oppure rimuovere il pinning.

**Strada 2: WireGuard.** Molte app ignorano il proxy impostato nel Wi-Fi e vanno dritte al server. Con WireGuard non importa: tutto il traffico del dispositivo passa nel tunnel.

```bash
# Start mitmweb as a WireGuard server (listens on 51820/udp by default)
mitmweb --mode wireguard
```

Mitmweb mostra un **QR code** con la configurazione: lo scansioni con l'app WireGuard sul telefono e il traffico arriva a mitmproxy senza toccare le impostazioni Wi-Fi. Anche qui serve la CA installata, e valgono le stesse regole di Android 7 sopra.

## SSL pinning: quando mitmproxy non vede niente

Se l'app si connette ma in mitmproxy vedi solo errori di handshake TLS, quasi sempre c'è il **certificate pinning**: l'app accetta solo un certificato o una chiave precisa, quindi ignora la tua CA.

Hai due scelte. Se il contenuto di quelle connessioni non ti serve, dici a mitmproxy di non toccarle:

```bash
# Do not intercept traffic to the pinned domain, just tunnel it
mitmproxy --ignore-hosts '^httpbin\.org:443$'
```

Se invece ti serve, devi modificare l'app. La documentazione di mitmproxy elenca strumenti pensati per questo: `apk-mitm` (rimuove il pinning dall'APK), `objection` (bypass a runtime con Frida) e [android-unpinner](https://github.com/mitmproxy/android-unpinner) (inietta Frida e script di unpinning). Su iOS con jailbreak c'è `ssl-kill-switch2`. Questi strumenti si usano **solo su app tue o con autorizzazione**.

## Filtri: trovare il traffico che conta

Quando il traffico cresce, i filtri sono la differenza tra capire e perdersi. Funzionano nella console (`f`), nell'intercettazione (`i`) e come argomento di `mitmdump`.

| Filtro           | Significato                    |
| ---------------- | ------------------------------ |
| `~d httpbin.org` | Dominio                        |
| `~u /api/`       | URL che contiene `/api/`       |
| `~m POST`        | Metodo HTTP                    |
| `~c 401`         | Codice di risposta             |
| `~t json`        | Content-Type                   |
| `~b password`    | Corpo che contiene la parola   |
| `~q` / `~s`      | Solo richieste / solo risposte |
| `&`, `\|`, `!`   | AND, OR, NOT                   |

Esempio da `mitmdump`: mostra solo le POST verso un dominio.

```bash
# Print only POST requests to httpbin.org
mitmdump "~m POST & ~d httpbin.org"
```

## Mitmproxy Python: addon e automazione

Qui mitmproxy diventa un tool serio. Un **addon** è uno script Python con funzioni che mitmproxy chiama a ogni evento: `request` quando arriva una richiesta, `response` quando arriva la risposta. Salva questo file come `aggiungi_header.py`:

```python
from mitmproxy import http


def request(flow: http.HTTPFlow) -> None:
    # Add a custom header to every request going to httpbin.org
    if flow.request.pretty_host == "httpbin.org":
        flow.request.headers["X-Hackita-Test"] = "intercepted"
```

Avvialo con `mitmdump -s` e fai una richiesta:

```bash
# Terminal 1: run the addon
mitmdump -s aggiungi_header.py

# Terminal 2: httpbin echoes back the headers it receives, including ours
curl --proxy http://127.0.0.1:8080 \
     --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem \
     https://httpbin.org/headers
```

Nella risposta compare `X-Hackita-Test: intercepted`: la richiesta è stata modificata **in volo**, il server l'ha ricevuta già cambiata.

Secondo addon, più da pentester: loggare tutti i token e i cookie che passano, per capire come un'app autentica le richieste. Salvalo come `estrai_token.py`:

```python
import logging

from mitmproxy import http

# Headers that usually carry credentials or session data
SENSITIVE_HEADERS = ("authorization", "cookie", "x-api-key")


def request(flow: http.HTTPFlow) -> None:
    for header_name in SENSITIVE_HEADERS:
        header_value = flow.request.headers.get(header_name)
        if header_value:
            logging.info(f"{flow.request.pretty_host} | {header_name}: {header_value}")
```

```bash
# Run it and browse the target app through the proxy
mitmdump -s estrai_token.py
```

Se un token compare in chiaro, ora sai dove cercare: è il punto di partenza per [session hijacking](https://hackita.it/articoli/session-hijacking/) o per capire come sono costruiti i [JWT](https://hackita.it/articoli/jwt/) di quell'app. Per attacchi più ampi alle API guarda la [guida agli attacchi API moderni](https://hackita.it/articoli/api-modern-web-attacks-guida-completa/).

Un addon può anche **rispondere al posto del server**, per simulare un backend e vedere come reagisce l'app:

```python
from mitmproxy import http


def request(flow: http.HTTPFlow) -> None:
    # Answer directly from the proxy: the request never reaches the real server
    if flow.request.pretty_url == "https://httpbin.org/anything":
        flow.response = http.Response.make(
            200,
            b'{"role": "admin"}',
            {"Content-Type": "application/json"},
        )
```

## Mitmdump: salvare, leggere e rigiocare il traffico

Con `-w` salvi tutti i flussi in un file. Poi li rileggi o li rigiochi quando vuoi, anche offline.

```bash
# Capture traffic to a file while you browse through the proxy
mitmdump -w sessione.mitm

# Read the file back without starting a proxy server (-n = no server, -r = read)
mitmdump -nr sessione.mitm

# Replay the captured client requests against the real servers
mitmdump -n -C sessione.mitm
```

Il replay è utile per rifare una richiesta dopo aver corretto un bug, oppure per rigiocare lo stesso flusso con un token diverso e vedere se il server controlla davvero l'autorizzazione.

## Mitmproxy nel workflow di un pentest

Un ordine che funziona su una web app o su un'app mobile:

* Parti dal proxy regolare. Se il traffico non passa, passa a WireGuard o local capture.
* Naviga tutta l'app con `mitmweb` e guarda l'elenco degli endpoint: spesso trovi API non documentate.
* Cerca nei flussi con `~b` parole come `token`, `password`, `secret`, `key`.
* Modifica con `e` ruoli, ID e parametri e guarda le risposte.
* Quando una prova funziona, trasformala in un addon e rilanciala in automatico.
* Salva la sessione con `-w`: ti serve come evidenza nel report.

## Mitmproxy vs Burp Suite vs Wireshark

|                | Mitmproxy                                 | Burp Suite                        | Wireshark                       |
| -------------- | ----------------------------------------- | --------------------------------- | ------------------------------- |
| Livello        | Applicativo (HTTP, WebSocket)             | Applicativo (web)                 | Rete (pacchetti)                |
| Decifra HTTPS  | Sì, con la sua CA                         | Sì, con la sua CA                 | Solo con le chiavi di sessione  |
| Interfaccia    | Terminale, web, script                    | Grafica                           | Grafica                         |
| Punto di forza | Automazione Python, mobile, replay da CLI | Scanner e strumenti web integrati | Analisi di qualsiasi protocollo |

Non sono alternativi: nei pentest seri li usi insieme. Mitmproxy per scriptare e per le app mobile, Burp per lo scanner e il lavoro a mano, Wireshark quando il problema è sotto HTTP.

## Come difendersi da un attacco con proxy MITM

Se lavori sul lato difensivo, questi sono i punti che contano:

* **HSTS** obbliga il browser a usare solo HTTPS e blocca i downgrade. Ma non ferma un attaccante con una CA installata sul dispositivo.
* **Certificate pinning** nelle app sensibili: l'app rifiuta qualsiasi certificato diverso dal suo, quindi anche una CA falsa non basta.
* **Controlla l'archivio dei certificati radice** sugli endpoint. Il certificato di mitmproxy ha come nome `mitmproxy`, quindi lo trovi subito:

```
:: Windows: list trusted root certificates that mention mitmproxy
certutil -store Root | findstr /i mitmproxy
```

```bash
# Linux: look for the mitmproxy CA in the system certificates
grep -ril "mitmproxy" /usr/local/share/ca-certificates/ 2>/dev/null
```

* **Allarmi nel browser**: un errore di certificato su un sito che conosci è un segnale, non un fastidio da ignorare.
* **Rete**: per fermare chi si mette in mezzo con ARP spoofing servono controlli sulla rete locale, come spiegato nella guida allo [sniffing](https://hackita.it/articoli/sniffing/). Sulle reti non fidate usa una [VPN](https://hackita.it/articoli/vpn/).

## Domande frequenti su mitmproxy

**Mitmproxy è legale?**
Il software è legale ed è usato da sviluppatori e pentester. Usarlo per intercettare traffico altrui senza autorizzazione no.

**Mitmproxy intercetta HTTPS?**
Sì, ma solo se il client si fida della sua CA. Senza il certificato installato vedi solo errori TLS.

**Che differenza c'è tra mitmproxy, mitmweb e mitmdump?**
Stesso motore, interfaccia diversa: console nel terminale, interfaccia web, solo riga di comando per automazione.

**Mitmproxy funziona su Windows?**
Sì. Su Windows usi `mitmweb` e `mitmdump`: la console `mitmproxy` non è supportata.

**Perché l'app Android non mostra traffico?**
Ci sono tre cause comuni: l'app ignora il proxy Wi-Fi (usa WireGuard), non si fida delle CA utente da Android 7 in poi (CA di sistema o build di debug), oppure usa il pinning.

**Mitmproxy è meglio di Burp Suite?**
Dipende dal lavoro. Per scripting e app mobile mitmproxy è più comodo, per scanner e lavoro manuale sul web Burp è più completo.

## Conclusione

Mitmproxy ti fa vedere la parte che di solito resta nascosta: quello che un'app dice davvero al suo server. Parti dal proxy regolare, impara i filtri, poi passa a WireGuard per Android e agli addon Python per automatizzare. Per continuare nel percorso web, studia come funzionano le richieste che hai appena intercettato nella guida al [protocollo HTTP sulla porta 80](https://hackita.it/articoli/porta-80-http/) e gli attacchi come [CSRF](https://hackita.it/articoli/csrf/). La documentazione ufficiale sui [proxy mode di mitmproxy](https://docs.mitmproxy.org/stable/concepts/modes/) è il riferimento per i dettagli di ogni modalità.
