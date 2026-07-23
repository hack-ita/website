---
title: 'GetADUsers.py Impacket: Enumerare Utenti Active Directory'
slug: getadusers
description: >-
  Guida a GetADUsers.py di Impacket per enumerare utenti Active Directory via
  LDAP con password, hash NTLM, chiave AES o Kerberos e analizzare pwdLastSet e
  lastLogon.
image: /getadusers-enumerazione-utenti-active-directory.webp
draft: false
date: 2026-07-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - user-enumeration
  - windows-enumeration
  - kerberos
  - pwdlastset
  - lastlogon
---

# GetADUsers.py — Enumerazione Utenti Active Directory con Impacket

`GetADUsers.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e interroga un Domain Controller via LDAP per ottenere una lista di utenti con quattro attributi: nome account, email, data ultimo cambio password e data ultimo logon. È uno strumento volutamente minimale — niente gruppi, niente descrizioni, niente SPN. Utile come primo passo rapido dopo aver ottenuto le prime credenziali di dominio, non come sostituto di BloodHound o di una query LDAP completa.

**Nota:** `GetADUsers.py` richiede sempre credenziali valide, anche minime. Se non ne hai ancora nessuna, puoi provare prima un'enumerazione username non autenticata via Kerberos (porta 88):

```bash
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='corp.local',userdb=usernames.txt 10.10.10.5
```

Riferimento ufficiale: [fortra/impacket — GetADUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetADUsers.py) (verificato identico anche sulla release stabile [impacket\_0\_13\_1](https://github.com/fortra/impacket/blob/impacket_0_13_1/examples/GetADUsers.py))

## Cosa enumera davvero (e cosa no)

Il codice esegue una ricerca LDAP paginata richiedendo **esattamente quattro attributi**: `sAMAccountName`, `pwdLastSet`, `mail`, `lastLogon`. Nient'altro.

|               Informazione               | Supportata |
| :--------------------------------------: | ---------- |
|        `sAMAccountName` (username)       | Sì         |
|              Email (`mail`)              | Sì         |
|               `pwdLastSet`               | Sì         |
|                `lastLogon`               | Sì         |
|            Descrizione account           | No         |
|                  Gruppi                  | No         |
|             Membri dei gruppi            | No         |
|            SPN (Kerberoasting)           | No         |
|       `userAccountControl` completo      | No         |
| `DONT_REQUIRE_PREAUTH` (AS-REP Roasting) | No         |
|               `badPwdCount`              | No         |
|               `adminCount`               | No         |
|          OU e Distinguished Name         | No         |

Se ti serve una di queste informazioni "No", GetADUsers.py non è lo strumento giusto — servono altri tool (li vedi più avanti in questo articolo).

## Sintassi e opzioni reali

```bash
impacket-GetADUsers [opzioni] dominio[/utente:password]
```

| Opzione             | Descrizione                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| `-user USERNAME`    | Richiede dati per un utente specifico                                    |
| `-all`              | Restituisce tutti gli utenti, inclusi account disabilitati e senza email |
| `-hashes LM:NT`     | Pass-the-Hash                                                            |
| `-k`                | Autenticazione Kerberos (ccache via KRB5CCNAME)                          |
| `-no-pass`          | Con `-k`, non chiede la password                                         |
| `-aesKey KEY`       | Chiave AES (128 o 256 bit) per l'autenticazione Kerberos                 |
| `-dc-ip IP`         | IP del Domain Controller                                                 |
| `-dc-host HOSTNAME` | Hostname del Domain Controller                                           |
| `-ts`               | Aggiunge timestamp ai messaggi di log                                    |
| `-debug`            | Output diagnostico                                                       |

**Non esistono** `-users`, `-groups`, `-port` o `-outputfile` in questa versione del tool — se li vedi citati altrove, sono sbagliati.

## Comportamento predefinito vs `-all`

Questa distinzione è la cosa più importante da capire prima di usare il tool.

**Senza `-all`:** il filtro LDAP richiede utenti con l'attributo `mail` valorizzato **e** non disabilitati (esclude il flag `UF_ACCOUNTDISABLE`). Un output corto o vuoto non significa che la query sia fallita — significa solo che pochi (o nessun) account hanno un'email impostata.

```bash
impacket-GetADUsers -dc-ip 10.10.10.5 corp.local/user:'Password123!'
```

**Con `-all`:** il filtro elimina il requisito email e disabilitato — restituisce tutti gli utenti, inclusi account disabilitati e senza email.

```bash
impacket-GetADUsers -all -dc-ip 10.10.10.5 corp.local/user:'Password123!'
```

## Enumerare un utente specifico

```bash
# Utile ad esempio per controllare rapidamente il pwdLastSet di krbtgt
impacket-GetADUsers -user krbtgt -all -dc-ip 10.10.10.5 corp.local/user:'Password123!'
```

## Autenticazione: password, hash NTLM, chiave AES

```bash
# Pass-the-Hash
impacket-GetADUsers -all -hashes ':NTHASH' -dc-ip 10.10.10.5 corp.local/user

# Con chiave AES
impacket-GetADUsers -all -aesKey 'AES256_KEY' -dc-ip 10.10.10.5 corp.local/user
```

## Kerberos con ccache

```bash
export KRB5CCNAME=/path/to/user.ccache

impacket-GetADUsers -all -k -no-pass \
  -dc-host DC01.corp.local \
  -dc-ip 10.10.10.5 \
  corp.local/user
```

`-dc-host` conta negli scenari Kerberos perché il tool deve costruire il principal LDAP con un hostname coerente — se lo ometti, usa la parte FQDN del target passato, che potrebbe non corrispondere all'host reale del DC.

## Salvare l'output

`-outputfile` non esiste. Usa redirect o `tee`:

```bash
impacket-GetADUsers -all -dc-ip 10.10.10.5 corp.local/user:'Password123!' | tee /tmp/getadusers.txt
```

## Output e come leggerlo

```
Name                  Email              PasswordLastSet      LastLogon
--------------------  -----------------  -------------------  -------------------
Administrator                            2024-01-15 10:23:11  2024-03-01 09:00:00
john.doe              jdoe@corp.local    2021-08-01 08:00:00  2024-02-28 15:30:00
svc_sql                                  2019-03-10 12:00:00  <never>
```

**Interpretazione corretta degli indicatori:**

| Indicatore                                     | Cosa puoi concludere                                                                                  |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `pwdLastSet` molto vecchio                     | La password non è stata cambiata da molto tempo — non dimostra che sia debole, solo che non è ruotata |
| `pwdLastSet = <never>`                         | Password mai impostata nel modo ordinario, o flag che richiede cambio al prossimo logon               |
| Timestamp `pwdLastSet` identici su più account | Possibile provisioning nello stesso momento — non prova che la password sia la stessa                 |
| `lastLogon = <never>`                          | Il **Domain Controller interrogato** non ha registrato un accesso — non significa account inattivo    |
| Nome che inizia con `svc_`                     | Possibile service account, da verificare con un controllo SPN reale                                   |
| Email presente                                 | Account con attributo `mail` valorizzato                                                              |

**Attenzione a `lastLogon`:** questo attributo **non viene replicato tra i Domain Controller**. Il valore mostrato è solo quello registrato dal DC che hai interrogato — l'utente potrebbe essersi autenticato tramite un altro DC in tutt'altro momento. Per un dato affidabile servirebbe interrogare tutti i DC e prendere il valore più recente.

**Un uso legittimo di `<never>`:** non ti dice nulla su AS-REP Roasting, ma è comunque un'informazione utile in altro modo. Account come Guest, krbtgt o vecchi service account con `lastLogon <never>` non hanno una baseline comportamentale — se decidi di appoggiarti a uno di questi per persistenza, un utilizzo occasionale ha meno probabilità di distinguersi da un pattern "normale" (che semplicemente non esiste per quell'account).

## Da GetADUsers a Kerberoasting e AS-REP Roasting

Un nome come `svc_sql` è solo un indizio, non una prova. Un account è **Kerberoastable** solo se possiede un `servicePrincipalName` — GetADUsers.py non lo verifica. Serve un tool dedicato che controlli gli SPN (es. GetUserSPNs.py di Impacket).

Allo stesso modo, un account è **AS-REP Roastable** solo se ha il flag `DONT_REQUIRE_PREAUTH` attivo — anche questo GetADUsers.py non lo controlla. `LastLogon = <never>` **non è un indicatore di AS-REP Roasting**, sono due cose completamente indipendenti.

```bash
# 1. Enumerazione generale
impacket-GetADUsers -all -dc-ip 10.10.10.5 corp.local/user:'Password123!' | tee getadusers.txt

# 2. Verifica reale degli account senza pre-authentication (AS-REP Roasting)
impacket-GetNPUsers corp.local/user:'Password123!' -dc-ip 10.10.10.5 -request -format hashcat

# 3. Verifica reale degli account con SPN (Kerberoasting) — vedi anche [Kerberoasting](https://hackita.it/articoli/kerberoasting/)
impacket-GetUserSPNs -dc-ip 10.10.10.5 corp.local/user:'Password123!'
```

## Gruppi e descrizioni: strumenti giusti

GetADUsers.py **non enumera gruppi né descrizioni**. Per quello servono altri strumenti:

```bash
# Gruppi e membri, con netexec
nxc ldap 10.10.10.5 -u user -p 'Password123!' --groups
nxc ldap 10.10.10.5 -u user -p 'Password123!' --groups 'Domain Admins'

# Descrizioni utente (dove a volte finiscono password dimenticate)
nxc ldap 10.10.10.5 -u user -p 'Password123!' -M get-desc-users

# Query LDAP libera su attributi specifici
nxc ldap 10.10.10.5 -u user -p 'Password123!' --query '(objectCategory=person)' 'sAMAccountName description'
```

Per il quadro completo delle relazioni tra utenti, gruppi e permessi nel dominio, lo strumento giusto resta [BloodHound](https://hackita.it/articoli/bloodhound/); per query LDAP personalizzate riga per riga, [ldapsearch](https://hackita.it/articoli/ldapsearch/).

## Workflow offensivo realistico

```
GetADUsers.py -all
│
├── Elenco username
│   └── Password spraying, solo dopo aver verificato la lockout policy
│
├── Utenti con naming da servizio (svc_*)
│   └── GetUserSPNs.py → verifica SPN reale prima di dare per Kerberoastable
│
├── Verifica pre-authentication
│   └── GetNPUsers.py → individua i veri candidati AS-REP Roastable
│
├── Descrizioni e attributi aggiuntivi
│   └── ldapsearch / nxc --query / nxc -M get-desc-users
│
└── Gruppi e privilegi
    └── nxc --groups / BloodHound
```

## GetADUsers vs alternative

| Tool                                                  | Protocollo | Dettaglio            | Note                                      |
| ----------------------------------------------------- | ---------- | -------------------- | ----------------------------------------- |
| `GetADUsers.py`                                       | LDAP       | Minimo (4 attributi) | Rapido, zero installazione, output pulito |
| [ldapsearch](https://hackita.it/articoli/ldapsearch/) | LDAP       | Completo             | Query personalizzabili, raw output        |
| [BloodHound](https://hackita.it/articoli/bloodhound/) | LDAP + SMB | Molto alto           | Grafo relazioni, trova attack path        |
| `nxc ldap`                                            | LDAP       | Alto                 | Gruppi, descrizioni, query libere, moduli |

## Errori comuni

| Errore                    | Causa probabile                                | Verifica                                                                                                               |
| ------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `invalidCredentials`      | Password, hash o dominio errato                | Controlla il formato `dominio/utente`                                                                                  |
| `strongerAuthRequired`    | Il DC richiede un canale LDAP protetto         | Impacket ritenta automaticamente in LDAPS quando riceve questo errore — non serve un flag `-port` manuale (non esiste) |
| `NTLM negotiation failed` | NTLM disabilitato sul DC                       | Usa Kerberos con `-k`                                                                                                  |
| Errore su hostname/KDC    | IP e hostname Kerberos incoerenti              | Usa insieme `-dc-host` e `-dc-ip`                                                                                      |
| Output vuoto senza `-all` | Nessun account abilitato ha `mail` valorizzata | Aggiungi `-all`                                                                                                        |
| `KRB_AP_ERR_SKEW`         | Orologio non sincronizzato col DC              | Sincronizza l'orario                                                                                                   |
| Ticket non trovato        | Ccache assente o principal non coerente        | Controlla `KRB5CCNAME` e `klist`                                                                                       |
| Connessione rifiutata     | LDAP/LDAPS filtrato o DC errato                | Verifica porte 389/636 con Nmap                                                                                        |

## Detection e mitigazioni

**Cosa può notare chi monitora:**

* Query LDAP massive di tutti gli oggetti utente da un account che normalmente non fa amministrazione
* Query ripetute sugli stessi attributi da workstation insolite
* **Event ID 1644** (Field Engineering / Expensive and Inefficient Searches) — se abilitato, logga ricerche LDAP costose o ad alto volume, ed è più specifico del solo 4662 per individuare un dump massivo di utenti
* Event ID 4662 — ma solo se è configurata una SACL sugli oggetti interessati, altrimenti non viene generato
* Microsoft Defender for Identity correla attività LDAP di reconnaissance su più segnali, non sulla singola query
* Honey-token account (falsi Domain Admin o service account) usati come esca: qualunque query LDAP/Kerberos/NTLM che li tocca è un segnale ad alta confidenza

**Mitigazioni realistiche:**

* Non lasciare password o informazioni operative nelle descrizioni degli account
* Verificare e rimuovere account davvero inattivi, controllando `lastLogon` su **tutti** i DC, non su uno solo
* Limitare i diritti di lettura sugli attributi più sensibili dove l'architettura lo consente
* LDAP signing e channel binding proteggono da manomissione e relay — non impediscono una normale query LDAP autenticata come questa

## Cheat Sheet

```bash
# Comportamento default (solo utenti abilitati con email)
impacket-GetADUsers -dc-ip DC_IP corp.local/user:pass

# Tutti gli utenti (inclusi disabilitati e senza email)
impacket-GetADUsers -all -dc-ip DC_IP corp.local/user:pass

# Utente specifico
impacket-GetADUsers -user krbtgt -all -dc-ip DC_IP corp.local/user:pass

# Pass-the-Hash
impacket-GetADUsers -all -hashes :NThash -dc-ip DC_IP corp.local/user

# Chiave AES
impacket-GetADUsers -all -aesKey AES256KEY -dc-ip DC_IP corp.local/user

# Kerberos
export KRB5CCNAME=ticket.ccache
impacket-GetADUsers -all -k -no-pass -dc-host DC01.corp.local -dc-ip DC_IP corp.local/user

# Salva output
impacket-GetADUsers -all -dc-ip DC_IP corp.local/user:pass | tee getadusers.txt

# Segue: verifica SPN e pre-auth reali
impacket-GetUserSPNs -dc-ip DC_IP corp.local/user:pass
impacket-GetNPUsers corp.local/user:pass -dc-ip DC_IP -request -format hashcat

# Gruppi (non fatto da GetADUsers)
nxc ldap DC_IP -u user -p pass --groups
```

## Domande frequenti

**A cosa serve GetADUsers.py?**
Enumera account utente Active Directory tramite LDAP e mostra nome, email, `pwdLastSet` e `lastLogon`. Non enumera gruppi, descrizioni, SPN o flag AS-REP.

**GetADUsers.py enumera anche i gruppi?**
No. Per i gruppi serve un altro tool — ad esempio `nxc ldap --groups`, o BloodHound per il quadro completo delle relazioni.

**Qual è la differenza tra il comando base e `-all`?**
Senza `-all` vedi solo account abilitati con email impostata. Con `-all` vedi tutti gli utenti, inclusi disabilitati e senza email.

**`lastLogon` è affidabile per capire se un account è inattivo?**
No, perché non è replicato tra Domain Controller. Il valore riflette solo il DC interrogato — l'utente potrebbe essersi autenticato altrove.

**Come trovo gli account AS-REP Roastable?**
Non con GetADUsers.py. Serve GetNPUsers.py, che verifica realmente il flag `DONT_REQUIRE_PREAUTH`.

**Come trovo gli account Kerberoastable?**
Non basandoti sul nome (`svc_*`). Serve verificare la presenza di un `servicePrincipalName` reale, con GetUserSPNs.py.

## Articoli correlati

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [Active Directory: guida all'exploitation](https://hackita.it/articoli/active-directory/)
* [ldapsearch — query LDAP avanzate](https://hackita.it/articoli/ldapsearch/)
* [BloodHound — mappa l'AD e trova attack path](https://hackita.it/articoli/bloodhound/)
* [Kerberoasting](https://hackita.it/articoli/kerberoasting/)
* [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/)
* [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)

> Uso esclusivo in ambienti autorizzati.
