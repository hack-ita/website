---
title: 'Ldapsearch: enumerazione utenti e directory in attacco'
description: >-
  Scopri come utilizzare ldapsearch per raccogliere informazioni su utenti,
  gruppi e strutture AD. Tecniche di enumeration reali per Red Team e pentester.
image: /LDAPSEARCH.webp
draft: true
date: 2026-01-23T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - ldapsearch
  - active directory
---

# ldapsearch: L'Arte dell'Enumerazione LDAP per Dominare l'Active Directory

**Report Red Team | Ambiente Controllato Autorizzato**

Quando ti trovi davanti a un server LDAP o Active Directory, hai due scelte: procedere alla cieca o usare ldapsearch per ottenere una mappa completa dell'ambiente. Questa guida ti trasformerà da principiante a esperto nell'enumerazione LDAP, mostrandoti come estrarre ogni informazione utile per i tuoi attacchi in ambienti controllati.

## Cos'è ldapsearch e Perché è Uno Strumento Fondamentale

ldapsearch è il **coltellino svizzero per interrogare directory LDAP**. È lo strumento che ti permette di passare da "porta 389 aperta" a "conosco ogni utente, gruppo, computer e relazione in questo dominio". Mentre strumenti grafici possono essere bloccati o limitati, ldapsearch funziona sempre - è diretto, potente e scriptabile.

### Il Potere di ldapsearch in un Attacco

* **Enumerazione completa**: Ottieni lista di tutti gli utenti, gruppi, computer
* **Scoperta relazioni**: Vedi chi è membro di cosa, chi controlla cosa
* **Ricerca target specifici**: Trova amministratori, service account, computer critici
* **Mappatura dell'ambiente**: Capisci la struttura dell'AD (OU, domini, trust)

## Come Funziona: Il Protocollo LDAP in Poche Parole

LDAP (Lightweight Directory Access Protocol) è un protocollo per accedere a servizi di directory. Active Directory è l'implementazione Microsoft più comune. ldapsearch ti permette di:

1. **Connettersi** al server (porte 389 o 636 per TLS)
2. **Autenticarti** (anonima o con credenziali)
3. **Cercare** informazioni usando filtri specifici
4. **Ricevere** i risultati in formato leggibile

## Setup e Primi Passi

### Installazione su Kali Linux

```bash
# ldapsearch è incluso in ldap-utils
sudo apt update && sudo apt install ldap-utils -y

# Verifica l'installazione
ldapsearch --version
```

### Scoperta del Servizio LDAP

Prima di usare ldapsearch, identifica il server LDAP:

```bash
# Scansione delle porte LDAP
nmap -sV -p 389,636 192.168.1.100

# Output tipico:
PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: corp.local, Site: Default-First-Site-Name)
636/tcp open  ssl/ldap Microsoft Windows Active Directory LDAP (Domain: corp.local, Site: Default-First-Site-Name)
```

## Tecniche di Enumerazione con ldapsearch

### Fase 1: RootDSE - La Chiave per Capire l'Ambiente

Il RootDSE contiene informazioni fondamentali sul server LDAP. È il primo passo obbligatorio.

```bash
# Interrogazione del RootDSE per informazioni base
ldapsearch -x -H ldap://192.168.1.100 -s base -b "" "(objectClass=*)" 

# Output selezionato:
dn:
structuralObjectClass: top
configurationNamingContext: CN=Configuration,DC=corp,DC=local
defaultNamingContext: DC=corp,DC=local
domainControllerFunctionality: 7
domainFunctionality: 7
```

**Estrazione del Base DN (fondamentale per tutte le query successive):**

```bash
# Estrai solo il defaultNamingContext
ldapsearch -x -H ldap://192.168.1.100 -s base -b "" "(objectClass=*)" defaultNamingContext | grep -i "defaultNamingContext"

# Output:
defaultNamingContext: DC=corp,DC=local
```

### Fase 2: Enumerazione Utenti

Con il Base DN, possiamo iniziare a enumerare gli utenti del dominio.

```bash
# Ricerca di tutti gli utenti
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person))" sAMAccountName userPrincipalName memberOf pwdLastSet

# Output parziale:
dn: CN=Administrator,CN=Users,DC=corp,DC=local
sAMAccountName: Administrator
userPrincipalName: Administrator@corp.local
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
memberOf: CN=Enterprise Admins,CN=Users,DC=corp,DC=local

dn: CN=Giovanni Rossi,OU=Amministrazione,DC=corp,DC=local
sAMAccountName: g.rossi
userPrincipalName: g.rossi@corp.local
pwdLastSet: 132801858325419492
```

**Ricerca utenti con password non scaduta:**

```bash
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" sAMAccountName
```

### Fase 3: Enumerazione Gruppi

I gruppi rivelano le relazioni di potere nell'AD.

```bash
# Tutti i gruppi
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(objectClass=group)" cn member

# Solo gruppi amministrativi
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=group)(adminCount=1))" cn member

# Cerca membri dei Domain Admins
ldapsearch -x -H ldap://192.168.1.100 -b "CN=Domain Admins,CN=Users,DC=corp,DC=local" "(objectClass=*)" member
```

### Fase 4: Enumerazione Computer

I computer sono i target per il movimento laterale.

```bash
# Tutti i computer
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(objectClass=computer)" name dNSHostName operatingSystem operatingSystemVersion

# Solo server
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=computer)(operatingSystem=*Server*))" name dNSHostName

# Computer con specifici sistemi operativi
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=computer)(operatingSystem=*Windows 10*))" name
```

### Fase 5: Ricerca di Informazioni Specifiche

**Service Account (spesso con privilegi elevati):**

```bash
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Output:
dn: CN=SQL Service,OU=Service Accounts,DC=corp,DC=local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sql01.corp.local:1433
servicePrincipalName: MSSQLSvc/sql01.corp.local
```

**Utenti con password mai cambiata:**

```bash
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(pwdLastSet=0))" sAMAccountName pwdLastSet
```

## Autenticazione e Sicurezza

### Bind Anonimo (se permesso)

```bash
# Prova bind anonimo
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" -s base "(objectClass=*)" 
```

### Bind Autenticato

```bash
# Con credenziali
ldapsearch -x -H ldap://192.168.1.100 -D "CN=Amministratore,CN=Users,DC=corp,DC=local" -w "Password123" -b "DC=corp,DC=local" "(objectClass=user)"

# Oppure con formato semplice
ldapsearch -x -H ldap://192.168.1.100 -D "corp\\administrator" -w "Password123" -b "DC=corp,DC=local" "(objectClass=user)"
```

### Utilizzo di TLS/SSL

```bash
# LDAPS (porta 636)
ldapsearch -x -H ldaps://192.168.1.100:636 -D "corp\\administrator" -w "Password123" -b "DC=corp,DC=local" "(objectClass=user)"

# StartTLS (upgrade su porta 389)
ldapsearch -x -H ldap://192.168.1.100 -Z -D "corp\\administrator" -w "Password123" -b "DC=corp,DC=local" "(objectClass=user)"
```

## Tecniche Avanzate di Interrogazione

### Filtri Complessi

```bash
# Utenti disabilitati
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))" sAMAccountName

# Utenti che non richiedono password
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))" sAMAccountName

# Account di dominio (esclude account computer)
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person)(!(objectClass=computer)))" sAMAccountName
```

### Attributi Specifici per l'Attacco

```bash
# Informazioni per Kerberoasting
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName pwdLastSet

# Informazioni per AS-REP Roasting
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName pwdLastSet
```

## Automazione e Output

### Salvataggio dei Risultati

```bash
# Salva tutto in un file
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(objectClass=user)" > all_users.ldif

# Solo attributi specifici, output pulito
ldapsearch -x -LLL -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person))" sAMAccountName | grep "^sAMAccountName:" | cut -d" " -f2 > usernames.txt
```

### Script per Enumerazione Completa

```bash
#!/bin/bash
# Script di enumerazione LDAP base
DOMAIN="192.168.1.100"
BASE_DN=$(ldapsearch -x -H ldap://$DOMAIN -s base -b "" "(objectClass=*)" defaultNamingContext | grep -i "defaultNamingContext" | cut -d" " -f2)

echo "[*] Base DN: $BASE_DN"
echo "[*] Iniziando enumerazione..."

# Utenti
echo "[*] Enumerazione utenti..."
ldapsearch -x -LLL -H ldap://$DOMAIN -b "$BASE_DN" "(&(objectClass=user)(objectCategory=person))" sAMAccountName > users.txt

# Gruppi
echo "[*] Enumerazione gruppi..."
ldapsearch -x -LLL -H ldap://$DOMAIN -b "$BASE_DN" "(objectClass=group)" cn > groups.txt

# Computer
echo "[*] Enumerazione computer..."
ldapsearch -x -LLL -H ldap://$DOMAIN -b "$BASE_DN" "(objectClass=computer)" name > computers.txt

echo "[+] Enumerazione completata"
```

## Scenario di Attacco Reale

### Step 1: Ricognizione Iniziale

```bash
# Identifica il server LDAP
nmap -sV -p 389,636 192.168.1.0/24

# Ottieni il Base DN
BASE_DN=$(ldapsearch -x -H ldap://192.168.1.100 -s base -b "" "(objectClass=*)" defaultNamingContext | grep -i "defaultNamingContext" | cut -d" " -f2)
echo "Base DN: $BASE_DN"
```

### Step 2: Enumerazione Senza Credenziali

```bash
# Prova bind anonimo
ldapsearch -x -H ldap://192.168.1.100 -b "$BASE_DN" -s base "(objectClass=*)" 

# Se funziona, enumera utenti base
ldapsearch -x -LLL -H ldap://192.168.1.100 -b "$BASE_DN" "(&(objectClass=user)(objectCategory=person))" sAMAccountName | grep "^sAMAccountName:" | cut -d" " -f2
```

### Step 3: Ottenimento Credenziali e Enumerazione Completa

Dopo aver ottenuto credenziali (phishing, brute force, ecc.):

```bash
# Enumerazione completa con credenziali
ldapsearch -x -H ldap://192.168.1.100 -D "corp\\g.rossi" -w "Password123" -b "$BASE_DN" "(&(objectClass=user)(objectCategory=person))" sAMAccountName memberOf > users_with_groups.txt

# Cerca amministratori
ldapsearch -x -H ldap://192.168.1.100 -D "corp\\g.rossi" -w "Password123" -b "$BASE_DN" "(&(objectClass=group)(cn=*Admin*))" cn member > admin_groups.txt
```

### Step 4: Identificazione Target per Movimento Laterale

```bash
# Computer con utenti loggati (dai gruppi amministrativi)
ldapsearch -x -H ldap://192.168.1.100 -D "corp\\g.rossi" -w "Password123" -b "$BASE_DN" "(objectClass=computer)" name dNSHostName operatingSystem > all_computers.txt

# Service account con SPN (per Kerberoasting)
ldapsearch -x -H ldap://192.168.1.100 -D "corp\\g.rossi" -w "Password123" -b "$BASE_DN" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName > service_accounts.txt
```

## Ottimizzazione e Troubleshooting

### Flag Utili di ldapsearch

* `-x`: Usa autenticazione semplice
* `-LLL`: Output LDIF senza commenti, perfetto per scripting
* `-z 1000`: Limita risultati (evita timeout)
* `-E pr=1000/noprompt`: Paginazione risultati
* `-o ldif-wrap=no`: Disabilita wrap righe lunghe

### Errori Comuni e Soluzioni

```bash
# Errore: "Invalid credentials"
# Soluzione: Verifica formato DN o usa formato DOMAIN\username
ldapsearch -x -H ldap://192.168.1.100 -D "corp\\username" -w "password" -b "DC=corp,DC=local" "(objectClass=*)"

# Errore: "Size limit exceeded"
# Soluzione: Usa paginazione
ldapsearch -x -H ldap://192.168.1.100 -b "DC=corp,DC=local" -E pr=1000/noprompt "(objectClass=user)"

# Errore: "TLS richiesto"
# Soluzione: Usa LDAPS o StartTLS
ldapsearch -x -H ldaps://192.168.1.100:636 -b "DC=corp,DC=local" "(objectClass=*)"
```

## Integrazione con Altri Strumenti Offensivi

### ldapsearch + BloodHound

```bash
# Estrai dati per BloodHound manualmente
ldapsearch -x -H ldap://192.168.1.100 -D "corp\\g.rossi" -w "Password123" -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person))" sAMAccountName memberOf > bloodhound_users.txt

ldapsearch -x -H ldap://192.168.1.100 -D "corp\\g.rossi" -w "Password123" -b "DC=corp,DC=local" "(objectClass=group)" cn member > bloodhound_groups.txt
```

### ldapsearch + CrackMapExec

```bash
# Genera lista utenti per password spraying
ldapsearch -x -LLL -H ldap://192.168.1.100 -b "DC=corp,DC=local" "(&(objectClass=user)(objectCategory=person))" sAMAccountName | grep "^sAMAccountName:" | cut -d" " -f2 > users_for_spray.txt

# Usa con CrackMapExec
crackmapexec smb 192.168.1.0/24 -u users_for_spray.txt -p 'Spring2024!' --continue-on-success
```

## Conclusione: Perché ldapsearch è Insostituibile

ldapsearch rimane uno strumento fondamentale perché:

1. **Leggero e disponibile**: Presente su ogni distribuzione Linux
2. **Preciso**: Ti dà esattamente quello che chiedi
3. **Scriptabile**: Perfetto per automazione
4. **Affidabile**: Funziona dove strumenti grafici falliscono
5. **Completo**: Accesso a ogni attributo LDAP

**Le 5 Regole d'Oro del Red Teamer con ldapsearch:**

1. Inizia sempre con RootDSE
2. Usa filtri specifici, non scaricare tutto
3. Privilegia LDAPS/StartTLS per l'autenticazione
4. Salva e organizza i risultati sistematicamente
5. Integra i dati con altri strumenti offensivi

***

### Vuoi Padroneggiare Veramente l'Enumerazione AD?

Questa guida mostra solo la superficie. Per imparare a condurre attacchi AD completi - dall'enumerazione alla compromissione totale - servono pratica reale e mentorship esperta.

**Hackita** offre formazione pratica e avanzata:

* **Corsi di Red Teaming** con focus su Active Directory
* **Laboratori AD realistici** con scenari complessi
* **Mentorship 1:1** con esperti del settore
* **Formazione aziendale** su misura per il tuo team

Imparerai:

* Enumerazione avanzata con ldapsearch e PowerView
* Tecniche di movimento laterale in AD
* Attacchi Kerberos (Kerberoasting, AS-REP Roasting)
* Persistenza in ambienti AD
* Evasione dai sistemi di detection

[Scopri i nostri servizi formativi](https://hackita.it/servizi/) e inizia il tuo percorso per diventare un esperto di sicurezza offensiva.

**Supporta la Comunità:**
Aiutaci a mantenere i laboratori e sviluppare nuovi contenuti. [Una donazione](https://hackita.it/supporto/) fa la differenza.

**Ricorda:** Queste tecniche sono per scopi didattici in ambienti controllati con autorizzazione esplicita.

**Formati. Sperimenta. Previeni.**

[Hackita - Excellence in Offensive Security](https://hackita.it)
