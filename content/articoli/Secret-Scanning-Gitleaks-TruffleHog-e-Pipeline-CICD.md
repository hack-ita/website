---
title: 'Secret Scanning: Gitleaks, TruffleHog e Pipeline CI/CD'
slug: secret-scanning-automation
description: 'Automatizza il secret scanning con Gitleaks pre-commit e TruffleHog in CI/CD: blocca API key e token, verifica i leak e rimuovi i secret dalla Git history.'
image: /secret-scanning-automation-gitleaks-trufflehog.webp
draft: true
date: 2026-08-23T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - Secret Scanning
  - Gitleaks
  - TruffleHog
  - GitHub Secret Scanning
  - Push Protection
  - CI/CD Security
  - git-filter-repo
---

# Secret Scanning Automation: Bloccare le Credenziali Prima che Escano

Milioni di credenziali vengono ancora esposte ogni anno nei repository pubblici, secondo i dati periodicamente pubblicati da provider come GitGuardian. Una chiave AWS committata per errore in un repo privato che diventa pubblico, un token GitHub in un file `.env` dimenticato, una password DB in un commit di test: il pattern è sempre lo stesso, cambia solo chi la trova per primo — tu, con uno scan automatico, o un attaccante con lo stesso identico tool.

**Quando usarla:** pentest con fase di OSINT su repository pubblici del target, DevSecOps interno, hardening di una pipeline CI/CD.
**Cosa copre:** Gitleaks (pre-commit, veloce, offline), TruffleHog (CI/CD, con verifica se il secret è ancora attivo), ricerca offensiva su repo pubblici.
**Cosa non copre:** gestione dei secret una volta ruotati (per quello serve un vault — HashiCorp Vault, AWS Secrets Manager, già visto nella nostra guida al pentest AWS).

***

## Gitleaks vs TruffleHog: Detection Veloce o Verificata

Prima di scegliere un tool, capisci la differenza di fondo:

* **Gitleaks** — usa regole di detection basate su pattern ed euristiche di configurazione, con scansione locale e senza bisogno di verificare ogni candidato tramite API esterne. Ti dice "questo sembra una chiave AWS" ma non sa se è ancora valida.
* **TruffleHog** — include un'ampia collezione di detector per provider e tipologie di secret, e per molti di questi effettua anche una verifica reale contro l'API del servizio (il comportamento dipende dal tipo di secret e dal detector specifico). Ti dice "questa chiave AWS è live e funziona ora", quando la verifica è disponibile per quel tipo di secret.

Non sono alternative, sono complementari: Gitleaks blocca veloce in locale, TruffleHog conferma in profondità in CI/CD. Lo standard del settore è usarli entrambi, a stadi diversi della pipeline.

***

## Gitleaks: Secret Scanning come Pre-Commit Hook

```bash
# Installazione (Linux/Mac, singolo binario Go)
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh
```

> Dalla v8.19.0 in poi, `gitleaks detect` e `gitleaks protect` sono deprecati (nascosti da `--help`, ma ancora funzionanti). I comandi correnti sono `gitleaks git`, `gitleaks dir` e `gitleaks stdin`. Se trovi tutorial più vecchi con `detect`/`protect`, sappi che funzionano ancora ma vanno aggiornati ai comandi seguenti.

Scan completo del repository, inclusa la history:

```bash
gitleaks git .
```

Scan di una directory che non è un repository Git:

```bash
gitleaks dir -s .
```

Scan solo delle modifiche in staging (quello che sta per essere committato):

```bash
git diff --cached | gitleaks stdin
```

### Hook automatico ad ogni commit

Lo script gira automaticamente prima di ogni `git commit`: se Gitleaks trova qualcosa, l'`exit 1` interrompe il commit prima che venga creato.

```bash
# .git/hooks/pre-commit
#!/bin/sh
git diff --cached | gitleaks stdin
if [ $? -ne 0 ]; then
  echo "Gitleaks ha trovato un secret nello staged. Commit bloccato."
  exit 1
fi
```

`chmod +x` rende lo script eseguibile — senza questo, Git ignora l'hook silenziosamente:

```bash
chmod +x .git/hooks/pre-commit
```

### Con il framework pre-commit (multi-hook, più manutenibile)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

```bash
pip install pre-commit --break-system-packages
pre-commit install
```

### Gestire i falsi positivi

```toml
# .gitleaks.toml
[allowlist]
paths = [
  '''test/.*''',
  '''.*\.test\.(js|ts|py)''',
]
regexes = [
  '''example-key-for-documentation''',
]
```

Allowlista solo fixture e valori chiaramente artificiali, verificati uno per uno — non intere directory generiche come `test/` senza controllare cosa contengono davvero: potrebbero finirci per errore anche credenziali reali usate per test manuali.

***

## TruffleHog: Verificare Secret in CI/CD

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

Scan con verifica attiva — solo secret che TruffleHog riesce a confermare come live tramite i detector che supportano la verifica:

```bash
trufflehog git file://. --results=verified --fail
```

### GitHub Actions — blocca la PR se trova un secret verificato

```yaml
name: Secret Scanning
on: [push, pull_request]
jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
```

`--only-verified` restringe il risultato ai secret che TruffleHog riesce effettivamente a verificare secondo i propri detector — utile per ridurre il rumore in un gate CI/CD automatico, ma non significa che ogni secret non verificato sia un falso positivo o sia innocuo: significa solo che per quel tipo di secret la verifica non è disponibile o non è riuscita.

### Scan oltre Git — S3, Docker, filesystem

```bash
trufflehog s3 --bucket=nome-bucket
trufflehog docker --image=nome-immagine:tag
trufflehog filesystem /path/da/scansionare
```

Un secret può finire anche in un layer Docker o in un bucket S3 di backup, non solo in un commit — per questo TruffleHog copre più sorgenti di Gitleaks, che resta focalizzato su Git.

***

## GitHub Secret Scanning e Push Protection

Prima di aggiungere tool esterni, sappi cosa GitHub fa già in automatico su repository pubblici (e privati con GitHub Advanced Security). La copertura oggi va oltre i soli pattern dei partner riconosciuti:

* **Provider pattern** — chiavi con formato noto di partner riconosciuti (AWS, Stripe, Slack e molti altri)
* **Pattern generici** — euristiche per credenziali senza un formato fisso riconoscibile (username/password generiche)
* **Rilevamento assistito da modelli** — su determinati piani, GitHub applica anche tecniche di detection oltre al semplice pattern matching per ridurre i falsi negativi sui pattern generici
* **Pattern custom** — regole definite dall'organizzazione per i propri formati di secret interni
* **Validity check** — per alcuni provider, GitHub verifica se il secret trovato è ancora attivo, in modo simile a `--only-verified` di TruffleHog

**Push Protection** è un livello più aggressivo: blocca il push *prima* che il secret entri nella cronologia, se corrisponde a un pattern ad alta confidenza. È possibile richiedere un bypass in casi legittimi (es. falso positivo confermato), ma un bypass non va considerato equivalente a una remediation: va sempre tracciato e rivisto da chi gestisce la sicurezza del repository.

```bash
# Abilitare Push Protection via API su un repository
curl -X PATCH -H "Authorization: token <TUO-TOKEN>" \
  https://api.github.com/repos/organizzazione/repo \
  -d '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}'
```

**Limite da capire:** GitHub Secret Scanning copre solo repository ospitati su GitHub. Non sostituisce Gitleaks/TruffleHog, che restano portabili su qualsiasi piattaforma Git — una configurazione solida usa entrambi: nativo come backstop, Gitleaks/TruffleHog come controllo primario configurabile.

***

## Secret Scanning dei Repository GitHub Pubblici (OSINT)

In un pentest con componente OSINT, cercare secret nei repository pubblici del target può diventare uno dei percorsi più rapidi per ottenere un primo accesso — quando una credenziale esposta è ancora valida e lo scope dell'engagement lo consente.

```bash
# Scan diretto su un repo pubblico GitHub
trufflehog github --repo=https://github.com/organizzazione-target/repo-pubblico --only-verified
```

```bash
# Scan su tutta l'organizzazione (richiede un token GitHub con permessi read)
trufflehog github --org=organizzazione-target --token=<github-token> --only-verified
```

### Strumenti nativi prima di installare tool esterni

Prima di tirare fuori TruffleHog, un grep mirato su una clone locale del repo copre già i pattern più comuni, senza dipendenze:

```bash
git clone https://github.com/organizzazione-target/repo-pubblico
cd repo-pubblico
grep -rE "(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|-----BEGIN.*PRIVATE KEY-----)" .
```

Utile per una verifica rapida in fase di recon, prima di lanciare uno scan completo con tool dedicati che copre anche l'intera commit history (dove i secret rimossi nell'ultimo commit sono spesso ancora presenti).

### Storia completa, non solo l'ultimo commit

Un errore comune: controllare solo lo stato attuale del repo. Un secret rimosso con un commit successivo resta nella cronologia Git finché quella history non viene riscritta — e anche dopo, copie in fork, clone locali o cache possono conservarlo:

```bash
trufflehog git file://./repo-pubblico --results=verified,unknown
```

Questo scansiona *tutta* la cronologia, non solo l'HEAD — dove finiscono la maggior parte dei secret dimenticati.

***

## Trovare Secret in Log, Docker e Artifact

Molti audit si fermano al codice sorgente e dimenticano che i secret finiscono anche altrove:

* **Log applicativi** (`application.log`, `debug.log`) — uno stacktrace con una connection string completa, stampato per errore in debug mode
* **Log del web server** (`nginx.log`, `access.log`) — un token passato come query parameter invece che come header finisce loggato in chiaro
* **Artifact di build** — file ZIP di release, cache CI/CD, pacchetti npm pubblicati per errore con un `.npmrc` che contiene un token
* **Layer Docker** — un `COPY .env .` in un Dockerfile lascia il file nei layer intermedi dell'immagine, anche se un comando successivo lo cancella nel layer finale

```bash
# TruffleHog copre anche filesystem generico, utile per log e cache locali
trufflehog filesystem /var/log/ --results=verified,unknown
```

```bash
# Controllo mirato su un artifact ZIP prima di pubblicarlo
unzip -p release.zip | trufflehog stdin
```

### Kubernetes — stessa logica, oggetti diversi

Se il target usa Kubernetes, i secret vivono anche in Secret object, ConfigMap e Helm chart — spesso in chiaro se non è configurata la cifratura at-rest. Esporta prima in un file controllato, poi passalo al detector:

```bash
kubectl get secrets --all-namespaces -o json > k8s-secrets-export.json
trufflehog filesystem k8s-secrets-export.json --results=verified,unknown
```

Verifica sempre la sintassi esatta contro la versione di TruffleHog che stai usando — le opzioni di scansione filesystem possono cambiare tra release.

Per i manifest YAML prima del deploy, lo stesso principio di shift-left visto per Terraform nella nostra guida alla cloud security automation si applica con Checkov anche qui.

### L'errore Docker più comune: `rm` dopo `COPY`

```dockerfile
COPY .env .
RUN pip install -r requirements.txt
RUN rm .env
```

Sembra pulito: il file non c'è più nell'immagine finale. In realtà Docker costruisce a **layer**, e `.env` rimane nel layer creato dal `COPY` — chi ha accesso all'immagine può estrarlo dai layer intermedi con `docker save`, anche se l'ultimo layer non lo mostra più:

```bash
docker save nome-immagine | tar -x -O -f - <layer-id>/layer.tar | tar -t
```

La soluzione corretta è un **multi-stage build**, dove il file non entra mai nell'immagine finale, oppure passare il secret come build-time secret (`--secret` di BuildKit) invece che come file copiato.

### Perché nessuno scanner trova tutto — i falsi negativi

Gitleaks e TruffleHog cercano pattern riconoscibili. Un secret offuscato può ridurre sensibilmente la probabilità di detection, soprattutto quando non corrisponde più al pattern atteso dal detector:

```python
# Più difficile da trovare per un regex scanner: la chiave è spezzata
key = "AKIA" + "IOSFODNN7EXAMPLE"

# Più difficile da trovare: codificato in modo non standard per il detector
import base64
secret = base64.b64decode("QUtJQUlPU0ZPRE5ON0VYQU1QTEU=")
```

Alcuni scanner supportano il decoding di formati comuni come base64 durante la scansione, ma un'offuscazione anche minima può comunque eludere pattern non pensati per quel caso specifico. Motivo in più per non fidarsi solo dello scanner: una code review umana su codice sensibile (auth, config, gestione credenziali) resta preziosa.

***

## Pattern di Secret più Comuni da Riconoscere

| Servizio                | Pattern indicativo                                                                                                             | Validazione                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| AWS Access Key          | `AKIA[0-9A-Z]{16}`                                                                                                             | Verificabile via API AWS                          |
| GitHub Token (classico) | `ghp_[a-zA-Z0-9]{36}`                                                                                                          | Verificabile via API GitHub                       |
| GitHub Fine-grained PAT | `github_pat_[a-zA-Z0-9_]{82}` — i nuovi token GitHub, sempre più diffusi                                                       | Verificabile via API GitHub                       |
| Slack Token             | `xox[baprs]-[0-9a-zA-Z-]{10,}`                                                                                                 | Verificabile via API Slack                        |
| Stripe Secret Key       | `sk_live_[0-9a-zA-Z]{24}`                                                                                                      | Verificabile via API Stripe                       |
| Google API Key          | `AIza[0-9A-Za-z\-_]{35}`                                                                                                       | Verificabile via API Google                       |
| Azure Storage Key       | stringa base64 di 88 caratteri in `AccountKey=`                                                                                | Verificabile via API Azure                        |
| JWT                     | struttura `header.payload.signature`, header Base64URL spesso riconoscibile da `eyJ`                                           | Non indica di per sé se il token è ancora valido  |
| SSH/Private Key         | blocco `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN OPENSSH PRIVATE KEY-----` o `-----BEGIN PRIVATE KEY-----` (non solo RSA) | Non verificabile via API, va testata direttamente |

Sia Gitleaks che TruffleHog hanno già questi pattern nei detector di default — questa tabella serve per riconoscerli a occhio durante una review manuale, quando lo scanner non è a portata di mano. La colonna "Validazione" distingue la semplice detection (il pattern sembra un secret) dalla verifica (il secret funziona davvero).

***

## Priorità di un Secret Trovato

Non tutti i secret trovati hanno lo stesso impatto — utile per dare priorità in un report:

| Tipo                                 | Priorità indicativa |
| ------------------------------------ | ------------------- |
| Credenziale fake/di test             | Bassa               |
| Secret già revocato                  | Bassa/Media         |
| API key con permessi limitati        | Media               |
| API key di produzione                | Alta                |
| Credenziale amministrativa cloud     | Critica             |
| Private key con accesso a produzione | Critica             |

## Secret Trovato ≠ Compromissione

Un pattern che sembra un secret non è ancora un finding completo. La sequenza corretta prima di scriverlo in un report:

```
Pattern trovato
      ↓
È davvero un secret, o un falso positivo?
      ↓
È ancora valido?
      ↓
Quali permessi possiede?
      ↓
Quale asset protegge?
      ↓
Ci sono segnali che sia già stato usato?
      ↓
Impatto reale
```

Questa è la differenza tra un output grezzo di uno scanner e un vero security assessment: il valore sta nel completare la catena, non solo nel far girare il tool.

***

## Recon Senza Rumore

Uno scan `trufflehog github --org` con verifica attiva genera chiamate reali alle API dei servizi proprietari dei secret trovati (AWS, Stripe, GitHub) — questo *non* è rumore verso il target, ma verso il provider del secret stesso. Se il secret è reale, quella chiamata di verifica può comparire nei log del servizio compromesso. Non tutti i detector di TruffleHog effettuano verifica via API — dipende dal tipo di secret e dal detector specifico.

**Low-noise:** `gitleaks git .` — solo pattern matching locale, nessuna chiamata esterna.
**Attenzione:** `trufflehog --only-verified` — per i detector che la supportano, ogni verifica è una richiesta reale contro l'API del servizio; se stai testando in un contesto dove anche questo deve restare silenzioso, usa prima uno scan senza verifica per l'individuazione, poi valuta caso per caso quali verificare manualmente.

***

## Errori Comuni

| Errore                                                        | Cosa controllare                                                                                             |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Gitleaks non trova niente in un repo che sai contenere secret | stai scansionando solo l'ultimo commit o solo la working tree — usa `gitleaks git .` per la history completa |
| TruffleHog troppo lento in pre-commit                         | passa `--only-verified` o sposta la verifica su push/CI invece che su ogni commit                            |
| Troppi falsi positivi con Gitleaks                            | configura un `.gitleaks.toml` con allowlist mirata, non intere directory generiche                           |
| `git commit --no-verify` bypassa l'hook locale                | serve sempre un secondo livello in CI — l'hook locale da solo non basta                                      |
| Shallow clone o branch esclusi dallo scan                     | verifica che la CI faccia un checkout con history completa (`fetch-depth: 0`)                                |
| Falso positivo trattato come incidente reale                  | verifica sempre validità e permessi prima di aprire un incidente                                             |
| Secret revocato ma mai rimosso dalla history                  | la revoca elimina il rischio immediato, ma la history va comunque ripulita per igiene generale               |

***

## Hardening Rapido (Lato Difensivo)

* **Gitleaks pre-commit + TruffleHog in CI** — due livelli, uno bypassabile localmente, l'altro no
* **`--only-verified` come gate di blocco** dove disponibile — meno rumore, azioni concrete sui secret confermati live
* **Rotazione immediata** di qualsiasi secret trovato verificato — trattalo come incidente, non come task da backlog
* **Vault dedicato** (HashiCorp Vault, AWS Secrets Manager) invece di variabili d'ambiente in chiaro nei file di config
* **Credenziali a vita breve e workload identity**, dove il provider lo consente, invece di chiavi statiche di lunga durata
* **Scan periodico della history completa**, non solo dei nuovi commit — i secret vecchi restano nella cronologia finché qualcuno non la riscrive

***

## Workflow di Rotazione — Cosa Fare Passo Passo Quando Trovi un Secret

Non basta dire "ruotalo". La sequenza corretta:

```
Secret trovato (verificato attivo)
      ↓
Valuta scope e impatto potenziale
      ↓
Revoca/ruota il secret presso il provider (AWS/Stripe/GitHub console)
      ↓
Controlla i log del servizio per uso non autorizzato
      ↓
Genera un nuovo secret e aggiorna CI/CD e vault (mai il file sorgente originale)
      ↓
Rimuovi il secret dalla history Git (git-filter-repo o BFG)
      ↓
Verifica che non resti esposto in fork, clone locali, PR o cache
      ↓
Chiudi l'incidente con nota su causa e remediation
```

Il passaggio spesso saltato è la **verifica dei log**: revocare la chiave non ti dice se qualcuno l'ha già usata. Controlla CloudTrail (AWS), audit log (GitHub), o i log applicativi del servizio prima di considerare chiuso l'incidente.

### L'errore più comune: pensare che `git rm` basti

```bash
git rm .env
git commit -m "rimosso .env"
```

Questo non cancella nulla dalla history. Il file `.env` con dentro il secret resta perfettamente recuperabile in un commit precedente — chiunque cloni il repo può risalirci con `git log -- .env` seguito da `git show <commit>`. Serve riscrivere la history, non aggiungere un commit sopra.

### Rimuovere davvero un secret dalla history — git-filter-repo

```bash
pip install git-filter-repo --break-system-packages
```

Per eliminare un file specifico da tutta la history:

```bash
git filter-repo --path .env --invert-paths
```

Per sostituire un valore specifico (es. una chiave trovata) ovunque compaia, senza rimuovere l'intero file:

```bash
echo "AKIAIOSFODNN7EXAMPLE==>***RIMOSSO***" > replacements.txt
git filter-repo --replace-text replacements.txt
```

**git-filter-repo vs BFG:** git-filter-repo è oggi lo strumento raccomandato da Git stesso per riscrivere la history, più veloce e flessibile. BFG resta un'alternativa valida se preferisci un jar Java pronto all'uso senza installare dipendenze Python.

**Il force-push non è una cancellazione globale.** Dopo il rewrite serve un `git push --force`, ma il secret può restare recuperabile in fork, clone locali già scaricati, pull request aperte o cache del provider Git — la rimozione completa spesso richiede interventi aggiuntivi oltre al rewrite lato tuo repository. E soprattutto: **la rotazione del secret resta obbligatoria comunque** — riscrivere la history non serve a niente se la chiave è già stata vista da qualcuno prima del rewrite.

### Baseline vs Nuovi Leak

Al primo scan di un repository esistente, aspettati centinaia di risultati — quello è il tuo **baseline**. Non ha senso trattarli tutti come incidenti attivi nello stesso momento. **detect-secrets** (di Yelp) è pensato apposta per questo: a differenza di Gitleaks/TruffleHog, il suo scopo primario non è bloccare, ma congelare uno stato iniziale e segnalare solo le differenze:

```bash
pip install detect-secrets --break-system-packages
detect-secrets scan > .secrets.baseline
```

Poi, ad ogni scan successivo:

```bash
detect-secrets scan --baseline .secrets.baseline
```

Restituisce solo i secret *nuovi* rispetto al baseline salvato. Utile su un repository legacy con centinaia di secret storici che non puoi ruotare tutti subito.

***

## Tool a Confronto

| Tool                   | Detection               | Verifica                         | Git history   | CI/CD         | Uso ideale  |
| ---------------------- | ----------------------- | -------------------------------- | ------------- | ------------- | ----------- |
| Gitleaks               | ✅                       | ❌                                | ✅             | ✅             | pre-commit  |
| TruffleHog             | ✅                       | ✅ (dove il detector la supporta) | ✅             | ✅             | verifica    |
| detect-secrets         | ✅                       | ❌                                | Solo baseline | ✅             | repo legacy |
| GitHub Secret Scanning | ✅                       | Per alcuni provider              | ✅             | Nativo GitHub | GitHub-only |
| Checkov                | ✅ (regole statiche IaC) | ❌                                | ❌             | ✅             | config/IaC  |

Lettura rapida: se ti serve *sapere se è ancora sfruttabile*, TruffleHog (per i detector che verificano). Se ti serve *velocità offline*, Gitleaks. Se hai un repo legacy pieno di rumore storico, detect-secrets con baseline. Nessuno copre tutto da solo.

### Il Costo Nascosto della Verifica Live

Ogni verifica di TruffleHog contro un'API esterna è una vera chiamata verso il servizio del secret (AWS, Stripe, GitHub...). Su uno scan con migliaia di candidati, questo significa potenzialmente migliaia di richieste esterne — con relativo rischio di **rate limiting** da parte del provider stesso. Per scan massivi, considera prima un pass senza verifica per ridurre il volume, poi verifica solo i candidati più plausibili.

***

## Secret Manager a Confronto — Dove Mettere i Secret Dopo Averli Ruotati

| Secret Manager        | Ambito                   |
| --------------------- | ------------------------ |
| AWS Secrets Manager   | AWS                      |
| HashiCorp Vault       | Multi-cloud, self-hosted |
| Azure Key Vault       | Azure                    |
| Google Secret Manager | GCP                      |

Scansionare e ruotare senza avere un posto sicuro dove mettere il nuovo secret riporta al punto di partenza — un vault è il passo finale del workflow di rotazione, non un optional.

***

## Pipeline CI/CD — Oltre GitHub Actions

Lo stesso principio (scan bloccante sulla pull request) si applica a qualsiasi piattaforma:

| Piattaforma    | Come integrarlo                                                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| GitHub Actions | action ufficiale `trufflesecurity/trufflehog@main` (vista sopra)                                                                      |
| GitLab CI      | step nello stage `test` che esegue TruffleHog/Gitleaks, oppure la Secret Detection nativa di GitLab                                   |
| Jenkins        | stage dedicato nella `Jenkinsfile` che lancia lo scan e usa `currentBuild.result = 'FAILURE'` se il tool esce con codice diverso da 0 |
| Azure DevOps   | task di tipo `Bash@3` nella pipeline YAML che esegue lo scan e usa `exit 1` per bloccare la build                                     |

Il principio è identico ovunque: eseguire il binario, controllare l'exit code, bloccare la pipeline se trova un match. Cambia solo la sintassi di orchestrazione.

***

## MITRE ATT\&CK

| Tattica                      | Tecnica                                                     | Applicazione                                                        |
| ---------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------- |
| Credential Access            | T1552.001 — Credentials In Files                            | Secret hardcoded trovato in codice/config                           |
| Reconnaissance               | T1593.003 — Search Open Websites/Domains: Code Repositories | Ricerca su repository pubblici                                      |
| Initial Access / Persistence | T1078 — Valid Accounts                                      | Uso della credenziale valida trovata, fase successiva alla scoperta |

Matrice completa: [MITRE ATT\&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)

***

## Checklist Operativa

```
[ ] Gitleaks installato come pre-commit hook (comandi git/dir/stdin aggiornati)
[ ] .gitleaks.toml configurato con allowlist mirata, non directory intere
[ ] TruffleHog in pipeline CI/CD con --only-verified
[ ] Scan periodico della history completa, non solo nuovi commit
[ ] Piano di rotazione immediata per ogni secret verificato trovato
[ ] git-filter-repo pronto per riscrivere la history, non solo git rm
[ ] Vault dedicato al posto di secret hardcoded in config
[ ] Verifica fork/clone/PR/cache dopo un rewrite della history
```

***

## FAQ

**Gitleaks o TruffleHog, quale scegliere se posso usarne solo uno?**
Gitleaks se ti serve velocità e semplicità in locale. TruffleHog se ti serve sapere se il secret trovato è ancora sfruttabile. Per la maggior parte dei team la risposta corretta è entrambi, a stadi diversi.

**Un pre-commit hook basta a fermare tutti i leak?**
No. `git commit --no-verify` lo bypassa. Serve sempre un secondo controllo lato CI/CD che nessun developer può saltare.

**Cercare secret nei repo pubblici di un'azienda durante un pentest è legale?**
Sì, se rientra nello scope autorizzato dell'engagement — è una tecnica OSINT standard, esattamente come cercare subdomain o email esposte.

**Cosa fare appena trovo un secret verificato attivo?**
Trattalo come incidente: revoca/ruota subito la credenziale, poi controlla i log del servizio per capire se è già stata usata da qualcun altro.

**`git rm` sul file con il secret basta a metterlo in sicurezza?**
No. Il file resta recuperabile in un commit precedente. Serve riscrivere la history con git-filter-repo (o BFG) e comunque ruotare il secret — il rewrite da solo non basta se qualcuno l'ha già visto.

**Gli scanner automatici trovano sempre tutti i secret?**
No. Un secret spezzato in più stringhe o codificato in modo non standard può eludere un regex scanner. Per codice davvero sensibile, una review umana resta necessaria.

**Come scansiono tutta la Git history alla ricerca di secret?**
Con `gitleaks git .` (che copre l'intera history per default) o `trufflehog git file://. --results=verified,unknown`, non fermandoti a un controllo del solo stato attuale.

**Gitleaks può verificare se una chiave è ancora valida?**
No, Gitleaks fa solo detection basata su pattern, non verifica live. Per quello serve TruffleHog (sui detector che la supportano) o un controllo manuale contro l'API del servizio.

**Cosa fare se un secret è già stato pubblicato su GitHub?**
Trattalo come compromesso: revoca/ruota subito, controlla i log del provider per uso non autorizzato, poi valuta la rimozione dalla history — sapendo che potrebbe già essere stato clonato o messo in cache prima che tu intervenga.

***

*Documentazione ufficiale: [TruffleHog su GitHub](https://github.com/trufflesecurity/trufflehog), [Gitleaks su GitHub](https://github.com/gitleaks/gitleaks). Per l'enumerazione cloud dopo aver trovato una chiave, vedi la nostra guida al pentest AWS, e [LinEnum su HackIta](https://hackita.it/articoli/linenum/) per i secret già presenti su Linux.*
