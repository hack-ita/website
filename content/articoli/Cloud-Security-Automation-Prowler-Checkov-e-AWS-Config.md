---
title: 'Cloud Security Automation: Prowler, Checkov e AWS Config'
slug: cloud-security-automation
description: 'Cloud security automation su AWS: usa Prowler, ScoutSuite e AWS Config; integra Checkov e tfsec nella CI/CD e rileva drift e misconfiguration con EventBridge.'
image: /cloud-security-automation-pipeline.webp
draft: true
date: 2026-08-22T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - Cloud Security Automation
  - AWS Config
  - Prowler
  - Checkov
  - Infrastructure as Code
  - CI/CD Security
---

# Cloud Security Automation: Automatizzare Audit, Scanning e Security Pipeline

Un audit cloud manuale fotografa un momento. In un ambiente dove IAM, S3 e Lambda cambiano ogni giorno via CI/CD, un audit fatto una volta è già superato la settimana dopo. Questa guida copre come automatizzare le scansioni — sia lato offensivo (recon ricorrente su un target), sia lato difensivo (audit continuo integrato in pipeline).

**Quando usarla:** pentest cloud con scope ricorrente, DevSecOps interno, hardening continuo su ambienti AWS.
**Cosa copre:** scheduling di ScoutSuite/Prowler, scanning IaC (Terraform/CloudFormation) in CI/CD, script di enumerazione ripetibili.
**Cosa non copre:** dettagli di sfruttamento IAM/S3 — per quello vedi la nostra guida al pentest AWS (IAM, S3, EC2).

***

## Cos'è la Cloud Security Automation?

La cloud security automation è l'automatizzazione dei controlli di sicurezza, dell'audit e del rilevamento di misconfiguration negli ambienti cloud, invece di affidarsi solo a verifiche manuali periodiche. Su AWS significa controllare in modo continuo IAM, S3, EC2 e l'infrastructure as code, così che una configurazione rischiosa venga rilevata in ore o minuti invece che al prossimo audit programmato.

## Perché Automatizzare la Sicurezza Cloud?

Un bucket S3 reso pubblico per errore durante un deploy alle 3 di notte resta esposto finché qualcuno non lo controlla di nuovo. La differenza tra un audit fatto bene e uno fatto bene *una volta* è l'automazione.

Casi reali che l'automazione intercetta e un audit manuale mensile no:

* un merge introduce una policy IAM con `"Action": "*"` per errore, in produzione da giorni prima del prossimo audit programmato
* un bucket S3 diventa pubblico dopo un deploy che sovrascrive l'ACL
* un secret hardcoded finisce in un file Terraform e viene committato
* l'ambiente dev ha `IMDSv1` attivo, prod no — drift silenzioso che nessuno nota finché non lo confronti

***

## Migliori Tool per Cloud Security Automation

| Tool        | Utilizzo                                             | Ambito                      | CI/CD |
| ----------- | ---------------------------------------------------- | --------------------------- | ----- |
| AWS Config  | Compliance e drift detection continua                | AWS                         | Sì    |
| Prowler     | Security audit con compliance mapping (CIS, PCI-DSS) | AWS, multi-cloud            | Sì    |
| ScoutSuite  | Cloud security assessment, report cross-servizio     | Multi-cloud                 | Sì    |
| Checkov     | IaC security scanning                                | Multi-cloud, più framework  | Sì    |
| tfsec       | Terraform security scanning                          | AWS/Azure/GCP via Terraform | Sì    |
| EventBridge | Detection near-real-time su eventi specifici         | AWS                         | Sì    |

***

## Come Automatizzare un Audit AWS

### Fase 0 — Strumenti Nativi Prima del Tooling Esterno

Approccio nativo prima di tutto: **AWS Config** valuta continuamente lo stato delle risorse con regole gestite, senza installare nulla:

```bash
aws configservice put-config-rule --config-rule file://s3-public-read-rule.json
```

Usa questo per compliance nativa senza dipendenze esterne. Passa a ScoutSuite/Prowler quando serve un report cross-servizio leggibile o compliance mapping (CIS, PCI-DSS).

### Fase 1 — Scheduling di ScoutSuite

```bash
pip install scoutsuite --break-system-packages
scout aws --profile default --report-dir /var/reports/scoutsuite-$(date +%F)
```

Automatizza con cron per avere uno snapshot giornaliero:

```bash
# crontab -e
0 3 * * * /usr/local/bin/scout aws --profile default --report-dir /var/reports/scoutsuite-$(date +\%F) >> /var/log/scoutsuite.log 2>&1
```

**Diff tra due scansioni — cosa è cambiato da ieri.** ScoutSuite salva i risultati in JSON. Un diff mirato ti dice cosa è cambiato senza rileggere l'intero report:

```bash
diff <(jq -S . /var/reports/scoutsuite-2026-07-05/scoutsuite_results.json) \
     <(jq -S . /var/reports/scoutsuite-2026-07-06/scoutsuite_results.json) > drift.diff
```

Questo è il concetto di **drift detection**: non ti interessa lo stato assoluto ogni volta, ti interessa cosa è cambiato rispetto a ieri.

### Fase 2 — Prowler in Pipeline CI/CD

```bash
pip install prowler --break-system-packages
prowler aws --output-formats json-ocsf --output-directory ./prowler-report
```

Esempio di step in una pipeline GitHub Actions, per bloccare il merge se emergono findings critici:

```yaml
- name: Prowler Cloud Security Scan
  run: |
    pip install prowler
    prowler aws --severity critical high --output-formats json-ocsf --output-directory ./report
    CRITICAL=$(jq '[.[] | select(.status_code=="FAIL")] | length' ./report/*.ocsf.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Trovati $CRITICAL finding critici, blocco il deploy"
      exit 1
    fi
```

Questo trasforma un audit periodico in un **gate automatico**: nessun deploy con misconfiguration critiche note passa in produzione.

### Fase 3 — Scansione IaC Prima del Deploy (Shift-Left)

Trovare la misconfiguration nel codice Terraform prima che diventi un bucket reale è molto più economico che trovarla dopo con ScoutSuite.

```bash
pip install checkov --break-system-packages
checkov -d ./terraform --framework terraform
```

```bash
# tfsec, alternativa focalizzata solo su Terraform
tfsec ./terraform
```

Esempio di regola che Checkov intercetta prima del deploy:

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "azienda-data-prod"
  acl    = "public-read"  # <- Checkov lo segnala come CKV_AWS_20
}
```

Integrazione in pipeline, stesso principio del gate visto per Prowler:

```yaml
- name: IaC Security Scan
  run: |
    pip install checkov
    checkov -d ./terraform --framework terraform --compact --quiet
```

### Fase 4 — Script di Enumerazione Ricorrente (Lato Offensivo)

Per un engagement con scope su più giorni, uno script che ripete l'enumerazione base e segnala solo le differenze è più efficiente che rilanciare ScoutSuite ogni volta a mano.

```bash
#!/bin/bash
# recon-diff.sh — enumerazione IAM/S3 ripetibile, evidenzia solo cosa cambia
OUTDIR="./recon-$(date +%F)"
mkdir -p "$OUTDIR"

aws iam list-users > "$OUTDIR/users.json"
aws iam list-roles > "$OUTDIR/roles.json"
aws s3 ls > "$OUTDIR/buckets.txt"

PREV=$(ls -d ./recon-* 2>/dev/null | sort | tail -2 | head -1)
if [ -n "$PREV" ] && [ "$PREV" != "$OUTDIR" ]; then
  echo "--- Nuovi utenti IAM ---"
  diff "$PREV/users.json" "$OUTDIR/users.json"
  echo "--- Nuovi bucket S3 ---"
  diff "$PREV/buckets.txt" "$OUTDIR/buckets.txt"
fi
```

Utile in un red team engagement lungo: un nuovo bucket o un nuovo utente IAM comparso durante il test è spesso il segnale di una modifica in corso da parte del blue team, o una nuova superficie da testare.

### Fase 5 — EventBridge per la Detection in Tempo Reale

**CloudWatch Events / EventBridge** reagisce in tempo reale a eventi specifici (es. `PutBucketAcl` con ACL pubblica) senza aspettare uno scanning periodico:

```bash
aws events put-rule --name detect-public-s3 \
  --event-pattern '{"source":["aws.s3"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventName":["PutBucketAcl"]}}'
```

Questo intercetta l'evento nel momento esatto in cui accade, invece di aspettare il prossimo scan schedulato — è la differenza tra rilevare un problema dopo 24 ore o dopo 24 secondi.

***

## Recon Senza Rumore

Anche l'automazione genera log. Uno scan Prowler/ScoutSuite completo ogni notte su tutti i servizi e region è centinaia di chiamate `Describe*`/`List*` concentrate in pochi minuti — pattern potenzialmente riconoscibile da GuardDuty se lanciato da un account non atteso.

AWS Config ed EventBridge sono servizi nativi e si integrano naturalmente nella normale architettura di monitoring dell'account — ma essere nativi non li rende automaticamente "invisibili": anche le attività che generano vanno considerate nel modello di logging e detection complessivo, specialmente se configurati o interrogati in modo anomalo rispetto all'uso quotidiano.

**Se il test richiede stealth:** esegui gli scan Prowler/ScoutSuite dallo stesso ruolo e range IP usati per l'attività quotidiana, o distribuiscili nell'arco della giornata invece che in un'unica finestra concentrata.

***

## Cloud Security Automation vs Pentest Manuale

|                 | Automation                         | Pentest / Assessment manuale                 |
| --------------- | ---------------------------------- | -------------------------------------------- |
| Frequenza       | Continua                           | Periodico                                    |
| Esecuzione      | Automatizzata                      | Manuale + tool di supporto                   |
| Cosa trova      | Misconfiguration note              | Percorsi di attacco specifici dell'ambiente  |
| Contesto tipico | CI/CD, drift detection, compliance | Exploitation, catena di privilege escalation |

L'automazione identifica rapidamente configurazioni rischiose note, ma non sostituisce un penetration test: da sola non determina il percorso di attacco reale né il blast radius di una compromissione — quello richiede ancora l'analisi umana vista nella guida al pentest AWS.

***

## Cosa Usare Quando

| Esigenza                                        | Strumento                        |
| ----------------------------------------------- | -------------------------------- |
| Compliance continua senza tool esterni          | AWS Config                       |
| Report leggibile cross-servizio per un cliente  | ScoutSuite o Prowler             |
| Bloccare deploy con misconfiguration note       | Prowler in pipeline (gate CI/CD) |
| Bloccare Terraform prima ancora del deploy      | Checkov o tfsec (shift-left)     |
| Reagire a un evento critico in secondi, non ore | EventBridge                      |
| Recon ripetuto su un engagement lungo           | script diff custom (Fase 4)      |

***

## Errori Comuni

| Errore                                     | Cosa controllare                                                        |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| `RateLimitExceeded`                        | riduci i worker/thread dello scanner                                    |
| Checkov non trova risorse                  | esegui `terraform init` prima dello scan                                |
| ScoutSuite si blocca su un servizio        | il profilo IAM usato deve avere almeno `ReadOnlyAccess`                 |
| Gate CI/CD non blocca nonostante i finding | verifica con `jq` la struttura reale del JSON prima di scriptarci sopra |

***

## Hardening Rapido (Lato Difensivo)

* **AWS Config attivo** su tutte le region con le regole gestite principali (S3 pubblico, MFA root, IMDSv2)
* **Gate CI/CD** su Checkov/tfsec — nessun Terraform con misconfiguration critiche arriva in produzione
* **EventBridge su eventi ad alto rischio** (`PutBucketAcl`, `AttachUserPolicy`, `CreateAccessKey`) per detection near-real-time
* **Drift detection giornaliera** — un diff automatico batte una rilettura manuale del report ogni volta
* **Least privilege sul ruolo di scanning stesso** — il tool di audit non deve avere più permessi del necessario per leggere, mai scrivere

***

## Workflow Operativo

```
Codice Terraform (pre-deploy)
      ↓
Checkov / tfsec (shift-left, gate CI/CD)
      ↓
Deploy in produzione
      ↓
AWS Config + EventBridge (detection continua)
      ↓
ScoutSuite / Prowler (scan schedulato, drift detection)
      ↓
Report differenziale (solo cosa è cambiato)
      ↓
Remediation o escalation al team
```

***

## MITRE ATT\&CK (Cloud Matrix)

| Tattica         | Tecnica                                |
| --------------- | -------------------------------------- |
| Discovery       | T1580 — Cloud Infrastructure Discovery |
| Defense Evasion | T1562.008 — Disable Cloud Logs         |
| Persistence     | T1098 — Account Manipulation           |
| Collection      | T1530 — Data from Cloud Storage        |

Matrice completa: [MITRE ATT\&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)

***

## Checklist Operativa

```
[ ] AWS Config attivo con regole gestite base
[ ] ScoutSuite/Prowler schedulati (cron o pipeline)
[ ] Diff automatico tra scan consecutivi (drift detection)
[ ] Checkov/tfsec come gate pre-deploy su IaC
[ ] EventBridge su eventi IAM/S3 ad alto rischio
[ ] Script di enumerazione ricorrente per engagement lunghi
[ ] Verifica permessi minimi sul ruolo usato per lo scanning
```

***

## FAQ

**Automatizzare l'audit sostituisce il pentest manuale?**
No. L'automazione copre quello che sai già cercare (misconfiguration note). Il pentest manuale trova le escalation path specifiche di quell'ambiente che nessuno scanner conosce in anticipo.

**Quali sono i migliori strumenti per la cloud security automation?**
Su AWS: AWS Config per compliance continua nativa, ScoutSuite e Prowler per audit cross-servizio, Checkov e tfsec per lo scanning dell'infrastructure as code, EventBridge per la detection in tempo reale.

**Come automatizzo un security audit AWS?**
Parti da AWS Config per compliance continua, aggiungi ScoutSuite o Prowler schedulati (cron o pipeline) per un report periodico, e un diff tra scan consecutivi per la drift detection.

**Come integro la cloud security nella CI/CD?**
Con un gate: Checkov/tfsec sul codice Terraform prima del deploy, Prowler sull'ambiente reale dopo il deploy, entrambi capaci di far fallire la pipeline se emergono finding critici.

**Conviene Checkov o tfsec per lo scanning IaC?**
Checkov copre più framework (Terraform, CloudFormation, Kubernetes, Dockerfile) con un solo tool. tfsec è più leggero e focalizzato solo su Terraform. Per un ambiente misto conviene Checkov.

**Quanto spesso schedulare ScoutSuite/Prowler?**
Giornaliero è lo standard per ambienti che cambiano spesso via CI/CD. Settimanale può bastare per ambienti stabili, ma un evento critico (bucket pubblico) va intercettato in tempo reale con EventBridge, non aspettando il prossimo scan.

**Come rilevo automaticamente il cloud security drift?**
Confrontando via `diff`/`jq` due scan ScoutSuite o Prowler consecutivi, invece di rileggere ogni volta l'intero report — vedi l'esempio nella Fase 1.

**AWS Config basta da solo, senza ScoutSuite/Prowler?**
Per compliance continua sì. Per un report leggibile cross-servizio con mapping CIS/PCI-DSS pronto per un cliente, Prowler resta più pratico.

***

*Documentazione ufficiale: [AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html). Per l'enumerazione IAM/S3/EC2 di base e la parte SSRF/IMDS, vedi la nostra guida al pentest AWS, [Tool Penetration Testing su HackIta](https://hackita.it/articoli/tool-penetration-testing/) e [HTTP e HTTPS su HackIta](https://hackita.it/articoli/http-https/).*
